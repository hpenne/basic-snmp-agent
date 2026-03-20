//! Central event loop for the SNMP agent.
//!
//! The loop multiplexes a TCP listener, accepted connections, and a
//! self-pipe using `mio` (epoll/kqueue). Inbound SNMP requests arrive over
//! plain TCP connections using RFC 3430 BER framing; outbound traps are sent
//! as plain UDP datagrams.
//!
//! # Design
//!
//! [`EventLoop::new`] binds the listener and allocates the self-pipe, then
//! returns a [`CommandSender`] that callers use to send [`Command`]s from any
//! thread. Writing one byte to the pipe's write end wakes the poll call so the
//! event loop drains the mpsc channel promptly.

use std::collections::HashMap;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::mpsc::{self, Receiver, Sender};

use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};

use crate::request;

/// mio token for the TCP listener.
const LISTENER_TOKEN: Token = Token(0);

/// mio token for the self-pipe read end.
const PIPE_TOKEN: Token = Token(1);

/// First token index available for accepted client connections.
const FIRST_CONN_TOKEN: usize = 2;

/// Maximum number of GETBULK repetitions the agent will honour per request.
///
/// Caps the `max-repetitions` field from the wire to prevent a single large
/// bulk request from monopolising the event loop for an extended period.
// Implements: REQ-0029, REQ-0031
const MAX_BULK_REPETITIONS: u32 = 100;

/// Maximum accepted RFC 3430 frame total size (tag + length + content),
/// matching the `SNMPv3` `maxMessageSize` upper bound. Frames whose total
/// size exceeds this are rejected and the connection is closed to prevent
/// memory exhaustion.
const MAX_FRAME_SIZE: usize = 65_535;

// ── EventLoopError ───────────────────────────────────────────────────────────

/// Error returned when [`EventLoop::new`] fails.
///
/// Each variant identifies precisely which operation failed, letting callers
/// map failures to appropriate higher-level errors without relying on
/// `io::ErrorKind` heuristics.
#[derive(Debug)]
pub enum EventLoopError {
    /// TCP listener could not be bound to the requested address.
    Bind { addr: SocketAddr, source: io::Error },
    /// Self-pipe creation or configuration failed.
    Pipe(io::Error),
    /// mio token registration for the listener or self-pipe failed.
    Registration(io::Error),
}

impl fmt::Display for EventLoopError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bind { addr, source } => {
                write!(f, "failed to bind TCP listener to {addr}: {source}")
            }
            Self::Pipe(e) => write!(f, "self-pipe creation failed: {e}"),
            Self::Registration(e) => write!(f, "mio token registration failed: {e}"),
        }
    }
}

impl std::error::Error for EventLoopError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Bind { source, .. } => Some(source),
            Self::Pipe(e) | Self::Registration(e) => Some(e),
        }
    }
}

// ── Command ──────────────────────────────────────────────────────────────────

/// Commands sent from application threads to the event loop.
///
/// Send commands via [`CommandSender::send`], which also wakes the poll loop.
#[derive(Debug)]
pub enum Command {
    /// Upsert a single OID in the MIB store.
    SetValue {
        oid: codec::Oid,
        value: codec::Value,
    },
    /// Shut down the event loop cleanly.
    Shutdown,
    /// Query a single OID from the MIB store and send the result back.
    ///
    /// Compiled only for unit tests within *this crate* (`cfg(test)`).
    /// Integration tests in `transport/tests/` compile the crate without
    /// `cfg(test)` and therefore cannot see this variant. Production code has
    /// no need to read values back out of the event loop — SNMP GET dispatch
    /// handles that.
    #[cfg(test)]
    QueryValue {
        oid: codec::Oid,
        reply: std::sync::mpsc::SyncSender<Option<codec::Value>>,
    },
}

// ── CommandSender ────────────────────────────────────────────────────────────

/// A cloneable handle for sending [`Command`]s to the event loop.
///
/// Wraps an mpsc `Sender` and the write end of the self-pipe. Each call to
/// [`send`][`CommandSender::send`] posts the command to the channel and writes
/// one byte to the pipe so the poll loop wakes up immediately.
///
/// # Clone behaviour
///
/// Cloning duplicates the pipe write fd via `OwnedFd::try_clone` so that each
/// instance owns an independent file descriptor. All clones share the same
/// underlying mpsc channel.
///
/// # Drop behaviour
///
/// The pipe write fd is closed on drop via `OwnedFd`.
///
/// # Examples
///
/// ```no_run
/// use std::net::SocketAddr;
/// use transport::event_loop::{Command, EventLoop};
///
/// let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
/// let engine_id = b"\x80\x00\x1f\x88\x04test".to_vec();
/// let (event_loop, _bound_addr, sender) = EventLoop::new(addr, engine_id).unwrap();
/// sender.send(Command::Shutdown).unwrap();
/// ```
pub struct CommandSender {
    tx: Sender<Command>,
    /// Write end of the self-pipe; `OwnedFd` closes it on drop automatically.
    pipe_write_fd: OwnedFd,
}

// Safety: `OwnedFd` is just an integer fd, and `Sender<Command>` is `Send`.
// The documented contract requires `CommandSender` to be `Send + Sync` so that
// `Agent` (which wraps it) can be shared across threads. This assertion catches
// any future field addition that would break the contract at compile time.
const _: () = {
    fn assert_send_sync<T: Send + Sync>() {}
    fn check() {
        assert_send_sync::<CommandSender>();
    }
    let _ = check;
};

impl CommandSender {
    /// Send a [`Command`] to the event loop and wake it via the self-pipe.
    ///
    /// # Errors
    ///
    /// Returns an error if the event loop thread has exited (broken channel)
    /// or if writing to the self-pipe fails.
    pub fn send(&self, cmd: Command) -> io::Result<()> {
        self.tx
            .send(cmd)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "event loop has exited"))?;
        // Write one byte to wake the poll call; the value is irrelevant.
        let byte: [u8; 1] = [1];
        let write_result =
            unsafe { libc::write(self.pipe_write_fd.as_raw_fd(), byte.as_ptr().cast(), 1) };
        if write_result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Clone for CommandSender {
    fn clone(&self) -> Self {
        // try_clone performs dup(2) and wraps the result in OwnedFd. Panic on
        // failure because Clone cannot return an error and a bad fd would cause
        // silent data loss rather than a clear diagnostic.
        let duped = self
            .pipe_write_fd
            .try_clone()
            .expect("dup failed for CommandSender pipe write fd");
        Self {
            tx: self.tx.clone(),
            pipe_write_fd: duped,
        }
    }
}

// ── ConnectionState ──────────────────────────────────────────────────────────

/// Per-connection state held in the event loop's connection map.
struct ConnectionState {
    stream: mio::net::TcpStream,
    /// Accumulates partially-received bytes until a complete RFC 3430 BER frame arrives.
    read_buf: Vec<u8>,
}

// ── EventLoop ────────────────────────────────────────────────────────────────

/// The mio-driven event loop that owns the TCP listener, accepted connections,
/// the self-pipe read end, and the MIB store.
///
/// Call [`run`][`EventLoop::run`] from a dedicated OS thread. The loop exits
/// when it receives [`Command::Shutdown`].
///
/// # Requirements
/// Implements: REQ-0048, REQ-0050, REQ-0051, REQ-0052, REQ-0053, REQ-0054
///
/// # Examples
///
/// ```no_run
/// use std::net::SocketAddr;
/// use transport::event_loop::EventLoop;
///
/// let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
/// let engine_id = b"\x80\x00\x1f\x88\x04test".to_vec();
/// let (event_loop, bound_addr, sender) = EventLoop::new(addr, engine_id).unwrap();
///
/// let handle = std::thread::spawn(move || event_loop.run());
/// sender.send(transport::event_loop::Command::Shutdown).unwrap();
/// handle.join().unwrap().unwrap();
/// ```
pub struct EventLoop {
    poll: Poll,
    listener: mio::net::TcpListener,
    /// Read end of the self-pipe. `OwnedFd` ensures the fd is closed on drop
    /// even if `run()` is never called or returns early with an error.
    pipe_read_fd: OwnedFd,
    rx: Receiver<Command>,
    /// Next token value to assign to an accepted connection.
    next_token: usize,
    connections: HashMap<Token, ConnectionState>,
    /// MIB store; updated by `SetValue` commands from application threads.
    store: mib::Store,
    /// This agent's `SNMPv3` engine ID; inbound messages with a different engine
    /// ID are discarded (REQ-0057).
    engine_id: Vec<u8>,
}

impl EventLoop {
    /// Create an [`EventLoop`] bound to `addr`, using `engine_id` to validate
    /// inbound `SNMPv3` messages.
    ///
    /// Returns the loop itself, the actual bound address (useful when `addr`
    /// uses port 0 for OS-assigned allocation), and a [`CommandSender`] for
    /// sending commands from other threads.
    ///
    /// # Errors
    ///
    /// Returns [`EventLoopError::Bind`] if the TCP listener cannot be bound,
    /// [`EventLoopError::Pipe`] if the self-pipe cannot be created, or
    /// [`EventLoopError::Registration`] if mio token registration fails.
    ///
    /// # Requirements
    /// Implements: REQ-0048, REQ-0050, REQ-0055, REQ-0068, REQ-0069, REQ-0072
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::net::SocketAddr;
    /// use transport::event_loop::EventLoop;
    ///
    /// let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    /// let engine_id = b"\x80\x00\x1f\x88\x04test".to_vec();
    /// let (event_loop, bound_addr, sender) = EventLoop::new(addr, engine_id).unwrap();
    /// println!("listening on {bound_addr}");
    /// ```
    pub fn new(
        addr: SocketAddr,
        engine_id: Vec<u8>,
    ) -> Result<(Self, SocketAddr, CommandSender), EventLoopError> {
        let poll = Poll::new().map_err(EventLoopError::Registration)?;
        let registry = poll.registry();

        // Bind the TCP listener and record the real address before handing it
        // to mio so callers (tests) know which port was chosen.
        let mut listener = mio::net::TcpListener::bind(addr)
            .map_err(|e| EventLoopError::Bind { addr, source: e })?;
        let bound_addr = listener
            .local_addr()
            .map_err(|e| EventLoopError::Bind { addr, source: e })?;
        registry
            .register(&mut listener, LISTENER_TOKEN, Interest::READABLE)
            .map_err(EventLoopError::Registration)?;

        // Allocate a Unix self-pipe for waking the poll loop from other threads.
        // `create_pipe` returns `OwnedFd` values, so partial failures inside it
        // automatically close any already-created fds.
        let (pipe_read_fd, pipe_write_fd) = create_pipe().map_err(EventLoopError::Pipe)?;

        // Register the pipe read end. If this fails the OwnedFd values are
        // dropped here, which closes the fds without leaking them.
        let mut source = SourceFd(&pipe_read_fd.as_raw_fd());
        registry
            .register(&mut source, PIPE_TOKEN, Interest::READABLE)
            .map_err(EventLoopError::Registration)?;

        let (tx, rx) = mpsc::channel::<Command>();

        let event_loop = Self {
            poll,
            listener,
            pipe_read_fd,
            rx,
            next_token: FIRST_CONN_TOKEN,
            connections: HashMap::new(),
            store: mib::Store::new(),
            engine_id,
        };
        let sender = CommandSender { tx, pipe_write_fd };

        Ok((event_loop, bound_addr, sender))
    }

    /// Run the event loop until [`Command::Shutdown`] is received.
    ///
    /// Intended to be called from a dedicated OS thread. Blocks until shutdown.
    ///
    /// # Requirements
    /// Implements: REQ-0048, REQ-0051, REQ-0052, REQ-0053, REQ-0054
    ///
    /// # Errors
    ///
    /// Returns an error if `mio::Poll::poll` fails unrecoverably.
    pub fn run(mut self) -> io::Result<()> {
        let mut events = Events::with_capacity(128);

        'outer: loop {
            // Block until at least one event is ready.
            self.poll.poll(&mut events, None)?;

            for event in &events {
                match event.token() {
                    LISTENER_TOKEN => {
                        self.accept_connections();
                    }
                    PIPE_TOKEN => {
                        // Drain the pipe bytes, then drain the command channel.
                        drain_pipe(self.pipe_read_fd.as_raw_fd());
                        if self.drain_commands() {
                            break 'outer;
                        }
                    }
                    token => {
                        self.handle_connection_event(token);
                    }
                }
            }
        }

        Ok(())
        // `self.pipe_read_fd` (OwnedFd) is closed here automatically on drop.
    }

    /// Accept all pending connections, registering each with a unique token.
    ///
    /// Transient accept errors (e.g. `EMFILE`, `ENFILE`, `ECONNABORTED`) are
    /// logged and skipped rather than killing the event loop, because a single
    /// resource-exhaustion moment should not bring down the agent.
    // Implements: REQ-0051
    fn accept_connections(&mut self) {
        loop {
            match self.listener.accept() {
                Ok((mut stream, peer_addr)) => {
                    let token = self.next_connection_token();
                    if let Err(e) =
                        self.poll
                            .registry()
                            .register(&mut stream, token, Interest::READABLE)
                    {
                        eprintln!(
                            "[event_loop] failed to register connection from {peer_addr}: {e}"
                        );
                        continue;
                    }
                    eprintln!(
                        "[event_loop] accepted connection from {peer_addr} (token {token:?})"
                    );
                    self.connections.insert(
                        token,
                        ConnectionState {
                            stream,
                            read_buf: Vec::new(),
                        },
                    );
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    // Transient errors should not kill the event loop.
                    eprintln!("[event_loop] accept error (continuing): {e}");
                    // TODO: On transient errors (e.g. EMFILE) we break rather
                    // than continue, so connections still in the kernel backlog
                    // are not drained until the next poll wakeup. A retry loop
                    // with a backlog cap would drain more eagerly under pressure.
                    break;
                }
            }
        }
    }

    /// Drain all pending commands from the mpsc channel.
    ///
    /// Returns `true` if a [`Command::Shutdown`] was received, signalling the
    /// loop should exit.
    // Implements: REQ-0052
    fn drain_commands(&mut self) -> bool {
        loop {
            match self.rx.try_recv() {
                Ok(Command::SetValue { oid, value }) => {
                    self.store.set(oid, value);
                }
                Ok(Command::Shutdown) => {
                    eprintln!("[event_loop] received Shutdown, exiting");
                    return true;
                }
                #[cfg(test)]
                Ok(Command::QueryValue { oid, reply }) => {
                    // Ignore send errors: the test may have timed out or dropped
                    // the receiver, and that should not kill the event loop.
                    let _ = reply.send(self.store.get(&oid).cloned());
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    // All senders have been dropped; treat as shutdown.
                    eprintln!("[event_loop] command channel disconnected, exiting");
                    return true;
                }
            }
        }
        false
    }

    /// Read available bytes from an accepted connection, parse RFC 3430 BER
    /// frames, dispatch each frame to the appropriate request handler, and
    /// write the encoded response back.
    ///
    /// Connection-level I/O errors (e.g. `ConnectionReset`) close and remove
    /// the connection but do not propagate to the caller — a single misbehaving
    /// client must not bring down the entire event loop.
    ///
    /// # Requirements
    /// Implements: REQ-0057, REQ-0058, REQ-0068, REQ-0071, REQ-0073
    fn handle_connection_event(&mut self, token: Token) {
        let Some(conn) = self.connections.get_mut(&token) else {
            return;
        };

        let mut chunk = [0u8; 4096];
        let mut closed = false;

        // Drain all immediately available bytes into the per-connection buffer.
        loop {
            match conn.stream.read(&mut chunk) {
                Ok(0) => {
                    closed = true;
                    break;
                }
                Ok(bytes_read) => {
                    conn.read_buf.extend_from_slice(&chunk[..bytes_read]);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    // Non-WouldBlock errors (e.g. ConnectionReset) mean the
                    // connection is broken; close it rather than killing the loop.
                    eprintln!("[event_loop] connection error (token {token:?}): {e}");
                    closed = true;
                    break;
                }
            }
        }

        // Process all complete RFC 3430 BER frames from the buffer.
        // Each frame is a raw BER SEQUENCE: tag 0x30, BER-encoded length, content.
        loop {
            // Need at least 2 bytes to read the tag and the first length byte.
            if conn.read_buf.len() < 2 {
                break;
            }

            // RFC 3430: frames must begin with the SEQUENCE tag (0x30).
            // A different tag indicates a corrupt or non-SNMP stream.
            if conn.read_buf[0] != 0x30 {
                eprintln!(
                    "[event_loop] non-SEQUENCE tag {:#04x} on token {token:?}, closing",
                    conn.read_buf[0]
                );
                closed = true;
                break;
            }

            // Distinguish incomplete data (wait for more) from invalid encoding (close).
            let (content_length, length_field_bytes) = match parse_ber_length(&conn.read_buf[1..]) {
                Ok(Some(parsed)) => parsed,
                Ok(None) => break,
                Err(()) => {
                    // Invalid BER length encoding (e.g., indefinite-length form 0x80).
                    // The stream is unrecoverable; close the connection.
                    eprintln!(
                        "[event_loop] invalid BER length encoding on token {token:?}, closing"
                    );
                    closed = true;
                    break;
                }
            };

            let total_frame_bytes = 1 + length_field_bytes + content_length;
            if total_frame_bytes > MAX_FRAME_SIZE {
                // Reject oversized frames to prevent memory exhaustion.
                eprintln!(
                    "[event_loop] oversized frame ({total_frame_bytes} bytes) on token {token:?}, closing"
                );
                closed = true;
                break;
            }
            if conn.read_buf.len() < total_frame_bytes {
                // Frame is incomplete; wait for more data on the next read event.
                break;
            }

            // The full BER frame (tag + length field + content) is the payload.
            let ber_frame: Vec<u8> = conn.read_buf[..total_frame_bytes].to_vec();
            conn.read_buf.drain(..total_frame_bytes);

            let Some(encoded_response) =
                Self::dispatch_snmpv3_frame(&ber_frame, token, &self.engine_id, &self.store)
            else {
                continue;
            };

            if let Err(write_error) = conn.stream.write_all(&encoded_response) {
                // Close the connection on any write error, including WouldBlock.
                // write_all on a non-blocking socket may have written a partial
                // response before returning WouldBlock, leaving the framing stream
                // in a corrupt state. Closing is the only safe option.
                eprintln!("[event_loop] write error (token {token:?}): {write_error}, closing");
                closed = true;
                break;
            }
        }

        if closed && let Some(mut conn) = self.connections.remove(&token) {
            if let Err(e) = self.poll.registry().deregister(&mut conn.stream) {
                eprintln!("[event_loop] deregister error (token {token:?}): {e}");
            }
            eprintln!("[event_loop] connection closed (token {token:?})");
        }
    }

    /// Decode, validate, and dispatch a single RFC 3430 BER frame.
    ///
    /// `ber_frame` is the complete BER bytes including the SEQUENCE tag, length
    /// field, and content. Returns `Some(encoded_response)` — raw BER bytes
    /// ready for writing — when the frame produces a response, or `None` when
    /// the frame should be silently discarded (invalid encoding, wrong engine
    /// ID, or unsupported context name).
    // Implements: REQ-0056, REQ-0057, REQ-0058, REQ-0066, REQ-0068, REQ-0073
    fn dispatch_snmpv3_frame(
        ber_frame: &[u8],
        token: Token,
        engine_id: &[u8],
        store: &mib::Store,
    ) -> Option<Vec<u8>> {
        // Decode as an SNMPv3 message. Non-v3 messages are silently discarded
        // per REQ-0073.
        let v3_msg = match codec::decode_v3_message(ber_frame) {
            Err(decode_error) => {
                eprintln!("[event_loop] SNMPv3 decode error (token {token:?}): {decode_error}");
                return None;
            }
            Ok(msg) => msg,
        };

        // Verify the engine ID matches ours. Requests for other engines are
        // silently discarded per REQ-0057.
        if v3_msg.engine_id != engine_id {
            eprintln!(
                "[event_loop] engine ID mismatch on token {token:?}: \
                 expected {:?}, got {:?}",
                engine_id, v3_msg.engine_id
            );
            return None;
        }

        // Only the default (empty) context name is supported per REQ-0058.
        if !v3_msg.context_name.is_empty() {
            eprintln!(
                "[event_loop] non-empty context name on token {token:?}: {:?}",
                v3_msg.context_name
            );
            return None;
        }

        let response = match v3_msg.pdu {
            codec::InboundPdu::GetRequest(req) => request::handle_get(&req, store),
            codec::InboundPdu::GetNextRequest(req) => request::handle_get_next(&req, store),
            codec::InboundPdu::GetBulkRequest(req) => {
                request::handle_get_bulk(&req, store, MAX_BULK_REPETITIONS)
            }
            codec::InboundPdu::SetRequest(req) => request::handle_set(&req),
        };

        // context_name is always empty here: non-empty values were rejected above.
        let encoded_response = match codec::encode_v3_response(
            v3_msg.msg_id,
            engine_id,
            &v3_msg.user_name,
            &v3_msg.context_name,
            &response,
        ) {
            Ok(encoded_bytes) => encoded_bytes,
            Err(encode_error) => {
                eprintln!("[event_loop] response encode error (token {token:?}): {encode_error}");
                return None;
            }
        };

        // The encoded response is already a complete BER frame — no prefix needed.
        Some(encoded_response)
    }

    /// Allocate the next unique connection token, skipping reserved values.
    ///
    /// Wraps safely around `usize::MAX` and skips `LISTENER_TOKEN` and
    /// `PIPE_TOKEN` to avoid collisions with reserved tokens. After wrap-around,
    /// also skips any token already present in the connection map to prevent
    /// silent entry overwrites under theoretical token exhaustion.
    fn next_connection_token(&mut self) -> Token {
        loop {
            let candidate = self.next_token;
            self.next_token = self.next_token.wrapping_add(1);
            // Defensive wrap: `next_token` starts at `FIRST_CONN_TOKEN` so the
            // check below fires only after `usize::MAX` wrapping, which is
            // effectively unreachable in practice. It exists to guarantee
            // correctness even under theoretical token exhaustion.
            if self.next_token < FIRST_CONN_TOKEN {
                self.next_token = FIRST_CONN_TOKEN;
            }
            if candidate >= FIRST_CONN_TOKEN && !self.connections.contains_key(&Token(candidate)) {
                return Token(candidate);
            }
        }
    }
}

/// Create a Unix self-pipe and set both ends to non-blocking mode.
///
/// Returns `(read_fd, write_fd)` as `OwnedFd` values so that any partial
/// failure automatically closes already-created fds on drop.
fn create_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds: [libc::c_int; 2] = [0; 2];
    let pipe_result = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if pipe_result < 0 {
        return Err(io::Error::last_os_error());
    }

    // Safety: pipe(2) succeeded, so both fds are valid and we own them.
    // Wrapping them in OwnedFd immediately means partial failures below
    // automatically close the fds on drop.
    let read_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let write_fd = unsafe { OwnedFd::from_raw_fd(fds[1]) };

    set_nonblocking(read_fd.as_raw_fd())?;
    set_nonblocking(write_fd.as_raw_fd())?;

    Ok((read_fd, write_fd))
}

/// Set a file descriptor to non-blocking mode via `fcntl`.
fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let set_nonblock_result = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if set_nonblock_result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Read and discard all bytes currently available on the pipe read end.
///
/// Stops on `WouldBlock`, which is the expected steady-state after draining.
fn drain_pipe(fd: RawFd) {
    let mut drain_buf = [0u8; 64];
    loop {
        let bytes_read = unsafe { libc::read(fd, drain_buf.as_mut_ptr().cast(), drain_buf.len()) };
        // TODO: `bytes_read <= 0` treats EAGAIN/WouldBlock and genuine errors (e.g.
        // EBADF) identically — both silently stop the drain. A real error here
        // would indicate a programming bug (bad fd); distinguishing the two
        // would improve observability but has no correctness impact in practice.
        if bytes_read <= 0 {
            break;
        }
    }
}

/// Parse a BER length field starting at `buf[0]`.
///
/// Returns:
/// - `Ok(Some((content_length, length_field_bytes)))` — parsed successfully.
/// - `Ok(None)` — buffer is incomplete; caller should wait for more data.
/// - `Err(())` — invalid encoding (indefinite-length form `0x80`, or more than
///   4 length octets); caller should close the connection.
///
/// BER length encoding (X.690 §8.1.3):
/// - Short form: `buf[0]` bit 7 is 0; length = `buf[0]` (0–127); field is 1 byte.
/// - Long form: `buf[0]` bit 7 is 1; low 7 bits = number of subsequent octets N;
///   content length is encoded in the next N octets (big-endian).
// Implements: REQ-0071
fn parse_ber_length(buf: &[u8]) -> Result<Option<(usize, usize)>, ()> {
    if buf.is_empty() {
        return Ok(None);
    }
    if buf[0] & 0x80 == 0 {
        // Short form: the byte itself is the length.
        return Ok(Some((buf[0] as usize, 1)));
    }
    let num_octets = (buf[0] & 0x7f) as usize;
    if num_octets == 0 || num_octets > 4 {
        // Indefinite-length (0x80) or absurdly large (>4 bytes) is a protocol
        // error; the connection cannot recover.
        return Err(());
    }
    if buf.len() < 1 + num_octets {
        // Incomplete length field; caller should wait for more data.
        return Ok(None);
    }
    let mut content_length: usize = 0;
    for &byte in &buf[1..=num_octets] {
        content_length = (content_length << 8) | (byte as usize);
    }
    Ok(Some((content_length, 1 + num_octets)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::SocketAddr;
    use std::thread;
    use std::time::Duration;

    /// The test engine ID shared across all dispatch tests.
    const TEST_ENGINE_ID: &[u8] = b"\x80\x00\x1f\x88\x04test";

    fn any_loopback() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    fn test_engine_id() -> Vec<u8> {
        TEST_ENGINE_ID.to_vec()
    }

    /// Read exactly `expected_len` bytes from `stream`, timing out after 2 seconds.
    fn read_exact_with_timeout(stream: &mut std::net::TcpStream, expected_len: usize) -> Vec<u8> {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut received = vec![0u8; expected_len];
        stream
            .read_exact(&mut received)
            .expect("timed out waiting for response bytes");
        received
    }

    #[test]
    fn given_running_event_loop_when_tcp_client_connects_then_connection_is_accepted() {
        // Verifies: REQ-0050, REQ-0051
        // Given: an event loop bound on a random loopback port.
        let (event_loop, bound_addr, sender) =
            EventLoop::new(any_loopback(), test_engine_id()).unwrap();
        let handle = thread::spawn(move || event_loop.run());

        // When: a TCP client connects.
        let _client = std::net::TcpStream::connect(bound_addr).unwrap();

        // Allow the event loop a moment to call accept().
        thread::sleep(Duration::from_millis(50));

        // Then: the loop exits cleanly after shutdown.
        sender.send(Command::Shutdown).unwrap();
        let event_loop_result = handle.join().expect("event loop thread panicked");
        assert!(event_loop_result.is_ok());
    }

    #[test]
    fn given_running_event_loop_when_shutdown_command_sent_then_loop_exits_cleanly() {
        // Verifies: REQ-0048, REQ-0052, REQ-0053, REQ-0054
        // Given: a running event loop.
        let (event_loop, _bound_addr, sender) =
            EventLoop::new(any_loopback(), test_engine_id()).unwrap();
        let handle = thread::spawn(move || event_loop.run());

        // When: Shutdown is sent.
        sender.send(Command::Shutdown).unwrap();

        // Then: the thread exits and returns Ok.
        let event_loop_result = handle.join().expect("event loop thread panicked");
        assert!(event_loop_result.is_ok());
    }

    #[test]
    fn given_running_event_loop_when_set_value_command_sent_then_loop_drains_channel() {
        // Verifies: REQ-0052
        // Given: a running event loop.
        let (event_loop, _bound_addr, sender) =
            EventLoop::new(any_loopback(), test_engine_id()).unwrap();
        let handle = thread::spawn(move || event_loop.run());

        // When: a SetValue command is followed by Shutdown.
        let oid: codec::Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        sender
            .send(Command::SetValue {
                oid,
                value: codec::Value::Integer32(42),
            })
            .unwrap();
        sender.send(Command::Shutdown).unwrap();

        // Then: the loop processes both commands and exits cleanly.
        let event_loop_result = handle.join().expect("event loop thread panicked");
        assert!(event_loop_result.is_ok());
    }

    #[test]
    fn given_running_event_loop_when_set_value_sent_then_loop_remains_alive_for_shutdown() {
        // Given: a running event loop.
        let (event_loop, _bound_addr, sender) =
            EventLoop::new(any_loopback(), test_engine_id()).unwrap();
        let handle = thread::spawn(move || event_loop.run());

        // When: a SetValue command is sent and the loop is given time to process it.
        let oid: codec::Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        sender
            .send(Command::SetValue {
                oid,
                value: codec::Value::Integer32(42),
            })
            .unwrap();
        thread::sleep(Duration::from_millis(50));

        // Then: the loop has NOT exited — SetValue must not trigger shutdown.
        // If drain_commands always returned true, send() here would fail with BrokenPipe.
        let send_result = sender.send(Command::Shutdown);
        assert!(
            send_result.is_ok(),
            "expected loop to still be running after SetValue, but send returned: {send_result:?}"
        );

        let join_result = handle.join().expect("event loop thread panicked");
        assert!(join_result.is_ok());
    }

    #[test]
    fn given_set_value_command_when_sent_then_mib_store_is_updated() {
        // Verifies: REQ-0066
        // Given: a running event loop.
        let (event_loop, _bound_addr, sender) =
            EventLoop::new(any_loopback(), test_engine_id()).unwrap();
        let handle = thread::spawn(move || event_loop.run());

        let oid: codec::Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();

        // When: a SetValue command is sent.
        sender
            .send(Command::SetValue {
                oid: oid.clone(),
                value: codec::Value::Integer32(99),
            })
            .unwrap();

        // Query the store via the test-only QueryValue command so we can verify
        // the value without requiring GET dispatch (which is not yet wired up).
        // Using the fully-qualified path avoids shadowing the `mpsc` binding
        // brought in by `use super::*`.
        let (reply_tx, reply_rx) = std::sync::mpsc::sync_channel(1);
        sender
            .send(Command::QueryValue {
                oid: oid.clone(),
                reply: reply_tx,
            })
            .unwrap();

        // Then: the store contains the value that was set.
        let stored_value = reply_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("timed out waiting for QueryValue reply");
        assert_eq!(
            stored_value,
            Some(codec::Value::Integer32(99)),
            "expected MIB store to hold Integer32(99) for oid {oid:?}"
        );

        sender.send(Command::Shutdown).unwrap();
        handle.join().expect("event loop thread panicked").unwrap();
    }

    #[test]
    fn given_no_set_value_when_queried_then_mib_returns_none() {
        // Given: a running event loop with no values inserted.
        let (event_loop, _bound_addr, sender) =
            EventLoop::new(any_loopback(), test_engine_id()).unwrap();
        let handle = thread::spawn(move || event_loop.run());

        let oid: codec::Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();

        // When: the OID is queried without having been set.
        let (reply_tx, reply_rx) = std::sync::mpsc::sync_channel(1);
        sender
            .send(Command::QueryValue {
                oid,
                reply: reply_tx,
            })
            .unwrap();

        // Then: the store returns None for the unknown OID.
        let stored_value = reply_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("timed out waiting for QueryValue reply");
        assert_eq!(
            stored_value, None,
            "expected MIB store to return None for an OID that was never set"
        );

        sender.send(Command::Shutdown).unwrap();
        handle.join().expect("event loop thread panicked").unwrap();
    }

    #[test]
    fn given_already_used_token_when_next_connection_token_called_then_token_is_skipped() {
        // Given: an event loop whose connection map already contains token 2
        // (the first candidate after FIRST_CONN_TOKEN). Bind a listener so we
        // can connect to it and get a real mio::net::TcpStream for the map.
        let listener_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let std_listener = std::net::TcpListener::bind(listener_addr).unwrap();
        let bound = std_listener.local_addr().unwrap();

        let mut event_loop = EventLoop {
            poll: Poll::new().unwrap(),
            listener: mio::net::TcpListener::bind("127.0.0.1:0".parse().unwrap()).unwrap(),
            pipe_read_fd: {
                // Create a real pipe so OwnedFd is valid.
                let mut fds: [libc::c_int; 2] = [0; 2];
                unsafe { libc::pipe(fds.as_mut_ptr()) };
                unsafe { OwnedFd::from_raw_fd(fds[0]) }
            },
            rx: mpsc::channel::<Command>().1,
            next_token: FIRST_CONN_TOKEN,
            connections: HashMap::new(),
            store: mib::Store::new(),
            engine_id: test_engine_id(),
        };

        // Connect to the std listener so the TcpStream is valid. mio's
        // connect is non-blocking and always returns Ok immediately on Unix.
        let dummy_stream = mio::net::TcpStream::connect(bound).unwrap();
        event_loop.connections.insert(
            Token(FIRST_CONN_TOKEN),
            ConnectionState {
                stream: dummy_stream,
                read_buf: Vec::new(),
            },
        );

        // When: the next token is requested.
        let token = event_loop.next_connection_token();

        // Then: the returned token must not be the one already in the map.
        assert_ne!(
            token,
            Token(FIRST_CONN_TOKEN),
            "expected token to skip the occupied slot"
        );
        assert!(token.0 >= FIRST_CONN_TOKEN);
    }

    #[test]
    fn given_event_loop_error_bind_when_display_then_contains_address_and_source() {
        let addr: SocketAddr = "127.0.0.1:10161".parse().unwrap();
        let bind_error = EventLoopError::Bind {
            addr,
            source: io::Error::new(io::ErrorKind::AddrInUse, "already in use"),
        };
        let error_message = bind_error.to_string();
        assert!(error_message.contains("127.0.0.1:10161"), "{error_message}");
        assert!(error_message.contains("already in use"), "{error_message}");
    }

    #[test]
    fn given_event_loop_error_pipe_when_display_then_mentions_self_pipe() {
        let pipe_error = EventLoopError::Pipe(io::Error::other("pipe failed"));
        assert!(
            pipe_error.to_string().contains("self-pipe"),
            "{}",
            pipe_error
        );
    }

    #[test]
    fn given_event_loop_error_registration_when_display_then_mentions_registration() {
        let registration_error =
            EventLoopError::Registration(io::Error::other("registration failed"));
        assert!(
            registration_error.to_string().contains("registration"),
            "{}",
            registration_error
        );
    }

    #[test]
    fn given_event_loop_error_when_source_then_returns_inner_io_error() {
        use std::error::Error;

        let addr: SocketAddr = "127.0.0.1:10161".parse().unwrap();
        let bind_err = EventLoopError::Bind {
            addr,
            source: io::Error::new(io::ErrorKind::AddrInUse, "bind source"),
        };
        assert!(
            bind_err
                .source()
                .unwrap()
                .to_string()
                .contains("bind source")
        );

        let pipe_err = EventLoopError::Pipe(io::Error::other("pipe source"));
        assert!(
            pipe_err
                .source()
                .unwrap()
                .to_string()
                .contains("pipe source")
        );

        let reg_err = EventLoopError::Registration(io::Error::other("reg source"));
        assert!(reg_err.source().unwrap().to_string().contains("reg source"));
    }

    // ── parse_ber_length unit tests ───────────────────────────────────────────

    #[test]
    fn given_short_form_length_when_parsed_then_returns_correct_length_and_field_size() {
        // Verifies: REQ-0071
        // Short form: single byte, bit 7 clear.
        assert_eq!(parse_ber_length(&[0x00]), Ok(Some((0, 1))));
        assert_eq!(parse_ber_length(&[0x7f]), Ok(Some((127, 1))));
        assert_eq!(parse_ber_length(&[0x05, 0xAA, 0xBB]), Ok(Some((5, 1))));
    }

    #[test]
    fn given_long_form_one_octet_when_parsed_then_returns_correct_length_and_field_size() {
        // Verifies: REQ-0071
        // Long form: 0x81 means one subsequent octet carries the length.
        assert_eq!(parse_ber_length(&[0x81, 0x80]), Ok(Some((128, 2))));
        assert_eq!(parse_ber_length(&[0x81, 0xFF]), Ok(Some((255, 2))));
    }

    #[test]
    fn given_long_form_two_octets_when_parsed_then_returns_correct_length_and_field_size() {
        // Verifies: REQ-0071
        // Long form: 0x82 means two subsequent octets carry the length.
        assert_eq!(parse_ber_length(&[0x82, 0x01, 0x00]), Ok(Some((256, 3))));
        assert_eq!(parse_ber_length(&[0x82, 0xFF, 0xFF]), Ok(Some((65535, 3))));
    }

    #[test]
    fn given_incomplete_buffer_when_parsed_then_returns_none() {
        // Verifies: REQ-0071
        assert_eq!(parse_ber_length(&[]), Ok(None));
        // Long form but not enough length octets.
        assert_eq!(parse_ber_length(&[0x82, 0x01]), Ok(None));
    }

    #[test]
    fn given_indefinite_length_when_parsed_then_returns_error() {
        // Verifies: REQ-0071
        // 0x80 = indefinite-length form; irrecoverable protocol error.
        assert_eq!(parse_ber_length(&[0x80]), Err(()));
    }

    #[test]
    fn given_oversized_length_field_when_parsed_then_returns_error() {
        // Verifies: REQ-0071
        // 0x85 = 5 subsequent octets; more than 4 is not supported, irrecoverable.
        assert_eq!(parse_ber_length(&[0x85, 0, 0, 0, 0, 1]), Err(()));
    }

    // ── RFC 3430 dispatch tests ───────────────────────────────────────────────

    /// Encode a `GetRequest` as a raw BER `SNMPv3` frame ready for TCP send (RFC 3430).
    fn framed_get_request(msg_id: i32, request_id: i32, oid: &codec::Oid) -> Vec<u8> {
        let pdu = codec::GetRequest {
            request_id,
            varbinds: vec![codec::Varbind {
                oid: oid.clone(),
                value: codec::VarbindValue::Unspecified,
            }],
        };
        // Raw BER output from the codec IS the RFC 3430 frame — no prefix needed.
        codec::encode_v3_get_request(msg_id, TEST_ENGINE_ID, b"", &pdu)
            .expect("encode_v3_get_request must succeed")
    }

    /// Read a complete RFC 3430 BER frame (tag + length + content) from the stream.
    fn read_framed_response(stream: &mut std::net::TcpStream) -> Vec<u8> {
        let tag = read_exact_with_timeout(stream, 1);
        assert_eq!(tag[0], 0x30, "expected SEQUENCE tag 0x30 in response");

        // Reuse parse_ber_length so the test helper stays consistent with
        // the production framing logic and cannot silently diverge.
        let mut length_buf = Vec::with_capacity(5);
        let (content_len, length_field_bytes) = loop {
            let next_byte = read_exact_with_timeout(stream, 1);
            length_buf.push(next_byte[0]);
            match parse_ber_length(&length_buf) {
                Ok(Some(parsed)) => break parsed,
                Ok(None) => {}
                Err(()) => panic!("invalid BER length encoding in response from event loop"),
            }
        };

        let content = read_exact_with_timeout(stream, content_len);

        // Reconstruct the complete BER frame for decode_v3_response_payload.
        let mut frame = Vec::with_capacity(1 + length_field_bytes + content_len);
        frame.extend_from_slice(&tag);
        frame.extend_from_slice(&length_buf[..length_field_bytes]);
        frame.extend_from_slice(&content);
        frame
    }

    /// Decode a raw BER response frame back into a `GetResponse` via the `SNMPv3` path,
    /// so we can assert on `request_id` and varbind values.
    fn decode_v3_response_payload(ber_frame: &[u8]) -> codec::GetResponse {
        use rasn_snmp::v3::{Message as V3Message, ScopedPduData};
        let v3_msg: V3Message = rasn::ber::decode(ber_frame).expect("must decode as V3Message");
        let scoped_pdu = match v3_msg.scoped_data {
            ScopedPduData::CleartextPdu(pdu) => pdu,
            ScopedPduData::EncryptedPdu(_) => panic!("expected cleartext"),
        };
        match scoped_pdu.data {
            rasn_snmp::v2::Pdus::Response(inner) => {
                let error_status =
                    codec::ErrorStatus::from_u32(inner.0.error_status).expect("valid error status");
                let varbinds = inner
                    .0
                    .variable_bindings
                    .into_iter()
                    .map(|vb| {
                        let oid_arcs: Vec<u32> = vb.name.as_ref().to_vec();
                        let oid = codec::Oid::try_from(oid_arcs).unwrap();
                        let value = match vb.value {
                            rasn_snmp::v2::VarBindValue::Value(
                                rasn_smi::v2::ObjectSyntax::Simple(
                                    rasn_smi::v2::SimpleSyntax::Integer(n),
                                ),
                            ) => codec::VarbindValue::Value(codec::Value::Integer32(
                                i32::try_from(n).unwrap(),
                            )),
                            rasn_snmp::v2::VarBindValue::Value(
                                rasn_smi::v2::ObjectSyntax::Simple(
                                    rasn_smi::v2::SimpleSyntax::String(s),
                                ),
                            ) => codec::VarbindValue::Value(codec::Value::OctetString(s.to_vec())),
                            rasn_snmp::v2::VarBindValue::NoSuchObject => {
                                codec::VarbindValue::NoSuchObject
                            }
                            rasn_snmp::v2::VarBindValue::EndOfMibView => {
                                codec::VarbindValue::EndOfMibView
                            }
                            _ => panic!("unexpected VarBindValue variant"),
                        };
                        codec::Varbind { oid, value }
                    })
                    .collect();
                codec::GetResponse {
                    request_id: inner.0.request_id,
                    error_status,
                    error_index: inner.0.error_index,
                    varbinds,
                }
            }
            other => panic!("expected Response PDU in ScopedPdu, got {other:?}"),
        }
    }

    #[test]
    fn given_get_request_when_sent_over_tcp_then_response_is_received() {
        // Verifies: REQ-0021, REQ-0051, REQ-0066, REQ-0068, REQ-0069, REQ-0070, REQ-0071
        // Given: a running event loop with a known OID in the MIB.
        let (event_loop, bound_addr, sender) =
            EventLoop::new(any_loopback(), test_engine_id()).unwrap();
        let loop_handle = thread::spawn(move || event_loop.run());

        let oid: codec::Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        sender
            .send(Command::SetValue {
                oid: oid.clone(),
                value: codec::Value::Integer32(42),
            })
            .unwrap();

        // Wait for the SetValue to be processed before connecting, so the MIB
        // is populated before the GetRequest arrives and dispatch cannot race.
        let (confirm_tx, confirm_rx) = std::sync::mpsc::sync_channel(1);
        sender
            .send(Command::QueryValue {
                oid: oid.clone(),
                reply: confirm_tx,
            })
            .unwrap();
        confirm_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("timed out waiting for SetValue confirmation");

        // When: a TCP client sends a raw BER SNMPv3 GetRequest (RFC 3430 framing).
        let mut client = std::net::TcpStream::connect(bound_addr).unwrap();
        client
            .write_all(&framed_get_request(1, 1, &oid))
            .expect("write must succeed");

        // Then: a raw BER SNMPv3 response is received with the expected value.
        let response_frame = read_framed_response(&mut client);
        let response = decode_v3_response_payload(&response_frame);
        assert_eq!(response.request_id, 1);
        assert_eq!(response.error_status, codec::ErrorStatus::NoError);
        assert_eq!(response.varbinds.len(), 1);
        assert_eq!(response.varbinds[0].oid, oid);
        assert_eq!(
            response.varbinds[0].value,
            codec::VarbindValue::Value(codec::Value::Integer32(42))
        );

        sender.send(Command::Shutdown).unwrap();
        loop_handle
            .join()
            .expect("event loop thread panicked")
            .unwrap();
    }

    #[test]
    fn given_partial_frame_when_split_across_reads_then_response_is_received() {
        // Verifies: REQ-0068, REQ-0071
        // Given: a running event loop with a known OID in the MIB.
        let (event_loop, bound_addr, sender) =
            EventLoop::new(any_loopback(), test_engine_id()).unwrap();
        let loop_handle = thread::spawn(move || event_loop.run());

        let oid: codec::Oid = "1.3.6.1.2.1.1.2.0".parse().unwrap();
        sender
            .send(Command::SetValue {
                oid: oid.clone(),
                value: codec::Value::Integer32(7),
            })
            .unwrap();

        // Wait for the SetValue to be processed before connecting, so the MIB
        // is populated before the GetRequest arrives and dispatch cannot race.
        let (confirm_tx, confirm_rx) = std::sync::mpsc::sync_channel(1);
        sender
            .send(Command::QueryValue {
                oid: oid.clone(),
                reply: confirm_tx,
            })
            .unwrap();
        confirm_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("timed out waiting for SetValue confirmation");

        // When: the framed PDU is sent in two separate writes to simulate
        // TCP segmentation where a frame arrives split across packets.
        let mut client = std::net::TcpStream::connect(bound_addr).unwrap();
        let framed = framed_get_request(2, 2, &oid);
        let midpoint = framed.len() / 2;
        client
            .write_all(&framed[..midpoint])
            .expect("first half write must succeed");
        // A brief pause gives the event loop a chance to process the partial frame,
        // verifying that it correctly waits for more data before dispatching.
        thread::sleep(Duration::from_millis(20));
        client
            .write_all(&framed[midpoint..])
            .expect("second half write must succeed");

        // Then: a complete response is received despite the split delivery.
        let response_frame = read_framed_response(&mut client);
        let response = decode_v3_response_payload(&response_frame);
        assert_eq!(response.request_id, 2);
        assert_eq!(
            response.varbinds[0].value,
            codec::VarbindValue::Value(codec::Value::Integer32(7))
        );

        sender.send(Command::Shutdown).unwrap();
        loop_handle
            .join()
            .expect("event loop thread panicked")
            .unwrap();
    }

    #[test]
    fn given_invalid_snmp_payload_in_sequence_when_received_then_connection_stays_open() {
        // Verifies: REQ-0073
        // Given: a running event loop.
        let (event_loop, bound_addr, sender) =
            EventLoop::new(any_loopback(), test_engine_id()).unwrap();
        let loop_handle = thread::spawn(move || event_loop.run());

        let oid: codec::Oid = "1.3.6.1.2.1.1.3.0".parse().unwrap();
        sender
            .send(Command::SetValue {
                oid: oid.clone(),
                value: codec::Value::Integer32(99),
            })
            .unwrap();

        // Wait for the SetValue to be processed before connecting, so the MIB
        // is populated before the GetRequest arrives and dispatch cannot race.
        let (confirm_tx, confirm_rx) = std::sync::mpsc::sync_channel(1);
        sender
            .send(Command::QueryValue {
                oid: oid.clone(),
                reply: confirm_tx,
            })
            .unwrap();
        confirm_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("timed out waiting for SetValue confirmation");

        let mut client = std::net::TcpStream::connect(bound_addr).unwrap();

        // When: garbage bytes are sent inside a valid SEQUENCE wrapper so the
        // BER frame parses correctly but the SNMP decode fails. The event loop
        // must discard the malformed PDU silently and keep the connection open.
        let garbage_content: &[u8] = &[0xFF, 0xFE, 0xFD];
        let mut garbage_frame = vec![0x30u8, u8::try_from(garbage_content.len()).unwrap()];
        garbage_frame.extend_from_slice(garbage_content);
        client
            .write_all(&garbage_frame)
            .expect("garbage write must succeed");

        // Then: a valid SNMPv3 GetRequest sent on the same connection still receives a response.
        client
            .write_all(&framed_get_request(3, 3, &oid))
            .expect("valid request write must succeed");
        let response_frame = read_framed_response(&mut client);
        let response = decode_v3_response_payload(&response_frame);
        assert_eq!(response.request_id, 3);
        assert_eq!(
            response.varbinds[0].value,
            codec::VarbindValue::Value(codec::Value::Integer32(99))
        );

        sender.send(Command::Shutdown).unwrap();
        loop_handle
            .join()
            .expect("event loop thread panicked")
            .unwrap();
    }

    #[test]
    fn given_empty_sequence_frame_when_received_then_connection_stays_open() {
        // Verifies: REQ-0073
        // Given: a running event loop with a known OID in the MIB.
        let (event_loop, bound_addr, sender) =
            EventLoop::new(any_loopback(), test_engine_id()).unwrap();
        let loop_handle = thread::spawn(move || event_loop.run());

        let oid: codec::Oid = "1.3.6.1.2.1.1.4.0".parse().unwrap();
        sender
            .send(Command::SetValue {
                oid: oid.clone(),
                value: codec::Value::Integer32(55),
            })
            .unwrap();

        let (confirm_tx, confirm_rx) = std::sync::mpsc::sync_channel(1);
        sender
            .send(Command::QueryValue {
                oid: oid.clone(),
                reply: confirm_tx,
            })
            .unwrap();
        confirm_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("timed out waiting for SetValue confirmation");

        let mut client = std::net::TcpStream::connect(bound_addr).unwrap();

        // When: an empty SEQUENCE frame is sent (tag 0x30, length 0x00, no content).
        // An empty payload is not a valid SNMP PDU; the decode error must be
        // handled without closing the connection.
        client
            .write_all(&[0x30u8, 0x00])
            .expect("empty sequence frame write must succeed");

        // Then: a valid SNMPv3 GetRequest sent on the same connection still receives a response,
        // confirming the connection survived the empty SEQUENCE frame.
        client
            .write_all(&framed_get_request(4, 4, &oid))
            .expect("valid request write must succeed");
        let response_frame = read_framed_response(&mut client);
        let response = decode_v3_response_payload(&response_frame);
        assert_eq!(response.request_id, 4);
        assert_eq!(
            response.varbinds[0].value,
            codec::VarbindValue::Value(codec::Value::Integer32(55))
        );

        sender.send(Command::Shutdown).unwrap();
        loop_handle
            .join()
            .expect("event loop thread panicked")
            .unwrap();
    }

    #[test]
    fn given_wrong_engine_id_when_request_sent_then_discarded_silently() {
        // Verifies: REQ-0057
        // Given: a running event loop with a known OID in the MIB.
        let (event_loop, bound_addr, sender) =
            EventLoop::new(any_loopback(), test_engine_id()).unwrap();
        let loop_handle = thread::spawn(move || event_loop.run());

        let oid: codec::Oid = "1.3.6.1.2.1.1.5.0".parse().unwrap();
        sender
            .send(Command::SetValue {
                oid: oid.clone(),
                value: codec::Value::Integer32(77),
            })
            .unwrap();

        let (confirm_tx, confirm_rx) = std::sync::mpsc::sync_channel(1);
        sender
            .send(Command::QueryValue {
                oid: oid.clone(),
                reply: confirm_tx,
            })
            .unwrap();
        confirm_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("timed out waiting for SetValue confirmation");

        let mut client = std::net::TcpStream::connect(bound_addr).unwrap();

        // When: a request with the wrong engine ID is sent, it should be discarded.
        let wrong_engine_id = b"\x80\x00\x1f\x88\x04wrong";
        let pdu = codec::GetRequest {
            request_id: 10,
            varbinds: vec![codec::Varbind {
                oid: oid.clone(),
                value: codec::VarbindValue::Unspecified,
            }],
        };
        let wrong_encoded = codec::encode_v3_get_request(10, wrong_engine_id, b"", &pdu)
            .expect("encode must succeed");
        client
            .write_all(&wrong_encoded)
            .expect("write must succeed");

        // Then: immediately sending a correct request gets a response,
        // confirming the wrong-engine request was silently discarded.
        client
            .write_all(&framed_get_request(11, 11, &oid))
            .expect("valid request write must succeed");
        let response_frame = read_framed_response(&mut client);
        let response = decode_v3_response_payload(&response_frame);
        assert_eq!(response.request_id, 11);
        assert_eq!(
            response.varbinds[0].value,
            codec::VarbindValue::Value(codec::Value::Integer32(77))
        );

        sender.send(Command::Shutdown).unwrap();
        loop_handle
            .join()
            .expect("event loop thread panicked")
            .unwrap();
    }

    #[test]
    fn given_non_empty_context_name_when_request_sent_then_discarded_silently() {
        // Verifies: REQ-0056, REQ-0058
        // A request with a non-empty context name must be silently discarded;
        // the connection must stay open so a subsequent valid request succeeds.

        // Given: a running event loop with a known OID in the MIB.
        let (event_loop, bound_addr, sender) =
            EventLoop::new(any_loopback(), test_engine_id()).unwrap();
        let loop_handle = thread::spawn(move || event_loop.run());

        let oid: codec::Oid = "1.3.6.1.2.1.1.6.0".parse().unwrap();
        sender
            .send(Command::SetValue {
                oid: oid.clone(),
                value: codec::Value::Integer32(88),
            })
            .unwrap();

        let (confirm_tx, confirm_rx) = std::sync::mpsc::sync_channel(1);
        sender
            .send(Command::QueryValue {
                oid: oid.clone(),
                reply: confirm_tx,
            })
            .unwrap();
        confirm_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("timed out waiting for SetValue confirmation");

        let mut client = std::net::TcpStream::connect(bound_addr).unwrap();

        // When: a request with a non-empty context name is sent, it should be discarded.
        let pdu = codec::GetRequest {
            request_id: 20,
            varbinds: vec![codec::Varbind {
                oid: oid.clone(),
                value: codec::VarbindValue::Unspecified,
            }],
        };
        let bad_context_encoded =
            codec::encode_v3_get_request(20, TEST_ENGINE_ID, b"badcontext", &pdu)
                .expect("encode must succeed");
        client
            .write_all(&bad_context_encoded)
            .expect("write must succeed");

        // Then: no response arrives for the bad-context request (connection stays open).
        // Confirm by sending a valid request on the same connection and receiving a response.
        client
            .write_all(&framed_get_request(21, 21, &oid))
            .expect("valid request write must succeed");
        let response_frame = read_framed_response(&mut client);
        let response = decode_v3_response_payload(&response_frame);
        assert_eq!(response.request_id, 21);
        assert_eq!(
            response.varbinds[0].value,
            codec::VarbindValue::Value(codec::Value::Integer32(88))
        );

        sender.send(Command::Shutdown).unwrap();
        loop_handle
            .join()
            .expect("event loop thread panicked")
            .unwrap();
    }

    #[test]
    fn given_indefinite_length_ber_frame_when_received_then_connection_is_closed() {
        // Verifies: REQ-0071
        // A client sending 0x30 0x80 (SEQUENCE + indefinite-length form) must
        // cause the connection to be closed, not stalled indefinitely.

        // Given: a running event loop.
        let (event_loop, bound_addr, sender) =
            EventLoop::new(any_loopback(), test_engine_id()).unwrap();
        let loop_handle = thread::spawn(move || event_loop.run());

        let mut client = std::net::TcpStream::connect(bound_addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        // When: a frame with indefinite-length encoding is sent.
        // 0x30 = SEQUENCE tag, 0x80 = indefinite-length (unsupported).
        client
            .write_all(&[0x30u8, 0x80])
            .expect("write must succeed");

        // Then: the server closes the connection; reading must return 0 bytes (EOF).
        let mut read_buf = [0u8; 1];
        let bytes_read = client.read(&mut read_buf).expect("read must not error");
        assert_eq!(
            bytes_read, 0,
            "server must close connection on invalid BER length"
        );

        sender.send(Command::Shutdown).unwrap();
        loop_handle
            .join()
            .expect("event loop thread panicked")
            .unwrap();
    }
}
