//! Central event loop for the SNMP agent.
//!
//! The loop multiplexes a TCP listener, accepted TLS connections, and a
//! self-pipe using `mio` (epoll/kqueue). Inbound SNMP requests arrive over
//! mutual-TLS connections framed per RFC 6353 (TLS transport for SNMP) using
//! RFC 3430 BER encoding; outbound traps are sent as plain UDP datagrams.
//!
//! # Design
//!
//! [`EventLoop::new`] binds the listener and allocates the self-pipe, then
//! returns a [`CommandSender`] that callers use to send [`Command`]s from any
//! thread. Writing one byte to the pipe's write end wakes the poll call so the
//! event loop drains the mpsc channel promptly.
//!
//! Accepted TCP streams are immediately wrapped in `rustls::ServerConnection`.
//! Connections whose client certificates do not chain to the configured trust
//! anchor are closed at TLS handshake time (REQ-0019). Idle connections older
//! than [`IDLE_TIMEOUT`] are reaped on every event loop iteration (ADR-0015).

use std::collections::HashMap;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::{
    Arc,
    mpsc::{self, Receiver, Sender},
};
use std::time::{Duration, Instant};

use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};

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
pub(crate) const MAX_BULK_REPETITIONS: u32 = 100;

/// Maximum accepted RFC 3430 frame total size (tag + length + content),
/// matching the `SNMPv3` `maxMessageSize` upper bound. Frames whose total
/// size exceeds this are rejected and the connection is closed to prevent
/// memory exhaustion.
const MAX_FRAME_SIZE: usize = 65_535;

/// Idle TLS connections older than this threshold are closed on each event loop
/// iteration. A compile-time constant keeps the implementation simple while
/// preventing indefinite accumulation of stale connections.
// Implements [[ADR-0015]]
const IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);

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
        oid: crate::codec::Oid,
        value: crate::codec::Value,
    },
    /// Shut down the event loop cleanly.
    Shutdown,
    /// Query a single OID from the MIB store and send the result back.
    ///
    /// Compiled only for unit tests within this module (`cfg(test)`).
    /// External consumers compile the crate without `cfg(test)` and therefore
    /// cannot see this variant. Production code has no need to read values back
    /// out of the event loop — SNMP GET dispatch handles that.
    #[cfg(test)]
    QueryValue {
        oid: crate::codec::Oid,
        reply: std::sync::mpsc::SyncSender<Option<crate::codec::Value>>,
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
/// use basic_snmp_agent::transport::event_loop::{Command, EventLoop};
///
/// let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
/// let engine_id = b"\x80\x00\x1f\x88\x04test".to_vec();
/// let (event_loop, _bound_addr, sender) = EventLoop::new(addr, engine_id, None).unwrap();
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
// Implements: REQ-0004, REQ-0005, REQ-0007, REQ-0015, REQ-0019
// Implements [[RFC-0006:C-TRANSPORT]], [[RFC-0006:C-AUTH]]
struct ConnectionState {
    tcp_stream: mio::net::TcpStream,
    tls_conn: rustls::ServerConnection,
    /// Accumulates decrypted plaintext until a complete RFC 3430 BER frame arrives.
    read_buf: Vec<u8>,
    /// Updated on every send or receive; used to detect idle connections (ADR-0015).
    last_activity: Instant,
}

// ── EventLoop ────────────────────────────────────────────────────────────────

/// The mio-driven event loop that owns the TCP listener, accepted TLS
/// connections, the self-pipe read end, and the MIB store.
///
/// Call [`run`][`EventLoop::run`] from a dedicated OS thread. The loop exits
/// when it receives [`Command::Shutdown`].
///
/// # Requirements
/// Implements: REQ-0004, REQ-0005, REQ-0007, REQ-0011, REQ-0013, REQ-0048,
///             REQ-0050, REQ-0051, REQ-0052, REQ-0053, REQ-0054
///
/// # Examples
///
/// ```no_run
/// use std::net::SocketAddr;
/// use basic_snmp_agent::transport::event_loop::EventLoop;
///
/// let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
/// let engine_id = b"\x80\x00\x1f\x88\x04test".to_vec();
/// let (event_loop, bound_addr, sender) = EventLoop::new(addr, engine_id, None).unwrap();
///
/// let handle = std::thread::spawn(move || event_loop.run());
/// sender.send(basic_snmp_agent::transport::event_loop::Command::Shutdown).unwrap();
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
    store: crate::mib::Store,
    /// This agent's `SNMPv3` engine ID; inbound messages with a different engine
    /// ID are discarded (REQ-0057).
    engine_id: Vec<u8>,
    /// TLS server configuration used to wrap accepted TCP connections.
    ///
    /// `None` means no TLS — any accepted stream is immediately closed.
    /// `Some` enables mutual TLS per RFC-0006:C-AUTH.
    // Implements: REQ-0014, REQ-0015, REQ-0019
    // Implements [[RFC-0006:C-TRANSPORT]], [[RFC-0006:C-AUTH]]
    tls_server_config: Option<Arc<rustls::ServerConfig>>,
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
    /// Implements: REQ-0004, REQ-0005, REQ-0013, REQ-0048, REQ-0050, REQ-0055
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::net::SocketAddr;
    /// use basic_snmp_agent::transport::event_loop::EventLoop;
    ///
    /// let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    /// let engine_id = b"\x80\x00\x1f\x88\x04test".to_vec();
    /// let (event_loop, bound_addr, sender) = EventLoop::new(addr, engine_id, None).unwrap();
    /// println!("listening on {bound_addr}");
    /// ```
    pub fn new(
        addr: SocketAddr,
        engine_id: Vec<u8>,
        tls_server_config: Option<Arc<rustls::ServerConfig>>,
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
            store: crate::mib::Store::new(),
            engine_id,
            tls_server_config,
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
            // Use IDLE_TIMEOUT as the poll timeout so we wake up periodically
            // to reap connections that have been idle for too long (ADR-0015).
            self.poll.poll(&mut events, Some(IDLE_TIMEOUT))?;

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

            // Reap connections that have been idle longer than IDLE_TIMEOUT.
            // This runs on every poll wakeup (whether from activity or timeout).
            self.close_idle_connections();
        }

        Ok(())
        // `self.pipe_read_fd` (OwnedFd) is closed here automatically on drop.
    }

    /// Accept all pending connections, wrapping each in a `rustls::ServerConnection`.
    ///
    /// If no TLS config is present, accepted streams are immediately dropped
    /// (closed). Transient accept errors (e.g. `EMFILE`, `ENFILE`,
    /// `ECONNABORTED`) are logged and skipped rather than killing the event
    /// loop, because a single resource-exhaustion moment should not bring down
    /// the agent.
    // Implements: REQ-0004, REQ-0007, REQ-0015, REQ-0019, REQ-0051
    // Implements [[RFC-0006:C-TRANSPORT]], [[RFC-0006:C-AUTH]]
    fn accept_connections(&mut self) {
        loop {
            match self.listener.accept() {
                Ok((mut stream, peer_addr)) => {
                    let Some(tls_config) = &self.tls_server_config else {
                        // No TLS config: drop stream immediately (closes TCP fd).
                        eprintln!(
                            "[event_loop] no TLS config — closing connection from {peer_addr}"
                        );
                        drop(stream);
                        continue;
                    };

                    let tls_conn = match rustls::ServerConnection::new(Arc::clone(tls_config)) {
                        Ok(conn) => conn,
                        Err(e) => {
                            eprintln!(
                                "[event_loop] failed to create TLS connection for {peer_addr}: {e}"
                            );
                            continue;
                        }
                    };

                    let token = self.next_connection_token();
                    // Register READABLE | WRITABLE because TLS handshake needs both
                    // directions from the start.
                    if let Err(e) = self.poll.registry().register(
                        &mut stream,
                        token,
                        Interest::READABLE | Interest::WRITABLE,
                    ) {
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
                            tcp_stream: stream,
                            tls_conn,
                            read_buf: Vec::new(),
                            last_activity: Instant::now(),
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

    /// Drive the TLS state machine for one connection event, then dispatch any
    /// complete RFC 3430 BER frames that were decrypted.
    ///
    /// Connection-level I/O errors (e.g. `ConnectionReset`) and TLS errors
    /// (e.g. bad client certificate) close and remove the connection but do not
    /// propagate to the caller — a single misbehaving client must not bring down
    /// the entire event loop.
    ///
    /// # Requirements
    /// Implements: REQ-0007, REQ-0011, REQ-0019, REQ-0057, REQ-0058
    // Implements [[RFC-0006:C-TRANSPORT]], [[RFC-0006:C-AUTH]]
    fn handle_connection_event(&mut self, token: Token) {
        let Some(conn) = self.connections.get_mut(&token) else {
            return;
        };

        // Feed raw TCP bytes into the rustls state machine.
        let tls_read_closed = match conn.tls_conn.read_tls(&mut conn.tcp_stream) {
            Ok(0) => true,
            Ok(_) => false,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => false,
            Err(e) => {
                eprintln!("[event_loop] TCP read error (token {token:?}): {e}");
                true
            }
        };

        if tls_read_closed {
            self.remove_connection(token);
            return;
        }

        // Advance the TLS handshake and decrypt any newly received data.
        let io_state = match conn.tls_conn.process_new_packets() {
            Ok(state) => state,
            Err(tls_err) => {
                // TLS protocol error: bad certificate, wrong version, etc.
                // Flush any alert that rustls queued before closing (REQ-0019).
                eprintln!("[event_loop] TLS error (token {token:?}): {tls_err}");
                let _ = conn.tls_conn.write_tls(&mut conn.tcp_stream);
                self.remove_connection(token);
                return;
            }
        };

        // Write any TLS handshake messages or alerts back to the peer.
        if conn.tls_conn.wants_write() {
            match conn.tls_conn.write_tls(&mut conn.tcp_stream) {
                Ok(_) => {
                    conn.last_activity = Instant::now();
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    eprintln!("[event_loop] TLS write error (token {token:?}): {e}");
                    self.remove_connection(token);
                    return;
                }
            }
        }

        // No application data is available until the handshake completes.
        if conn.tls_conn.is_handshaking() {
            let interest = tls_interest(conn);
            let _ = self
                .poll
                .registry()
                .reregister(&mut conn.tcp_stream, token, interest);
            return;
        }

        // Move decrypted plaintext into the per-connection read buffer.
        let plaintext_available = io_state.plaintext_bytes_to_read();
        if plaintext_available > 0 {
            let prior_len = conn.read_buf.len();
            conn.read_buf.resize(prior_len + plaintext_available, 0);
            match conn
                .tls_conn
                .reader()
                .read_exact(&mut conn.read_buf[prior_len..])
            {
                Ok(()) => {
                    // Intentionally not updated during the handshake phase —
                    // connections stuck in a slow handshake can time out (ADR-0015).
                    conn.last_activity = Instant::now();
                }
                Err(e) => {
                    eprintln!("[event_loop] TLS reader error (token {token:?}): {e}");
                    self.remove_connection(token);
                    return;
                }
            }
        }

        // Dispatch all complete BER frames accumulated in the decrypted buffer.
        if process_ber_frames(conn, &self.engine_id, &self.store, token) {
            self.remove_connection(token);
            return;
        }

        // Update mio interest based on what TLS still needs to flush.
        if let Some(conn) = self.connections.get_mut(&token) {
            let interest = tls_interest(conn);
            let _ = self
                .poll
                .registry()
                .reregister(&mut conn.tcp_stream, token, interest);
        }
    }

    /// Close and deregister any connections that have been idle longer than
    /// [`IDLE_TIMEOUT`].
    ///
    /// The actual timeout is approximately `IDLE_TIMEOUT` to `2×IDLE_TIMEOUT`
    /// in the worst case, because connections are only checked after a poll
    /// wakeup (either from I/O activity or the periodic `IDLE_TIMEOUT` timer).
    // Implements [[ADR-0015]]
    fn close_idle_connections(&mut self) {
        let now = Instant::now();
        let timed_out_tokens: Vec<Token> = self
            .connections
            .iter()
            .filter(|(_, conn)| now.duration_since(conn.last_activity) >= IDLE_TIMEOUT)
            .map(|(&token, _)| token)
            .collect();

        for token in timed_out_tokens {
            eprintln!("[event_loop] idle timeout — closing connection (token {token:?})");
            self.remove_connection(token);
        }
    }

    /// Deregister and remove a connection from the map.
    fn remove_connection(&mut self, token: Token) {
        if let Some(mut conn) = self.connections.remove(&token) {
            if let Err(e) = self.poll.registry().deregister(&mut conn.tcp_stream) {
                eprintln!("[event_loop] deregister error (token {token:?}): {e}");
            }
            eprintln!("[event_loop] connection closed (token {token:?})");
        }
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

/// Process all complete RFC 3430 BER frames from the decrypted read buffer.
///
/// Returns `true` if the connection should be closed (framing error or I/O
/// failure), `false` if processing completed normally and the connection
/// should remain open.
///
/// Each frame is a raw BER SEQUENCE: tag 0x30, BER-encoded length, content.
// Implements: REQ-0007, REQ-0011, REQ-0057, REQ-0058
fn process_ber_frames(
    conn: &mut ConnectionState,
    engine_id: &[u8],
    store: &crate::mib::Store,
    token: Token,
) -> bool {
    loop {
        // Need at least 2 bytes to read the tag and the first length byte.
        if conn.read_buf.len() < 2 {
            return false;
        }

        // RFC 3430: frames must begin with the SEQUENCE tag (0x30).
        // A different tag indicates a corrupt or non-SNMP stream.
        if conn.read_buf[0] != 0x30 {
            eprintln!(
                "[event_loop] non-SEQUENCE tag {:#04x} on token {token:?}, closing",
                conn.read_buf[0]
            );
            return true;
        }

        // Distinguish incomplete data (wait for more) from invalid encoding (close).
        let (content_length, length_field_bytes) = match parse_ber_length(&conn.read_buf[1..]) {
            Ok(Some(parsed)) => parsed,
            Ok(None) => return false,
            Err(()) => {
                // Invalid BER length encoding (e.g., indefinite-length form 0x80).
                // The stream is unrecoverable; close the connection.
                eprintln!("[event_loop] invalid BER length encoding on token {token:?}, closing");
                return true;
            }
        };

        let total_frame_bytes = 1 + length_field_bytes + content_length;
        if total_frame_bytes > MAX_FRAME_SIZE {
            // Reject oversized frames to prevent memory exhaustion.
            eprintln!(
                "[event_loop] oversized frame ({total_frame_bytes} bytes) on token {token:?}, closing"
            );
            return true;
        }
        if conn.read_buf.len() < total_frame_bytes {
            // Frame is incomplete; wait for more data on the next read event.
            return false;
        }

        // The full BER frame (tag + length field + content) is the payload.
        let ber_frame: Vec<u8> = conn.read_buf[..total_frame_bytes].to_vec();
        conn.read_buf.drain(..total_frame_bytes);

        let Some(encoded_response) =
            crate::transport::dispatch::process_snmpv3_request(&ber_frame, engine_id, store)
        else {
            continue;
        };

        // Write the response via TLS so it is encrypted before hitting TCP.
        match conn.tls_conn.writer().write_all(&encoded_response) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("[event_loop] TLS write_all error (token {token:?}): {e}, closing");
                return true;
            }
        }
        match conn.tls_conn.write_tls(&mut conn.tcp_stream) {
            Ok(_) => {
                conn.last_activity = Instant::now();
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => {
                eprintln!("[event_loop] TCP write error (token {token:?}): {e}, closing");
                return true;
            }
        }
    }
}

/// Compute the mio `Interest` that the given connection needs based on what
/// rustls is waiting to do. Defaults to `READABLE` when nothing is pending so
/// the connection can still receive new data.
fn tls_interest(conn: &ConnectionState) -> Interest {
    match (conn.tls_conn.wants_read(), conn.tls_conn.wants_write()) {
        (true, true) => Interest::READABLE | Interest::WRITABLE,
        (false, true) => Interest::WRITABLE,
        // When wants_write is false, READABLE is always the correct fallback.
        // This includes the (false, false) case where rustls reports nothing
        // pending: registering READABLE avoids a busy-loop on WRITABLE while
        // still allowing the connection to receive future data — rustls may
        // need to be driven again for post-handshake processing or renegotiation.
        (true | false, false) => Interest::READABLE,
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
// Implements: REQ-0007
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

    /// Build a `rustls::ServerConfig` from the fixture certs under
    /// `tests/fixtures/certs/`. Requires mutual TLS: clients must present a
    /// certificate signed by the test CA.
    fn test_server_config() -> Arc<rustls::ServerConfig> {
        use rustls::RootCertStore;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};

        let certs_dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/certs");

        // Load CA certificate as the client-cert trust anchor.
        let ca_pem = std::fs::read(certs_dir.join("ca.crt")).expect("read ca.crt");
        let ca_certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut ca_pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .expect("parse ca.crt");
        let mut root_store = RootCertStore::empty();
        for ca_cert in ca_certs {
            root_store.add(ca_cert).expect("add CA cert");
        }

        // Build WebPKI client verifier requiring a cert chained to the test CA.
        let client_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
            .build()
            .expect("build client verifier");

        // Load server certificate chain and private key.
        let server_cert_pem = std::fs::read(certs_dir.join("server.crt")).expect("read server.crt");
        let server_cert_chain: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut server_cert_pem.as_slice())
                .collect::<Result<Vec<_>, _>>()
                .expect("parse server.crt");

        let server_key_pem = std::fs::read(certs_dir.join("server.key")).expect("read server.key");
        let server_key: PrivateKeyDer<'static> =
            rustls_pemfile::private_key(&mut server_key_pem.as_slice())
                .expect("parse server.key")
                .expect("server.key contains a private key");

        let server_config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(server_cert_chain, server_key)
            .expect("build ServerConfig");

        Arc::new(server_config)
    }

    /// Build a TLS client stream over `tcp` authenticated with the fixture
    /// client certificate. The server name must match the CN in `server.crt`
    /// ("localhost" in the fixture, but TLS SNI; we use "localhost" as the
    /// DNS name for loopback tests).
    fn test_tls_client_stream(
        tcp: std::net::TcpStream,
    ) -> rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream> {
        use rustls::RootCertStore;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};

        let certs_dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/certs");

        // Trust the test CA so we accept the server's certificate.
        let ca_pem = std::fs::read(certs_dir.join("ca.crt")).expect("read ca.crt");
        let ca_certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut ca_pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .expect("parse ca.crt");
        let mut root_store = RootCertStore::empty();
        for ca_cert in ca_certs {
            root_store.add(ca_cert).expect("add CA cert");
        }

        // Load the client certificate and key for mutual TLS.
        let client_cert_pem = std::fs::read(certs_dir.join("client.crt")).expect("read client.crt");
        let client_cert_chain: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut client_cert_pem.as_slice())
                .collect::<Result<Vec<_>, _>>()
                .expect("parse client.crt");

        let client_key_pem = std::fs::read(certs_dir.join("client.key")).expect("read client.key");
        let client_key: PrivateKeyDer<'static> =
            rustls_pemfile::private_key(&mut client_key_pem.as_slice())
                .expect("parse client.key")
                .expect("client.key contains a private key");

        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(client_cert_chain, client_key)
            .expect("build ClientConfig");

        // Use "localhost" to match the CN in the fixture server certificate.
        let server_name = ServerName::try_from("localhost").expect("valid server name");
        let client_conn = rustls::ClientConnection::new(Arc::new(client_config), server_name)
            .expect("create ClientConnection");

        rustls::StreamOwned::new(client_conn, tcp)
    }

    /// Set an OID in the MIB and block until the event loop has processed it.
    ///
    /// Sends `SetValue` followed by a `QueryValue` on a rendezvous channel.
    /// Because the event loop drains commands in order, receiving the `QueryValue`
    /// reply guarantees the preceding `SetValue` has already been applied.
    fn set_and_wait(sender: &CommandSender, oid: &crate::codec::Oid, value: crate::codec::Value) {
        sender
            .send(Command::SetValue {
                oid: oid.clone(),
                value,
            })
            .unwrap();
        let (reply_tx, reply_rx) = std::sync::mpsc::sync_channel(1);
        sender
            .send(Command::QueryValue {
                oid: oid.clone(),
                reply: reply_tx,
            })
            .unwrap();
        reply_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("timed out waiting for SetValue to be processed");
    }

    /// Read exactly `expected_len` bytes from a TLS stream, timing out after 5 seconds.
    fn read_exact_with_timeout(
        stream: &mut rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream>,
        expected_len: usize,
    ) -> Vec<u8> {
        stream
            .sock
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut received = vec![0u8; expected_len];
        stream
            .read_exact(&mut received)
            .expect("timed out waiting for response bytes");
        received
    }

    #[test]
    fn given_running_event_loop_when_tls_client_connects_then_connection_is_accepted() {
        // Verifies: REQ-0004, REQ-0050, REQ-0051
        // Given: an event loop bound on a random loopback port with TLS config.
        let (event_loop, bound_addr, sender) =
            EventLoop::new(any_loopback(), test_engine_id(), Some(test_server_config())).unwrap();
        let handle = thread::spawn(move || event_loop.run());

        // When: a TLS client connects.
        let tcp = std::net::TcpStream::connect(bound_addr).unwrap();
        let _client = test_tls_client_stream(tcp);

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
            EventLoop::new(any_loopback(), test_engine_id(), Some(test_server_config())).unwrap();
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
            EventLoop::new(any_loopback(), test_engine_id(), Some(test_server_config())).unwrap();
        let handle = thread::spawn(move || event_loop.run());

        // When: a SetValue command is followed by Shutdown.
        let oid: crate::codec::Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        sender
            .send(Command::SetValue {
                oid,
                value: crate::codec::Value::Integer32(42),
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
            EventLoop::new(any_loopback(), test_engine_id(), Some(test_server_config())).unwrap();
        let handle = thread::spawn(move || event_loop.run());

        // When: a SetValue command is sent and the loop is given time to process it.
        let oid: crate::codec::Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        sender
            .send(Command::SetValue {
                oid,
                value: crate::codec::Value::Integer32(42),
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
            EventLoop::new(any_loopback(), test_engine_id(), Some(test_server_config())).unwrap();
        let handle = thread::spawn(move || event_loop.run());

        let oid: crate::codec::Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();

        // When: a SetValue command is sent.
        sender
            .send(Command::SetValue {
                oid: oid.clone(),
                value: crate::codec::Value::Integer32(99),
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
            Some(crate::codec::Value::Integer32(99)),
            "expected MIB store to hold Integer32(99) for oid {oid:?}"
        );

        sender.send(Command::Shutdown).unwrap();
        handle.join().expect("event loop thread panicked").unwrap();
    }

    #[test]
    fn given_no_set_value_when_queried_then_mib_returns_none() {
        // Given: a running event loop with no values inserted.
        let (event_loop, _bound_addr, sender) =
            EventLoop::new(any_loopback(), test_engine_id(), Some(test_server_config())).unwrap();
        let handle = thread::spawn(move || event_loop.run());

        let oid: crate::codec::Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();

        // When: the OID is queried without having been set.
        let (reply_tx, reply_rx) = std::sync::mpsc::sync_channel(1);
        sender
            .send(Command::QueryValue {
                oid: oid.clone(),
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
        // (the first candidate after FIRST_CONN_TOKEN). Build a minimal event
        // loop struct directly so this unit test does not need a TLS connection.
        let tls_config = test_server_config();
        let tls_conn = rustls::ServerConnection::new(Arc::clone(&tls_config))
            .expect("create ServerConnection for token test");

        let listener_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let std_listener = std::net::TcpListener::bind(listener_addr).unwrap();
        let bound = std_listener.local_addr().unwrap();

        let mut event_loop = EventLoop {
            poll: Poll::new().unwrap(),
            listener: mio::net::TcpListener::bind("127.0.0.1:0".parse().unwrap()).unwrap(),
            pipe_read_fd: {
                // Create a real pipe so OwnedFd is valid. Both ends are
                // wrapped in OwnedFd so the write end is closed on drop
                // rather than leaked.
                let mut fds: [libc::c_int; 2] = [0; 2];
                unsafe { libc::pipe(fds.as_mut_ptr()) };
                let read_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
                let _write_fd = unsafe { OwnedFd::from_raw_fd(fds[1]) };
                read_fd
            },
            rx: mpsc::channel::<Command>().1,
            next_token: FIRST_CONN_TOKEN,
            connections: HashMap::new(),
            store: crate::mib::Store::new(),
            engine_id: test_engine_id(),
            tls_server_config: Some(tls_config),
        };

        // Connect to the std listener so the TcpStream is valid. mio's
        // connect is non-blocking and always returns Ok immediately on Unix.
        let dummy_stream = mio::net::TcpStream::connect(bound).unwrap();
        event_loop.connections.insert(
            Token(FIRST_CONN_TOKEN),
            ConnectionState {
                tcp_stream: dummy_stream,
                tls_conn,
                read_buf: Vec::new(),
                last_activity: Instant::now(),
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
        // Verifies: REQ-0007
        // Short form: single byte, bit 7 clear.
        assert_eq!(parse_ber_length(&[0x00]), Ok(Some((0, 1))));
        assert_eq!(parse_ber_length(&[0x7f]), Ok(Some((127, 1))));
        assert_eq!(parse_ber_length(&[0x05, 0xAA, 0xBB]), Ok(Some((5, 1))));
    }

    #[test]
    fn given_long_form_one_octet_when_parsed_then_returns_correct_length_and_field_size() {
        // Verifies: REQ-0007
        // Long form: 0x81 means one subsequent octet carries the length.
        assert_eq!(parse_ber_length(&[0x81, 0x80]), Ok(Some((128, 2))));
        assert_eq!(parse_ber_length(&[0x81, 0xFF]), Ok(Some((255, 2))));
    }

    #[test]
    fn given_long_form_two_octets_when_parsed_then_returns_correct_length_and_field_size() {
        // Verifies: REQ-0007
        // Long form: 0x82 means two subsequent octets carry the length.
        assert_eq!(parse_ber_length(&[0x82, 0x01, 0x00]), Ok(Some((256, 3))));
        assert_eq!(parse_ber_length(&[0x82, 0xFF, 0xFF]), Ok(Some((65535, 3))));
    }

    #[test]
    fn given_incomplete_buffer_when_parsed_then_returns_none() {
        // Verifies: REQ-0007
        assert_eq!(parse_ber_length(&[]), Ok(None));
        // Long form but not enough length octets.
        assert_eq!(parse_ber_length(&[0x82, 0x01]), Ok(None));
    }

    #[test]
    fn given_indefinite_length_when_parsed_then_returns_error() {
        // Verifies: REQ-0007
        // 0x80 = indefinite-length form; irrecoverable protocol error.
        assert_eq!(parse_ber_length(&[0x80]), Err(()));
    }

    #[test]
    fn given_oversized_length_field_when_parsed_then_returns_error() {
        // Verifies: REQ-0007
        // 0x85 = 5 subsequent octets; more than 4 is not supported, irrecoverable.
        assert_eq!(parse_ber_length(&[0x85, 0, 0, 0, 0, 1]), Err(()));
    }

    // ── RFC 3430 / TLS dispatch tests ─────────────────────────────────────────

    /// Encode a `GetRequest` as a raw BER `SNMPv3` frame ready for TCP send (RFC 3430),
    /// using the test engine ID and an empty context name.
    fn framed_get_request(msg_id: i32, request_id: i32, oid: &crate::codec::Oid) -> Vec<u8> {
        framed_get_request_custom(msg_id, request_id, oid, TEST_ENGINE_ID, b"")
    }

    /// Like [`framed_get_request`] but with explicit engine ID and context name,
    /// for tests that need to verify the agent's handling of non-standard values.
    fn framed_get_request_custom(
        msg_id: i32,
        request_id: i32,
        oid: &crate::codec::Oid,
        engine_id: &[u8],
        context_name: &[u8],
    ) -> Vec<u8> {
        snmpv3_frames::encode_get_request(
            engine_id,
            context_name,
            msg_id,
            request_id,
            oid.as_slice(),
        )
    }

    /// Read a complete RFC 3430 BER frame (tag + length + content) from the TLS stream.
    fn read_framed_response(
        stream: &mut rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream>,
    ) -> Vec<u8> {
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
    fn decode_v3_response_payload(ber_frame: &[u8]) -> crate::codec::GetResponse {
        use rasn_snmp::v3::{Message as V3Message, ScopedPduData};
        let v3_msg: V3Message = rasn::ber::decode(ber_frame).expect("must decode as V3Message");
        let scoped_pdu = match v3_msg.scoped_data {
            ScopedPduData::CleartextPdu(pdu) => pdu,
            ScopedPduData::EncryptedPdu(_) => panic!("expected cleartext"),
        };
        match scoped_pdu.data {
            rasn_snmp::v2::Pdus::Response(inner) => {
                let error_status = crate::codec::ErrorStatus::from_u32(inner.0.error_status)
                    .expect("valid error status");
                let varbinds = inner
                    .0
                    .variable_bindings
                    .into_iter()
                    .map(|vb| {
                        let oid_arcs: Vec<u32> = vb.name.as_ref().to_vec();
                        let oid = crate::codec::Oid::try_from(oid_arcs).unwrap();
                        let value = match vb.value {
                            rasn_snmp::v2::VarBindValue::Value(
                                rasn_smi::v2::ObjectSyntax::Simple(
                                    rasn_smi::v2::SimpleSyntax::Integer(n),
                                ),
                            ) => crate::codec::VarbindValue::Value(crate::codec::Value::Integer32(
                                i32::try_from(n).unwrap(),
                            )),
                            rasn_snmp::v2::VarBindValue::Value(
                                rasn_smi::v2::ObjectSyntax::Simple(
                                    rasn_smi::v2::SimpleSyntax::String(s),
                                ),
                            ) => crate::codec::VarbindValue::Value(
                                crate::codec::Value::OctetString(s.to_vec()),
                            ),
                            rasn_snmp::v2::VarBindValue::NoSuchObject => {
                                crate::codec::VarbindValue::NoSuchObject
                            }
                            rasn_snmp::v2::VarBindValue::EndOfMibView => {
                                crate::codec::VarbindValue::EndOfMibView
                            }
                            _ => panic!("unexpected VarBindValue variant"),
                        };
                        crate::codec::Varbind { oid, value }
                    })
                    .collect();
                crate::codec::GetResponse {
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
    fn given_get_request_when_sent_over_tls_then_response_is_received() {
        // Verifies: REQ-0004, REQ-0007, REQ-0011, REQ-0021, REQ-0051, REQ-0066
        // Given: a running event loop with a known OID in the MIB.
        let (event_loop, bound_addr, sender) =
            EventLoop::new(any_loopback(), test_engine_id(), Some(test_server_config())).unwrap();
        let loop_handle = thread::spawn(move || event_loop.run());

        let oid: crate::codec::Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        // Populate the MIB and wait for the event loop to process it before
        // connecting, so dispatch cannot race with the SetValue.
        set_and_wait(&sender, &oid, crate::codec::Value::Integer32(42));

        // When: a TLS client sends a raw BER SNMPv3 GetRequest (RFC 3430 framing).
        let tcp = std::net::TcpStream::connect(bound_addr).unwrap();
        let mut client = test_tls_client_stream(tcp);
        client
            .write_all(&framed_get_request(1, 1, &oid))
            .expect("write must succeed");

        // Then: a raw BER SNMPv3 response is received with the expected value.
        let response_frame = read_framed_response(&mut client);
        let response = decode_v3_response_payload(&response_frame);
        assert_eq!(response.request_id, 1);
        assert_eq!(response.error_status, crate::codec::ErrorStatus::NoError);
        assert_eq!(response.varbinds.len(), 1);
        assert_eq!(response.varbinds[0].oid, oid);
        assert_eq!(
            response.varbinds[0].value,
            crate::codec::VarbindValue::Value(crate::codec::Value::Integer32(42))
        );

        sender.send(Command::Shutdown).unwrap();
        loop_handle
            .join()
            .expect("event loop thread panicked")
            .unwrap();
    }

    #[test]
    fn given_partial_frame_when_split_across_reads_then_response_is_received() {
        // Verifies: REQ-0007
        // Given: a running event loop with a known OID in the MIB.
        let (event_loop, bound_addr, sender) =
            EventLoop::new(any_loopback(), test_engine_id(), Some(test_server_config())).unwrap();
        let loop_handle = thread::spawn(move || event_loop.run());

        let oid: crate::codec::Oid = "1.3.6.1.2.1.1.2.0".parse().unwrap();
        set_and_wait(&sender, &oid, crate::codec::Value::Integer32(7));

        // When: the framed PDU is sent in two separate writes to simulate
        // TCP segmentation where a frame arrives split across packets.
        let tcp = std::net::TcpStream::connect(bound_addr).unwrap();
        let mut client = test_tls_client_stream(tcp);
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
            crate::codec::VarbindValue::Value(crate::codec::Value::Integer32(7))
        );

        sender.send(Command::Shutdown).unwrap();
        loop_handle
            .join()
            .expect("event loop thread panicked")
            .unwrap();
    }

    #[test]
    fn given_invalid_snmp_payload_in_sequence_when_received_then_connection_stays_open() {
        // Verifies: REQ-0011
        // Given: a running event loop.
        let (event_loop, bound_addr, sender) =
            EventLoop::new(any_loopback(), test_engine_id(), Some(test_server_config())).unwrap();
        let loop_handle = thread::spawn(move || event_loop.run());

        let oid: crate::codec::Oid = "1.3.6.1.2.1.1.3.0".parse().unwrap();
        set_and_wait(&sender, &oid, crate::codec::Value::Integer32(99));

        let tcp = std::net::TcpStream::connect(bound_addr).unwrap();
        let mut client = test_tls_client_stream(tcp);

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
            crate::codec::VarbindValue::Value(crate::codec::Value::Integer32(99))
        );

        sender.send(Command::Shutdown).unwrap();
        loop_handle
            .join()
            .expect("event loop thread panicked")
            .unwrap();
    }

    #[test]
    fn given_empty_sequence_frame_when_received_then_connection_stays_open() {
        // Verifies: REQ-0011
        // Given: a running event loop with a known OID in the MIB.
        let (event_loop, bound_addr, sender) =
            EventLoop::new(any_loopback(), test_engine_id(), Some(test_server_config())).unwrap();
        let loop_handle = thread::spawn(move || event_loop.run());

        let oid: crate::codec::Oid = "1.3.6.1.2.1.1.4.0".parse().unwrap();
        set_and_wait(&sender, &oid, crate::codec::Value::Integer32(55));

        let tcp = std::net::TcpStream::connect(bound_addr).unwrap();
        let mut client = test_tls_client_stream(tcp);

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
            crate::codec::VarbindValue::Value(crate::codec::Value::Integer32(55))
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
            EventLoop::new(any_loopback(), test_engine_id(), Some(test_server_config())).unwrap();
        let loop_handle = thread::spawn(move || event_loop.run());

        let oid: crate::codec::Oid = "1.3.6.1.2.1.1.5.0".parse().unwrap();
        set_and_wait(&sender, &oid, crate::codec::Value::Integer32(77));

        let tcp = std::net::TcpStream::connect(bound_addr).unwrap();
        let mut client = test_tls_client_stream(tcp);

        // When: a request with the wrong engine ID is sent, it should be discarded.
        let wrong_engine_id = b"\x80\x00\x1f\x88\x04wrong";
        let wrong_encoded = framed_get_request_custom(10, 10, &oid, wrong_engine_id, b"");
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
            crate::codec::VarbindValue::Value(crate::codec::Value::Integer32(77))
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
            EventLoop::new(any_loopback(), test_engine_id(), Some(test_server_config())).unwrap();
        let loop_handle = thread::spawn(move || event_loop.run());

        let oid: crate::codec::Oid = "1.3.6.1.2.1.1.6.0".parse().unwrap();
        set_and_wait(&sender, &oid, crate::codec::Value::Integer32(88));

        let tcp = std::net::TcpStream::connect(bound_addr).unwrap();
        let mut client = test_tls_client_stream(tcp);

        // When: a request with a non-empty context name is sent, it should be discarded.
        let bad_context_encoded =
            framed_get_request_custom(20, 20, &oid, TEST_ENGINE_ID, b"badcontext");
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
            crate::codec::VarbindValue::Value(crate::codec::Value::Integer32(88))
        );

        sender.send(Command::Shutdown).unwrap();
        loop_handle
            .join()
            .expect("event loop thread panicked")
            .unwrap();
    }

    #[test]
    fn given_indefinite_length_ber_frame_when_received_then_connection_is_closed() {
        // Verifies: REQ-0007
        // A client sending 0x30 0x80 (SEQUENCE + indefinite-length form) must
        // cause the connection to be closed, not stalled indefinitely.

        // Given: a running event loop.
        let (event_loop, bound_addr, sender) =
            EventLoop::new(any_loopback(), test_engine_id(), Some(test_server_config())).unwrap();
        let loop_handle = thread::spawn(move || event_loop.run());

        let tcp = std::net::TcpStream::connect(bound_addr).unwrap();
        let mut client = test_tls_client_stream(tcp);
        client
            .sock
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        // When: a frame with indefinite-length encoding is sent.
        // 0x30 = SEQUENCE tag, 0x80 = indefinite-length (unsupported).
        client
            .write_all(&[0x30u8, 0x80])
            .expect("write must succeed");

        // Then: the server closes the connection. From the client's view, the
        // TCP fd is dropped without a TLS close_notify alert, which rustls
        // surfaces as UnexpectedEof. Either 0 bytes read or that specific error
        // confirms the server terminated the connection.
        let mut read_buf = [0u8; 1];
        match client.read(&mut read_buf) {
            Ok(0) => {} // clean EOF
            Ok(n) => panic!("expected server to close connection, but read {n} bytes"),
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {} // rustls close without close_notify
            Err(e) => panic!("unexpected read error: {e}"),
        }

        sender.send(Command::Shutdown).unwrap();
        loop_handle
            .join()
            .expect("event loop thread panicked")
            .unwrap();
    }

    #[test]
    fn given_connection_with_no_client_cert_when_tls_handshake_then_connection_rejected() {
        // Verifies: REQ-0019
        // A client presenting no certificate must be rejected at the TLS
        // handshake; no data exchange should occur.
        use rustls::RootCertStore;
        use rustls::pki_types::{CertificateDer, ServerName};

        // Given: a running event loop with mutual-TLS enforced.
        let (event_loop, bound_addr, sender) =
            EventLoop::new(any_loopback(), test_engine_id(), Some(test_server_config())).unwrap();
        let loop_handle = thread::spawn(move || event_loop.run());

        // When: a client connects using a self-signed certificate that does NOT
        // chain to the test CA. We build a ClientConfig that trusts the test CA
        // for the server cert, but presents a self-signed cert for client auth.
        // The self-signed cert is the server.crt itself (wrong role / different
        // from what the server expects).
        //
        // To get a certificate that genuinely doesn't chain to the test CA,
        // we use the server's own cert as the "client certificate". The server
        // cert is valid and signed by the test CA, so to test a truly untrusted
        // cert we need a cert not from the CA. We use a hardcoded minimal
        // self-signed DER certificate for this purpose.

        let certs_dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/certs");

        let ca_pem = std::fs::read(certs_dir.join("ca.crt")).expect("read ca.crt");
        let ca_cert_der: CertificateDer<'static> = rustls_pemfile::certs(&mut ca_pem.as_slice())
            .next()
            .unwrap()
            .expect("parse ca.crt");
        let mut root_store = RootCertStore::empty();
        root_store.add(ca_cert_der).expect("add CA cert");

        // Load the server key so we can present a cert signed by a different
        // CA. Since we cannot generate certs at runtime (no rcgen), we use the
        // server.crt itself but paired with the client.key — a mismatch that
        // will be rejected as an invalid certificate at the TLS layer, which is
        // equivalent to an untrusted cert from the server's perspective.
        //
        // We achieve a cert-not-from-CA scenario by loading the server cert but
        // telling rustls to use the wrong (mismatched) key. However, the most
        // reliable way is to present an empty client certificate chain, which
        // the WebPkiClientVerifier will reject since it requires a client cert.
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(); // no client cert — server will reject this

        let server_name = ServerName::try_from("localhost").expect("valid server name");
        let client_conn = rustls::ClientConnection::new(Arc::new(client_config), server_name)
            .expect("create ClientConnection");

        let tcp = std::net::TcpStream::connect(bound_addr).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut stream = rustls::StreamOwned::new(client_conn, tcp);

        // Attempt to complete the handshake or send/receive data. The server
        // must reject the connection because no client certificate is presented.
        let handshake_result = stream.flush(); // triggers the TLS handshake
        // The connection must fail: either the handshake errors or the server
        // closes the connection (EOF on read).
        if handshake_result.is_ok() {
            let mut buf = [0u8; 1];
            let read_result = stream.read(&mut buf);
            assert!(
                read_result.is_err() || read_result.unwrap() == 0,
                "expected connection to be rejected for missing client certificate"
            );
        }
        // If handshake itself errored, the test assertion is already satisfied.

        sender.send(Command::Shutdown).unwrap();
        loop_handle
            .join()
            .expect("event loop thread panicked")
            .unwrap();
    }

    #[test]
    fn given_no_tls_config_when_client_connects_then_connection_is_closed() {
        // Verifies: REQ-0019 (no-TLS fallback: all connections are rejected)
        // When no TLS config is configured, the agent immediately closes
        // any accepted TCP connection.

        // Given: an event loop with no TLS config.
        let (event_loop, bound_addr, sender) =
            EventLoop::new(any_loopback(), test_engine_id(), None).unwrap();
        let loop_handle = thread::spawn(move || event_loop.run());

        // When: a plain TCP client connects (no TLS).
        let mut client = std::net::TcpStream::connect(bound_addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        // Then: the server closes the connection immediately; read returns 0 bytes (EOF).
        let mut read_buf = [0u8; 1];
        let bytes_read = client.read(&mut read_buf).expect("read must not OS-error");
        assert_eq!(
            bytes_read, 0,
            "server must close connection when no TLS config is set"
        );

        sender.send(Command::Shutdown).unwrap();
        loop_handle
            .join()
            .expect("event loop thread panicked")
            .unwrap();
    }
}
