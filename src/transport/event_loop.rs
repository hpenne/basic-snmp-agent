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
use std::time::{Duration, Instant};

use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};

// Implements: [[RFC-0009:C-FACADE]]
use log::{debug, info};

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
// Implements: REQ-0117
const MAX_FRAME_SIZE: usize = 65_535;

/// Default maximum number of concurrent TCP connections the agent will accept.
/// When this limit is reached, new connections are rejected until existing
/// ones close.
///
/// # Requirements
/// Implements: REQ-0120
pub const DEFAULT_MAX_CONNECTIONS: usize = 64;

/// Default idle timeout for connections under normal conditions.
///
/// # Requirements
/// Implements: REQ-0123
pub const NORMAL_IDLE_TIMEOUT: Duration = Duration::from_mins(5);

/// Reduced idle timeout when the connection count is near the maximum.
///
/// # Requirements
/// Implements: REQ-0124
pub const PRESSURE_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// How many free connection slots trigger "pressure" mode.
/// When `connections >= max_connections - PRESSURE_HEADROOM`, the shorter
/// timeout applies.
///
/// # Requirements
/// Implements: REQ-0124
pub const PRESSURE_HEADROOM: usize = 5;

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

// ── BerLengthError ─────────────────────────────────────────────────────────

/// Error returned by [`parse_ber_length`] when the BER length encoding is invalid.
///
/// This indicates a protocol error from which the connection cannot recover.
#[derive(Debug, PartialEq, Eq)]
pub struct BerLengthError;

impl fmt::Display for BerLengthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid BER length encoding (indefinite-length or >4-octet long form)")
    }
}

impl std::error::Error for BerLengthError {}

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
/// use basic_snmp_agent::transport::event_loop::{
///     Command, ConnectionTimeoutConfig, DEFAULT_MAX_CONNECTIONS, EventLoop,
/// };
///
/// let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
/// let engine_id = b"\x80\x00\x1f\x88\x04test".to_vec();
/// let (event_loop, _bound_addr, sender) =
///     EventLoop::new(addr, engine_id, 1, None, DEFAULT_MAX_CONNECTIONS,
///                    ConnectionTimeoutConfig::default()).unwrap();
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
    let _ = assert_send_sync::<CommandSender>;
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

// ── ConnectionTimeoutConfig ───────────────────────────────────────────────────

/// Configuration for idle-connection sweeping.
///
/// When the connection count stays below `max_connections - pressure_headroom`,
/// idle connections are closed after `normal_timeout`. Once the count reaches
/// that threshold, `pressure_timeout` applies instead.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use basic_snmp_agent::transport::event_loop::ConnectionTimeoutConfig;
///
/// let config = ConnectionTimeoutConfig {
///     normal_timeout: Duration::from_secs(120),
///     pressure_timeout: Duration::from_secs(10),
///     pressure_headroom: 3,
/// };
/// assert_eq!(config.normal_timeout, Duration::from_secs(120));
/// ```
///
/// # Requirements
/// Implements: REQ-0122, REQ-0123, REQ-0124
#[derive(Debug, Clone, Copy)]
pub struct ConnectionTimeoutConfig {
    /// Idle timeout under normal conditions.
    pub normal_timeout: Duration,
    /// Idle timeout when connection count is near the limit.
    pub pressure_timeout: Duration,
    /// Number of free slots below `max_connections` that triggers pressure mode.
    pub pressure_headroom: usize,
}

impl Default for ConnectionTimeoutConfig {
    fn default() -> Self {
        Self {
            normal_timeout: NORMAL_IDLE_TIMEOUT,
            pressure_timeout: PRESSURE_IDLE_TIMEOUT,
            pressure_headroom: PRESSURE_HEADROOM,
        }
    }
}

// ── ConnectionState ──────────────────────────────────────────────────────────

/// Per-connection state held in the event loop's connection map.
struct ConnectionState {
    stream: mio::net::TcpStream,
    /// Accumulates partially-received bytes until a complete RFC 3430 BER frame arrives.
    read_buf: Vec<u8>,
    /// Instant of the last successful read; used to detect and close idle connections.
    last_activity: Instant,
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
/// use basic_snmp_agent::transport::event_loop::{
///     ConnectionTimeoutConfig, DEFAULT_MAX_CONNECTIONS, EventLoop,
/// };
///
/// let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
/// let engine_id = b"\x80\x00\x1f\x88\x04test".to_vec();
/// let (event_loop, bound_addr, sender) =
///     EventLoop::new(addr, engine_id, 1, None, DEFAULT_MAX_CONNECTIONS,
///                    ConnectionTimeoutConfig::default()).unwrap();
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
    /// Maximum number of concurrent TCP connections to accept. Connections
    /// beyond this limit are dropped at the OS level on the next poll cycle.
    max_connections: usize,
    /// Idle-connection sweep parameters.
    timeout_config: ConnectionTimeoutConfig,
    /// MIB store; updated by `SetValue` commands from application threads.
    store: crate::mib::Store,
    /// This agent's `SNMPv3` engine ID; inbound messages with a different engine
    /// ID are rejected with a Report PDU (REQ-0104).
    engine_id: Vec<u8>,
    /// `snmpEngineBoots` counter, initialised at agent start-up.
    // Implements: REQ-0094
    engine_boots: u32,
    /// Instant at which the engine started; used to compute `snmpEngineTime`.
    // Implements: REQ-0094
    engine_start: Instant,
    /// Counter for `usmStatsUnknownEngineIDs`; incremented for each discovery probe.
    // Implements: REQ-0093
    unknown_engine_ids_counter: u32,
    /// Counter for `usmStatsUnknownUserNames`; incremented when user-name lookup fails.
    // Implements: REQ-0078
    unknown_user_names_counter: u32,
    /// Counter for `usmStatsUnsupportedSecLevels`; incremented when security-level check fails.
    // Implements: REQ-0079
    unsupported_sec_levels_counter: u32,
    /// Counter for `usmStatsWrongDigests`; incremented when HMAC verification fails.
    // Implements: REQ-0100
    wrong_digests_counter: u32,
    /// Counter for `usmStatsNotInTimeWindows`; incremented when time-window check fails.
    // Implements: REQ-0098
    not_in_time_windows_counter: u32,
    /// Counter for `usmStatsDecryptionErrors`; incremented when decryption fails.
    // Implements: REQ-0101
    decryption_errors_counter: u32,
    /// Counter for `snmpUnknownSecurityModels`; incremented when an inbound message
    /// uses a security model other than USM (RFC 3412 §7.1).
    // Implements: REQ-0115
    unknown_security_models_counter: u32,
    /// Configured USM user; `None` when no USM user is configured.
    // Implements: REQ-0076
    usm_user: Option<std::sync::Arc<crate::usm::user::UsmUser>>,
}

impl EventLoop {
    /// Create an [`EventLoop`] bound to `addr`, using `engine_id` to validate
    /// inbound `SNMPv3` messages.
    ///
    /// Returns the loop itself, the actual bound address (useful when `addr`
    /// uses port 0 for OS-assigned allocation), and a [`CommandSender`] for
    /// sending commands from other threads.
    ///
    /// `max_connections` caps the number of concurrently tracked TCP connections.
    /// Pass [`DEFAULT_MAX_CONNECTIONS`] for the standard limit of 64.
    ///
    /// `timeout_config` controls how long idle connections are kept before being
    /// swept. Pass [`ConnectionTimeoutConfig::default`] for the standard timeouts.
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
    /// use basic_snmp_agent::transport::event_loop::{
    ///     ConnectionTimeoutConfig, DEFAULT_MAX_CONNECTIONS, EventLoop,
    /// };
    ///
    /// let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    /// let engine_id = b"\x80\x00\x1f\x88\x04test".to_vec();
    /// let (event_loop, bound_addr, sender) =
    ///     EventLoop::new(addr, engine_id, 1, None, DEFAULT_MAX_CONNECTIONS,
    ///                    ConnectionTimeoutConfig::default()).unwrap();
    /// println!("listening on {bound_addr}");
    /// ```
    pub fn new(
        addr: SocketAddr,
        engine_id: Vec<u8>,
        engine_boots: u32,
        usm_user: Option<std::sync::Arc<crate::usm::user::UsmUser>>,
        max_connections: usize,
        timeout_config: ConnectionTimeoutConfig,
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
            max_connections,
            timeout_config,
            store: crate::mib::Store::new(),
            engine_id,
            engine_boots,
            engine_start: Instant::now(),
            unknown_engine_ids_counter: 0,
            unknown_user_names_counter: 0,
            unsupported_sec_levels_counter: 0,
            wrong_digests_counter: 0,
            not_in_time_windows_counter: 0,
            decryption_errors_counter: 0,
            unknown_security_models_counter: 0,
            usm_user,
        };
        let sender = CommandSender { tx, pipe_write_fd };

        Ok((event_loop, bound_addr, sender))
    }

    /// Return `snmpEngineTime`: seconds elapsed since engine start-up, capped at `u32::MAX`.
    ///
    /// # Requirements
    /// Implements: REQ-0094
    fn engine_time_seconds(&self) -> u32 {
        // Saturate at u32::MAX rather than wrapping; `as_secs()` returns u64.
        u32::try_from(self.engine_start.elapsed().as_secs()).unwrap_or(u32::MAX)
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
        info!("event loop started");
        let mut events = Events::with_capacity(128);

        'outer: loop {
            // Use a 30-second timeout so idle-connection sweeping happens even
            // when no network events arrive, preventing connections that become
            // idle during a quiet period from being held open indefinitely.
            self.poll.poll(&mut events, Some(Duration::from_secs(30)))?;

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

            // Sweep idle connections after every batch of events (including
            // on poll timeout when no events arrived).
            self.sweep_idle_connections();
        }

        Ok(())
        // `self.pipe_read_fd` (OwnedFd) is closed here automatically on drop.
    }

    /// Accept all pending connections, registering each with a unique token.
    ///
    /// When the connection limit is reached, the accept loop stops processing
    /// new connections for this poll cycle. Transient accept errors (e.g.
    /// `EMFILE`, `ENFILE`, `ECONNABORTED`) are logged and skipped rather than
    /// killing the event loop, because a single resource-exhaustion moment
    /// should not bring down the agent.
    // Implements: REQ-0051, REQ-0120, REQ-0121
    fn accept_connections(&mut self) {
        loop {
            // Stop accepting when the connection table is at capacity so that
            // a burst of inbound connections cannot exhaust memory. The OS
            // kernel backlog buffers the excess; they will be accepted once
            // existing connections close.
            if self.connections.len() >= self.max_connections {
                debug!(
                    "connection limit ({}) reached, not accepting new connections",
                    self.max_connections
                );
                break;
            }

            match self.listener.accept() {
                Ok((mut stream, peer_addr)) => {
                    let token = self.next_connection_token();
                    if let Err(e) =
                        self.poll
                            .registry()
                            .register(&mut stream, token, Interest::READABLE)
                    {
                        debug!("failed to register connection from {peer_addr}: {e}");
                        continue;
                    }
                    info!("accepted connection from {peer_addr} (token {token:?})");
                    self.connections.insert(
                        token,
                        ConnectionState {
                            stream,
                            read_buf: Vec::new(),
                            last_activity: Instant::now(),
                        },
                    );
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    // Transient errors should not kill the event loop.
                    debug!("accept error (continuing): {e}");
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
                    info!("received Shutdown, exiting");
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
                    info!("command channel disconnected, exiting");
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
    /// Implements: REQ-0058, REQ-0068, REQ-0071, REQ-0073, REQ-0104
    fn handle_connection_event(&mut self, token: Token) {
        // Extract engine state before borrowing the connection map.
        // `engine_time_seconds()` takes `&self`; calling it after `connections.get_mut()`
        // would conflict because the mutable reference to the connection map holds
        // a partial mutable borrow of `self` that the borrow checker cannot prove
        // is disjoint from `&self`.
        let engine_boots = self.engine_boots;
        let engine_time = self.engine_time_seconds();

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
                    // Record activity so the idle-connection sweep does not
                    // evict a connection that is actively receiving data.
                    conn.last_activity = Instant::now();
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    // Non-WouldBlock errors (e.g. ConnectionReset) mean the
                    // connection is broken; close it rather than killing the loop.
                    debug!("connection error (token {token:?}): {e}");
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
                debug!(
                    "non-SEQUENCE tag {:#04x} on token {token:?}, closing",
                    conn.read_buf[0]
                );
                closed = true;
                break;
            }

            // Distinguish incomplete data (wait for more) from invalid encoding (close).
            let (content_length, length_field_bytes) = match parse_ber_length(&conn.read_buf[1..]) {
                Ok(Some(parsed)) => parsed,
                Ok(None) => break,
                Err(_) => {
                    // Invalid BER length encoding (e.g., indefinite-length form 0x80).
                    // The stream is unrecoverable; close the connection.
                    debug!("invalid BER length encoding on token {token:?}, closing");
                    closed = true;
                    break;
                }
            };

            let total_frame_bytes = 1 + length_field_bytes + content_length;
            // Implements: REQ-0117
            if total_frame_bytes > MAX_FRAME_SIZE {
                // Reject oversized frames to prevent memory exhaustion.
                debug!("oversized frame ({total_frame_bytes} bytes) on token {token:?}, closing");
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

            let Some(encoded_response) = Self::dispatch_snmpv3_frame(
                &ber_frame,
                &mut crate::transport::dispatch::DispatchContext {
                    engine_id: &self.engine_id,
                    engine_boots,
                    engine_time,
                    unknown_engine_ids_counter: &mut self.unknown_engine_ids_counter,
                    unknown_user_names_counter: &mut self.unknown_user_names_counter,
                    unsupported_sec_levels_counter: &mut self.unsupported_sec_levels_counter,
                    wrong_digests_counter: &mut self.wrong_digests_counter,
                    not_in_time_windows_counter: &mut self.not_in_time_windows_counter,
                    decryption_errors_counter: &mut self.decryption_errors_counter,
                    unknown_security_models_counter: &mut self.unknown_security_models_counter,
                    usm_user: self.usm_user.as_deref(),
                },
                &self.store,
            ) else {
                continue;
            };

            if let Err(write_error) = conn.stream.write_all(&encoded_response) {
                // Close the connection on any write error, including WouldBlock.
                // write_all on a non-blocking socket may have written a partial
                // response before returning WouldBlock, leaving the framing stream
                // in a corrupt state. Closing is the only safe option.
                debug!("write error (token {token:?}): {write_error}, closing");
                closed = true;
                break;
            }
        }

        if closed && let Some(mut conn) = self.connections.remove(&token) {
            if let Err(e) = self.poll.registry().deregister(&mut conn.stream) {
                debug!("deregister error (token {token:?}): {e}");
            }
            info!("connection closed (token {token:?})");
        }
    }

    /// Decode, validate, and dispatch a single RFC 3430 BER frame.
    ///
    /// Thin wrapper around [`crate::transport::dispatch::process_snmpv3_request`].
    // Implements: REQ-0056, REQ-0058, REQ-0066, REQ-0068, REQ-0073, REQ-0093, REQ-0104
    fn dispatch_snmpv3_frame(
        ber_frame: &[u8],
        ctx: &mut crate::transport::dispatch::DispatchContext<'_>,
        store: &crate::mib::Store,
    ) -> Option<Vec<u8>> {
        crate::transport::dispatch::process_snmpv3_request(ber_frame, ctx, store)
    }

    /// Close connections that have been idle longer than the configured timeout.
    ///
    /// Under pressure (connection count near maximum), a shorter timeout applies
    /// to free slots for new clients more aggressively.
    // Implements: REQ-0122, REQ-0124
    fn sweep_idle_connections(&mut self) {
        let now = Instant::now();
        let under_pressure =
            self.connections.len() + self.timeout_config.pressure_headroom >= self.max_connections;
        let timeout = if under_pressure {
            self.timeout_config.pressure_timeout
        } else {
            self.timeout_config.normal_timeout
        };

        let stale_tokens: Vec<Token> = self
            .connections
            .iter()
            .filter(|(_, conn)| now.duration_since(conn.last_activity) >= timeout)
            .map(|(token, _)| *token)
            .collect();

        for token in stale_tokens {
            if let Some(mut conn) = self.connections.remove(&token) {
                let _ = self.poll.registry().deregister(&mut conn.stream);
                info!("closed idle connection (token {token:?})");
            }
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
/// Returns `Ok(Some((content_length, length_field_bytes)))` on success,
/// `Ok(None)` when the buffer is incomplete (caller should wait for more data).
///
/// BER length encoding (X.690 §8.1.3):
/// - Short form: `buf[0]` bit 7 is 0; length = `buf[0]` (0–127); field is 1 byte.
/// - Long form: `buf[0]` bit 7 is 1; low 7 bits = number of subsequent octets N;
///   content length is encoded in the next N octets (big-endian).
///
/// # Errors
///
/// Returns [`BerLengthError`] for invalid encodings: the indefinite-length form
/// (`0x80`) and long forms with more than 4 subsequent octets. The caller should
/// close the connection on error, as the stream is unrecoverable.
// Implements: REQ-0071
pub fn parse_ber_length(buf: &[u8]) -> Result<Option<(usize, usize)>, BerLengthError> {
    if buf.is_empty() {
        return Ok(None);
    }
    if buf[0] & 0x80 == 0 {
        // Short form: the byte itself is the length.
        return Ok(Some((usize::from(buf[0]), 1)));
    }
    let num_octets = usize::from(buf[0] & 0x7f);
    if num_octets == 0 || num_octets > 4 {
        // Indefinite-length (0x80) or absurdly large (>4 bytes) is a protocol
        // error; the connection cannot recover.
        return Err(BerLengthError);
    }
    if buf.len() < 1 + num_octets {
        // Incomplete length field; caller should wait for more data.
        return Ok(None);
    }
    let mut content_length: usize = 0;
    for &byte in &buf[1..=num_octets] {
        content_length = (content_length << 8) | usize::from(byte);
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

    /// Create an event loop with default timeout config for tests that do not
    /// exercise idle-connection sweeping.
    fn new_test_event_loop(max_connections: usize) -> (EventLoop, SocketAddr, CommandSender) {
        EventLoop::new(
            any_loopback(),
            test_engine_id(),
            1,
            None,
            max_connections,
            ConnectionTimeoutConfig::default(),
        )
        .unwrap()
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
        let (event_loop, bound_addr, sender) = new_test_event_loop(DEFAULT_MAX_CONNECTIONS);
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
        let (event_loop, _bound_addr, sender) = new_test_event_loop(DEFAULT_MAX_CONNECTIONS);
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
        let (event_loop, _bound_addr, sender) = new_test_event_loop(DEFAULT_MAX_CONNECTIONS);
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
        let (event_loop, _bound_addr, sender) = new_test_event_loop(DEFAULT_MAX_CONNECTIONS);
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
        let (event_loop, _bound_addr, sender) = new_test_event_loop(DEFAULT_MAX_CONNECTIONS);
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
        let (event_loop, _bound_addr, sender) = new_test_event_loop(DEFAULT_MAX_CONNECTIONS);
        let handle = thread::spawn(move || event_loop.run());

        let oid: crate::codec::Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();

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
            max_connections: DEFAULT_MAX_CONNECTIONS,
            timeout_config: ConnectionTimeoutConfig::default(),
            store: crate::mib::Store::new(),
            engine_id: test_engine_id(),
            engine_boots: 1,
            engine_start: Instant::now(),
            unknown_engine_ids_counter: 0,
            unknown_user_names_counter: 0,
            unsupported_sec_levels_counter: 0,
            wrong_digests_counter: 0,
            not_in_time_windows_counter: 0,
            decryption_errors_counter: 0,
            unknown_security_models_counter: 0,
            usm_user: None,
        };

        // Connect to the std listener so the TcpStream is valid. mio's
        // connect is non-blocking and always returns Ok immediately on Unix.
        let dummy_stream = mio::net::TcpStream::connect(bound).unwrap();
        event_loop.connections.insert(
            Token(FIRST_CONN_TOKEN),
            ConnectionState {
                stream: dummy_stream,
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
        assert_eq!(parse_ber_length(&[0x80]), Err(BerLengthError));
    }

    #[test]
    fn given_oversized_length_field_when_parsed_then_returns_error() {
        // Verifies: REQ-0071
        // 0x85 = 5 subsequent octets; more than 4 is not supported, irrecoverable.
        assert_eq!(
            parse_ber_length(&[0x85, 0, 0, 0, 0, 1]),
            Err(BerLengthError)
        );
    }

    #[test]
    fn given_four_octet_length_field_when_parsed_then_returns_ok() {
        // Verifies: REQ-0071
        // 0x84 = 4 subsequent octets; 4 is the maximum supported long-form length.
        // The mutant `> with >=` would incorrectly reject this valid 4-octet field.
        // content_length = 0x00_01_00_00 = 65536; field_size = 1 (long-form marker byte) + 4 = 5.
        assert_eq!(
            parse_ber_length(&[0x84, 0x00, 0x01, 0x00, 0x00]),
            Ok(Some((65536, 5)))
        );
    }

    #[test]
    fn given_ber_length_error_when_displayed_then_shows_expected_message() {
        // Verifies: REQ-0071
        let error = BerLengthError;
        assert_eq!(
            error.to_string(),
            "invalid BER length encoding (indefinite-length or >4-octet long form)"
        );
    }

    // ── RFC 3430 dispatch tests ───────────────────────────────────────────────

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
            let result = parse_ber_length(&length_buf)
                .expect("invalid BER length encoding in response from event loop");
            if let Some(parsed) = result {
                break parsed;
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
    fn given_get_request_when_sent_over_tcp_then_response_is_received() {
        // Verifies: REQ-0021, REQ-0051, REQ-0066, REQ-0068, REQ-0069, REQ-0070, REQ-0071
        // Given: a running event loop with a known OID in the MIB.
        let (event_loop, bound_addr, sender) = new_test_event_loop(DEFAULT_MAX_CONNECTIONS);
        let loop_handle = thread::spawn(move || event_loop.run());

        let oid: crate::codec::Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        // Populate the MIB and wait for the event loop to process it before
        // connecting, so dispatch cannot race with the SetValue.
        set_and_wait(&sender, &oid, crate::codec::Value::Integer32(42));

        // When: a TCP client sends a raw BER SNMPv3 GetRequest (RFC 3430 framing).
        let mut client = std::net::TcpStream::connect(bound_addr).unwrap();
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
        // Verifies: REQ-0068, REQ-0071
        // Given: a running event loop with a known OID in the MIB.
        let (event_loop, bound_addr, sender) = new_test_event_loop(DEFAULT_MAX_CONNECTIONS);
        let loop_handle = thread::spawn(move || event_loop.run());

        let oid: crate::codec::Oid = "1.3.6.1.2.1.1.2.0".parse().unwrap();
        set_and_wait(&sender, &oid, crate::codec::Value::Integer32(7));

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
        // Verifies: REQ-0073
        // Given: a running event loop.
        let (event_loop, bound_addr, sender) = new_test_event_loop(DEFAULT_MAX_CONNECTIONS);
        let loop_handle = thread::spawn(move || event_loop.run());

        let oid: crate::codec::Oid = "1.3.6.1.2.1.1.3.0".parse().unwrap();
        set_and_wait(&sender, &oid, crate::codec::Value::Integer32(99));

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
        // Verifies: REQ-0073
        // Given: a running event loop with a known OID in the MIB.
        let (event_loop, bound_addr, sender) = new_test_event_loop(DEFAULT_MAX_CONNECTIONS);
        let loop_handle = thread::spawn(move || event_loop.run());

        let oid: crate::codec::Oid = "1.3.6.1.2.1.1.4.0".parse().unwrap();
        set_and_wait(&sender, &oid, crate::codec::Value::Integer32(55));

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
            crate::codec::VarbindValue::Value(crate::codec::Value::Integer32(55))
        );

        sender.send(Command::Shutdown).unwrap();
        loop_handle
            .join()
            .expect("event loop thread panicked")
            .unwrap();
    }

    #[test]
    fn given_wrong_engine_id_when_request_sent_then_report_pdu_returned() {
        // Verifies: REQ-0104
        // Given: a running event loop with a known OID in the MIB.
        let (event_loop, bound_addr, sender) = new_test_event_loop(DEFAULT_MAX_CONNECTIONS);
        let loop_handle = thread::spawn(move || event_loop.run());

        let oid: crate::codec::Oid = "1.3.6.1.2.1.1.5.0".parse().unwrap();
        set_and_wait(&sender, &oid, crate::codec::Value::Integer32(77));

        let mut client = std::net::TcpStream::connect(bound_addr).unwrap();

        // When: a request with the wrong engine ID is sent.
        let wrong_engine_id = b"\x80\x00\x1f\x88\x04wrong";
        let wrong_encoded = framed_get_request_custom(10, 10, &oid, wrong_engine_id, b"");
        client
            .write_all(&wrong_encoded)
            .expect("write must succeed");

        // Then: the agent responds with a Report PDU (usmStatsUnknownEngineIDs).
        let report_frame = read_framed_response(&mut client);
        let report_v3_msg: rasn_snmp::v3::Message =
            rasn::ber::decode(&report_frame).expect("Report must decode as V3Message");
        let rasn_snmp::v3::ScopedPduData::CleartextPdu(report_scoped_pdu) =
            report_v3_msg.scoped_data
        else {
            panic!("Report response must contain a cleartext ScopedPDU");
        };
        assert!(
            matches!(report_scoped_pdu.data, rasn_snmp::v2::Pdus::Report(_)),
            "first response to wrong-engine request must be a Report PDU"
        );

        // And: a subsequent correct request on the same connection still succeeds,
        // confirming the connection was not closed by the Report response.
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
        let (event_loop, bound_addr, sender) = new_test_event_loop(DEFAULT_MAX_CONNECTIONS);
        let loop_handle = thread::spawn(move || event_loop.run());

        let oid: crate::codec::Oid = "1.3.6.1.2.1.1.6.0".parse().unwrap();
        set_and_wait(&sender, &oid, crate::codec::Value::Integer32(88));

        let mut client = std::net::TcpStream::connect(bound_addr).unwrap();

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
        // Verifies: REQ-0071
        // A client sending 0x30 0x80 (SEQUENCE + indefinite-length form) must
        // cause the connection to be closed, not stalled indefinitely.

        // Given: a running event loop.
        let (event_loop, bound_addr, sender) = new_test_event_loop(DEFAULT_MAX_CONNECTIONS);
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

    #[test]
    fn given_frame_at_exactly_max_size_when_received_then_connection_stays_open() {
        // Verifies: REQ-0071, REQ-0073, REQ-0117
        // MAX_FRAME_SIZE is 65535. A frame of exactly 65535 bytes must be accepted
        // (not cause connection closure). The mutant `> with >=` would incorrectly
        // close the connection for this boundary frame.
        //
        // Frame layout (total = 65535 bytes):
        //   - 1 byte:  SEQUENCE tag 0x30
        //   - 5 bytes: BER long-form length (0x84 = 4 subsequent octets, then
        //              0x00 0x00 0xFF 0xF9 = 65529 in big-endian)
        //   - 65529 bytes: garbage content (not a valid SNMP PDU, so the event
        //              loop will silently discard it but keep the connection open)
        //
        // Verification: 1 + 5 + 65529 = 65535 == MAX_FRAME_SIZE.
        let (event_loop, bound_addr, sender) = new_test_event_loop(DEFAULT_MAX_CONNECTIONS);
        let loop_handle = thread::spawn(move || event_loop.run());

        let oid: crate::codec::Oid = "1.3.6.1.2.1.1.7.0".parse().unwrap();
        set_and_wait(&sender, &oid, crate::codec::Value::Integer32(42));

        let mut client = std::net::TcpStream::connect(bound_addr).unwrap();

        // When: a frame of exactly 65535 bytes is sent. The content is garbage
        // (not valid SNMP), so the event loop discards it and keeps the connection.
        // 1 tag + 5 length bytes + 65529 content = 65535 == MAX_FRAME_SIZE.
        let mut boundary_frame = Vec::with_capacity(65535);
        boundary_frame.push(0x30u8); // SEQUENCE tag
        boundary_frame.push(0x84u8); // long form: 4 subsequent octets
        boundary_frame.push(0x00u8); // content_length high byte
        boundary_frame.push(0x00u8);
        boundary_frame.push(0xFFu8);
        boundary_frame.push(0xF9u8); // content_length: 0x0000FFF9 = 65529
        boundary_frame.extend(vec![0xAAu8; 65529]);
        assert_eq!(
            boundary_frame.len(),
            65535,
            "boundary frame must be exactly 65535 bytes"
        );

        client
            .write_all(&boundary_frame)
            .expect("boundary frame write must succeed");

        // Then: a valid SNMPv3 GetRequest on the same connection still gets a response,
        // proving that the boundary frame did NOT close the connection.
        client
            .write_all(&framed_get_request(99, 99, &oid))
            .expect("valid request write must succeed");
        let response_frame = read_framed_response(&mut client);
        let response = decode_v3_response_payload(&response_frame);
        assert_eq!(response.request_id, 99);
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
    fn given_max_connections_reached_when_new_connection_then_rejected() {
        // Verifies: REQ-0120, REQ-0121
        // The event loop accepts at most `max_connections` TCP connections. When
        // the limit is full, the loop stops calling accept() for the current poll
        // cycle; any connections the OS has buffered in the backlog are not
        // registered and will be dropped/RST once the event loop drops the
        // accepted-but-unregistered stream.

        // Given: an event loop with a connection limit of 2.
        let (event_loop, bound_addr, sender) = new_test_event_loop(2);
        let loop_handle = thread::spawn(move || event_loop.run());

        // When: two clients connect (filling the connection table).
        let client_a = std::net::TcpStream::connect(bound_addr).unwrap();
        let client_b = std::net::TcpStream::connect(bound_addr).unwrap();

        // Allow the event loop time to accept both connections.
        thread::sleep(Duration::from_millis(50));

        // Then: a third client connects to the listener socket. The OS accepts
        // the TCP handshake into the kernel backlog, but the event loop will not
        // register it because the limit is already reached.
        let mut client_c = std::net::TcpStream::connect(bound_addr).unwrap();
        client_c
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();

        // The third client receives no data — the event loop neither processes
        // its frames nor sends any response. Attempting to read must time out
        // (WouldBlock / TimedOut) rather than returning data.
        let mut buf = [0u8; 1];
        let read_result = client_c.read(&mut buf);
        // An Ok(0) (EOF/RST) or a timeout error are both acceptable outcomes,
        // because the connection was not registered by the event loop and the
        // OS may close it. What must NOT happen is receiving any data.
        match read_result {
            Ok(bytes_read) => assert_eq!(
                bytes_read, 0,
                "third connection must not receive any data from the event loop"
            ),
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                // Expected: the read timed out because no data was sent.
            }
            Err(e) => panic!("unexpected read error on third connection: {e}"),
        }

        // Clean up: close the first two clients and shut down.
        drop(client_a);
        drop(client_b);
        sender.send(Command::Shutdown).unwrap();
        loop_handle
            .join()
            .expect("event loop thread panicked")
            .unwrap();
    }

    // ── idle connection sweep tests ───────────────────────────────────────────

    #[test]
    fn given_idle_connection_when_timeout_elapses_then_connection_is_closed() {
        // Verifies: REQ-0122
        // Verifies that sweep_idle_connections() closes connections that have
        // been idle longer than the configured timeout.

        // Given: an event loop with a 1 ms idle timeout so the sweep fires almost
        // immediately after the connection is accepted.
        let short_timeout = ConnectionTimeoutConfig {
            normal_timeout: Duration::from_millis(1),
            pressure_timeout: Duration::from_millis(1),
            pressure_headroom: PRESSURE_HEADROOM,
        };
        let (event_loop, bound_addr, sender) = EventLoop::new(
            any_loopback(),
            test_engine_id(),
            1,
            None,
            DEFAULT_MAX_CONNECTIONS,
            short_timeout,
        )
        .unwrap();
        let loop_handle = thread::spawn(move || event_loop.run());

        // When: a client connects and then sends nothing (remains idle).
        let mut client = std::net::TcpStream::connect(bound_addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        // Wait long enough for the timeout to elapse, then wake the event loop
        // so the sweep runs. Sending a Shutdown command wakes the poll and also
        // causes the loop to exit, which is fine — we will check EOF first.
        thread::sleep(Duration::from_millis(50));
        sender.send(Command::Shutdown).unwrap();

        // Then: the client sees EOF because the event loop swept the idle connection.
        let mut read_buf = [0u8; 1];
        let bytes_read = client.read(&mut read_buf).expect("read must not error");
        assert_eq!(bytes_read, 0, "idle connection must be closed by the sweep");

        loop_handle
            .join()
            .expect("event loop thread panicked")
            .unwrap();
    }

    #[test]
    fn given_pressure_headroom_exceeded_when_sweep_then_pressure_timeout_applies() {
        // Verifies: REQ-0124
        // Verifies that when the number of connections reaches max_connections -
        // pressure_headroom, the pressure timeout is used instead of the normal one.
        //
        // Strategy: use a max of 3, headroom of 2, normal timeout of 1 hour, and
        // pressure timeout of 1 ms. With 2 connections open the count (2) satisfies
        // 2 + 2 >= 3, so pressure mode must activate and the 1 ms timeout fires.

        let max_conns = 3usize;
        let pressure_config = ConnectionTimeoutConfig {
            normal_timeout: Duration::from_hours(1), // long enough never to fire
            pressure_timeout: Duration::from_millis(1),
            pressure_headroom: 2,
        };
        let (event_loop, bound_addr, sender) = EventLoop::new(
            any_loopback(),
            test_engine_id(),
            1,
            None,
            max_conns,
            pressure_config,
        )
        .unwrap();
        let loop_handle = thread::spawn(move || event_loop.run());

        // When: two clients connect, putting the agent into pressure mode.
        let mut client_a = std::net::TcpStream::connect(bound_addr).unwrap();
        let mut client_b = std::net::TcpStream::connect(bound_addr).unwrap();
        client_a
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client_b
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        // Wait for the pressure timeout to elapse, then trigger a sweep.
        thread::sleep(Duration::from_millis(50));
        sender.send(Command::Shutdown).unwrap();

        // Then: both clients are closed by the pressure-mode sweep.
        let mut buf = [0u8; 1];
        let a_read = client_a
            .read(&mut buf)
            .expect("client_a read must not error");
        let b_read = client_b
            .read(&mut buf)
            .expect("client_b read must not error");
        assert_eq!(a_read, 0, "client_a must be closed under pressure mode");
        assert_eq!(b_read, 0, "client_b must be closed under pressure mode");

        loop_handle
            .join()
            .expect("event loop thread panicked")
            .unwrap();
    }

    #[test]
    fn given_active_connection_when_sweep_then_not_closed() {
        // Verifies that sweep_idle_connections() does NOT close a connection that
        // has received data recently (i.e., last_activity is fresh).

        // Given: an event loop with a 50 ms normal timeout and a very short
        // pressure timeout. We use a large max_connections so pressure mode is
        // never triggered, isolating the normal-timeout behaviour.
        let config = ConnectionTimeoutConfig {
            normal_timeout: Duration::from_millis(500),
            pressure_timeout: Duration::from_millis(1),
            pressure_headroom: PRESSURE_HEADROOM,
        };
        let (event_loop, bound_addr, sender) = EventLoop::new(
            any_loopback(),
            test_engine_id(),
            1,
            None,
            DEFAULT_MAX_CONNECTIONS,
            config,
        )
        .unwrap();
        let loop_handle = thread::spawn(move || event_loop.run());

        let oid: crate::codec::Oid = "1.3.6.1.2.1.1.8.0".parse().unwrap();
        set_and_wait(&sender, &oid, crate::codec::Value::Integer32(7));

        // When: a client sends a valid request and receives a response, then
        // immediately sends another request after only a brief pause (well within
        // the normal timeout).
        let mut client = std::net::TcpStream::connect(bound_addr).unwrap();
        client
            .write_all(&framed_get_request(50, 50, &oid))
            .expect("first request write must succeed");
        let first_response = read_framed_response(&mut client);
        let first = decode_v3_response_payload(&first_response);
        assert_eq!(first.request_id, 50);

        // Only wait 20 ms — well below the 500 ms normal timeout.
        thread::sleep(Duration::from_millis(20));
        client
            .write_all(&framed_get_request(51, 51, &oid))
            .expect("second request write must succeed");

        // Then: the second request still receives a response, proving the connection
        // was not swept between the two requests.
        let second_response = read_framed_response(&mut client);
        let second = decode_v3_response_payload(&second_response);
        assert_eq!(
            second.request_id, 51,
            "connection must remain open for an active client"
        );

        sender.send(Command::Shutdown).unwrap();
        loop_handle
            .join()
            .expect("event loop thread panicked")
            .unwrap();
    }
}
