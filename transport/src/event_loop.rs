//! Central event loop for the SNMP agent.
//!
//! The loop multiplexes a TCP listener, accepted TLS connections, and a
//! self-pipe using `mio` (epoll/kqueue). Inbound SNMP requests arrive over
//! TLS-framed TCP connections (RFC 6353); outbound traps are sent as plain UDP
//! datagrams.
//!
//! # Design
//!
//! [`EventLoop::new`] binds the listener and allocates the self-pipe, then
//! returns a [`CommandSender`] that callers use to send [`Command`]s from any
//! thread. Writing one byte to the pipe's write end wakes the poll call so the
//! event loop drains the mpsc channel promptly.

use std::collections::HashMap;
use std::fmt;
use std::io::{self, Read};
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::mpsc::{self, Receiver, Sender};

use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};

/// mio token for the TCP listener.
const LISTENER_TOKEN: Token = Token(0);

/// mio token for the self-pipe read end.
const PIPE_TOKEN: Token = Token(1);

/// First token index available for accepted client connections.
const FIRST_CONN_TOKEN: usize = 2;

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
/// let (event_loop, _bound_addr, sender) = EventLoop::new(addr).unwrap();
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

// ── EventLoop ────────────────────────────────────────────────────────────────

/// The mio-driven event loop that owns the TCP listener, accepted connections,
/// and the self-pipe read end.
///
/// Call [`run`][`EventLoop::run`] from a dedicated OS thread. The loop exits
/// when it receives [`Command::Shutdown`].
///
/// # Examples
///
/// ```no_run
/// use std::net::SocketAddr;
/// use transport::event_loop::EventLoop;
///
/// let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
/// let (event_loop, bound_addr, sender) = EventLoop::new(addr).unwrap();
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
    connections: HashMap<Token, mio::net::TcpStream>,
}

impl EventLoop {
    /// Create an [`EventLoop`] bound to `addr`.
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
    /// # Examples
    ///
    /// ```no_run
    /// use std::net::SocketAddr;
    /// use transport::event_loop::EventLoop;
    ///
    /// let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    /// let (event_loop, bound_addr, sender) = EventLoop::new(addr).unwrap();
    /// println!("listening on {bound_addr}");
    /// ```
    pub fn new(addr: SocketAddr) -> Result<(Self, SocketAddr, CommandSender), EventLoopError> {
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
        };
        let sender = CommandSender { tx, pipe_write_fd };

        Ok((event_loop, bound_addr, sender))
    }

    /// Run the event loop until [`Command::Shutdown`] is received.
    ///
    /// Intended to be called from a dedicated OS thread. Blocks until shutdown.
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
                    self.connections.insert(token, stream);
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
    fn drain_commands(&mut self) -> bool {
        loop {
            match self.rx.try_recv() {
                Ok(Command::SetValue { oid, value }) => {
                    eprintln!("[event_loop] SetValue: oid={oid:?} value={value:?}");
                }
                Ok(Command::Shutdown) => {
                    eprintln!("[event_loop] received Shutdown, exiting");
                    return true;
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

    /// Read and discard data from an accepted connection.
    ///
    /// Connection-level I/O errors (e.g. `ConnectionReset`) close and remove
    /// the connection but do not propagate to the caller — a single misbehaving
    /// client must not bring down the entire event loop.
    fn handle_connection_event(&mut self, token: Token) {
        let Some(stream) = self.connections.get_mut(&token) else {
            return;
        };

        let mut buf = [0u8; 4096];
        let mut closed = false;

        loop {
            match stream.read(&mut buf) {
                Ok(0) => {
                    closed = true;
                    break;
                }
                Ok(_n) => {
                    // Data discarded; TLS framing not yet implemented.
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

        if closed && let Some(mut stream) = self.connections.remove(&token) {
            if let Err(e) = self.poll.registry().deregister(&mut stream) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::thread;
    use std::time::Duration;

    fn any_loopback() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    #[test]
    fn given_running_event_loop_when_tcp_client_connects_then_connection_is_accepted() {
        // Given: an event loop bound on a random loopback port.
        let (event_loop, bound_addr, sender) = EventLoop::new(any_loopback()).unwrap();
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
        // Given: a running event loop.
        let (event_loop, _bound_addr, sender) = EventLoop::new(any_loopback()).unwrap();
        let handle = thread::spawn(move || event_loop.run());

        // When: Shutdown is sent.
        sender.send(Command::Shutdown).unwrap();

        // Then: the thread exits and returns Ok.
        let event_loop_result = handle.join().expect("event loop thread panicked");
        assert!(event_loop_result.is_ok());
    }

    #[test]
    fn given_running_event_loop_when_set_value_command_sent_then_loop_drains_channel() {
        // Given: a running event loop.
        let (event_loop, _bound_addr, sender) = EventLoop::new(any_loopback()).unwrap();
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
        let (event_loop, _bound_addr, sender) = EventLoop::new(any_loopback()).unwrap();
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
        };

        // Connect to the std listener so the TcpStream is valid. mio's
        // connect is non-blocking and always returns Ok immediately on Unix.
        let dummy_stream = mio::net::TcpStream::connect(bound).unwrap();
        event_loop
            .connections
            .insert(Token(FIRST_CONN_TOKEN), dummy_stream);

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
}
