//! SNMPv3 agent library.
//!
//! This crate is the public API surface. It exposes [`Agent`], the primary
//! entry point for embedding applications, and ties together the [`codec`],
//! [`mib`], and [`transport`] crates.
//!
//! The agent runs its event loop on a dedicated OS thread spawned at
//! construction time. Application threads communicate with the event loop
//! through channel-based commands: MIB value updates. [`Agent`] is
//! `Clone + Send + Sync` and holds only channel senders, so it can be shared
//! freely across threads.
//!
//! # Quick start
//!
//! ```no_run
//! use basic_snmp_agent::{AgentBuilder, TrapPdu};
//!
//! let agent = AgentBuilder::new()
//!     .listen_addr("0.0.0.0:10161".parse().unwrap())
//!     .build()
//!     .unwrap();
//!
//! let pdu = TrapPdu {
//!     request_id: 1,
//!     trap_oid: "1.3.6.1.6.3.1.1.5.1".parse().unwrap(),
//!     varbinds: vec![],
//! };
//! let dest = "192.0.2.1:162".parse().unwrap();
//! let results = agent.send_trap(&pdu, &[dest]).unwrap();
//! for r in results {
//!     println!("{}: {:?}", r.destination, r.outcome);
//! }
//! ```

mod error;

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub use codec::{Oid, Value, Varbind, VarbindValue};
pub use error::{AgentError, SetError, TrapError};
pub use transport::{TrapPdu, TrapResult};

use transport::event_loop::{Command, EventLoop};
use transport::trap::TrapSender;

// ── AgentInner ───────────────────────────────────────────────────────────────

/// Shared state behind the [`Arc`] in [`Agent`].
///
/// Owns the resources needed to interact with the event loop and to send
/// traps. [`Drop`] sends a [`Command::Shutdown`] and joins the event loop
/// thread, ensuring clean termination when all [`Agent`] clones are dropped.
struct AgentInner {
    command_sender: transport::event_loop::CommandSender,
    trap_sender: TrapSender,
    thread_handle: Mutex<Option<std::thread::JoinHandle<io::Result<()>>>>,
}

impl Drop for AgentInner {
    fn drop(&mut self) {
        // Errors are ignored: the event loop may have already exited.
        let _ = self.command_sender.send(Command::Shutdown);
        // `unwrap_or_else` recovers a poisoned mutex so the thread handle is
        // always joined, even if a panic occurred while the lock was held.
        let mut guard = self
            .thread_handle
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(handle) = guard.take() {
            let _ = handle.join();
        }
    }
}

// ── Agent ────────────────────────────────────────────────────────────────────

/// A running SNMP agent.
///
/// `Agent` is a cheap-to-clone handle: all clones share the same underlying
/// event loop thread and UDP trap socket. The event loop shuts down
/// automatically when all `Agent` clones are dropped.
///
/// Construct an `Agent` via [`AgentBuilder`].
///
/// # Examples
///
/// ```no_run
/// use basic_snmp_agent::{AgentBuilder, TrapPdu};
///
/// let agent = AgentBuilder::new().build().unwrap();
/// let pdu = TrapPdu {
///     request_id: 1,
///     trap_oid: "1.3.6.1.6.3.1.1.5.1".parse().unwrap(),
///     varbinds: vec![],
/// };
/// let dest = "192.0.2.1:162".parse().unwrap();
/// let results = agent.send_trap(&pdu, &[dest]).unwrap();
/// ```
#[derive(Clone)]
pub struct Agent(Arc<AgentInner>);

impl Agent {
    /// Send a trap PDU to one or more destinations.
    ///
    /// Blocks until all destinations have been attempted and returns one
    /// [`TrapResult`] per destination, in the same order as `destinations`.
    ///
    /// The agent automatically prepends `sysUpTime.0` and `snmpTrapOID.0` as
    /// the first two varbinds, as required by RFC 3416 §4.2.6.
    ///
    /// **Note:** Only IPv4 destinations are supported. Passing an IPv6
    /// `SocketAddr` will produce an `Err` in the corresponding [`TrapResult`].
    ///
    /// # Errors
    ///
    /// Returns [`TrapError::EmptyDestinations`] immediately if `destinations`
    /// is empty, without sending any PDU.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use basic_snmp_agent::{AgentBuilder, TrapPdu};
    ///
    /// let agent = AgentBuilder::new().build().unwrap();
    /// let pdu = TrapPdu {
    ///     request_id: 1,
    ///     trap_oid: "1.3.6.1.6.3.1.1.5.1".parse().unwrap(),
    ///     varbinds: vec![],
    /// };
    /// let results = agent.send_trap(&pdu, &["127.0.0.1:162".parse().unwrap()]).unwrap();
    /// assert!(results[0].outcome.is_ok());
    /// ```
    pub fn send_trap(
        &self,
        pdu: &TrapPdu,
        destinations: &[SocketAddr],
    ) -> Result<Vec<TrapResult>, TrapError> {
        if destinations.is_empty() {
            return Err(TrapError::EmptyDestinations);
        }
        Ok(self.0.trap_sender.send_trap(pdu, destinations))
    }

    /// Update or insert a single OID in the agent's MIB store.
    ///
    /// Uses upsert semantics: if the OID already exists, its value is updated;
    /// otherwise a new entry is created. Safe to call from any thread.
    ///
    /// # Errors
    ///
    /// Returns [`SetError::Disconnected`] if the event loop has terminated.
    pub fn set(&self, oid: Oid, value: Value) -> Result<(), SetError> {
        self.0
            .command_sender
            .send(Command::SetValue { oid, value })
            .map_err(|_| SetError::Disconnected)
    }
}

// ── AgentBuilder ─────────────────────────────────────────────────────────────

/// Builder for constructing and starting an [`Agent`].
///
/// # Examples
///
/// ```no_run
/// use basic_snmp_agent::AgentBuilder;
///
/// let agent = AgentBuilder::new()
///     .listen_addr("0.0.0.0:10161".parse().unwrap())
///     .build()
///     .unwrap();
/// ```
pub struct AgentBuilder {
    listen_addr: SocketAddr,
}

impl AgentBuilder {
    /// Create a builder with default settings.
    ///
    /// Default listen address: `0.0.0.0:10161` (IANA-assigned SNMP-over-TLS port).
    pub fn new() -> Self {
        Self {
            listen_addr: "0.0.0.0:10161"
                .parse()
                .expect("default listen address is valid"),
        }
    }

    /// Override the TCP listen address and port.
    ///
    /// Use port `0` to let the OS assign a free port (useful in tests).
    #[must_use]
    pub fn listen_addr(mut self, addr: SocketAddr) -> Self {
        self.listen_addr = addr;
        self
    }

    /// Construct and start the agent.
    ///
    /// Binds the TCP listener on [`listen_addr`][`Self::listen_addr`], creates
    /// the UDP socket for outbound traps, and spawns the event loop thread.
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] if the TCP listener cannot be bound
    /// ([`AgentError::Bind`]), the event loop infrastructure cannot be
    /// initialised ([`AgentError::Socket`]), the UDP trap socket cannot be
    /// created ([`AgentError::UdpSocket`]), or the event loop thread cannot be
    /// spawned ([`AgentError::Spawn`]).
    pub fn build(self) -> Result<Agent, AgentError> {
        let listen_addr = self.listen_addr;

        // Heuristic: `AddrInUse`/`AddrNotAvailable` almost certainly come from
        // `TcpListener::bind`; any other error kind is treated as a socket
        // configuration failure. `EventLoop::new` does not yet return a
        // structured error type that would let us distinguish these precisely.
        let (event_loop, _bound_addr, command_sender) =
            EventLoop::new(listen_addr).map_err(|e| match e.kind() {
                io::ErrorKind::AddrInUse | io::ErrorKind::AddrNotAvailable => {
                    AgentError::Bind { addr: listen_addr, source: e }
                }
                _ => AgentError::Socket(e),
            })?;

        let trap_sender = TrapSender::new(Instant::now()).map_err(AgentError::UdpSocket)?;

        let thread_handle = std::thread::Builder::new()
            .name("snmp-agent-event-loop".into())
            .spawn(move || event_loop.run())
            .map_err(AgentError::Spawn)?;

        Ok(Agent(Arc::new(AgentInner {
            command_sender,
            trap_sender,
            thread_handle: Mutex::new(Some(thread_handle)),
        })))
    }
}

impl Default for AgentBuilder {
    fn default() -> Self {
        Self::new()
    }
}
