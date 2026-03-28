//! `SNMPv3` agent library.
//!
//! This crate is the public API surface. It exposes [`Agent`], the primary
//! entry point for embedding applications, and ties together the [`codec`],
//! [`mib`], and [`transport`] modules.
//!
//! The agent runs its event loop on a dedicated OS thread spawned at
//! construction time. Application threads communicate with the event loop
//! through channel-based commands: MIB value updates. [`Agent`] is
//! `Clone + Send + Sync` and holds only channel senders, so it can be shared
//! freely across threads.
//!
//! # Requirements
//! Implements: REQ-0001, REQ-0002, REQ-0003, REQ-0049
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

pub mod codec;
mod error;
pub mod mib;
pub mod transport;

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub use crate::codec::{Oid, Value, Varbind, VarbindValue};
pub use crate::transport::process_snmpv3_request;
pub use crate::transport::{TrapPdu, TrapResult};
pub use error::{AgentError, SetError, TrapError};

use crate::transport::event_loop::{Command, EventLoop, EventLoopError};
use crate::transport::trap::TrapSender;

// ── AgentInner ───────────────────────────────────────────────────────────────

/// Shared state behind the [`Arc`] in [`Agent`].
///
/// Owns the resources needed to interact with the event loop and to send
/// traps. [`Drop`] sends a [`Command::Shutdown`] and joins the event loop
/// thread, ensuring clean termination when all [`Agent`] clones are dropped.
struct AgentInner {
    command_sender: crate::transport::event_loop::CommandSender,
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
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
/// # Requirements
/// Implements: REQ-0002, REQ-0003, REQ-0046
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
    /// **Note:** This method performs UDP I/O on the caller's thread directly —
    /// it does not route through the event loop. The UDP socket is intentionally
    /// not registered with mio (per ADR-0003), so no channel round-trip is
    /// needed. The caller's thread is the one issuing the `sendto` syscall for
    /// each destination.
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
    /// # Requirements
    /// Implements: REQ-0034, REQ-0035, REQ-0040, REQ-0042, REQ-0043, REQ-0047
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
    /// # Requirements
    /// Implements: REQ-0062, REQ-0063, REQ-0064, REQ-0065
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
    /// `SNMPv3` engine ID for this agent instance. Inbound requests with a
    /// different engine ID are silently discarded (REQ-0057).
    engine_id: Vec<u8>,
}

impl AgentBuilder {
    /// Create a builder with default settings.
    ///
    /// Default listen address: `0.0.0.0:10161` (IANA-assigned SNMP-over-TLS port).
    /// Default engine ID: enterprise-format OID-based identifier (REQ-0055).
    ///
    /// # Panics
    ///
    /// Never panics in practice; the `expect` guards a compile-time constant address.
    #[must_use]
    pub fn new() -> Self {
        Self {
            listen_addr: "0.0.0.0:10161"
                .parse()
                .expect("default listen address is valid"),
            // Default engine ID: enterprise OID format (0x80 = enterprise,
            // 0x00 0x1f 0x88 = enterprise number 8072, 0x04 = text format).
            engine_id: b"\x80\x00\x1f\x88\x04basic-snmp-agent".to_vec(),
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

    /// Override the `SNMPv3` engine ID.
    ///
    /// The engine ID identifies this agent uniquely in the network. Inbound
    /// `SNMPv3` messages with a different engine ID are silently discarded.
    ///
    /// # Requirements
    /// Implements: REQ-0055
    #[must_use]
    pub fn engine_id(mut self, engine_id: Vec<u8>) -> Self {
        self.engine_id = engine_id;
        self
    }

    /// Construct and start the agent.
    ///
    /// Binds the TCP listener on [`listen_addr`][`Self::listen_addr`], creates
    /// the UDP socket for outbound traps, and spawns the event loop thread.
    ///
    /// # Requirements
    /// Implements: REQ-0037, REQ-0048, REQ-0050, REQ-0051, REQ-0052, REQ-0053, REQ-0054, REQ-0055
    ///
    /// # Errors
    ///
    /// Returns an [`AgentError`] if the engine ID length is outside the RFC 3411 §5
    /// range of 5–32 octets ([`AgentError::InvalidEngineId`]), the TCP listener
    /// cannot be bound ([`AgentError::Bind`]), the event loop infrastructure cannot
    /// be initialised ([`AgentError::Socket`]), the UDP trap socket cannot be created
    /// ([`AgentError::UdpSocket`]), or the event loop thread cannot be spawned
    /// ([`AgentError::Spawn`]).
    pub fn build(self) -> Result<Agent, AgentError> {
        // RFC 3411 §5: SnmpEngineID must be between 5 and 32 octets inclusive.
        if self.engine_id.len() < 5 || self.engine_id.len() > 32 {
            return Err(AgentError::InvalidEngineId);
        }

        let listen_addr = self.listen_addr;

        let (event_loop, _bound_addr, command_sender) = EventLoop::new(listen_addr, self.engine_id)
            .map_err(|e| match e {
                EventLoopError::Bind { addr, source } => AgentError::Bind { addr, source },
                EventLoopError::Pipe(source) | EventLoopError::Registration(source) => {
                    AgentError::Socket(source)
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;

    fn test_agent() -> Agent {
        // Port 0 lets the OS assign a free port, avoiding conflicts between tests.
        AgentBuilder::new()
            .listen_addr("127.0.0.1:0".parse().unwrap())
            .build()
            .unwrap()
    }

    #[test]
    fn given_empty_destinations_when_send_trap_then_error() {
        // Verifies: REQ-0043
        let agent = test_agent();
        let pdu = TrapPdu {
            request_id: 1,
            trap_oid: "1.3.6.1.6.3.1.1.5.1".parse().unwrap(),
            varbinds: vec![],
        };

        let result = agent.send_trap(&pdu, &[]);

        assert!(matches!(result, Err(TrapError::EmptyDestinations)));
    }

    #[test]
    fn given_trap_pdu_with_varbinds_when_send_trap_then_result_ok() {
        // Verifies: REQ-0034, REQ-0040, REQ-0042, REQ-0050
        let agent = test_agent();
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let dest = receiver.local_addr().unwrap();
        let pdu = TrapPdu {
            request_id: 1,
            trap_oid: "1.3.6.1.6.3.1.1.5.1".parse().unwrap(),
            varbinds: vec![Varbind {
                oid: "1.3.6.1.2.1.1.1.0".parse().unwrap(),
                value: VarbindValue::Value(Value::Integer32(42)),
            }],
        };

        let results = agent.send_trap(&pdu, &[dest]).unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].destination, dest);
        assert!(results[0].outcome.is_ok());
    }

    #[test]
    fn given_custom_engine_id_when_build_then_agent_starts() {
        // Verifies: REQ-0001, REQ-0002, REQ-0048, REQ-0049, REQ-0055
        let custom_engine_id = b"\x80\x00\x1f\x88\x04custom".to_vec();
        let agent = AgentBuilder::new()
            .listen_addr("127.0.0.1:0".parse().unwrap())
            .engine_id(custom_engine_id)
            .build();

        assert!(
            agent.is_ok(),
            "expected agent to build with custom engine ID"
        );
    }

    #[test]
    fn given_engine_id_too_short_when_build_then_invalid_engine_id_error() {
        // Verifies: REQ-0055
        let too_short = b"ab".to_vec(); // 2 bytes, below the 5-byte minimum
        let result = AgentBuilder::new()
            .listen_addr("127.0.0.1:0".parse().unwrap())
            .engine_id(too_short)
            .build();
        assert!(
            matches!(result, Err(AgentError::InvalidEngineId)),
            "expected InvalidEngineId error for too-short engine ID"
        );
    }

    #[test]
    fn given_engine_id_too_long_when_build_then_invalid_engine_id_error() {
        // Verifies: REQ-0055
        let too_long = vec![0u8; 33]; // 33 bytes, above the 32-byte maximum
        let result = AgentBuilder::new()
            .listen_addr("127.0.0.1:0".parse().unwrap())
            .engine_id(too_long)
            .build();
        assert!(
            matches!(result, Err(AgentError::InvalidEngineId)),
            "expected InvalidEngineId error for too-long engine ID"
        );
    }

    #[test]
    fn given_agent_when_set_called_then_returns_ok() {
        // Verifies: REQ-0062
        let agent = test_agent();
        let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();

        let result = agent.set(oid, Value::Integer32(42));

        assert!(result.is_ok());
    }

    #[test]
    fn given_agent_when_set_called_from_another_thread_then_returns_ok() {
        // Verifies: REQ-0003, REQ-0064
        let agent = test_agent();
        let agent_clone = agent.clone();
        let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();

        let thread_result = std::thread::spawn(move || agent_clone.set(oid, Value::Integer32(1)))
            .join()
            .unwrap();

        assert!(thread_result.is_ok());
    }

    #[test]
    fn given_non_mut_agent_when_set_called_then_compiles_and_returns_ok() {
        // Verifies: REQ-0065
        // `agent` is a non-`mut` binding; `set` takes `&self`, so no `mut` is needed.
        let agent = test_agent();
        let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();

        let result = agent.set(oid, Value::Integer32(7));

        assert!(result.is_ok());
    }
}
