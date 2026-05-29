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
//! use basic_snmp_agent::{AgentBuilder, SecurityConfig, TrapPdu};
//!
//! let agent = AgentBuilder::new(SecurityConfig::NoAuthNoPriv)
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
pub mod usm;

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub use crate::codec::{Oid, Value, Varbind, VarbindValue};
pub use crate::transport::event_loop::ConnectionTimeoutConfig;
pub use crate::transport::process_snmpv3_request;
pub use crate::transport::{TrapPdu, TrapResult};
pub use crate::usm::user::{AuthNoPrivUser, AuthPrivUser};
pub use error::{AgentError, SetError, TrapError};

use crate::transport::event_loop::{Command, DEFAULT_MAX_CONNECTIONS, EventLoop, EventLoopError};
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
    /// Actual address the TCP listener bound to; stored so [`Agent::local_addr`] can return it.
    bound_addr: SocketAddr,
}

impl Drop for AgentInner {
    fn drop(&mut self) {
        // Errors are ignored: the event loop may have already exited.
        let _send_result = self.command_sender.send(Command::Shutdown);
        // `unwrap_or_else` recovers a poisoned mutex so the thread handle is
        // always joined, even if a panic occurred while the lock was held.
        let mut guard = self
            .thread_handle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(handle) = guard.take() {
            // Panics and I/O errors from the event loop thread cannot be
            // propagated from Drop and are non-actionable during shutdown.
            let _join_result = handle.join();
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
/// use basic_snmp_agent::{AgentBuilder, SecurityConfig, TrapPdu};
///
/// let agent = AgentBuilder::new(SecurityConfig::NoAuthNoPriv).build().unwrap();
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
    /// use basic_snmp_agent::{AgentBuilder, SecurityConfig, TrapPdu};
    ///
    /// let agent = AgentBuilder::new(SecurityConfig::NoAuthNoPriv).build().unwrap();
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

    /// Return the local address the agent's TCP listener is bound to.
    ///
    /// Useful when the agent was built with port `0` (OS-assigned port) to
    /// discover which port was selected.
    ///
    /// # Requirements
    /// Implements: REQ-0050
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use basic_snmp_agent::{AgentBuilder, SecurityConfig};
    ///
    /// let agent = AgentBuilder::new(SecurityConfig::NoAuthNoPriv)
    ///     .listen_addr("127.0.0.1:0".parse().unwrap())
    ///     .build()
    ///     .unwrap();
    /// let addr = agent.local_addr();
    /// assert_eq!(addr.ip(), std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    /// ```
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.0.bound_addr
    }
}

// ── SecurityConfig ────────────────────────────────────────────────────────────

/// The security configuration supplied to [`AgentBuilder`].
///
/// Each variant corresponds to one of the three USM security levels defined in
/// RFC 3414. The variant chosen determines which key material is required and
/// what behaviour the agent enforces when processing inbound requests and
/// sending outbound traps.
///
/// # Requirements
/// Implements: REQ-0075, REQ-0076, REQ-0077, REQ-0129
///
/// # Examples
///
/// ```
/// use basic_snmp_agent::{SecurityConfig, AuthNoPrivUser, AuthPrivUser};
/// use basic_snmp_agent::usm::boots::{EngineBootsStore, StoredBootsState};
/// use basic_snmp_agent::usm::user::UserName;
/// use basic_snmp_agent::usm::auth::AuthProtocol;
/// use basic_snmp_agent::usm::keys::SecretKey;
/// use basic_snmp_agent::usm::privacy::PrivProtocol;
///
/// struct NullStore;
/// impl EngineBootsStore for NullStore {
///     fn load(&mut self) -> Result<Option<StoredBootsState>, std::io::Error> { Ok(None) }
///     fn save(&mut self, _: &[u8], _: u32) -> Result<(), std::io::Error> { Ok(()) }
/// }
///
/// // No authentication or encryption.
/// let _config = SecurityConfig::NoAuthNoPriv;
///
/// // Authentication without encryption.
/// let key = SecretKey::new_from_exposed_slice(&[0_u8; 32]);
/// let user = AuthNoPrivUser::new(UserName::new("alice").unwrap(), AuthProtocol::HmacSha256, key).unwrap();
/// assert_eq!(user.name().as_str(), "alice");
/// let _config = SecurityConfig::AuthNoPriv { user, boots_store: Box::new(NullStore) };
///
/// // Authentication with encryption.
/// let key = SecretKey::new_from_exposed_slice(&[0_u8; 32]);
/// let user = AuthPrivUser::new(UserName::new("bob").unwrap(), AuthProtocol::HmacSha256, key, PrivProtocol::Aes128).unwrap();
/// assert_eq!(user.name().as_str(), "bob");
/// let _config = SecurityConfig::AuthPriv { user, boots_store: Box::new(NullStore) };
/// ```
pub enum SecurityConfig {
    /// No authentication and no privacy.
    ///
    /// Requests are accepted without any credential check. No engine-boots
    /// counter is maintained.
    ///
    /// # Requirements
    /// Implements: REQ-0075
    NoAuthNoPriv,

    /// Authentication without privacy.
    ///
    /// Inbound requests must carry a valid HMAC-SHA-2 MAC; outbound traps are
    /// authenticated. Payloads are transmitted in the clear. The engine-boots
    /// counter is persisted via the provided [`EngineBootsStore`][crate::usm::boots::EngineBootsStore].
    ///
    /// # Requirements
    /// Implements: REQ-0076
    AuthNoPriv {
        /// The authenticated user.
        user: AuthNoPrivUser,
        /// Storage for the persistent engine-boots counter (RFC 3414 §2.2).
        boots_store: Box<dyn crate::usm::boots::EngineBootsStore + Send>,
    },

    /// Authentication with privacy.
    ///
    /// Inbound requests must carry a valid HMAC-SHA-2 MAC and an encrypted
    /// payload; outbound traps are both authenticated and encrypted. The
    /// engine-boots counter is persisted via the provided
    /// [`EngineBootsStore`][crate::usm::boots::EngineBootsStore].
    ///
    /// # Requirements
    /// Implements: REQ-0077
    AuthPriv {
        /// The authenticated and privacy-enabled user.
        user: AuthPrivUser,
        /// Storage for the persistent engine-boots counter (RFC 3414 §2.2).
        boots_store: Box<dyn crate::usm::boots::EngineBootsStore + Send>,
    },
}

// ── AgentBuilder ─────────────────────────────────────────────────────────────

/// Builder for constructing and starting an [`Agent`].
///
/// # Examples
///
/// ```no_run
/// use basic_snmp_agent::{AgentBuilder, SecurityConfig};
///
/// let agent = AgentBuilder::new(SecurityConfig::NoAuthNoPriv)
///     .listen_addr("0.0.0.0:10161".parse().unwrap())
///     .build()
///     .unwrap();
/// ```
pub struct AgentBuilder {
    listen_addr: SocketAddr,
    /// `SNMPv3` engine ID for this agent instance. Inbound requests with a
    /// different engine ID are rejected with a Report PDU (REQ-0104).
    engine_id: Vec<u8>,
    // Security configuration supplied at construction time.
    // Implements: REQ-0075, REQ-0076, REQ-0077, REQ-0129
    security: SecurityConfig,
    // Maximum number of concurrent TCP connections; defaults to DEFAULT_MAX_CONNECTIONS.
    max_connections: usize,
    // Idle-connection sweep configuration; defaults to ConnectionTimeoutConfig::default().
    timeout_config: ConnectionTimeoutConfig,
}

impl AgentBuilder {
    /// Create a builder with the given security configuration.
    ///
    /// The [`SecurityConfig`] determines the agent's minimum security level and
    /// bundles all required parameters for that level (user credentials and
    /// engine-boots store). Optional parameters (listen address, engine ID,
    /// max connections, timeout config) are set via builder methods.
    ///
    /// Default listen address: `0.0.0.0:10161` (IANA-assigned SNMP-over-TLS port).
    /// Default engine ID: enterprise-format OID-based identifier (REQ-0055).
    ///
    /// # Requirements
    /// Implements: REQ-0129
    ///
    /// # Panics
    ///
    /// Never panics in practice; the `expect` guards a compile-time constant address.
    #[must_use]
    pub fn new(security: SecurityConfig) -> Self {
        Self {
            listen_addr: "0.0.0.0:10161"
                .parse()
                .expect("default listen address is valid"),
            // Default engine ID: enterprise OID format (0x80 = enterprise,
            // 0x00 0x1f 0x88 = enterprise number 8072, 0x04 = text format).
            engine_id: b"\x80\x00\x1f\x88\x04basic-snmp-agent".to_vec(),
            security,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            timeout_config: ConnectionTimeoutConfig::default(),
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

    /// Override the maximum number of concurrent TCP connections.
    ///
    /// Default: [`DEFAULT_MAX_CONNECTIONS`] (64). When this limit is reached,
    /// new connections are rejected until existing ones close.
    ///
    /// # Requirements
    /// Implements: REQ-0120
    #[must_use]
    pub fn max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    /// Override the idle-connection timeout configuration.
    ///
    /// Controls how long a TCP connection may remain idle before it is closed.
    /// Two timeouts are supported: a normal timeout that applies when the
    /// connection count is well below the maximum, and a shorter pressure timeout
    /// that applies when the count nears the limit.
    ///
    /// Default: [`ConnectionTimeoutConfig::default`] (300 s normal, 30 s pressure,
    /// headroom of 5).
    ///
    /// # Requirements
    /// Implements: REQ-0123
    #[must_use]
    pub fn connection_timeout_config(mut self, config: ConnectionTimeoutConfig) -> Self {
        self.timeout_config = config;
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
    ///
    /// Returns [`AgentError::EngineBoots`] if the `snmpEngineBoots` counter is at its ceiling
    /// (per RFC 3414 §2.2) or the backing store fails.
    pub fn build(self) -> Result<Agent, AgentError> {
        // RFC 3411 §5: SnmpEngineID must be between 5 and 32 octets inclusive.
        if self.engine_id.len() < 5 || self.engine_id.len() > 32 {
            return Err(AgentError::InvalidEngineId);
        }

        let (usm_user, mut boots_store) = match self.security {
            SecurityConfig::NoAuthNoPriv => (None, None),
            SecurityConfig::AuthNoPriv { user, boots_store } => (
                Some(crate::usm::user::UsmUser::from(user)),
                Some(boots_store),
            ),
            SecurityConfig::AuthPriv { user, boots_store } => (
                Some(crate::usm::user::UsmUser::from(user)),
                Some(boots_store),
            ),
        };

        let engine_boots = match boots_store.as_deref_mut() {
            Some(store) => crate::usm::boots::initialise_engine_boots(store, &self.engine_id)
                .map_err(AgentError::EngineBoots)?,
            // NoAuthNoPriv carries no boots store; boots is unused at this
            // security level but the event loop still expects a value.
            None => 1,
        };
        let usm_user = usm_user.map(std::sync::Arc::new);

        let listen_addr = self.listen_addr;

        // Clone engine_id so both the event loop and the trap sender get their
        // own copy; the event loop takes ownership of the original.
        let trap_engine_id = self.engine_id.clone();

        let (event_loop, bound_addr, command_sender) = EventLoop::new(
            listen_addr,
            self.engine_id,
            engine_boots,
            usm_user.clone(),
            self.max_connections,
            self.timeout_config,
        )
        .map_err(|e| match e {
            EventLoopError::Bind { addr, source } => AgentError::Bind { addr, source },
            EventLoopError::Waker(source) | EventLoopError::Registration(source) => {
                AgentError::Socket(source)
            }
        })?;

        let trap_sender = TrapSender::new(Instant::now(), trap_engine_id, engine_boots, usm_user)
            .map_err(AgentError::UdpSocket)?;

        let thread_handle = std::thread::Builder::new()
            .name("snmp-agent-event-loop".into())
            .spawn(move || event_loop.run())
            .map_err(AgentError::Spawn)?;

        Ok(Agent(Arc::new(AgentInner {
            command_sender,
            trap_sender,
            thread_handle: Mutex::new(Some(thread_handle)),
            bound_addr,
        })))
    }
}

const _: () = {
    fn assert_send_sync<T: Send + Sync>() {}
    let _ = assert_send_sync::<crate::usm::user::UsmUser>;
    let _ = assert_send_sync::<Agent>;
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::time::Duration;

    use crate::usm::boots::{EngineBootsStore, StoredBootsState};

    struct NullStore;
    impl EngineBootsStore for NullStore {
        fn load(&mut self) -> Result<Option<StoredBootsState>, std::io::Error> {
            Ok(None)
        }
        fn save(&mut self, _: &[u8], _: u32) -> Result<(), std::io::Error> {
            Ok(())
        }
    }

    fn test_agent() -> Agent {
        // Port 0 lets the OS assign a free port, avoiding conflicts between tests.
        AgentBuilder::new(SecurityConfig::NoAuthNoPriv)
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
        results[0].outcome.as_ref().expect("trap send must succeed");
    }

    #[test]
    fn given_custom_engine_id_when_build_then_agent_starts() {
        // Verifies: REQ-0001, REQ-0002, REQ-0048, REQ-0049, REQ-0055
        let custom_engine_id = b"\x80\x00\x1f\x88\x04custom".to_vec();
        let agent = AgentBuilder::new(SecurityConfig::NoAuthNoPriv)
            .listen_addr("127.0.0.1:0".parse().unwrap())
            .engine_id(custom_engine_id)
            .build();

        agent.expect("expected agent to build with custom engine ID");
    }

    #[test]
    fn given_engine_id_too_short_when_build_then_invalid_engine_id_error() {
        // Verifies: REQ-0055
        let too_short = b"ab".to_vec(); // 2 bytes, below the 5-byte minimum
        let result = AgentBuilder::new(SecurityConfig::NoAuthNoPriv)
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
        let too_long = vec![0_u8; 33]; // 33 bytes, above the 32-byte maximum
        let result = AgentBuilder::new(SecurityConfig::NoAuthNoPriv)
            .listen_addr("127.0.0.1:0".parse().unwrap())
            .engine_id(too_long)
            .build();
        assert!(
            matches!(result, Err(AgentError::InvalidEngineId)),
            "expected InvalidEngineId error for too-long engine ID"
        );
    }

    #[test]
    fn given_engine_id_exactly_5_bytes_when_build_then_succeeds() {
        // Verifies: REQ-0055
        // 5 bytes is the minimum valid length per RFC 3411 §5. The mutant
        // `< with <=` would incorrectly reject this boundary value.
        let min_valid = vec![0x80_u8, 0x00, 0x1f, 0x88, 0x01]; // exactly 5 bytes
        let result = AgentBuilder::new(SecurityConfig::NoAuthNoPriv)
            .listen_addr("127.0.0.1:0".parse().unwrap())
            .engine_id(min_valid)
            .build();
        result.expect("expected Ok for 5-byte engine ID (minimum valid length)");
    }

    #[test]
    fn given_engine_id_exactly_32_bytes_when_build_then_succeeds() {
        // Verifies: REQ-0055
        // 32 bytes is the maximum valid length per RFC 3411 §5. The mutant
        // `> with >=` would incorrectly reject this boundary value.
        let max_valid = vec![0xAA_u8; 32]; // exactly 32 bytes
        let result = AgentBuilder::new(SecurityConfig::NoAuthNoPriv)
            .listen_addr("127.0.0.1:0".parse().unwrap())
            .engine_id(max_valid)
            .build();
        result.expect("expected Ok for 32-byte engine ID (maximum valid length)");
    }

    #[test]
    fn given_agent_when_set_called_then_returns_ok() {
        // Verifies: REQ-0062
        let agent = test_agent();
        let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();

        let result = agent.set(oid, Value::Integer32(42));

        result.expect("set must succeed");
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

        thread_result.expect("set from spawned thread must succeed");
        // Use the original handle to confirm both clones remain functional.
        let another_oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        agent
            .set(another_oid, Value::Integer32(2))
            .expect("set from original handle must succeed");
    }

    #[test]
    fn given_non_mut_agent_when_set_called_then_compiles_and_returns_ok() {
        // Verifies: REQ-0065
        // `agent` is a non-`mut` binding; `set` takes `&self`, so no `mut` is needed.
        let agent = test_agent();
        let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();

        let result = agent.set(oid, Value::Integer32(7));

        result.expect("set must succeed");
    }

    #[test]
    fn given_agent_when_set_called_then_value_is_stored_in_event_loop() {
        // Verifies: REQ-0062, REQ-0063
        // The mutant replaces Agent::set with Ok(()) without forwarding the command.
        // This test catches that by querying the event loop directly via the
        // internal command_sender after calling agent.set(), proving the command
        // was actually forwarded and not silently dropped.
        let agent = test_agent();
        let oid: Oid = "1.3.6.1.2.1.1.9.0".parse().unwrap();

        agent.set(oid.clone(), Value::Integer32(123)).unwrap();

        // Use QueryValue on the same channel to verify the value landed in the store.
        // Because the event loop processes commands in order, the QueryValue reply
        // arriving confirms the preceding SetValue has been applied.
        let (reply_tx, reply_rx) = std::sync::mpsc::sync_channel(1);
        agent
            .0
            .command_sender
            .send(Command::QueryValue {
                oid,
                reply: reply_tx,
            })
            .unwrap();

        let stored_value = reply_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("timed out waiting for QueryValue reply");

        assert_eq!(
            stored_value,
            Some(Value::Integer32(123)),
            "expected the value set via Agent::set to be present in the MIB store"
        );
    }

    #[test]
    fn given_auth_no_priv_config_when_build_then_agent_starts() {
        // Verifies: REQ-0076, REQ-0129
        use crate::usm::auth::AuthProtocol;
        use crate::usm::keys::SecretKey;
        use crate::usm::user::UserName;

        let key = SecretKey::new_from_exposed_slice(&[0_u8; 32]);
        let user = AuthNoPrivUser::new(
            UserName::new("public").unwrap(),
            AuthProtocol::HmacSha256,
            key,
        )
        .unwrap();
        let config = SecurityConfig::AuthNoPriv {
            user,
            boots_store: Box::new(NullStore),
        };
        let result = AgentBuilder::new(config)
            .listen_addr("127.0.0.1:0".parse().unwrap())
            .build();
        result.expect("expected agent to start with AuthNoPriv SecurityConfig");
    }

    #[test]
    fn given_auth_no_priv_config_with_boots_store_when_build_then_boots_initialised() {
        // Verifies: REQ-0094, REQ-0095, REQ-0129
        use crate::usm::auth::AuthProtocol;
        use crate::usm::keys::SecretKey;
        use crate::usm::user::UserName;
        use std::sync::{Arc, Mutex};

        struct TrackingStore {
            loaded: bool,
            saved: bool,
            saved_boots: u32,
        }
        impl EngineBootsStore for TrackingStore {
            fn load(&mut self) -> Result<Option<StoredBootsState>, std::io::Error> {
                self.loaded = true;
                Ok(None)
            }
            fn save(&mut self, _engine_id: &[u8], boots: u32) -> Result<(), std::io::Error> {
                self.saved = true;
                self.saved_boots = boots;
                Ok(())
            }
        }

        struct ObservableStore(Arc<Mutex<TrackingStore>>);
        impl EngineBootsStore for ObservableStore {
            fn load(&mut self) -> Result<Option<StoredBootsState>, std::io::Error> {
                self.0
                    .lock()
                    .map_err(|_| std::io::Error::other("store lock poisoned"))?
                    .load()
            }
            fn save(&mut self, engine_id: &[u8], boots: u32) -> Result<(), std::io::Error> {
                self.0
                    .lock()
                    .map_err(|_| std::io::Error::other("store lock poisoned"))?
                    .save(engine_id, boots)
            }
        }

        let inner = Arc::new(Mutex::new(TrackingStore {
            loaded: false,
            saved: false,
            saved_boots: 0,
        }));
        let store = ObservableStore(Arc::clone(&inner));
        let key = SecretKey::new_from_exposed_slice(&[0_u8; 32]);
        let user = AuthNoPrivUser::new(
            UserName::new("testuser").unwrap(),
            AuthProtocol::HmacSha256,
            key,
        )
        .unwrap();
        let config = SecurityConfig::AuthNoPriv {
            user,
            boots_store: Box::new(store),
        };
        AgentBuilder::new(config)
            .listen_addr("127.0.0.1:0".parse().unwrap())
            .build()
            .unwrap();

        let state = inner.lock().unwrap();
        assert!(state.loaded, "store.load() must be called at build time");
        assert!(state.saved, "store.save() must be called at build time");
        assert_eq!(
            state.saved_boots, 1,
            "first-time initialisation must save boots = 1"
        );
        drop(state);
    }

    #[test]
    fn given_boots_at_ceiling_when_build_then_engine_boots_error() {
        // Verifies: REQ-0097
        use crate::error::AgentError;
        use crate::usm::auth::AuthProtocol;
        use crate::usm::boots::MAX_ENGINE_BOOTS;
        use crate::usm::keys::SecretKey;
        use crate::usm::user::UserName;

        struct CeilingStore;
        impl EngineBootsStore for CeilingStore {
            fn load(&mut self) -> Result<Option<StoredBootsState>, std::io::Error> {
                Ok(Some(StoredBootsState {
                    // Must match the default engine ID in AgentBuilder::new()
                    engine_id: b"\x80\x00\x1f\x88\x04basic-snmp-agent".to_vec(),
                    boots: MAX_ENGINE_BOOTS,
                }))
            }
            #[expect(
                clippy::unreachable,
                reason = "test assertion: save must never be called when boots is at the ceiling"
            )]
            fn save(&mut self, _engine_id: &[u8], _boots: u32) -> Result<(), std::io::Error> {
                unreachable!("save must not be called at ceiling")
            }
        }

        let key = SecretKey::new_from_exposed_slice(&[0_u8; 32]);
        let user = AuthNoPrivUser::new(
            UserName::new("testuser").unwrap(),
            AuthProtocol::HmacSha256,
            key,
        )
        .unwrap();
        let config = SecurityConfig::AuthNoPriv {
            user,
            boots_store: Box::new(CeilingStore),
        };
        let result = AgentBuilder::new(config)
            .listen_addr("127.0.0.1:0".parse().unwrap())
            .build();
        assert!(matches!(result, Err(AgentError::EngineBoots(_))));
    }

    #[test]
    fn given_auth_no_priv_config_when_send_trap_then_v3_authenticated_trap() {
        // Verifies: REQ-0076, REQ-0081, REQ-0129
        // Without a stored user the agent falls back to SNMPv2c (version 1). This test
        // detects that by verifying the received datagram carries SNMP version 3.
        use crate::usm::auth::AuthProtocol;
        use crate::usm::keys::SecretKey;
        use crate::usm::user::UserName;

        let auth_key = SecretKey::new_from_exposed_slice(&[0x11_u8; 32]);
        let user = AuthNoPrivUser::new(
            UserName::new("testuser").unwrap(),
            AuthProtocol::HmacSha256,
            auth_key,
        )
        .unwrap();
        let config = SecurityConfig::AuthNoPriv {
            user,
            boots_store: Box::new(NullStore),
        };

        let agent = AgentBuilder::new(config)
            .listen_addr("127.0.0.1:0".parse().unwrap())
            .build()
            .expect("agent must build");

        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let dest = receiver.local_addr().unwrap();

        let pdu = TrapPdu {
            request_id: 1,
            trap_oid: "1.3.6.1.6.3.1.1.5.1".parse().unwrap(),
            varbinds: vec![],
        };
        let results = agent.send_trap(&pdu, &[dest]).unwrap();
        assert_eq!(results.len(), 1);
        results[0].outcome.as_ref().expect("trap send must succeed");

        // Verify the datagram decodes as a V3 message (not V2c). If the security
        // config was not applied, the agent would fall back to V2c and rasn would
        // fail to decode the datagram as a V3 message.
        let mut recv_buf = vec![0_u8; 2048];
        let (bytes_received, _src) = receiver
            .recv_from(&mut recv_buf)
            .expect("must receive a datagram");
        let received_bytes = &recv_buf[..bytes_received];
        let decoded: rasn_snmp::v3::Message = rasn::ber::decode(received_bytes)
            .expect("datagram must decode as SNMPv3 Message when auth config is set");
        let version: i64 = decoded.version.try_into().expect("version must fit in i64");
        assert_eq!(
            version, 3,
            "version must be 3 (SNMPv3) when auth config is set"
        );
        // Also verify the auth flag is set, confirming the auth user was stored.
        let flags_byte = decoded.global_data.flags.first().copied().unwrap_or(0);
        assert_ne!(
            flags_byte & 0x01,
            0,
            "authFlag must be set when an AuthNoPriv SecurityConfig is configured"
        );
    }

    #[test]
    fn given_auth_priv_config_when_send_trap_then_v3_authenticated_encrypted_trap() {
        // Verifies: REQ-0077, REQ-0081, REQ-0129
        use crate::usm::auth::AuthProtocol;
        use crate::usm::keys::SecretKey;
        use crate::usm::privacy::PrivProtocol;
        use crate::usm::user::UserName;

        let auth_key = SecretKey::new_from_exposed_slice(&[0x22_u8; 32]);
        let user = AuthPrivUser::new(
            UserName::new("privtester").unwrap(),
            AuthProtocol::HmacSha256,
            auth_key,
            PrivProtocol::Aes128,
        )
        .unwrap();
        let config = SecurityConfig::AuthPriv {
            user,
            boots_store: Box::new(NullStore),
        };

        let agent = AgentBuilder::new(config)
            .listen_addr("127.0.0.1:0".parse().unwrap())
            .build()
            .expect("agent must build");

        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let dest = receiver.local_addr().unwrap();

        let pdu = TrapPdu {
            request_id: 2,
            trap_oid: "1.3.6.1.6.3.1.1.5.1".parse().unwrap(),
            varbinds: vec![],
        };
        let results = agent.send_trap(&pdu, &[dest]).unwrap();
        assert_eq!(results.len(), 1);
        results[0].outcome.as_ref().expect("trap send must succeed");

        let mut recv_buf = vec![0_u8; 2048];
        let (bytes_received, _src) = receiver
            .recv_from(&mut recv_buf)
            .expect("must receive a datagram");
        let received_bytes = &recv_buf[..bytes_received];
        let decoded: rasn_snmp::v3::Message = rasn::ber::decode(received_bytes)
            .expect("datagram must decode as SNMPv3 Message when authPriv config is set");
        let version: i64 = decoded.version.try_into().expect("version must fit in i64");
        assert_eq!(
            version, 3,
            "version must be 3 (SNMPv3) when authPriv config is set"
        );
        let flags_byte = decoded.global_data.flags.first().copied().unwrap_or(0);
        assert_ne!(
            flags_byte & 0x01,
            0,
            "authFlag must be set when an AuthPriv SecurityConfig is configured"
        );
        assert_ne!(
            flags_byte & 0x02,
            0,
            "privFlag must be set when an AuthPriv SecurityConfig is configured"
        );
    }

    #[test]
    fn given_listen_addr_when_set_then_agent_binds_to_specified_address() {
        // Verifies: REQ-0050
        // The mutant replaces listen_addr() with Default::default(), resetting
        // the address to "0.0.0.0:10161". local_addr() exposes the actual bound
        // address so we can confirm it is 127.0.0.1, not 0.0.0.0.
        let agent = AgentBuilder::new(SecurityConfig::NoAuthNoPriv)
            .listen_addr("127.0.0.1:0".parse().unwrap())
            .build()
            .expect("agent must bind to 127.0.0.1");
        let bound = agent.local_addr();
        assert_eq!(
            bound.ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            "agent must bind on 127.0.0.1, not the default 0.0.0.0"
        );
    }

    #[test]
    fn given_max_connections_when_set_then_prior_listen_addr_is_preserved() {
        // Verifies: REQ-0120
        // The mutant replaces max_connections() with Default::default(), resetting
        // all previously chained builder fields. Setting listen_addr first and then
        // checking local_addr() detects the reset: the agent must still bind on
        // 127.0.0.1 rather than the default 0.0.0.0.
        let agent = AgentBuilder::new(SecurityConfig::NoAuthNoPriv)
            .listen_addr("127.0.0.1:0".parse().unwrap())
            .max_connections(2)
            .build()
            .expect("agent must build with custom max_connections");
        let bound = agent.local_addr();
        assert_eq!(
            bound.ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            "listen_addr set before max_connections must be preserved"
        );
    }

    #[test]
    fn given_connection_timeout_config_when_set_then_prior_listen_addr_is_preserved() {
        // Verifies: REQ-0123
        // The mutant replaces connection_timeout_config() with Default::default(),
        // resetting all previously chained builder fields. Setting listen_addr first
        // detects the reset via local_addr().
        let config = ConnectionTimeoutConfig {
            normal_timeout: Duration::from_secs(60),
            pressure_timeout: Duration::from_secs(10),
            pressure_headroom: 3,
        };
        let agent = AgentBuilder::new(SecurityConfig::NoAuthNoPriv)
            .listen_addr("127.0.0.1:0".parse().unwrap())
            .connection_timeout_config(config)
            .build()
            .expect("agent must build with custom timeout config");
        let bound = agent.local_addr();
        assert_eq!(
            bound.ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            "listen_addr set before connection_timeout_config must be preserved"
        );
    }

    // ── SecurityConfig ────────────────────────────────────────────────────────

    #[test]
    fn given_auth_no_priv_variant_when_constructed_then_holds_user_and_store() {
        // Verifies: REQ-0076, REQ-0129
        use crate::usm::auth::AuthProtocol;
        use crate::usm::keys::SecretKey;
        use crate::usm::user::UserName;

        let key = SecretKey::new_from_exposed_slice(&[0_u8; 32]);
        let user = AuthNoPrivUser::new(
            UserName::new("alice").unwrap(),
            AuthProtocol::HmacSha256,
            key,
        )
        .unwrap();
        let config = SecurityConfig::AuthNoPriv {
            user,
            boots_store: Box::new(NullStore),
        };
        let SecurityConfig::AuthNoPriv { user, .. } = config else {
            panic!("expected AuthNoPriv variant");
        };
        assert_eq!(user.name().as_str(), "alice");
    }

    #[test]
    fn given_auth_priv_variant_when_constructed_then_holds_user_and_store() {
        // Verifies: REQ-0077, REQ-0129
        use crate::usm::auth::AuthProtocol;
        use crate::usm::keys::SecretKey;
        use crate::usm::privacy::PrivProtocol;
        use crate::usm::user::UserName;

        let key = SecretKey::new_from_exposed_slice(&[0_u8; 32]);
        let user = AuthPrivUser::new(
            UserName::new("bob").unwrap(),
            AuthProtocol::HmacSha256,
            key,
            PrivProtocol::Aes128,
        )
        .unwrap();
        let config = SecurityConfig::AuthPriv {
            user,
            boots_store: Box::new(NullStore),
        };
        let SecurityConfig::AuthPriv { user, .. } = config else {
            panic!("expected AuthPriv variant");
        };
        assert_eq!(user.name().as_str(), "bob");
    }

    #[test]
    fn given_auth_priv_config_when_build_then_agent_starts() {
        // Verifies: REQ-0077, REQ-0129
        use crate::usm::auth::AuthProtocol;
        use crate::usm::keys::SecretKey;
        use crate::usm::privacy::PrivProtocol;
        use crate::usm::user::UserName;

        let key = SecretKey::new_from_exposed_slice(&[0_u8; 32]);
        let user = AuthPrivUser::new(
            UserName::new("bob").unwrap(),
            AuthProtocol::HmacSha256,
            key,
            PrivProtocol::Aes128,
        )
        .unwrap();
        let config = SecurityConfig::AuthPriv {
            user,
            boots_store: Box::new(NullStore),
        };
        let result = AgentBuilder::new(config)
            .listen_addr("127.0.0.1:0".parse().unwrap())
            .build();
        result.expect("expected agent to start with AuthPriv SecurityConfig");
    }
}
