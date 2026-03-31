//! Error types for the `basic-snmp-agent` public API.

use std::fmt;
use std::io;
use std::net::SocketAddr;

// ── AgentError ────────────────────────────────────────────────────────────────

/// Error returned when [`Agent`](crate::Agent) construction fails.
#[derive(Debug)]
pub enum AgentError {
    /// The TCP listener could not be bound to the requested address.
    Bind { addr: SocketAddr, source: io::Error },
    /// A TCP listener configuration call (`set_nonblocking`, `local_addr`) failed.
    Socket(io::Error),
    /// The UDP socket for trap sending could not be created.
    UdpSocket(io::Error),
    /// The event loop thread could not be spawned.
    Spawn(io::Error),
    /// The engine ID length is outside the RFC 3411 §5 range of 5–32 octets.
    InvalidEngineId,
    /// Returned when TLS configuration is partially supplied or invalid.
    ///
    /// The source error is not preserved; inspect the `Display` output for details.
    ///
    /// # Requirements
    /// Implements: REQ-0017
    TlsConfig(String),
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bind { addr, source } => {
                write!(f, "failed to bind TCP listener to {addr}: {source}")
            }
            Self::Socket(e) => write!(f, "failed to configure TCP listener: {e}"),
            Self::UdpSocket(e) => write!(f, "failed to create UDP trap socket: {e}"),
            Self::Spawn(e) => write!(f, "failed to spawn event loop thread: {e}"),
            Self::InvalidEngineId => write!(
                f,
                "engine ID length is invalid: must be between 5 and 32 octets (RFC 3411 \u{a7}5)"
            ),
            Self::TlsConfig(msg) => write!(f, "TLS configuration error: {msg}"),
        }
    }
}

impl std::error::Error for AgentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Bind { source, .. } => Some(source),
            Self::Socket(e) | Self::UdpSocket(e) | Self::Spawn(e) => Some(e),
            Self::InvalidEngineId | Self::TlsConfig(_) => None,
        }
    }
}

// ── SetError ──────────────────────────────────────────────────────────────────

/// Error returned when [`Agent::set`](crate::Agent::set) fails.
///
/// Kept as an enum (rather than a unit struct) to allow additional variants
/// in the future without a breaking API change.
#[derive(Debug, PartialEq, Eq)]
pub enum SetError {
    /// The event loop has terminated; the command channel is disconnected.
    Disconnected,
}

impl fmt::Display for SetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disconnected => write!(f, "agent event loop has terminated"),
        }
    }
}

impl std::error::Error for SetError {}

// ── TrapError ─────────────────────────────────────────────────────────────────

/// Error returned when [`Agent::send_trap`](crate::Agent::send_trap) fails.
///
/// Kept as an enum (rather than a unit struct) to allow additional variants
/// in the future without a breaking API change.
#[derive(Debug, PartialEq, Eq)]
pub enum TrapError {
    /// No destination addresses were provided.
    EmptyDestinations,
}

impl fmt::Display for TrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyDestinations => write!(f, "trap destination list is empty"),
        }
    }
}

impl std::error::Error for TrapError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    fn io_err() -> io::Error {
        io::Error::new(io::ErrorKind::AddrInUse, "test")
    }

    // ── AgentError Display ───────────────────────────────────────────────

    #[test]
    fn agent_error_bind_display_contains_address_and_cause() {
        let addr: SocketAddr = "127.0.0.1:10161".parse().unwrap();
        let bind_error = AgentError::Bind {
            addr,
            source: io_err(),
        };
        let error_message = bind_error.to_string();
        assert!(error_message.contains("127.0.0.1:10161"), "{error_message}");
        assert!(error_message.contains("test"), "{error_message}");
    }

    #[test]
    fn agent_error_socket_display_mentions_tcp_listener() {
        let socket_error = AgentError::Socket(io_err());
        assert!(socket_error.to_string().contains("TCP listener"));
    }

    #[test]
    fn agent_error_udp_socket_display_mentions_udp_trap_socket() {
        let udp_socket_error = AgentError::UdpSocket(io_err());
        assert!(udp_socket_error.to_string().contains("UDP trap socket"));
    }

    #[test]
    fn agent_error_spawn_display_mentions_event_loop() {
        let spawn_error = AgentError::Spawn(io_err());
        assert!(spawn_error.to_string().contains("event loop"));
    }

    #[test]
    fn agent_error_invalid_engine_id_display_mentions_rfc() {
        let invalid_error = AgentError::InvalidEngineId;
        let msg = invalid_error.to_string();
        assert!(msg.contains('5') && msg.contains("32"), "{msg}");
    }

    #[test]
    fn agent_error_tls_config_display_contains_message() {
        // Verifies: REQ-0017
        let tls_error = AgentError::TlsConfig("missing private key".to_string());
        let msg = tls_error.to_string();
        assert!(msg.contains("TLS"), "{msg}");
        assert!(msg.contains("missing private key"), "{msg}");
    }

    // ── AgentError source ────────────────────────────────────────────────

    #[test]
    fn agent_error_bind_source_returns_inner_io_error() {
        let addr: SocketAddr = "127.0.0.1:10161".parse().unwrap();
        let bind_error = AgentError::Bind {
            addr,
            source: io_err(),
        };
        let source = bind_error.source().expect("source should be Some");
        assert!(source.to_string().contains("test"));
    }

    #[test]
    fn agent_error_socket_source_returns_inner_io_error() {
        let socket_error = AgentError::Socket(io_err());
        assert!(
            socket_error
                .source()
                .expect("source should be Some")
                .to_string()
                .contains("test")
        );
    }

    #[test]
    fn agent_error_udp_socket_source_returns_inner_io_error() {
        let udp_socket_error = AgentError::UdpSocket(io_err());
        assert!(
            udp_socket_error
                .source()
                .expect("source should be Some")
                .to_string()
                .contains("test")
        );
    }

    #[test]
    fn agent_error_spawn_source_returns_inner_io_error() {
        let spawn_error = AgentError::Spawn(io_err());
        assert!(
            spawn_error
                .source()
                .expect("source should be Some")
                .to_string()
                .contains("test")
        );
    }

    #[test]
    fn agent_error_invalid_engine_id_source_returns_none() {
        let invalid_error = AgentError::InvalidEngineId;
        assert!(invalid_error.source().is_none());
    }

    #[test]
    fn agent_error_tls_config_source_returns_none() {
        // Verifies: REQ-0017
        let tls_error = AgentError::TlsConfig("some message".to_string());
        assert!(tls_error.source().is_none());
    }

    // ── SetError Display ─────────────────────────────────────────────────

    #[test]
    fn set_error_disconnected_display_mentions_event_loop() {
        let set_error = SetError::Disconnected;
        assert!(
            set_error.to_string().contains("event loop"),
            "{}",
            set_error
        );
    }

    // ── TrapError Display ────────────────────────────────────────────────

    #[test]
    fn trap_error_empty_destinations_display_mentions_destination() {
        let trap_error = TrapError::EmptyDestinations;
        assert!(
            trap_error.to_string().contains("destination"),
            "{}",
            trap_error
        );
    }
}
