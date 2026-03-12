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
        }
    }
}

impl std::error::Error for AgentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Bind { source, .. } => Some(source),
            Self::Socket(e) | Self::UdpSocket(e) | Self::Spawn(e) => Some(e),
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
        let err = AgentError::Bind {
            addr,
            source: io_err(),
        };
        let msg = err.to_string();
        assert!(msg.contains("127.0.0.1:10161"), "{msg}");
        assert!(msg.contains("test"), "{msg}");
    }

    #[test]
    fn agent_error_socket_display_mentions_tcp_listener() {
        let err = AgentError::Socket(io_err());
        assert!(err.to_string().contains("TCP listener"));
    }

    #[test]
    fn agent_error_udp_socket_display_mentions_udp_trap_socket() {
        let err = AgentError::UdpSocket(io_err());
        assert!(err.to_string().contains("UDP trap socket"));
    }

    #[test]
    fn agent_error_spawn_display_mentions_event_loop() {
        let err = AgentError::Spawn(io_err());
        assert!(err.to_string().contains("event loop"));
    }

    // ── AgentError source ────────────────────────────────────────────────

    #[test]
    fn agent_error_bind_source_returns_inner_io_error() {
        let addr: SocketAddr = "127.0.0.1:10161".parse().unwrap();
        let err = AgentError::Bind {
            addr,
            source: io_err(),
        };
        let source = err.source().expect("source should be Some");
        assert!(source.to_string().contains("test"));
    }

    #[test]
    fn agent_error_socket_source_returns_inner_io_error() {
        let err = AgentError::Socket(io_err());
        assert!(err.source().expect("source should be Some").to_string().contains("test"));
    }

    #[test]
    fn agent_error_udp_socket_source_returns_inner_io_error() {
        let err = AgentError::UdpSocket(io_err());
        assert!(err.source().expect("source should be Some").to_string().contains("test"));
    }

    #[test]
    fn agent_error_spawn_source_returns_inner_io_error() {
        let err = AgentError::Spawn(io_err());
        assert!(err.source().expect("source should be Some").to_string().contains("test"));
    }

    // ── SetError Display ─────────────────────────────────────────────────

    #[test]
    fn set_error_disconnected_display_mentions_event_loop() {
        let err = SetError::Disconnected;
        assert!(err.to_string().contains("event loop"), "{}", err);
    }

    // ── TrapError Display ────────────────────────────────────────────────

    #[test]
    fn trap_error_empty_destinations_display_mentions_destination() {
        let err = TrapError::EmptyDestinations;
        assert!(err.to_string().contains("destination"), "{}", err);
    }
}
