//! TLS transport layer and event loop for the SNMP agent.
//!
//! Responsibilities:
//!
//! - **Inbound connections**: accepts TLS-over-TCP connections on port 10161
//!   (IANA SNMP-over-TLS), using `rustls` for the TLS engine. Frames inbound
//!   messages per RFC 6353.
//! - **Outbound traps**: sends plain UDP datagrams to trap destinations on
//!   port 162. No encryption or authentication is applied to traps.
//! - **Certificate handling**: stores the agent's own certificate/key and the
//!   set of trusted CA certificates, provided at construction time. Replacing
//!   certificates requires restarting the agent.
//! - **Event loop**: the central poll loop driven by `mio` (epoll/kqueue).
//!   Sequences TCP listener events, TLS connection I/O, command channel
//!   draining (via self-pipe wakeup), and MIB request dispatch.
//!
//! This module uses [`codec`] for `SNMPv3` message framing and [`mib`] for
//! OID resolution during request handling.

pub mod dispatch;
pub mod event_loop;
pub mod request;
pub mod trap;

pub use dispatch::process_snmpv3_request;
pub use event_loop::EventLoopError;
pub use request::TrapPdu;
pub use trap::{TrapResult, TrapSender};
