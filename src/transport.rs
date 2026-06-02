//! Plain TCP transport layer and event loop for the SNMP agent.
//!
//! Responsibilities:
//!
//! - **Inbound connections**: accepts plain TCP connections, framing inbound
//!   messages per RFC 6353.
//! - **Outbound traps**: sends plain UDP datagrams to trap destinations.
//! - **Event loop**: the central poll loop driven by `mio` (epoll/kqueue).
//!   Sequences TCP listener events, connection I/O, command channel draining
//!   (via `mio::Waker` wakeup), and MIB request dispatch.
//!
//! This module uses [`codec`] for `SNMPv3` message framing and [`mib`] for
//! OID resolution during request handling.

pub mod dispatch;
pub mod event_loop;
pub mod request;
pub mod trap;

// Kept `pub` only so the out-of-workspace `fuzz` crate can drive dispatch directly;
// `#[doc(hidden)]` keeps it off the advertised API. Not a supported public entry point — do not widen.
#[doc(hidden)]
pub use dispatch::process_snmpv3_request;
pub use event_loop::{BerLengthError, EventLoopError, parse_ber_length};
pub use request::TrapPdu;
pub use trap::TrapResult;
