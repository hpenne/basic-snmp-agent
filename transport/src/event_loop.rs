//! Central event loop for the SNMP agent.
//!
//! The loop will multiplex a TCP listener, TLS connections, and a self-pipe
//! using `mio` (epoll/kqueue). Inbound SNMP requests arrive over TLS-framed
//! TCP connections (RFC 6353); outbound traps are sent as plain UDP datagrams.
//!
//! Not yet implemented — types are defined here to anchor the public API.

use std::io;
use std::net::SocketAddr;
use std::sync::mpsc::SyncSender;

use crate::request::ApiTrapPdu;

/// Per-destination outcome of a trap send attempt.
#[derive(Debug)]
pub struct TrapResult {
    /// The destination address this result pertains to.
    pub destination: SocketAddr,
    /// `Ok(())` if the datagram was sent, `Err` with I/O detail otherwise.
    pub outcome: Result<(), io::Error>,
}

/// Commands sent from `Agent` handle threads to the event loop.
#[derive(Debug)]
pub enum Command {
    /// Upsert a single OID in the MIB store.
    SetValue {
        oid: codec::Oid,
        value: codec::Value,
    },
    /// Send a trap to all listed destinations and report per-destination results.
    SendTrap {
        pdu: ApiTrapPdu,
        destinations: Vec<SocketAddr>,
        reply: SyncSender<Vec<TrapResult>>,
    },
    /// Shut down the event loop cleanly.
    Shutdown,
}
