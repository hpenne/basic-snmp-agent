//! DTLS transport layer and event loop.
//!
//! Responsibilities:
//!
//! - **UDP I/O**: binds and polls the UDP socket; reads incoming datagrams and
//!   writes outgoing ones.
//! - **DTLS session management**: maintains one `dimpl` [`Dtls`] instance per peer,
//!   keyed by [`SocketAddr`]. Drives the sans-IO state machine in response to socket
//!   readiness and timer events.
//! - **Certificate handling**: stores the agent's own certificate/key and the set of
//!   trusted CA certificates; supports runtime replacement without dropping existing
//!   sessions.
//! - **Event loop**: the central poll loop that sequences socket I/O, DTLS state
//!   machine steps, command channel draining, and timer management.
//!
//! This crate depends on [`codec`] for SNMPv3 message framing and [`mib`] for OID
//! resolution during request handling.
