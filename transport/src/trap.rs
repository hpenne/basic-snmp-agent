//! UDP trap sender for outbound SNMP notifications.
//!
//! Traps are sent as plain UDP datagrams with no encryption or authentication,
//! per the agent's design (ADR-0008). Each [`TrapSender`] owns a bound UDP
//! socket and the agent's start time (needed to compute `sysUpTime.0`).
//!
//! The MTU cap of 1500 bytes matches the standard Ethernet payload limit
//! (ADR-0008). Traps that would exceed this limit are rejected before any
//! datagram is sent.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Instant;

use crate::request::{TrapPdu, build_wire_trap};

/// The UDP MTU cap for outbound trap datagrams (ADR-0008).
const TRAP_MTU_BYTES: usize = 1500;

/// Per-destination outcome of a single trap send attempt.
#[derive(Debug)]
pub struct TrapResult {
    /// The destination address this result pertains to.
    pub destination: SocketAddr,
    /// `Ok(())` if the datagram was sent, `Err` with I/O detail otherwise.
    pub outcome: Result<(), io::Error>,
}

/// Sends outbound SNMP trap notifications as plain UDP datagrams.
///
/// The socket is bound to an OS-assigned local port on `0.0.0.0` at
/// construction time and reused for all subsequent sends. `TrapSender` is
/// cheap to clone — all clones share the same underlying socket via [`Arc`].
///
/// # Examples
///
/// ```no_run
/// use std::net::SocketAddr;
/// use std::time::Instant;
/// use transport::trap::TrapSender;
/// use transport::TrapPdu;
///
/// let sender = TrapSender::new(Instant::now()).unwrap();
/// let pdu = TrapPdu {
///     request_id: 1,
///     trap_oid: "1.3.6.1.6.3.1.1.5.1".parse().unwrap(),
///     varbinds: vec![],
/// };
/// let dest: SocketAddr = "192.0.2.1:162".parse().unwrap();
/// let results = sender.send_trap(&pdu, &[dest]);
/// for r in results {
///     println!("{}: {:?}", r.destination, r.outcome);
/// }
/// ```
#[derive(Clone)]
pub struct TrapSender {
    socket: Arc<UdpSocket>,
    start_time: Instant,
}

// `Arc<UdpSocket>` is `Send + Sync` and `Instant` is `Copy`, so `TrapSender`
// inherits both. This assertion catches any future field addition that would
// break the contract at compile time.
const _: () = {
    fn assert_send_sync<T: Send + Sync>() {}
    fn check() {
        assert_send_sync::<TrapSender>();
    }
    let _ = check;
};

impl TrapSender {
    /// Create a new [`TrapSender`] with `start_time` as the agent start instant.
    ///
    /// Binds a UDP socket to `0.0.0.0:0` (OS-assigned port). The same socket
    /// is reused for all subsequent [`send_trap`][`TrapSender::send_trap`] calls.
    ///
    /// **Limitation:** Only IPv4 destinations are supported. Sending to an IPv6
    /// address will produce an I/O error for that destination.
    ///
    /// # Errors
    ///
    /// Returns an error if the UDP socket cannot be bound.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::time::Instant;
    /// use transport::trap::TrapSender;
    ///
    /// let sender = TrapSender::new(Instant::now()).unwrap();
    /// ```
    pub fn new(start_time: Instant) -> io::Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        Ok(Self {
            socket: Arc::new(socket),
            start_time,
        })
    }

    /// Encode `pdu` and send it as a UDP datagram to each address in `destinations`.
    ///
    /// Returns one [`TrapResult`] per destination, in the same order as
    /// `destinations`. If encoding fails or the encoded PDU exceeds the MTU cap
    /// (1500 bytes), every destination receives an `Err` result and no datagrams
    /// are sent.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::net::SocketAddr;
    /// use std::time::Instant;
    /// use transport::trap::TrapSender;
    /// use transport::TrapPdu;
    ///
    /// let sender = TrapSender::new(Instant::now()).unwrap();
    /// let pdu = TrapPdu {
    ///     request_id: 1,
    ///     trap_oid: "1.3.6.1.6.3.1.1.5.1".parse().unwrap(),
    ///     varbinds: vec![],
    /// };
    /// let dest: SocketAddr = "192.0.2.1:162".parse().unwrap();
    /// let results = sender.send_trap(&pdu, &[dest]);
    /// ```
    #[must_use]
    pub fn send_trap(&self, pdu: &TrapPdu, destinations: &[SocketAddr]) -> Vec<TrapResult> {
        let wire_pdu = build_wire_trap(pdu, self.start_time);

        let encoded_pdu = match codec::encode_trap(&wire_pdu) {
            Ok(encoded_pdu) => encoded_pdu,
            Err(e) => {
                let msg = format!("trap PDU encoding failed: {e}");
                return encode_error_for_all(destinations, &msg);
            }
        };

        if encoded_pdu.len() > TRAP_MTU_BYTES {
            let msg = format!(
                "encoded trap PDU ({} bytes) exceeds MTU ({TRAP_MTU_BYTES} bytes)",
                encoded_pdu.len()
            );
            return encode_error_for_all(destinations, &msg);
        }

        destinations
            .iter()
            .map(|&dest| {
                let outcome = self.socket.send_to(&encoded_pdu, dest).map(|_| ());
                TrapResult {
                    destination: dest,
                    outcome,
                }
            })
            .collect()
    }
}

/// Build a [`TrapResult`] with `InvalidData` for every destination in the slice.
///
/// Used when encoding fails before any datagram can be sent, so the same
/// logical error is reported uniformly across all destinations.
fn encode_error_for_all(destinations: &[SocketAddr], message: &str) -> Vec<TrapResult> {
    destinations
        .iter()
        .map(|&dest| TrapResult {
            destination: dest,
            outcome: Err(io::Error::new(io::ErrorKind::InvalidData, message)),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::{Value, Varbind, VarbindValue};

    fn trap_oid() -> codec::Oid {
        "1.3.6.1.6.3.1.1.5.1".parse().unwrap()
    }

    fn minimal_pdu() -> TrapPdu {
        TrapPdu {
            request_id: 1,
            trap_oid: trap_oid(),
            varbinds: vec![],
        }
    }

    /// Bind a loopback UDP socket on an OS-assigned port and return it together
    /// with its address. The socket is kept alive for the duration of each test.
    fn loopback_receiver() -> (UdpSocket, SocketAddr) {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        (sock, addr)
    }

    #[test]
    fn given_trap_pdu_within_mtu_when_send_trap_then_all_destinations_get_ok() {
        // Given: a sender and a loopback receiver socket.
        let sender = TrapSender::new(Instant::now()).unwrap();
        let (receiver, dest) = loopback_receiver();
        let pdu = minimal_pdu();

        // When: the trap is sent.
        let results = sender.send_trap(&pdu, &[dest]);

        // Then: the single result is Ok.
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].destination, dest);
        assert!(
            results[0].outcome.is_ok(),
            "expected Ok, got {:?}",
            results[0].outcome
        );

        // And: the receiver socket actually received a non-empty datagram that
        // matches the encoded bytes for the same PDU.
        let wire_pdu = crate::request::build_wire_trap(&pdu, sender.start_time);
        let expected_encoded_pdu = codec::encode_trap(&wire_pdu).unwrap();
        let mut recv_buf = vec![0u8; TRAP_MTU_BYTES];
        let (bytes_received, _src) = receiver.recv_from(&mut recv_buf).unwrap();
        assert!(bytes_received > 0, "expected non-empty datagram");
        assert_eq!(&recv_buf[..bytes_received], expected_encoded_pdu.as_slice());
    }

    #[test]
    fn given_trap_pdu_exceeding_mtu_when_send_trap_then_all_destinations_get_error() {
        // Given: a sender and a pdu whose BER encoding will exceed 1500 bytes.
        // Each varbind carries 200 bytes of OctetString, so 10 varbinds give
        // roughly 2000+ bytes after BER overhead.
        let sender = TrapSender::new(Instant::now()).unwrap();
        let (_receiver, dest) = loopback_receiver();

        let large_varbinds: Vec<Varbind> = (0u32..10)
            .map(|i| Varbind {
                oid: format!("1.3.6.1.2.1.1.{i}.0").parse().unwrap(),
                value: VarbindValue::Value(Value::OctetString(vec![0xAA; 200])),
            })
            .collect();

        let pdu = TrapPdu {
            request_id: 2,
            trap_oid: trap_oid(),
            varbinds: large_varbinds,
        };

        // When: the trap is sent.
        let results = sender.send_trap(&pdu, &[dest]);

        // Then: the result is an InvalidData error with an MTU message.
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].destination, dest);
        let err = results[0].outcome.as_ref().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("MTU"),
            "expected MTU error message, got: {err}"
        );
    }

    #[test]
    fn given_empty_destinations_when_send_trap_then_returns_empty_vec() {
        // Given: a sender and a valid PDU.
        let sender = TrapSender::new(Instant::now()).unwrap();
        let pdu = minimal_pdu();

        // When: the trap is sent with no destinations.
        let results = sender.send_trap(&pdu, &[]);

        // Then: the result is an empty vec.
        assert!(results.is_empty());
    }

    #[test]
    fn given_multiple_destinations_when_send_trap_then_result_per_destination() {
        // Given: a sender and two loopback receiver sockets.
        let sender = TrapSender::new(Instant::now()).unwrap();
        let (_recv_a, dest_a) = loopback_receiver();
        let (_recv_b, dest_b) = loopback_receiver();
        let pdu = minimal_pdu();

        // When: the trap is sent to both destinations.
        let results = sender.send_trap(&pdu, &[dest_a, dest_b]);

        // Then: two results are returned, both Ok, matching the destinations.
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].destination, dest_a);
        assert_eq!(results[1].destination, dest_b);
        assert!(
            results[0].outcome.is_ok(),
            "expected Ok for dest_a, got {:?}",
            results[0].outcome
        );
        assert!(
            results[1].outcome.is_ok(),
            "expected Ok for dest_b, got {:?}",
            results[1].outcome
        );
    }
}
