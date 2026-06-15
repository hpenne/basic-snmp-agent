//! UDP trap sender for outbound SNMP notifications.
//!
//! When no USM user is configured, traps are sent as plain `SNMPv2c` datagrams
//! (backward-compatible mode). When a USM user is configured, traps are sent
//! as `SNMPv3` messages authenticated and, if applicable, encrypted according
//! to the user's security level (REQ-0105, REQ-0106).
//!
//! Each [`TrapSender`] owns a bound UDP socket and the agent's start time
//! (needed to compute `sysUpTime.0`). The MTU cap of 1500 bytes matches the
//! standard Ethernet payload limit (ADR-0008). Traps that would exceed this
//! limit are rejected before any datagram is sent.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::AtomicI32;
use std::time::Instant;

use crate::codec::MessageId;
use crate::transport::request::{TrapPdu, build_wire_trap};
use crate::usm::engine_time::EngineBoots;

/// The UDP MTU cap for outbound trap datagrams (ADR-0008).
const TRAP_MTU_BYTES: usize = 1500;

// Each SNMPv3 trap must carry a unique msgID so managers can correlate
// responses and detect duplicates. A process-global counter provides
// monotonically increasing IDs without requiring synchronisation beyond
// a relaxed atomic increment.
static TRAP_MSG_ID_COUNTER: AtomicI32 = AtomicI32::new(1);

/// Per-destination outcome of a single trap send attempt.
///
/// # Requirements
/// Implements: REQ-0047
#[derive(Debug)]
pub struct TrapResult {
    /// The destination address this result pertains to.
    pub destination: SocketAddr,
    /// `Ok(())` if the datagram was sent, `Err` with I/O detail otherwise.
    pub outcome: Result<(), io::Error>,
}

/// Sends outbound SNMP trap notifications as UDP datagrams.
///
/// When no USM user is configured, traps are sent as plain `SNMPv2c` datagrams.
/// When a USM user is configured, traps are sent as `SNMPv3` messages with
/// authentication and, if applicable, encryption matching the user's security
/// level. The socket is bound to an OS-assigned local port on `0.0.0.0` at
/// construction time and reused for all subsequent sends. `TrapSender` is
/// cheap to clone — all clones share the same underlying socket via [`Arc`].
///
/// # Requirements
/// Implements: REQ-0036, REQ-0105, REQ-0106
#[derive(Clone)]
pub(crate) struct TrapSender {
    socket: Arc<UdpSocket>,
    start_time: Instant,
    // Implements: REQ-0055
    engine_id: crate::usm::engine_id::EngineId,
    engine_boots: EngineBoots,
    usm_user: Option<Arc<crate::usm::user::UsmUser>>,
}

// `Arc<UdpSocket>`, `Instant`, `Vec<u8>`, `EngineBoots`, and `Arc<UsmUser>` are all
// `Send + Sync`, so `TrapSender` inherits both. This assertion catches any
// future field addition that would break the contract at compile time.
const _: () = {
    fn assert_send_sync<T: Send + Sync>() {}
    let _ = assert_send_sync::<TrapSender>;
};

impl TrapSender {
    /// Create a new [`TrapSender`].
    ///
    /// `start_time` is used to compute `sysUpTime.0` in each outbound trap.
    /// `engine_id` and `engine_boots` are embedded in `SNMPv3` USM parameters
    /// when `usm_user` is `Some`. When `usm_user` is `None`, traps are sent as
    /// plain `SNMPv2c` datagrams.
    ///
    /// Binds a UDP socket to `0.0.0.0:0` (OS-assigned port). The same socket
    /// is reused for all subsequent [`send_trap`][`TrapSender::send_trap`] calls.
    ///
    /// **Limitation:** Only IPv4 destinations are supported. Sending to an IPv6
    /// address will produce an I/O error for that destination.
    ///
    /// # Requirements
    /// Implements: REQ-0036, REQ-0037
    ///
    /// # Errors
    ///
    /// Returns an error if the UDP socket cannot be bound.
    pub(crate) fn new(
        start_time: Instant,
        engine_id: crate::usm::engine_id::EngineId,
        engine_boots: EngineBoots,
        usm_user: Option<Arc<crate::usm::user::UsmUser>>,
    ) -> io::Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        Ok(Self {
            socket: Arc::new(socket),
            start_time,
            engine_id,
            engine_boots,
            usm_user,
        })
    }

    /// Encode `pdu` and send it as a UDP datagram to each address in `destinations`.
    ///
    /// Returns one [`TrapResult`] per destination, in the same order as
    /// `destinations`. If encoding fails or the encoded PDU exceeds the MTU cap
    /// (1500 bytes), every destination receives an `Err` result and no datagrams
    /// are sent.
    ///
    /// # Requirements
    /// Implements: REQ-0035, REQ-0042, REQ-0044, REQ-0045, REQ-0047, REQ-0105, REQ-0106
    #[must_use]
    pub(crate) fn send_trap(&self, pdu: &TrapPdu, destinations: &[SocketAddr]) -> Vec<TrapResult> {
        let wire_pdu = build_wire_trap(pdu, self.start_time);

        let encoded_pdu = match self.encode_trap_pdu(&wire_pdu) {
            Ok(encoded_pdu) => encoded_pdu,
            Err(e) => {
                let error_message = format!("trap PDU encoding failed: {e}");
                return encode_error_for_all(destinations, &error_message);
            }
        };

        if encoded_pdu.len() > TRAP_MTU_BYTES {
            let error_message = format!(
                "encoded trap PDU ({} bytes) exceeds MTU ({TRAP_MTU_BYTES} bytes)",
                encoded_pdu.len()
            );
            return encode_error_for_all(destinations, &error_message);
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

    // Implements: REQ-0105, REQ-0106
    fn encode_trap_pdu(
        &self,
        wire_pdu: &crate::codec::WireTrapPdu,
    ) -> Result<Vec<u8>, crate::codec::EncodeError> {
        let Some(ref usm_user) = self.usm_user else {
            // No USM user configured: fall back to SNMPv2c for backward compatibility.
            return crate::codec::encode_trap(wire_pdu);
        };
        let engine_time_secs =
            u32::try_from(self.start_time.elapsed().as_secs()).unwrap_or(u32::MAX);
        let trap_auth = usm_user.auth_protocol().zip(usm_user.auth_key());
        let trap_priv = usm_user.priv_protocol().zip(usm_user.priv_key());
        crate::codec::encode_v3_trap(
            MessageId::next_sequential(&TRAP_MSG_ID_COUNTER),
            self.engine_id.as_ref(),
            usm_user.name().as_bytes(),
            b"",
            u32::from(self.engine_boots),
            engine_time_secs,
            trap_auth,
            trap_priv,
            wire_pdu,
        )
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
    use crate::codec::{RequestId, Value, Varbind, VarbindValue};

    fn trap_oid() -> crate::codec::Oid {
        "1.3.6.1.6.3.1.1.5.1".parse().unwrap()
    }

    fn minimal_pdu() -> TrapPdu {
        TrapPdu {
            request_id: RequestId::from(1),
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

    // V2c mode (usm_user=None) does not use the engine_id; a minimal valid
    // placeholder satisfies the EngineId invariant without affecting behaviour.
    fn no_usm_sender() -> TrapSender {
        let placeholder_engine_id =
            crate::usm::engine_id::EngineId::try_from(b"\x80\x00\x1f\x88\x04".to_vec())
                .expect("5-byte placeholder is the minimum valid engine ID");
        TrapSender::new(
            Instant::now(),
            placeholder_engine_id,
            EngineBoots::ZERO,
            None,
        )
        .unwrap()
    }

    /// Verify that the HMAC embedded in `encoded_message` is correct.
    ///
    /// Locates the MAC bytes using the same two-step search as the production
    /// code (USM region first, then MAC within USM), zeroes the placeholder,
    /// and then calls `verify_mac` to confirm the signature is valid.
    fn verify_embedded_hmac(
        encoded_message: &[u8],
        security_parameters_raw: &[u8],
        embedded_mac: &[u8],
        auth_protocol: crate::usm::auth::AuthProtocol,
        auth_key: &crate::usm::keys::SecretKey,
    ) {
        let usm_pos = encoded_message
            .windows(security_parameters_raw.len())
            .position(|w| w == security_parameters_raw)
            .expect("USM bytes must appear in encoded message");
        let auth_pos = encoded_message[usm_pos..usm_pos + security_parameters_raw.len()]
            .windows(embedded_mac.len())
            .position(|w| w == embedded_mac)
            .expect("MAC must appear within USM region");
        let auth_params_offset = usm_pos + auth_pos;

        let mut zeroed = encoded_message.to_vec();
        zeroed[auth_params_offset..auth_params_offset + embedded_mac.len()].fill(0);

        auth_protocol
            .verify_mac(auth_key, &zeroed, embedded_mac)
            .expect("HMAC must verify");
    }

    #[test]
    fn given_trap_pdu_within_mtu_when_send_trap_then_all_destinations_get_ok() {
        // Verifies: REQ-0035, REQ-0036, REQ-0044, REQ-0047
        // Given: a sender and a loopback receiver socket.
        let sender = no_usm_sender();
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
        let wire_pdu = crate::transport::request::build_wire_trap(&pdu, sender.start_time);
        let expected_encoded_pdu = crate::codec::encode_trap(&wire_pdu).unwrap();
        let mut recv_buf = vec![0_u8; TRAP_MTU_BYTES];
        let (bytes_received, _src) = receiver.recv_from(&mut recv_buf).unwrap();
        assert!(bytes_received > 0, "expected non-empty datagram");
        assert_eq!(&recv_buf[..bytes_received], expected_encoded_pdu.as_slice());
    }

    #[test]
    fn given_trap_pdu_exceeding_mtu_when_send_trap_then_all_destinations_get_error() {
        // Given: a sender and a pdu whose BER encoding will exceed 1500 bytes.
        // Each varbind carries 200 bytes of OctetString, so 10 varbinds give
        // roughly 2000+ bytes after BER overhead.
        let sender = no_usm_sender();
        let (_receiver, dest) = loopback_receiver();

        let large_varbinds: Vec<Varbind> = (0_u32..10)
            .map(|i| Varbind {
                oid: format!("1.3.6.1.2.1.1.{i}.0").parse().unwrap(),
                value: VarbindValue::Value(Value::OctetString(vec![0xAA; 200])),
            })
            .collect();

        let pdu = TrapPdu {
            request_id: RequestId::from(2),
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
        let sender = no_usm_sender();
        let pdu = minimal_pdu();

        // When: the trap is sent with no destinations.
        let results = sender.send_trap(&pdu, &[]);

        // Then: the result is an empty vec.
        assert!(results.is_empty());
    }

    #[test]
    fn given_multiple_destinations_when_send_trap_then_result_per_destination() {
        // Verifies: REQ-0044, REQ-0045, REQ-0047
        // Given: a sender and two loopback receiver sockets.
        let sender = no_usm_sender();
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

    #[test]
    fn given_one_failing_destination_when_send_trap_then_failure_does_not_prevent_remaining_delivery()
     {
        // Verifies: REQ-0044, REQ-0045, REQ-0047
        // Sending to an IPv6 address from an IPv4-only socket (bound to 0.0.0.0)
        // produces a synchronous I/O error, giving us a reliable per-destination
        // failure without any external coordination.
        let sender = no_usm_sender();
        let ipv6_unreachable_dest: SocketAddr = "[::1]:9999".parse().unwrap();
        let (recv_ok, ipv4_reachable_dest) = loopback_receiver();
        let pdu = minimal_pdu();

        // When: the trap is sent to a failing destination followed by a reachable one.
        let results = sender.send_trap(&pdu, &[ipv6_unreachable_dest, ipv4_reachable_dest]);

        // Then: two results are returned in the original order.
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].destination, ipv6_unreachable_dest);
        assert_eq!(results[1].destination, ipv4_reachable_dest);

        // And: the IPv6 destination produces a known socket-level send error.
        // macOS yields InvalidInput; Linux yields an OS error (EAFNOSUPPORT, os
        // error 97) which has no stable ErrorKind variant but always carries a
        // raw_os_error. Both are distinct from our synthetic InvalidData errors,
        // which carry no OS error code.
        let send_err = results[0].outcome.as_ref().unwrap_err();
        assert!(
            send_err.kind() == io::ErrorKind::InvalidInput || send_err.raw_os_error().is_some(),
            "expected InvalidInput or an OS error for IPv6 on IPv4 socket, got {send_err}"
        );

        // And: the IPv4 destination succeeds despite the earlier failure.
        assert!(
            results[1].outcome.is_ok(),
            "expected Ok for IPv4 destination, got {:?}",
            results[1].outcome
        );

        // And: the receiver socket actually received a non-empty datagram, proving
        // the earlier per-destination failure did not abort subsequent sends.
        let mut recv_buf = vec![0_u8; TRAP_MTU_BYTES];
        let (bytes_received, _src) = recv_ok.recv_from(&mut recv_buf).unwrap();
        assert!(
            bytes_received > 0,
            "expected datagram on reachable destination despite earlier failure"
        );
    }

    #[test]
    fn given_trap_pdu_encoded_to_exactly_mtu_when_send_trap_then_ok() {
        // Verifies: REQ-0042, REQ-0044, REQ-0045
        // The MTU check is `encoded_pdu.len() > TRAP_MTU_BYTES`. The mutant
        // `> with >=` would incorrectly reject a PDU that encodes to exactly
        // TRAP_MTU_BYTES (1500) bytes.
        //
        // Strategy: encode a candidate PDU with a large OctetString payload,
        // measure the encoded size, then extend the payload by the exact delta so
        // the final encoding is exactly 1500 bytes. Because the initial payload
        // (1200 bytes) puts the OctetString length field in 3-byte form, adding
        // bytes to the payload adds the same number of bytes to the encoding.
        //
        // `sender.start_time` is used for all pre-flight encoding to guarantee
        // the sysUpTime encoding is identical to what send_trap will use internally.
        let sender = no_usm_sender();
        let (receiver, dest) = loopback_receiver();

        let candidate_payload_size = 1200_usize;
        let varbind_oid: crate::codec::Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();

        let candidate_pdu = TrapPdu {
            request_id: RequestId::from(42),
            trap_oid: trap_oid(),
            varbinds: vec![Varbind {
                oid: varbind_oid.clone(),
                value: VarbindValue::Value(Value::OctetString(vec![
                    0xBB_u8;
                    candidate_payload_size
                ])),
            }],
        };
        let candidate_wire = build_wire_trap(&candidate_pdu, sender.start_time);
        let candidate_encoded = crate::codec::encode_trap(&candidate_wire)
            .expect("candidate PDU must encode without error");
        let candidate_size = candidate_encoded.len();
        assert!(
            candidate_size < TRAP_MTU_BYTES,
            "candidate PDU ({candidate_size} bytes) must be below MTU to compute delta"
        );

        let delta = TRAP_MTU_BYTES - candidate_size;
        let final_payload_size = candidate_payload_size + delta;

        let exact_mtu_pdu = TrapPdu {
            request_id: RequestId::from(42),
            trap_oid: trap_oid(),
            varbinds: vec![Varbind {
                oid: varbind_oid,
                value: VarbindValue::Value(Value::OctetString(vec![0xBB_u8; final_payload_size])),
            }],
        };
        let exact_mtu_wire = build_wire_trap(&exact_mtu_pdu, sender.start_time);
        let exact_mtu_encoded = crate::codec::encode_trap(&exact_mtu_wire)
            .expect("exact-MTU PDU must encode without error");
        assert_eq!(
            exact_mtu_encoded.len(),
            TRAP_MTU_BYTES,
            "final encoded PDU must be exactly {TRAP_MTU_BYTES} bytes"
        );

        // When: the trap is sent.
        let results = sender.send_trap(&exact_mtu_pdu, &[dest]);

        // Then: the result must be Ok, not an MTU error. The PDU is exactly at
        // the boundary (1500 bytes == TRAP_MTU_BYTES), so `len() > 1500` is false
        // and no MTU error is raised.
        assert_eq!(results.len(), 1);
        assert!(
            results[0].outcome.is_ok(),
            "expected Ok for PDU at exactly TRAP_MTU_BYTES, got {:?}",
            results[0].outcome
        );
        // Drain the socket so it does not interfere with other tests.
        let mut recv_buf = vec![0_u8; TRAP_MTU_BYTES + 1];
        receiver.recv_from(&mut recv_buf).unwrap();
    }

    #[test]
    fn given_auth_no_priv_user_when_send_trap_then_v3_message_with_hmac() {
        // Verifies: REQ-0105
        use crate::usm::auth::AuthProtocol;
        use crate::usm::keys::SecretKey;
        use crate::usm::user::{AuthNoPrivUser, UserName, UsmUser};
        use rasn_snmp::v3::{Message as V3Message, USMSecurityParameters};

        let auth_key = SecretKey::new_from_exposed_slice(&[0x42_u8; 32]);
        let auth_key_for_verify = SecretKey::new_from_exposed_slice(&[0x42_u8; 32]);
        let auth_protocol = AuthProtocol::HmacSha256;
        let engine_id =
            crate::usm::engine_id::EngineId::try_from(b"\x80\x00\x1f\x88\x04test".to_vec())
                .unwrap();
        let user: Arc<UsmUser> = Arc::new(
            AuthNoPrivUser::new(UserName::new("trapauth").unwrap(), auth_protocol, auth_key)
                .unwrap()
                .into(),
        );
        let sender = TrapSender::new(
            Instant::now(),
            engine_id,
            EngineBoots::from(1_u32),
            Some(user),
        )
        .unwrap();
        let (receiver, dest) = loopback_receiver();
        receiver
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();

        let pdu = minimal_pdu();
        let results = sender.send_trap(&pdu, &[dest]);
        assert_eq!(results.len(), 1);
        assert!(results[0].outcome.is_ok(), "send must succeed");

        // Receive and decode the datagram.
        let mut recv_buf = vec![0_u8; TRAP_MTU_BYTES];
        let (bytes_received, _src) = receiver.recv_from(&mut recv_buf).unwrap();
        let received_bytes = &recv_buf[..bytes_received];

        let decoded: V3Message =
            rasn::ber::decode(received_bytes).expect("received bytes must decode as V3Message");

        // Verify authFlag is set.
        let flags_byte = decoded.global_data.flags.first().copied().unwrap_or(0);
        assert_eq!(
            flags_byte & 0x01,
            0x01,
            "authFlag must be set for authNoPriv trap"
        );

        // Verify HMAC is present and valid.
        let usm_params: USMSecurityParameters =
            rasn::ber::decode(decoded.security_parameters.as_ref())
                .expect("USM security parameters must decode");
        let embedded_mac = usm_params.authentication_parameters.to_vec();
        assert_eq!(embedded_mac.len(), 24, "HMAC-SHA-256 MAC must be 24 bytes");

        verify_embedded_hmac(
            received_bytes,
            decoded.security_parameters.as_ref(),
            &embedded_mac,
            auth_protocol,
            &auth_key_for_verify,
        );
    }

    #[test]
    fn given_auth_priv_user_when_send_trap_then_v3_message_encrypted() {
        // Verifies: REQ-0105
        use crate::usm::auth::AuthProtocol;
        use crate::usm::keys::SecretKey;
        use crate::usm::privacy::PrivProtocol;
        use crate::usm::user::{AuthPrivUser, UserName, UsmUser};
        use rasn_snmp::v3::{Message as V3Message, ScopedPduData, USMSecurityParameters};

        let auth_key = SecretKey::new_from_exposed_slice(&[0xAA_u8; 32]);
        let engine_id =
            crate::usm::engine_id::EngineId::try_from(b"\x80\x00\x1f\x88\x04test".to_vec())
                .unwrap();
        let user: Arc<UsmUser> = Arc::new(
            AuthPrivUser::new(
                UserName::new("trappriv").unwrap(),
                AuthProtocol::HmacSha256,
                auth_key,
                PrivProtocol::Aes128,
            )
            .unwrap()
            .into(),
        );
        let sender = TrapSender::new(
            Instant::now(),
            engine_id,
            EngineBoots::from(2_u32),
            Some(user),
        )
        .unwrap();
        let (receiver, dest) = loopback_receiver();
        receiver
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();

        let pdu = minimal_pdu();
        let results = sender.send_trap(&pdu, &[dest]);
        assert_eq!(results.len(), 1);
        assert!(results[0].outcome.is_ok(), "send must succeed");

        let mut recv_buf = vec![0_u8; TRAP_MTU_BYTES];
        let (bytes_received, _src) = receiver.recv_from(&mut recv_buf).unwrap();
        let received_bytes = &recv_buf[..bytes_received];

        let decoded: V3Message =
            rasn::ber::decode(received_bytes).expect("received bytes must decode as V3Message");

        // Verify flags = 0x03 (authPriv).
        let flags_byte = decoded.global_data.flags.first().copied().unwrap_or(0);
        assert_eq!(flags_byte, 0x03, "msgFlags must be 0x03 for authPriv trap");

        // Verify ScopedPduData is encrypted.
        let usm_params: USMSecurityParameters =
            rasn::ber::decode(decoded.security_parameters.as_ref())
                .expect("USM security parameters must decode");
        assert_eq!(
            usm_params.privacy_parameters.len(),
            8,
            "salt must be 8 bytes"
        );
        assert!(
            matches!(decoded.scoped_data, ScopedPduData::EncryptedPdu(_)),
            "expected EncryptedPdu for authPriv trap"
        );
    }

    #[test]
    fn given_no_auth_no_priv_user_when_send_trap_then_v3_message_without_security() {
        // Verifies: REQ-0106
        use crate::usm::user::{UserName, UsmUser};
        use rasn_snmp::v3::{Message as V3Message, ScopedPduData};

        let engine_id =
            crate::usm::engine_id::EngineId::try_from(b"\x80\x00\x1f\x88\x04test".to_vec())
                .unwrap();
        let user = Arc::new(UsmUser::no_auth_no_priv(UserName::new("public").unwrap()));
        let sender =
            TrapSender::new(Instant::now(), engine_id, EngineBoots::ZERO, Some(user)).unwrap();
        let (receiver, dest) = loopback_receiver();
        receiver
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();

        let pdu = minimal_pdu();
        let results = sender.send_trap(&pdu, &[dest]);
        assert_eq!(results.len(), 1);
        assert!(results[0].outcome.is_ok(), "send must succeed");

        let mut recv_buf = vec![0_u8; TRAP_MTU_BYTES];
        let (bytes_received, _src) = receiver.recv_from(&mut recv_buf).unwrap();
        let received_bytes = &recv_buf[..bytes_received];

        let decoded: V3Message =
            rasn::ber::decode(received_bytes).expect("received bytes must decode as V3Message");

        // Verify flags = 0x00 (noAuthNoPriv), V3 format.
        let flags_byte = decoded.global_data.flags.first().copied().unwrap_or(0xFF);
        assert_eq!(
            flags_byte, 0x00,
            "msgFlags must be 0x00 for noAuthNoPriv trap"
        );

        // Verify scoped data is cleartext.
        assert!(
            matches!(decoded.scoped_data, ScopedPduData::CleartextPdu(_)),
            "expected CleartextPdu for noAuthNoPriv trap"
        );
    }

    #[test]
    fn given_two_consecutive_v3_traps_when_sent_then_msg_ids_differ() {
        // Verifies: REQ-0105
        // The mutant replaces next_trap_msg_id() with a constant (0, 1, or -1).
        // Two consecutive V3 trap sends must have different message IDs.
        use crate::usm::user::{UserName, UsmUser};
        use rasn_snmp::v3::Message as V3Message;

        let engine_id =
            crate::usm::engine_id::EngineId::try_from(b"\x80\x00\x1f\x88\x04test".to_vec())
                .unwrap();
        let user = std::sync::Arc::new(UsmUser::no_auth_no_priv(UserName::new("public").unwrap()));
        let sender =
            TrapSender::new(Instant::now(), engine_id, EngineBoots::ZERO, Some(user)).unwrap();
        let (receiver, dest) = loopback_receiver();
        receiver
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();

        let pdu = minimal_pdu();

        // Send two traps and verify each was delivered.
        let trap_results_1 = sender.send_trap(&pdu, &[dest]);
        assert_eq!(trap_results_1.len(), 1);
        assert_eq!(trap_results_1[0].destination, dest);
        trap_results_1[0]
            .outcome
            .as_ref()
            .expect("first trap send must succeed");
        let trap_results_2 = sender.send_trap(&pdu, &[dest]);
        assert_eq!(trap_results_2.len(), 1);
        assert_eq!(trap_results_2[0].destination, dest);
        trap_results_2[0]
            .outcome
            .as_ref()
            .expect("second trap send must succeed");

        // Receive both datagrams.
        let mut recv_buf_1 = vec![0_u8; TRAP_MTU_BYTES];
        let (bytes_1, _) = receiver
            .recv_from(&mut recv_buf_1)
            .expect("must receive first trap datagram");
        let mut recv_buf_2 = vec![0_u8; TRAP_MTU_BYTES];
        let (bytes_2, _) = receiver
            .recv_from(&mut recv_buf_2)
            .expect("must receive second trap datagram");

        let decoded_1: V3Message =
            rasn::ber::decode(&recv_buf_1[..bytes_1]).expect("first datagram must decode");
        let decoded_2: V3Message =
            rasn::ber::decode(&recv_buf_2[..bytes_2]).expect("second datagram must decode");

        let msg_id_1: i32 = decoded_1
            .global_data
            .message_id
            .try_into()
            .expect("msg_id_1 must fit in i32");
        let msg_id_2: i32 = decoded_2
            .global_data
            .message_id
            .try_into()
            .expect("msg_id_2 must fit in i32");

        assert_ne!(
            msg_id_1, msg_id_2,
            "consecutive V3 traps must carry different message IDs"
        );
    }

    #[test]
    fn given_counter_near_max_when_next_sequential_then_stays_non_negative() {
        // Verifies: RFC 3412 §6.2
        // Use a local counter to avoid racing with TRAP_MSG_ID_COUNTER used by
        // other concurrent tests. The test exercises MessageId::next_sequential,
        // which accepts any &AtomicI32.
        let counter = AtomicI32::new(i32::MAX - 1);
        assert_eq!(
            MessageId::next_sequential(&counter),
            MessageId::from(i32::MAX - 1)
        );
        assert_eq!(
            MessageId::next_sequential(&counter),
            MessageId::from(i32::MAX)
        );
        assert_eq!(MessageId::next_sequential(&counter), MessageId::from(0));
        assert_eq!(MessageId::next_sequential(&counter), MessageId::from(1));
        assert_eq!(MessageId::next_sequential(&counter), MessageId::from(2));
    }
}
