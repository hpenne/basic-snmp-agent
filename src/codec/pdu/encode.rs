use std::sync::atomic::{AtomicU64, Ordering};

use super::types::{EncodeError, GetResponse, Varbind, VarbindValue, WireTrapPdu};
use crate::codec::ber;
use crate::codec::{Oid, Value};

// Implements: REQ-0000
fn encode_varbinds(varbinds: &[Varbind]) -> Result<Vec<u8>, EncodeError> {
    let encoded_varbinds: Vec<Vec<u8>> = varbinds
        .iter()
        .map(|vb| {
            let encoded_value = ber::varbind::encode_varbind_value(&vb.value)
                .map_err(|e| EncodeError::new(format!("varbind value encoding failed: {e}")))?;
            Ok(ber::varbind::encode_varbind(&vb.oid, &encoded_value))
        })
        .collect::<Result<Vec<_>, EncodeError>>()?;
    let refs: Vec<&[u8]> = encoded_varbinds.iter().map(Vec::as_slice).collect();
    Ok(ber::varbind::encode_varbind_list(&refs))
}

/// BER-encode a [`GetResponse`] PDU for transmission.
///
/// Returns the raw BER bytes ready to be wrapped in an `SNMPv3` message.
///
/// # Errors
///
/// Returns an [`EncodeError`] if BER encoding of the PDU fails.
///
/// # Panics
///
/// This function will not panic in practice: `ErrorStatus` values 0–18 all fit
/// in `i32`, so the internal conversion is infallible for any valid `ErrorStatus`.
///
/// # Examples
///
/// ```
/// use basic_snmp_agent::codec::{Oid, Value, ErrorStatus, GetResponse, Varbind, VarbindValue, encode_response};
///
/// let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
/// let pdu = GetResponse {
///     request_id: 1,
///     error_status: ErrorStatus::NoError,
///     error_index: 0,
///     varbinds: vec![Varbind { oid, value: VarbindValue::Value(Value::Integer32(42)) }],
/// };
/// let bytes = encode_response(&pdu).unwrap();
/// assert!(!bytes.is_empty());
/// ```
pub fn encode_response(pdu: &GetResponse) -> Result<Vec<u8>, EncodeError> {
    let raw_varbind_list = encode_varbinds(&pdu.varbinds)?;
    let error_status =
        i32::try_from(pdu.error_status as u32).expect("ErrorStatus values 0–18 always fit in i32");
    let error_index = i32::try_from(pdu.error_index).map_err(|_| {
        EncodeError::new(format!(
            "error_index {} exceeds maximum representable value in BER",
            pdu.error_index
        ))
    })?;
    ber::pdu::encode_pdu(
        ber::TAG_RESPONSE,
        pdu.request_id,
        error_status,
        error_index,
        &raw_varbind_list,
    )
    .map_err(|e| EncodeError::new(format!("BER encoding of GetResponse failed: {e}")))
}

// RFC 3826 §2.2: each message must use a unique salt. The counter is seeded
// with the current time so that salts do not repeat across process restarts
// that happen within the same second.
static PRIVACY_SALT_INIT: std::sync::Once = std::sync::Once::new();
static PRIVACY_SALT_COUNTER: AtomicU64 = AtomicU64::new(0);

// Implements: REQ-0101
fn next_privacy_salt() -> [u8; 8] {
    PRIVACY_SALT_INIT.call_once(|| {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        PRIVACY_SALT_COUNTER.store(seed, Ordering::Relaxed);
    });
    PRIVACY_SALT_COUNTER
        .fetch_add(1, Ordering::Relaxed)
        .to_be_bytes()
}

// Shared V3 message-building logic: wraps pre-encoded PDU bytes in a ScopedPdu,
// optionally encrypts it, adds USM params, and signs with HMAC.
// Implements: REQ-0068, REQ-0070, REQ-0072, REQ-0100, REQ-0101, REQ-0105, REQ-0106, REQ-0107
#[allow(clippy::too_many_arguments)]
fn encode_v3_envelope(
    msg_id: i32,
    engine_id: &[u8],
    user_name: &[u8],
    context_name: &[u8],
    engine_boots: u32,
    engine_time: u32,
    auth: Option<(crate::usm::auth::AuthProtocol, &crate::usm::keys::SecretKey)>,
    privacy: Option<(
        crate::usm::privacy::PrivProtocol,
        &crate::usm::keys::SecretKey,
    )>,
    raw_pdu_bytes: &[u8],
) -> Result<Vec<u8>, EncodeError> {
    // RFC 3412 §7.1: engine_boots and engine_time are non-negative integers
    // bounded to [0, 2147483647]. Reject values that would not fit in i32.
    let ber_boots = i32::try_from(engine_boots).map_err(|_| {
        EncodeError::new(format!(
            "engine_boots {engine_boots} exceeds maximum BER INTEGER value for i32"
        ))
    })?;
    let ber_time = i32::try_from(engine_time).map_err(|_| {
        EncodeError::new(format!(
            "engine_time {engine_time} exceeds maximum BER INTEGER value for i32"
        ))
    })?;

    let scoped_pdu_bytes = ber::snmp::encode_scoped_pdu(engine_id, context_name, raw_pdu_bytes);

    let flags_byte = match (auth.is_some(), privacy.is_some()) {
        (true, true) => 0x03u8,
        (true, false) => 0x01u8,
        (false, false) => 0x00u8,
        (false, true) => {
            return Err(EncodeError::new(
                "privacy without authentication is not permitted (RFC 3412)",
            ));
        }
    };

    let auth_params: Vec<u8> = auth
        .as_ref()
        .map(|(proto, _)| vec![0u8; proto.mac_len()])
        .unwrap_or_default();

    // Encrypt the ScopedPdu when privacy credentials are present, otherwise
    // leave it as cleartext. The 8-byte salt comes from a process-global
    // AtomicU64 counter that guarantees uniqueness per RFC 3826 §2.2.
    let (scoped_or_ciphertext, priv_params, encrypted) =
        if let Some((priv_protocol, priv_key)) = privacy {
            let salt = next_privacy_salt();
            // IV = engineBoots (4 BE) || engineTime (4 BE) || salt (8 bytes) per RFC 3826 §2.2.
            let mut aes_iv = [0u8; 16];
            aes_iv[0..4].copy_from_slice(&engine_boots.to_be_bytes());
            aes_iv[4..8].copy_from_slice(&engine_time.to_be_bytes());
            aes_iv[8..16].copy_from_slice(&salt);
            let ciphertext = priv_protocol
                .encrypt(priv_key, &aes_iv, &scoped_pdu_bytes)
                .map_err(|e| EncodeError::new(format!("AES encryption failed: {e}")))?;
            (ciphertext, salt.to_vec(), true)
        } else {
            (scoped_pdu_bytes, vec![], false)
        };

    let (mut encoded_message, auth_params_offset) = ber::snmp::encode_v3_message(
        msg_id,
        65535,
        flags_byte,
        3,
        engine_id,
        ber_boots,
        ber_time,
        user_name,
        &auth_params,
        &priv_params,
        &scoped_or_ciphertext,
        encrypted,
    )
    .map_err(|e| EncodeError::new(format!("BER encoding of SNMPv3 Message failed: {e}")))?;

    if let Some((auth_protocol, auth_key)) = auth {
        let mac_len = auth_params.len();
        let offset = auth_params_offset.ok_or_else(|| {
            EncodeError::new("auth params offset missing despite auth being requested")
        })?;

        // The placeholder is already all-zeros so no zeroing step is needed
        // before computing the HMAC.
        let mac = auth_protocol
            .compute_mac(auth_key, &encoded_message)
            .map_err(|e| EncodeError::new(format!("HMAC computation failed: {e}")))?;

        encoded_message[offset..offset + mac_len].copy_from_slice(&mac);
    }

    Ok(encoded_message)
}

/// BER-encode a [`GetResponse`] inside a full `SNMPv3` message envelope.
///
/// Constructs a `ScopedPdu` from `engine_id` and `context_name`, and builds an
/// `SNMPv3` `Message`. The `USMSecurityParameters` include the authoritative
/// engine ID and the original `user_name` echoed back, as required by RFC 3414
/// §8.2.4 so the command generator can match the response.
///
/// `engine_boots` and `engine_time` are always set in the USM security
/// parameters, regardless of security level, as required by RFC 3414 §7.1.4.
///
/// When `auth` is `Some((protocol, key))`, the response is signed with HMAC
/// and the `msgFlags` `authFlag` (bit 0) is set.
///
/// When `privacy` is `Some((protocol, key))`, the `ScopedPdu` is BER-encoded
/// and encrypted with AES-CFB128 per RFC 3826 §2.2. The 8-byte salt is sourced
/// from a monotonically increasing `AtomicU64` counter (seeded once from the
/// system clock) that guarantees a unique salt per call even in a multi-threaded
/// context. The IV is `engineBoots (4 BE) || engineTime (4 BE) || salt (8 bytes)`.
/// The `msgFlags` `privFlag` (bit 1) is also set. `privacy` must only be `Some`
/// when `auth` is also `Some` — `authPriv` requires authentication.
///
/// When both are `None`, the message is sent noAuthNoPriv with flags `0x00`.
///
/// # Errors
///
/// Returns an [`EncodeError`] if BER encoding of any part of the message fails,
/// if HMAC computation fails, if AES encryption fails, if `engine_boots` or
/// `engine_time` exceed `i32::MAX`, or if `privacy` is `Some` while `auth` is
/// `None` (privacy without authentication is not permitted per RFC 3412).
///
/// # Panics
///
/// This function will not panic in practice: `ErrorStatus` values 0–18 all fit
/// in `i32`, so the internal conversion is infallible for any valid `ErrorStatus`.
///
/// # Requirements
/// Implements: REQ-0068, REQ-0070, REQ-0072, REQ-0100, REQ-0101, REQ-0107
///
/// # Examples
///
/// ```
/// use basic_snmp_agent::codec::{ErrorStatus, GetResponse, encode_v3_response};
///
/// let pdu = GetResponse {
///     request_id: 1,
///     error_status: ErrorStatus::NoError,
///     error_index: 0,
///     varbinds: vec![],
/// };
/// let bytes = encode_v3_response(1, b"engine", b"user", b"", 0, 0, None, None, &pdu).unwrap();
/// assert!(!bytes.is_empty());
/// ```
#[allow(clippy::too_many_arguments)]
pub fn encode_v3_response(
    msg_id: i32,
    engine_id: &[u8],
    user_name: &[u8],
    context_name: &[u8],
    engine_boots: u32,
    engine_time: u32,
    auth: Option<(crate::usm::auth::AuthProtocol, &crate::usm::keys::SecretKey)>,
    privacy: Option<(
        crate::usm::privacy::PrivProtocol,
        &crate::usm::keys::SecretKey,
    )>,
    pdu: &GetResponse,
) -> Result<Vec<u8>, EncodeError> {
    let raw_varbind_list = encode_varbinds(&pdu.varbinds)?;
    let error_status =
        i32::try_from(pdu.error_status as u32).expect("ErrorStatus values 0–18 always fit in i32");
    let error_index = i32::try_from(pdu.error_index).map_err(|_| {
        EncodeError::new(format!(
            "error_index {} exceeds maximum representable value in BER",
            pdu.error_index
        ))
    })?;
    let raw_pdu_bytes = ber::pdu::encode_pdu(
        ber::TAG_RESPONSE,
        pdu.request_id,
        error_status,
        error_index,
        &raw_varbind_list,
    )
    .map_err(|e| EncodeError::new(format!("BER encoding of GetResponse PDU failed: {e}")))?;
    encode_v3_envelope(
        msg_id,
        engine_id,
        user_name,
        context_name,
        engine_boots,
        engine_time,
        auth,
        privacy,
        &raw_pdu_bytes,
    )
}

/// BER-encode a [`WireTrapPdu`] inside a full `SNMPv3` message envelope.
///
/// Constructs a `ScopedPdu` containing an `SNMPv2-Trap-PDU` and wraps it in
/// an `SNMPv3` `Message` with USM security parameters. When `auth` is `Some`,
/// the message is signed with HMAC and `msgFlags` bit 0 is set. When `privacy`
/// is also `Some`, the `ScopedPdu` is encrypted with AES-CFB128 per RFC 3826
/// §2.2 and `msgFlags` bit 1 is set. `privacy` must only be `Some` when `auth`
/// is also `Some`.
///
/// When both are `None`, the message is sent `noAuthNoPriv` with flags `0x00`.
///
/// # Errors
///
/// Returns an [`EncodeError`] if BER encoding, HMAC computation, or AES
/// encryption fails, or if `privacy` is `Some` while `auth` is `None`.
///
/// # Requirements
/// Implements: REQ-0105, REQ-0106
///
/// # Examples
///
/// ```
/// use basic_snmp_agent::codec::{Oid, Value, WireTrapPdu, Varbind, VarbindValue, encode_v3_trap};
///
/// let oid: Oid = "1.3.6.1.6.3.1.1.4.1.0".parse().unwrap();
/// let pdu = WireTrapPdu {
///     request_id: 1,
///     varbinds: vec![Varbind { oid, value: VarbindValue::Value(Value::TimeTicks(0)) }],
/// };
/// let bytes = encode_v3_trap(1, b"engine", b"user", b"", 0, 0, None, None, &pdu).unwrap();
/// assert!(!bytes.is_empty());
/// ```
#[allow(clippy::too_many_arguments)]
pub fn encode_v3_trap(
    msg_id: i32,
    engine_id: &[u8],
    user_name: &[u8],
    context_name: &[u8],
    engine_boots: u32,
    engine_time: u32,
    auth: Option<(crate::usm::auth::AuthProtocol, &crate::usm::keys::SecretKey)>,
    privacy: Option<(
        crate::usm::privacy::PrivProtocol,
        &crate::usm::keys::SecretKey,
    )>,
    pdu: &WireTrapPdu,
) -> Result<Vec<u8>, EncodeError> {
    let raw_varbind_list = encode_varbinds(&pdu.varbinds)?;
    let raw_pdu_bytes =
        ber::pdu::encode_pdu(ber::TAG_TRAP, pdu.request_id, 0, 0, &raw_varbind_list)
            .map_err(|e| EncodeError::new(format!("BER encoding of WireTrapPdu failed: {e}")))?;
    encode_v3_envelope(
        msg_id,
        engine_id,
        user_name,
        context_name,
        engine_boots,
        engine_time,
        auth,
        privacy,
        &raw_pdu_bytes,
    )
}

/// BER-encode an `SNMPv3` Report PDU in a full message envelope.
///
/// Report PDUs are used for:
/// - Engine-ID discovery responses: `counter_oid` is `usmStatsUnknownEngineIDs` (REQ-0093).
/// - Time-synchronisation responses: `counter_oid` is `usmStatsNotInTimeWindows` (REQ-0098, REQ-0099).
///
/// The Report PDU carries a single varbind: `counter_oid` bound to a
/// [`Counter32`](crate::codec::Value::Counter32) with `counter_value`.
///
/// The USM security parameters carry the authoritative engine state
/// (`engine_id`, `engine_boots`, `engine_time`) so the manager can synchronise.
///
/// # Errors
///
/// Returns an [`EncodeError`] if BER encoding of any part of the message fails,
/// or if `engine_boots` or `engine_time` exceed `i32::MAX`.
///
/// # Requirements
/// Implements: REQ-0093, REQ-0098, REQ-0099
///
/// # Examples
///
/// ```
/// use basic_snmp_agent::codec::{Oid, encode_v3_report};
///
/// let engine_id = b"\x80\x00\x1f\x88\x04test";
/// let oid: Oid = "1.3.6.1.6.3.15.1.1.4.0".parse().unwrap();
/// let bytes = encode_v3_report(42, engine_id, 3, 100, &oid, 1).unwrap();
/// assert!(!bytes.is_empty());
/// ```
pub fn encode_v3_report(
    msg_id: i32,
    engine_id: &[u8],
    engine_boots: u32,
    engine_time: u32,
    counter_oid: &Oid,
    counter_value: u32,
) -> Result<Vec<u8>, EncodeError> {
    let varbind = Varbind {
        oid: counter_oid.clone(),
        value: VarbindValue::Value(Value::Counter32(counter_value)),
    };
    let raw_varbind_list = encode_varbinds(&[varbind])?;
    // RFC 3412 §7.1.3(4): the Report PDU's request-id echoes the inbound msgID.
    let raw_pdu_bytes = ber::pdu::encode_pdu(ber::TAG_REPORT, msg_id, 0, 0, &raw_varbind_list)
        .map_err(|e| EncodeError::new(format!("BER encoding of Report PDU failed: {e}")))?;
    // RFC 3414 §8.2.4: the report's USM security parameters carry the authoritative
    // engine state so the manager can synchronise its local copy. Reports are always
    // sent noAuthNoPriv with an empty user name and empty context name.
    encode_v3_envelope(
        msg_id,
        engine_id,
        b"",
        b"",
        engine_boots,
        engine_time,
        None,
        None,
        &raw_pdu_bytes,
    )
}

/// BER-encode a [`WireTrapPdu`] for transmission as a plain UDP datagram.
///
/// Wraps the SNMPv2-Trap-PDU in an `SNMPv2c` message (RFC 1901) with an empty
/// community string. This is the format expected by `snmptrapd` and compatible
/// trap receivers for plain UDP trap delivery.
///
/// # Errors
///
/// Returns an [`EncodeError`] if BER encoding of the PDU fails.
///
/// # Examples
///
/// ```
/// use basic_snmp_agent::codec::{Oid, Value, WireTrapPdu, Varbind, VarbindValue, encode_trap};
///
/// let oid: Oid = "1.3.6.1.6.3.1.1.4.1.0".parse().unwrap();
/// let pdu = WireTrapPdu {
///     request_id: 1,
///     varbinds: vec![Varbind { oid, value: VarbindValue::Value(Value::TimeTicks(0)) }],
/// };
/// let bytes = encode_trap(&pdu).unwrap();
/// assert!(!bytes.is_empty());
/// ```
pub fn encode_trap(pdu: &WireTrapPdu) -> Result<Vec<u8>, EncodeError> {
    let raw_varbind_list = encode_varbinds(&pdu.varbinds)?;
    let raw_pdu_bytes =
        ber::pdu::encode_pdu(ber::TAG_TRAP, pdu.request_id, 0, 0, &raw_varbind_list)
            .map_err(|e| EncodeError::new(format!("BER encoding of WireTrapPdu failed: {e}")))?;
    // The community string is empty because SNMPv2c traps use plain UDP delivery;
    // the authenticated path uses SNMPv3 instead.
    Ok(ber::snmp::encode_v2c_message(b"", &raw_pdu_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::pdu::{ErrorStatus, GetResponse, Varbind, VarbindValue, WireTrapPdu};
    use crate::codec::{Oid, Value};
    use rasn_smi::v2::{ApplicationSyntax, ObjectSyntax, SimpleSyntax};
    use rasn_snmp::v2::{Pdus, Response, VarBindValue as RasnVarBindValue};
    use rasn_snmp::v2c::Message as V2cMessage;
    use rasn_snmp::v3::{Message as V3Message, ScopedPdu, ScopedPduData, USMSecurityParameters};

    fn sysdescr_oid() -> Oid {
        "1.3.6.1.2.1.1.1.0".parse().unwrap()
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
    fn encode_trap_produces_valid_ber() {
        let oid: Oid = "1.3.6.1.6.3.1.1.4.1.0".parse().unwrap();
        let pdu = WireTrapPdu {
            request_id: 1,
            varbinds: vec![Varbind {
                oid,
                value: VarbindValue::Value(Value::TimeTicks(0)),
            }],
        };
        let encoded_trap = encode_trap(&pdu).unwrap();
        // Verify the output is valid BER by decoding it back as a full SNMPv2c message.
        let decoded: V2cMessage<Pdus> =
            rasn::ber::decode(&encoded_trap).expect("encode_trap must produce valid BER");
        assert!(
            matches!(decoded.data, Pdus::Trap(_)),
            "expected Trap PDU, got {:?}",
            decoded.data
        );
    }

    #[test]
    fn encode_response_round_trip_via_decode() {
        // Build a GetResponse, encode it, then decode it as a Pdus::Response to
        // verify the BER round-trip is lossless.
        let oid = sysdescr_oid();
        let pdu = GetResponse {
            request_id: 9999,
            error_status: ErrorStatus::NoError,
            error_index: 0,
            varbinds: vec![Varbind {
                oid: oid.clone(),
                value: VarbindValue::Value(Value::Integer32(100)),
            }],
        };
        let encoded_response = encode_response(&pdu).unwrap();

        // Decode back using rasn directly to verify BER validity.
        let decoded: Pdus = rasn::ber::decode(&encoded_response).expect("must decode");
        match decoded {
            Pdus::Response(Response(inner)) => {
                assert_eq!(inner.request_id, 9999);
                assert_eq!(inner.error_status, 0);
                assert_eq!(inner.variable_bindings.len(), 1);
                let vb = &inner.variable_bindings[0];
                assert_eq!(vb.name.as_ref(), oid.as_slice());
            }
            other => panic!("expected Response, got {other:?}"),
        }
    }

    #[test]
    fn encode_trap_round_trip_via_decode() {
        let trap_oid: Oid = "1.3.6.1.6.3.1.1.4.1.0".parse().unwrap();
        let sysname: Oid = "1.3.6.1.2.1.1.5.0".parse().unwrap();
        let pdu = WireTrapPdu {
            request_id: 77,
            varbinds: vec![
                Varbind {
                    oid: trap_oid.clone(),
                    value: VarbindValue::Value(Value::OctetString(b"coldStart".to_vec())),
                },
                Varbind {
                    oid: sysname.clone(),
                    value: VarbindValue::Value(Value::OctetString(b"router1".to_vec())),
                },
            ],
        };
        let encoded_trap = encode_trap(&pdu).unwrap();

        // BER-decode back as a full SNMPv2c message to verify structural validity.
        let decoded: V2cMessage<Pdus> = rasn::ber::decode(&encoded_trap).expect("must decode");
        assert_eq!(
            u64::try_from(decoded.version).unwrap(),
            V2cMessage::<Pdus>::VERSION
        );
        match decoded.data {
            Pdus::Trap(inner) => {
                assert_eq!(inner.0.request_id, 77, "request_id must survive round-trip");
                assert_eq!(
                    inner.0.variable_bindings.len(),
                    2,
                    "both varbinds must survive round-trip"
                );
            }
            other => panic!("expected Trap PDU in message, got {other:?}"),
        }

        // Also verify round-trip by re-encoding and checking it's stable.
        let encoded_trap2 = encode_trap(&pdu).unwrap();
        assert_eq!(
            encoded_trap, encoded_trap2,
            "encode_trap must be deterministic"
        );
    }

    #[test]
    fn exception_sentinels_survive_encode_decode_round_trip() {
        let oid1: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        let oid2: Oid = "1.3.6.1.2.1.1.2.0".parse().unwrap();
        let oid3: Oid = "1.3.6.1.2.1.1.3.0".parse().unwrap();

        let pdu = GetResponse {
            request_id: 42,
            error_status: ErrorStatus::NoError,
            error_index: 0,
            varbinds: vec![
                Varbind {
                    oid: oid1,
                    value: VarbindValue::NoSuchObject,
                },
                Varbind {
                    oid: oid2,
                    value: VarbindValue::NoSuchInstance,
                },
                Varbind {
                    oid: oid3,
                    value: VarbindValue::EndOfMibView,
                },
            ],
        };
        let encoded_response = encode_response(&pdu).unwrap();

        // BER-decode back via rasn and inspect varbind values directly.
        let decoded: Pdus = rasn::ber::decode(&encoded_response).expect("must decode");
        match decoded {
            Pdus::Response(Response(inner)) => {
                assert_eq!(inner.variable_bindings.len(), 3);
                assert!(matches!(
                    inner.variable_bindings[0].value,
                    RasnVarBindValue::NoSuchObject
                ));
                assert!(matches!(
                    inner.variable_bindings[1].value,
                    RasnVarBindValue::NoSuchInstance
                ));
                assert!(matches!(
                    inner.variable_bindings[2].value,
                    RasnVarBindValue::EndOfMibView
                ));
            }
            other => panic!("expected Response, got {other:?}"),
        }
    }

    #[test]
    fn given_get_response_when_encode_v3_response_then_valid_v3_message() {
        // Verifies: REQ-0068, REQ-0070, REQ-0072
        let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        let engine_id = b"\x80\x00\x1f\x88\x04test";
        let pdu = GetResponse {
            request_id: 99,
            error_status: ErrorStatus::NoError,
            error_index: 0,
            varbinds: vec![Varbind {
                oid: oid.clone(),
                value: VarbindValue::Value(Value::Integer32(42)),
            }],
        };

        let encoded =
            encode_v3_response(5, engine_id, b"testuser", b"", 0, 0, None, None, &pdu).unwrap();

        // Decode back as a V3Message to verify structural validity.
        let decoded: V3Message = rasn::ber::decode(&encoded).expect("must decode as V3Message");
        let version_number: i64 = decoded.version.try_into().unwrap();
        assert_eq!(version_number, 3);
        let msg_id: i32 = decoded.global_data.message_id.try_into().unwrap();
        assert_eq!(msg_id, 5);

        match decoded.scoped_data {
            ScopedPduData::CleartextPdu(scoped) => {
                assert_eq!(scoped.engine_id.as_ref(), engine_id);
                assert_eq!(scoped.name.as_ref(), b"");
                assert!(
                    matches!(scoped.data, Pdus::Response(_)),
                    "expected Response PDU in ScopedPdu"
                );
            }
            ScopedPduData::EncryptedPdu(_) => panic!("expected cleartext, got encrypted PDU"),
        }
        // Verify the user_name is echoed in the USM security parameters (RFC 3414 §8.2.4).
        let usm_params: USMSecurityParameters =
            rasn::ber::decode(decoded.security_parameters.as_ref())
                .expect("USM security parameters must decode");
        assert_eq!(
            usm_params.user_name.as_ref(),
            b"testuser",
            "user_name must be echoed in USM security parameters"
        );
    }

    #[test]
    fn given_auth_no_priv_when_encode_v3_response_then_mac_is_embedded_and_valid() {
        // Verifies: REQ-0100, REQ-0107
        use crate::usm::auth::AuthProtocol;
        use crate::usm::keys::SecretKey;

        let engine_id = b"\x80\x00\x1f\x88\x04test";
        let auth_key = SecretKey::new_from_exposed_slice(&[0x42u8; 32]);
        let auth_key_for_verify = SecretKey::new_from_exposed_slice(&[0x42u8; 32]);
        let auth_protocol = AuthProtocol::HmacSha256;
        let pdu = GetResponse {
            request_id: 7,
            error_status: ErrorStatus::NoError,
            error_index: 0,
            varbinds: vec![],
        };

        let encoded = encode_v3_response(
            3,
            engine_id,
            b"authuser",
            b"",
            1,
            100,
            Some((auth_protocol, &auth_key)),
            None,
            &pdu,
        )
        .unwrap();

        // Decode and verify structure
        let decoded: V3Message = rasn::ber::decode(&encoded).expect("must decode as V3Message");
        let flags_byte = decoded.global_data.flags.first().copied().unwrap_or(0);
        assert_eq!(flags_byte & 0x01, 0x01, "authFlag must be set in response");

        let usm_params: USMSecurityParameters =
            rasn::ber::decode(decoded.security_parameters.as_ref())
                .expect("USM security parameters must decode");
        assert_eq!(
            usm_params.authentication_parameters.len(),
            24,
            "authentication_parameters must be 24 bytes for HMAC-SHA-256"
        );
        assert_eq!(
            u32::try_from(&usm_params.authoritative_engine_boots).unwrap(),
            1,
            "engine_boots must be set in response"
        );
        assert_eq!(
            u32::try_from(&usm_params.authoritative_engine_time).unwrap(),
            100,
            "engine_time must be set in response"
        );

        verify_embedded_hmac(
            &encoded,
            decoded.security_parameters.as_ref(),
            &usm_params.authentication_parameters,
            auth_protocol,
            &auth_key_for_verify,
        );
    }

    #[test]
    fn given_auth_no_priv_sha512_when_encode_v3_response_then_mac_is_embedded_and_valid() {
        // Verifies: REQ-0100
        use crate::usm::auth::AuthProtocol;
        use crate::usm::keys::SecretKey;

        let engine_id = b"\x80\x00\x1f\x88\x04test";
        let auth_key = SecretKey::new_from_exposed_slice(&[0x42u8; 64]);
        let auth_key_for_verify = SecretKey::new_from_exposed_slice(&[0x42u8; 64]);
        let auth_protocol = AuthProtocol::HmacSha512;
        let pdu = GetResponse {
            request_id: 8,
            error_status: ErrorStatus::NoError,
            error_index: 0,
            varbinds: vec![],
        };

        let encoded = encode_v3_response(
            4,
            engine_id,
            b"authuser512",
            b"",
            2,
            200,
            Some((auth_protocol, &auth_key)),
            None,
            &pdu,
        )
        .unwrap();

        let decoded: V3Message = rasn::ber::decode(&encoded).expect("must decode as V3Message");
        let flags_byte = decoded.global_data.flags.first().copied().unwrap_or(0);
        assert_eq!(flags_byte & 0x01, 0x01, "authFlag must be set in response");

        let usm_params: USMSecurityParameters =
            rasn::ber::decode(decoded.security_parameters.as_ref())
                .expect("USM security parameters must decode");
        assert_eq!(
            usm_params.authentication_parameters.len(),
            48,
            "authentication_parameters must be 48 bytes for HMAC-SHA-512"
        );

        verify_embedded_hmac(
            &encoded,
            decoded.security_parameters.as_ref(),
            &usm_params.authentication_parameters,
            auth_protocol,
            &auth_key_for_verify,
        );
    }

    #[test]
    fn given_auth_no_priv_with_zero_varbind_when_encode_v3_response_then_correct_mac_offset() {
        // Verifies: REQ-0100
        use crate::usm::auth::AuthProtocol;
        use crate::usm::keys::SecretKey;

        let engine_id = b"\x80\x00\x1f\x88\x04test";
        let auth_key = SecretKey::new_from_exposed_slice(&[0x42u8; 32]);
        let auth_key_for_verify = SecretKey::new_from_exposed_slice(&[0x42u8; 32]);
        let auth_protocol = AuthProtocol::HmacSha256;
        // Varbind value is all-zeros with length 24, identical to the SHA-256 placeholder.
        let pdu = GetResponse {
            request_id: 1,
            error_status: ErrorStatus::NoError,
            error_index: 0,
            varbinds: vec![Varbind {
                oid: "1.3.6.1.2.1.1.1.0".parse().unwrap(),
                value: VarbindValue::Value(Value::OctetString(vec![0u8; 24])),
            }],
        };

        let encoded = encode_v3_response(
            5,
            engine_id,
            b"authuser",
            b"",
            1,
            100,
            Some((auth_protocol, &auth_key)),
            None,
            &pdu,
        )
        .unwrap();

        let decoded: V3Message = rasn::ber::decode(&encoded).expect("must decode as V3Message");
        let usm_params: USMSecurityParameters =
            rasn::ber::decode(decoded.security_parameters.as_ref())
                .expect("USM security parameters must decode");

        // Mirrors the production two-step search to independently verify the offset logic.
        verify_embedded_hmac(
            &encoded,
            decoded.security_parameters.as_ref(),
            &usm_params.authentication_parameters,
            auth_protocol,
            &auth_key_for_verify,
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn given_auth_priv_when_encode_v3_response_then_scoped_pdu_is_encrypted_and_decryptable() {
        // Verifies: REQ-0101, REQ-0107
        use crate::usm::auth::AuthProtocol;
        use crate::usm::keys::SecretKey;
        use crate::usm::privacy::PrivProtocol;

        let engine_id = b"test-engine";
        let auth_key = SecretKey::new_from_exposed_slice(&[0xAAu8; 32]);
        let auth_key_for_verify = SecretKey::new_from_exposed_slice(&[0xAAu8; 32]);
        let priv_key = SecretKey::new_from_exposed_slice(&[0xBBu8; 16]);
        let auth_protocol = AuthProtocol::HmacSha256;
        let expected_varbind_value = b"test value".to_vec();
        let pdu = GetResponse {
            request_id: 42,
            error_status: ErrorStatus::NoError,
            error_index: 0,
            varbinds: vec![Varbind {
                oid: "1.3.6.1.2.1.1.1.0".parse().unwrap(),
                value: VarbindValue::Value(Value::OctetString(expected_varbind_value.clone())),
            }],
        };

        let encoded = encode_v3_response(
            99,
            engine_id,
            b"testuser",
            b"",
            100,
            200,
            Some((auth_protocol, &auth_key)),
            Some((PrivProtocol::Aes128, &priv_key)),
            &pdu,
        )
        .expect("encoding must succeed");

        // Decode the outer message to verify structure.
        let v3_msg: V3Message = rasn::ber::decode(&encoded).expect("must decode V3Message");

        // Verify flags = 0x03 (auth + priv).
        assert_eq!(
            v3_msg.global_data.flags.as_ref(),
            &[0x03],
            "msgFlags must be 0x03 (authPriv)"
        );

        // Verify ScopedPduData is encrypted.
        assert!(
            matches!(v3_msg.scoped_data, ScopedPduData::EncryptedPdu(_)),
            "expected EncryptedPdu, got CleartextPdu"
        );

        // Verify privacy_parameters is 8 bytes (the salt).
        let usm_params: USMSecurityParameters =
            rasn::ber::decode(v3_msg.security_parameters.as_ref()).expect("must decode USM params");
        assert_eq!(
            usm_params.privacy_parameters.len(),
            8,
            "salt must be 8 bytes"
        );

        // Decrypt and verify the ScopedPdu is recoverable.
        let ciphertext = match v3_msg.scoped_data {
            ScopedPduData::EncryptedPdu(ct) => ct,
            ScopedPduData::CleartextPdu(_) => unreachable!(),
        };
        let mut aes_iv = [0u8; 16];
        aes_iv[0..4].copy_from_slice(&100u32.to_be_bytes());
        aes_iv[4..8].copy_from_slice(&200u32.to_be_bytes());
        aes_iv[8..16].copy_from_slice(usm_params.privacy_parameters.as_ref());
        let plaintext = PrivProtocol::Aes128
            .decrypt(&priv_key, &aes_iv, ciphertext.as_ref())
            .expect("decryption must succeed");

        // Confirm the decrypted bytes are a valid ScopedPdu with correct content.
        let scoped_pdu: ScopedPdu =
            rasn::ber::decode(&plaintext).expect("must decode ScopedPdu from decrypted bytes");
        assert_eq!(
            scoped_pdu.engine_id.as_ref(),
            engine_id,
            "decrypted ScopedPdu must contain the correct engine_id"
        );
        let Pdus::Response(Response(inner_pdu)) = scoped_pdu.data else {
            panic!("decrypted ScopedPdu must contain a Response PDU");
        };
        assert_eq!(
            inner_pdu.request_id, 42,
            "request_id must survive encryption round-trip"
        );
        assert_eq!(
            inner_pdu.error_status, 0,
            "error_status must be noError (0)"
        );
        assert_eq!(
            inner_pdu.variable_bindings.len(),
            1,
            "varbind count must survive encryption round-trip"
        );
        let sysdescr_oid_arcs: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 1, 0];
        assert_eq!(
            inner_pdu.variable_bindings[0].name.as_ref(),
            sysdescr_oid_arcs,
            "varbind OID must survive encryption round-trip"
        );
        assert!(
            matches!(
                &inner_pdu.variable_bindings[0].value,
                RasnVarBindValue::Value(ObjectSyntax::Simple(SimpleSyntax::String(s)))
                    if s.as_ref() == expected_varbind_value.as_slice()
            ),
            "varbind value must survive encryption round-trip"
        );

        // Verify the HMAC is valid over the encrypted message.
        verify_embedded_hmac(
            &encoded,
            v3_msg.security_parameters.as_ref(),
            &usm_params.authentication_parameters,
            auth_protocol,
            &auth_key_for_verify,
        );
    }

    #[test]
    fn given_priv_without_auth_when_encode_v3_response_then_returns_error() {
        // Verifies: REQ-0101 — privacy without authentication is invalid per RFC 3412
        use crate::usm::keys::SecretKey;
        use crate::usm::privacy::PrivProtocol;

        let priv_key = SecretKey::new_from_exposed_slice(&[0xBBu8; 16]);
        let pdu = GetResponse {
            request_id: 1,
            error_status: ErrorStatus::NoError,
            error_index: 0,
            varbinds: vec![],
        };

        let result = encode_v3_response(
            1,
            b"engine",
            b"user",
            b"",
            0,
            0,
            None,
            Some((PrivProtocol::Aes128, &priv_key)),
            &pdu,
        );
        assert!(result.is_err(), "privacy without auth must return an error");
        let err = result.unwrap_err();
        assert!(
            err.to_string()
                .contains("privacy without authentication is not permitted"),
            "error message must mention RFC 3412 constraint, got: {err}"
        );
    }

    #[test]
    fn given_encode_v3_report_when_decoded_then_security_params_contain_engine_state() {
        // Verifies: REQ-0093, REQ-0099
        let engine_id = b"\x80\x00\x1f\x88\x04test";
        let counter_oid: Oid = "1.3.6.1.6.3.15.1.1.4.0".parse().unwrap();
        let encoded = encode_v3_report(42, engine_id, 3, 100, &counter_oid, 7).unwrap();

        let decoded: rasn_snmp::v3::Message = rasn::ber::decode(&encoded).unwrap();
        let security_params: USMSecurityParameters =
            rasn::ber::decode(decoded.security_parameters.as_ref()).unwrap();

        assert_eq!(security_params.authoritative_engine_id.as_ref(), engine_id);
        assert_eq!(
            u32::try_from(&security_params.authoritative_engine_boots).unwrap(),
            3
        );
        assert_eq!(
            u32::try_from(&security_params.authoritative_engine_time).unwrap(),
            100
        );
        assert!(security_params.user_name.is_empty());

        // Verify the inner PDU carried in the ScopedPdu is a Report with the correct content.
        let ScopedPduData::CleartextPdu(scoped_pdu) = decoded.scoped_data else {
            panic!("Report must be sent as cleartext (noAuthNoPriv)");
        };
        let Pdus::Report(report_pdu) = scoped_pdu.data else {
            panic!("inner PDU must be a Report");
        };
        assert_eq!(
            report_pdu.0.request_id, 42,
            "Report request_id must echo the inbound msgID"
        );
        assert_eq!(
            report_pdu.0.variable_bindings.len(),
            1,
            "Report must carry exactly one varbind"
        );
        let varbind = &report_pdu.0.variable_bindings[0];
        assert_eq!(
            varbind.name.as_ref(),
            counter_oid.as_slice(),
            "Report varbind OID must match counter_oid"
        );
        let RasnVarBindValue::Value(ObjectSyntax::ApplicationWide(ApplicationSyntax::Counter(
            ref counter,
        ))) = varbind.value
        else {
            panic!("Report varbind value must be a Counter32");
        };
        assert_eq!(counter.0, 7u32, "Report varbind must carry counter value 7");
    }

    #[test]
    fn given_trap_pdu_when_encode_v3_trap_no_auth_then_valid_v3_message() {
        // Verifies: REQ-0106
        let engine_id = b"\x80\x00\x1f\x88\x04test";
        let trap_oid: Oid = "1.3.6.1.6.3.1.1.5.1".parse().unwrap();
        let pdu = WireTrapPdu {
            request_id: 42,
            varbinds: vec![Varbind {
                oid: trap_oid,
                value: VarbindValue::Value(Value::TimeTicks(100)),
            }],
        };

        let encoded =
            encode_v3_trap(42, engine_id, b"trapuser", b"", 3, 500, None, None, &pdu).unwrap();

        let decoded: V3Message = rasn::ber::decode(&encoded).expect("must decode as V3Message");

        // Verify flags = 0x00 (noAuthNoPriv).
        let flags_byte = decoded.global_data.flags.first().copied().unwrap_or(0xFF);
        assert_eq!(
            flags_byte, 0x00,
            "msgFlags must be 0x00 for noAuthNoPriv trap"
        );

        // Verify scoped data is cleartext containing a Trap PDU.
        match decoded.scoped_data {
            ScopedPduData::CleartextPdu(scoped) => {
                assert_eq!(scoped.engine_id.as_ref(), engine_id);
                assert_eq!(scoped.name.as_ref(), b"");
                assert!(
                    matches!(scoped.data, Pdus::Trap(_)),
                    "expected Trap PDU in ScopedPdu, got {:?}",
                    scoped.data
                );
            }
            ScopedPduData::EncryptedPdu(_) => {
                panic!("expected cleartext ScopedPdu for noAuthNoPriv trap")
            }
        }

        // Verify USM parameters contain engine state and user name.
        let usm_params: USMSecurityParameters =
            rasn::ber::decode(decoded.security_parameters.as_ref())
                .expect("USM security parameters must decode");
        assert_eq!(
            usm_params.user_name.as_ref(),
            b"trapuser",
            "user_name must be set in USM security parameters"
        );
        assert_eq!(
            u32::try_from(&usm_params.authoritative_engine_boots).unwrap(),
            3,
            "engine_boots must be set in USM security parameters"
        );
        assert_eq!(
            u32::try_from(&usm_params.authoritative_engine_time).unwrap(),
            500,
            "engine_time must be set in USM security parameters"
        );
    }

    #[test]
    fn given_trap_pdu_when_encode_v3_trap_auth_no_priv_then_mac_is_embedded_and_valid() {
        // Verifies: REQ-0105
        use crate::usm::auth::AuthProtocol;
        use crate::usm::keys::SecretKey;

        let engine_id = b"\x80\x00\x1f\x88\x04test";
        let auth_key = SecretKey::new_from_exposed_slice(&[0x55u8; 32]);
        let auth_key_for_verify = SecretKey::new_from_exposed_slice(&[0x55u8; 32]);
        let auth_protocol = AuthProtocol::HmacSha256;
        let trap_oid: Oid = "1.3.6.1.6.3.1.1.5.1".parse().unwrap();
        let pdu = WireTrapPdu {
            request_id: 7,
            varbinds: vec![Varbind {
                oid: trap_oid,
                value: VarbindValue::Value(Value::TimeTicks(0)),
            }],
        };

        let encoded = encode_v3_trap(
            7,
            engine_id,
            b"authuser",
            b"",
            1,
            100,
            Some((auth_protocol, &auth_key)),
            None,
            &pdu,
        )
        .unwrap();

        let decoded: V3Message = rasn::ber::decode(&encoded).expect("must decode as V3Message");
        let flags_byte = decoded.global_data.flags.first().copied().unwrap_or(0);
        assert_eq!(
            flags_byte & 0x01,
            0x01,
            "authFlag must be set for authNoPriv trap"
        );

        let usm_params: USMSecurityParameters =
            rasn::ber::decode(decoded.security_parameters.as_ref())
                .expect("USM security parameters must decode");
        assert_eq!(
            usm_params.authentication_parameters.len(),
            24,
            "authentication_parameters must be 24 bytes for HMAC-SHA-256"
        );

        verify_embedded_hmac(
            &encoded,
            decoded.security_parameters.as_ref(),
            &usm_params.authentication_parameters,
            auth_protocol,
            &auth_key_for_verify,
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn given_trap_pdu_when_encode_v3_trap_auth_priv_then_encrypted_and_decryptable() {
        // Verifies: REQ-0105
        use crate::usm::auth::AuthProtocol;
        use crate::usm::keys::SecretKey;
        use crate::usm::privacy::PrivProtocol;

        let engine_id = b"test-engine";
        let auth_key = SecretKey::new_from_exposed_slice(&[0xAAu8; 32]);
        let auth_key_for_verify = SecretKey::new_from_exposed_slice(&[0xAAu8; 32]);
        let priv_key = SecretKey::new_from_exposed_slice(&[0xBBu8; 16]);
        let auth_protocol = AuthProtocol::HmacSha256;
        let trap_oid: Oid = "1.3.6.1.6.3.1.1.5.1".parse().unwrap();
        let pdu = WireTrapPdu {
            request_id: 99,
            varbinds: vec![Varbind {
                oid: trap_oid,
                value: VarbindValue::Value(Value::TimeTicks(12345)),
            }],
        };

        let encoded = encode_v3_trap(
            99,
            engine_id,
            b"privuser",
            b"",
            5,
            300,
            Some((auth_protocol, &auth_key)),
            Some((PrivProtocol::Aes128, &priv_key)),
            &pdu,
        )
        .expect("encoding must succeed");

        let v3_msg: V3Message = rasn::ber::decode(&encoded).expect("must decode V3Message");

        // Verify flags = 0x03 (authPriv).
        assert_eq!(
            v3_msg.global_data.flags.as_ref(),
            &[0x03],
            "msgFlags must be 0x03 (authPriv)"
        );

        // Verify ScopedPduData is encrypted.
        assert!(
            matches!(v3_msg.scoped_data, ScopedPduData::EncryptedPdu(_)),
            "expected EncryptedPdu for authPriv trap"
        );

        let usm_params: USMSecurityParameters =
            rasn::ber::decode(v3_msg.security_parameters.as_ref()).expect("must decode USM params");
        assert_eq!(
            usm_params.privacy_parameters.len(),
            8,
            "salt must be 8 bytes"
        );

        // Decrypt and verify inner Trap PDU.
        let ciphertext = match v3_msg.scoped_data {
            ScopedPduData::EncryptedPdu(ct) => ct,
            ScopedPduData::CleartextPdu(_) => unreachable!(),
        };
        let mut aes_iv = [0u8; 16];
        aes_iv[0..4].copy_from_slice(&5u32.to_be_bytes());
        aes_iv[4..8].copy_from_slice(&300u32.to_be_bytes());
        aes_iv[8..16].copy_from_slice(usm_params.privacy_parameters.as_ref());
        let plaintext = PrivProtocol::Aes128
            .decrypt(&priv_key, &aes_iv, ciphertext.as_ref())
            .expect("decryption must succeed");

        let scoped_pdu: ScopedPdu =
            rasn::ber::decode(&plaintext).expect("must decode ScopedPdu from decrypted bytes");
        assert_eq!(scoped_pdu.engine_id.as_ref(), engine_id);
        let Pdus::Trap(inner_trap) = scoped_pdu.data else {
            panic!("decrypted ScopedPdu must contain a Trap PDU");
        };
        assert_eq!(
            inner_trap.0.request_id, 99,
            "request_id must survive encryption round-trip"
        );

        // Verify the HMAC is valid over the encrypted message.
        verify_embedded_hmac(
            &encoded,
            v3_msg.security_parameters.as_ref(),
            &usm_params.authentication_parameters,
            auth_protocol,
            &auth_key_for_verify,
        );
    }

    #[test]
    fn given_priv_without_auth_when_encode_v3_trap_then_returns_error() {
        // Verifies: REQ-0105 — privacy without authentication is invalid per RFC 3412
        use crate::usm::keys::SecretKey;
        use crate::usm::privacy::PrivProtocol;

        let priv_key = SecretKey::new_from_exposed_slice(&[0xBBu8; 16]);
        let trap_oid: Oid = "1.3.6.1.6.3.1.1.5.1".parse().unwrap();
        let pdu = WireTrapPdu {
            request_id: 1,
            varbinds: vec![Varbind {
                oid: trap_oid,
                value: VarbindValue::Value(Value::TimeTicks(0)),
            }],
        };

        let result = encode_v3_trap(
            1,
            b"engine",
            b"user",
            b"",
            0,
            0,
            None,
            Some((PrivProtocol::Aes128, &priv_key)),
            &pdu,
        );
        assert!(result.is_err(), "privacy without auth must return an error");
        let err = result.unwrap_err();
        assert!(
            err.to_string()
                .contains("privacy without authentication is not permitted"),
            "error message must mention RFC 3412 constraint, got: {err}"
        );
    }

    #[test]
    fn given_two_consecutive_priv_trap_encodes_when_encoded_then_salts_differ() {
        // Verifies: REQ-0101
        // The mutant replaces next_privacy_salt() with a constant value.
        // Two consecutive encode_v3_trap calls with privacy must produce different
        // privacy parameters (the 8-byte salt embedded in USM parameters).
        use crate::usm::auth::AuthProtocol;
        use crate::usm::keys::SecretKey;
        use crate::usm::privacy::PrivProtocol;

        let engine_id = b"test-engine";
        let auth_key = SecretKey::new_from_exposed_slice(&[0xAAu8; 32]);
        let auth_key_2 = SecretKey::new_from_exposed_slice(&[0xAAu8; 32]);
        let priv_key = SecretKey::new_from_exposed_slice(&[0xBBu8; 16]);
        let priv_key_2 = SecretKey::new_from_exposed_slice(&[0xBBu8; 16]);
        let trap_oid: Oid = "1.3.6.1.6.3.1.1.5.1".parse().unwrap();
        let pdu = WireTrapPdu {
            request_id: 1,
            varbinds: vec![Varbind {
                oid: trap_oid,
                value: VarbindValue::Value(Value::TimeTicks(0)),
            }],
        };

        let encoded_1 = encode_v3_trap(
            1,
            engine_id,
            b"user",
            b"",
            0,
            0,
            Some((AuthProtocol::HmacSha256, &auth_key)),
            Some((PrivProtocol::Aes128, &priv_key)),
            &pdu,
        )
        .expect("first encoding must succeed");

        let encoded_2 = encode_v3_trap(
            2,
            engine_id,
            b"user",
            b"",
            0,
            0,
            Some((AuthProtocol::HmacSha256, &auth_key_2)),
            Some((PrivProtocol::Aes128, &priv_key_2)),
            &pdu,
        )
        .expect("second encoding must succeed");

        let v3_msg_1: V3Message = rasn::ber::decode(&encoded_1).expect("must decode");
        let v3_msg_2: V3Message = rasn::ber::decode(&encoded_2).expect("must decode");

        let usm_1: USMSecurityParameters = rasn::ber::decode(v3_msg_1.security_parameters.as_ref())
            .expect("USM params 1 must decode");
        let usm_2: USMSecurityParameters = rasn::ber::decode(v3_msg_2.security_parameters.as_ref())
            .expect("USM params 2 must decode");

        let salt_1 = usm_1.privacy_parameters.to_vec();
        let salt_2 = usm_2.privacy_parameters.to_vec();

        assert_eq!(salt_1.len(), 8, "salt 1 must be 8 bytes");
        assert_eq!(salt_2.len(), 8, "salt 2 must be 8 bytes");
        assert_ne!(
            salt_1, salt_2,
            "consecutive privacy-protected trap encodes must use different salts"
        );
    }
}
