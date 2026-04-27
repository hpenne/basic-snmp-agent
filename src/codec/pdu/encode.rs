use std::sync::atomic::{AtomicU64, Ordering};

use rasn_smi::v2::{ApplicationSyntax, Counter64, ObjectSyntax, SimpleSyntax};
use rasn_snmp::v2::{
    Pdu as RasnPdu, Pdus, Response, Trap, VarBind, VarBindValue as RasnVarBindValue,
};
use rasn_snmp::v2c::Message as V2cMessage;
use rasn_snmp::v3::{
    HeaderData, Message as V3Message, ScopedPdu, ScopedPduData, USMSecurityParameters,
};

use super::types::{EncodeError, GetResponse, Varbind, VarbindValue, WireTrapPdu};
use crate::codec::{Oid, Value};

/// Converts our `Oid` into a `rasn` `ObjectIdentifier`.
fn oid_to_rasn(oid: &Oid) -> rasn::types::ObjectIdentifier {
    // rasn ObjectIdentifier owns its arcs via a Cow<'static, [u32]>.
    // We clone the slice into an owned Vec wrapped in a Cow.
    let components: Vec<u32> = oid.as_slice().to_vec();
    rasn::types::ObjectIdentifier::new_unchecked(std::borrow::Cow::Owned(components))
}

/// Constructs an `smi::Opaque` value from raw bytes.
///
/// `Opaque`'s constructor is private inside `rasn-smi`, so we reconstruct it
/// by BER-decoding a hand-crafted `APPLICATION 4` encoding.  The bytes stored
/// inside `Opaque` are the raw payload bytes (identical to what `as_ref()`
/// returns when decoding from the wire).
///
/// # Panics
///
/// Panics if `bytes.len() > 0xFFFF`, since BER lengths above 65535 are not
/// supported by this helper.  In practice `Opaque` payloads in SNMP are far
/// below this limit; exceeding it is treated as a programming error.
// The casts to u8 below are guarded: each branch is only reached when the
// length fits in the target byte width.
#[allow(clippy::cast_possible_truncation)]
fn bytes_to_opaque(bytes: &[u8]) -> rasn_smi::v1::Opaque {
    let payload_len = bytes.len();
    assert!(
        payload_len <= 0xFFFF,
        "bytes_to_opaque: payload length {payload_len} exceeds maximum supported BER length (65535)"
    );

    // BER tag for APPLICATION 4 (primitive): class=application(0x40),
    // constructed=0, tag=4  →  0x44.
    let mut ber = Vec::with_capacity(4 + payload_len);
    ber.push(0x44u8);
    if payload_len <= 0x7F {
        // Short-form length: single byte, no high-bit set.
        ber.push(payload_len as u8);
    } else if payload_len <= 0xFF {
        // Long-form length: 0x81 indicates one following length byte.
        ber.push(0x81u8);
        ber.push(payload_len as u8);
    } else {
        // Long-form length: 0x82 indicates two following length bytes.
        ber.push(0x82u8);
        ber.push((payload_len >> 8) as u8);
        ber.push((payload_len & 0xFF) as u8);
    }
    ber.extend_from_slice(bytes);
    rasn::ber::decode::<rasn_smi::v1::Opaque>(&ber)
        .expect("hand-crafted APPLICATION 4 BER must decode to Opaque")
}

/// Converts our public [`Value`] into the rasn-snmp wire type `ObjectSyntax`.
fn value_to_object_syntax(value: &Value) -> ObjectSyntax {
    // The rasn_smi::v2 types (Counter32, IpAddress, TimeTicks, Unsigned32) are
    // type aliases for the v1 concrete structs (Counter, IpAddress, TimeTicks,
    // Gauge).  We use the v1 constructors directly.
    match value {
        Value::Integer32(n) => ObjectSyntax::Simple(SimpleSyntax::Integer((*n).into())),
        Value::OctetString(bytes) => {
            ObjectSyntax::Simple(SimpleSyntax::String(bytes.clone().into()))
        }
        Value::ObjectIdentifier(oid) => {
            ObjectSyntax::Simple(SimpleSyntax::ObjectId(oid_to_rasn(oid)))
        }
        Value::IpAddress(octets) => {
            let fixed = rasn::types::FixedOctetString::<4>::from(*octets);
            ObjectSyntax::ApplicationWide(ApplicationSyntax::Address(rasn_smi::v1::IpAddress(
                fixed,
            )))
        }
        Value::Counter32(n) => {
            ObjectSyntax::ApplicationWide(ApplicationSyntax::Counter(rasn_smi::v1::Counter(*n)))
        }
        Value::Counter64(n) => {
            ObjectSyntax::ApplicationWide(ApplicationSyntax::BigCounter(Counter64(*n)))
        }
        Value::Gauge32(n) => {
            ObjectSyntax::ApplicationWide(ApplicationSyntax::Unsigned(rasn_smi::v1::Gauge(*n)))
        }
        Value::TimeTicks(n) => {
            ObjectSyntax::ApplicationWide(ApplicationSyntax::Ticks(rasn_smi::v1::TimeTicks(*n)))
        }
        Value::Opaque(bytes) => {
            ObjectSyntax::ApplicationWide(ApplicationSyntax::Arbitrary(bytes_to_opaque(bytes)))
        }
    }
}

/// Converts our [`VarbindValue`] to the rasn-snmp wire type.
fn varbind_value_to_rasn(value: &VarbindValue) -> RasnVarBindValue {
    match value {
        VarbindValue::Value(v) => RasnVarBindValue::Value(value_to_object_syntax(v)),
        VarbindValue::Unspecified => RasnVarBindValue::Unspecified,
        VarbindValue::NoSuchObject => RasnVarBindValue::NoSuchObject,
        VarbindValue::NoSuchInstance => RasnVarBindValue::NoSuchInstance,
        VarbindValue::EndOfMibView => RasnVarBindValue::EndOfMibView,
    }
}

/// Converts our [`Varbind`] to the rasn-snmp wire type.
fn varbind_to_rasn(varbind: &Varbind) -> VarBind {
    VarBind {
        name: oid_to_rasn(&varbind.oid),
        value: varbind_value_to_rasn(&varbind.value),
    }
}

/// BER-encode a [`GetResponse`] PDU for transmission.
///
/// Returns the raw BER bytes ready to be wrapped in an `SNMPv3` message.
///
/// # Errors
///
/// Returns an [`EncodeError`] if `rasn` fails to BER-encode the PDU.
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
    let rasn_pdu = Response(RasnPdu {
        request_id: pdu.request_id,
        error_status: pdu.error_status as u32,
        error_index: pdu.error_index,
        variable_bindings: pdu.varbinds.iter().map(varbind_to_rasn).collect(),
    });
    rasn::ber::encode(&rasn_pdu)
        .map_err(|e| EncodeError::new(format!("BER encoding of GetResponse failed: {e}")))
}

// RFC 3826 §2.2: each message must use a unique salt. The counter is
// initialised with the current time on first use so that salts do not repeat
// across process restarts that happen within the same second.
static PRIVACY_SALT_COUNTER: AtomicU64 = AtomicU64::new(0);

// Implements: REQ-0101
fn next_privacy_salt() -> [u8; 8] {
    // Lazy-initialise with current seconds so salts differ across restarts.
    // The compare-exchange only runs once; subsequent calls just increment.
    // as_secs() returns u64 directly, avoiding any truncation.
    let _ = PRIVACY_SALT_COUNTER.compare_exchange(
        0,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            | 1, // ensure non-zero so the CAS never fires again
        Ordering::Relaxed,
        Ordering::Relaxed,
    );
    PRIVACY_SALT_COUNTER
        .fetch_add(1, Ordering::Relaxed)
        .to_be_bytes()
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
/// Returns an [`EncodeError`] if `rasn` fails to BER-encode any part of the
/// message, if HMAC computation fails, if the auth-params placeholder cannot be
/// located within the encoded message, if AES encryption fails, or if `privacy`
/// is `Some` while `auth` is `None` (privacy without authentication is not
/// permitted per RFC 3412).
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
    let rasn_response = Response(RasnPdu {
        request_id: pdu.request_id,
        error_status: pdu.error_status as u32,
        error_index: pdu.error_index,
        variable_bindings: pdu.varbinds.iter().map(varbind_to_rasn).collect(),
    });

    let scoped_pdu = ScopedPdu {
        engine_id: engine_id.to_vec().into(),
        name: context_name.to_vec().into(),
        data: Pdus::Response(rasn_response),
    };

    // Encrypt the ScopedPdu when privacy credentials are present, otherwise
    // leave it as cleartext. The 8-byte salt comes from a process-global
    // AtomicU64 counter that guarantees uniqueness per RFC 3826 §2.2.
    let (scoped_data, privacy_salt) = if let Some((priv_protocol, priv_key)) = privacy {
        let scoped_pdu_bytes = rasn::ber::encode(&scoped_pdu).map_err(|e| {
            EncodeError::new(format!(
                "BER encoding of ScopedPdu for encryption failed: {e}"
            ))
        })?;
        let salt = next_privacy_salt();
        // IV = engineBoots (4 BE) || engineTime (4 BE) || salt (8 bytes) per RFC 3826 §2.2.
        let mut aes_iv = [0u8; 16];
        aes_iv[0..4].copy_from_slice(&engine_boots.to_be_bytes());
        aes_iv[4..8].copy_from_slice(&engine_time.to_be_bytes());
        aes_iv[8..16].copy_from_slice(&salt);
        let ciphertext = priv_protocol
            .encrypt(priv_key, &aes_iv, &scoped_pdu_bytes)
            .map_err(|e| EncodeError::new(format!("AES encryption failed: {e}")))?;
        (
            ScopedPduData::EncryptedPdu(ciphertext.into()),
            salt.to_vec(),
        )
    } else {
        (ScopedPduData::CleartextPdu(scoped_pdu), vec![])
    };

    let auth_params: Vec<u8> = auth
        .as_ref()
        .map(|(proto, _)| vec![0u8; proto.mac_len()])
        .unwrap_or_default();
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

    // RFC 3414 §8.2.4: echo engine state and user name; auth placeholder is
    // already all-zeros so no separate zeroing step is needed before HMAC.
    let usm_params = USMSecurityParameters {
        authoritative_engine_id: engine_id.to_vec().into(),
        authoritative_engine_boots: engine_boots.into(),
        authoritative_engine_time: engine_time.into(),
        user_name: user_name.to_vec().into(),
        authentication_parameters: rasn::types::OctetString::from(auth_params.clone()),
        privacy_parameters: rasn::types::OctetString::from(privacy_salt),
    };

    let security_parameters_bytes = rasn::ber::encode(&usm_params).map_err(|e| {
        EncodeError::new(format!("BER encoding of USMSecurityParameters failed: {e}"))
    })?;

    let v3_message = V3Message {
        version: 3.into(),
        global_data: HeaderData {
            message_id: msg_id.into(),
            max_size: 65535.into(),
            flags: rasn::types::OctetString::from(vec![flags_byte]),
            // Security model 3 = USM (RFC 3414).
            security_model: 3.into(),
        },
        // Cloned because security_parameters_bytes is needed for the two-step
        // auth_params offset search after the message is encoded.
        security_parameters: security_parameters_bytes.clone().into(),
        scoped_data,
    };

    let mut encoded_message = rasn::ber::encode(&v3_message)
        .map_err(|e| EncodeError::new(format!("BER encoding of SNMPv3 Message failed: {e}")))?;

    if let Some((auth_protocol, auth_key)) = auth {
        let mac_len = auth_params.len();

        // Locate the auth_params placeholder within the encoded message using
        // the two-step search to avoid false positives from attacker-controlled
        // varbind data coincidentally matching the placeholder.
        let usm_pos = encoded_message
            .windows(security_parameters_bytes.len())
            .position(|w| w == security_parameters_bytes.as_slice())
            .ok_or_else(|| {
                EncodeError::new("USM security parameters not found in encoded message")
            })?;
        let auth_pos = encoded_message[usm_pos..usm_pos + security_parameters_bytes.len()]
            .windows(mac_len)
            .position(|w| w == auth_params.as_slice())
            .ok_or_else(|| {
                EncodeError::new(
                    "auth params placeholder not found in USM security parameters region",
                )
            })?;
        let auth_params_offset = usm_pos + auth_pos;

        // The placeholder is already all-zeros so no zeroing step is needed
        // before computing the HMAC.
        let mac = auth_protocol
            .compute_mac(auth_key, &encoded_message)
            .map_err(|e| EncodeError::new(format!("HMAC computation failed: {e}")))?;

        encoded_message[auth_params_offset..auth_params_offset + mac_len].copy_from_slice(&mac);

        Ok(encoded_message)
    } else {
        Ok(encoded_message)
    }
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
/// Returns an [`EncodeError`] if `rasn` fails to BER-encode any part of the message.
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
    use rasn_snmp::v2::Report;

    let varbind = Varbind {
        oid: counter_oid.clone(),
        value: VarbindValue::Value(Value::Counter32(counter_value)),
    };
    let report_pdu = Report(RasnPdu {
        request_id: msg_id,
        error_status: 0,
        error_index: 0,
        variable_bindings: vec![varbind_to_rasn(&varbind)],
    });
    let scoped_pdu = ScopedPdu {
        engine_id: engine_id.to_vec().into(),
        name: vec![].into(),
        data: Pdus::Report(report_pdu),
    };
    // RFC 3414 §8.2.4: the report's USM security parameters carry the authoritative
    // engine state so the manager can synchronise its local copy.
    let usm_params = USMSecurityParameters {
        authoritative_engine_id: engine_id.to_vec().into(),
        authoritative_engine_boots: engine_boots.into(),
        authoritative_engine_time: engine_time.into(),
        user_name: vec![].into(),
        authentication_parameters: rasn::types::OctetString::from(vec![]),
        privacy_parameters: rasn::types::OctetString::from(vec![]),
    };
    let security_parameters_bytes = rasn::ber::encode(&usm_params).map_err(|e| {
        EncodeError::new(format!("BER encoding of USMSecurityParameters failed: {e}"))
    })?;
    // Flags byte 0x00: noAuthNoPriv, reportable bit clear (this is a report).
    let v3_message = V3Message {
        version: 3.into(),
        global_data: HeaderData {
            message_id: msg_id.into(),
            max_size: 65535.into(),
            flags: rasn::types::OctetString::from(vec![0x00]),
            security_model: 3.into(),
        },
        security_parameters: security_parameters_bytes.into(),
        scoped_data: ScopedPduData::CleartextPdu(scoped_pdu),
    };
    rasn::ber::encode(&v3_message)
        .map_err(|e| EncodeError::new(format!("BER encoding of SNMPv3 Report failed: {e}")))
}

/// BER-encode a [`WireTrapPdu`] for transmission as a plain UDP datagram.
///
/// Wraps the SNMPv2-Trap-PDU in an `SNMPv2c` message (RFC 1901) with an empty
/// community string. This is the format expected by `snmptrapd` and compatible
/// trap receivers for plain UDP trap delivery.
///
/// # Errors
///
/// Returns an [`EncodeError`] if `rasn` fails to BER-encode the PDU.
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
    let rasn_pdu = Trap(RasnPdu {
        request_id: pdu.request_id,
        error_status: 0,
        error_index: 0,
        variable_bindings: pdu.varbinds.iter().map(varbind_to_rasn).collect(),
    });
    let v2c_message = V2cMessage {
        version: V2cMessage::<Pdus>::VERSION.into(),
        // An empty community string is intentional: this agent does not
        // implement SNMPv2c community-based authentication. Trap receivers
        // used in this project are configured with `disableAuthorization yes`
        // to accept unauthenticated traps.
        community: rasn::types::OctetString::from(vec![]),
        data: Pdus::Trap(rasn_pdu),
    };
    rasn::ber::encode(&v2c_message)
        .map_err(|e| EncodeError::new(format!("BER encoding of WireTrapPdu failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::pdu::{ErrorStatus, GetResponse, Varbind, VarbindValue, WireTrapPdu};
    use crate::codec::{Oid, Value};

    fn sysdescr_oid() -> Oid {
        "1.3.6.1.2.1.1.1.0".parse().unwrap()
    }

    #[test]
    fn encode_response_produces_non_empty_bytes() {
        let oid = sysdescr_oid();
        let pdu = GetResponse {
            request_id: 1234,
            error_status: ErrorStatus::NoError,
            error_index: 0,
            varbinds: vec![Varbind {
                oid,
                value: VarbindValue::Value(Value::OctetString(b"Linux".to_vec())),
            }],
        };
        let encoded_response = encode_response(&pdu).unwrap();
        assert!(!encoded_response.is_empty());
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

    // Exercises the one-byte long-form BER length path (0x80 <= len <= 0xFF).
    // A 128-byte payload uses BER long-form length 0x81 0x80.
    #[test]
    fn bytes_to_opaque_medium_payload_round_trips() {
        let opaque_payload: Vec<u8> = (0u8..128).collect();
        let opaque = bytes_to_opaque(&opaque_payload);
        assert_eq!(opaque.as_ref(), opaque_payload.as_slice());
    }

    // Exercises the two-byte long-form BER length path (len > 0xFF).
    // A 256-byte payload uses BER long-form length 0x82 0x01 0x00.
    // This catches mutations to the `>>` shift and `&` mask on the high/low bytes.
    #[test]
    fn bytes_to_opaque_large_payload_round_trips() {
        let opaque_payload: Vec<u8> = (0u8..=255).collect(); // exactly 256 bytes
        let opaque = bytes_to_opaque(&opaque_payload);
        assert_eq!(opaque.as_ref(), opaque_payload.as_slice());
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

        // Verify the embedded MAC using verify_mac for constant-time comparison.
        let embedded_mac = usm_params.authentication_parameters.to_vec();
        let usm_raw = decoded.security_parameters.as_ref();
        let usm_pos = encoded
            .windows(usm_raw.len())
            .position(|w| w == usm_raw)
            .expect("USM bytes must appear in encoded message");
        let auth_pos = encoded[usm_pos..usm_pos + usm_raw.len()]
            .windows(embedded_mac.len())
            .position(|w| w == embedded_mac.as_slice())
            .expect("MAC must appear within USM region");
        let auth_params_offset = usm_pos + auth_pos;

        let mut zeroed = encoded.clone();
        zeroed[auth_params_offset..auth_params_offset + embedded_mac.len()].fill(0);

        auth_protocol
            .verify_mac(&auth_key_for_verify, &zeroed, &embedded_mac)
            .expect("MAC must verify");
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

        let embedded_mac = usm_params.authentication_parameters.to_vec();
        let usm_raw = decoded.security_parameters.as_ref();
        let usm_pos = encoded
            .windows(usm_raw.len())
            .position(|w| w == usm_raw)
            .expect("USM bytes must appear in encoded message");
        let auth_pos = encoded[usm_pos..usm_pos + usm_raw.len()]
            .windows(embedded_mac.len())
            .position(|w| w == embedded_mac.as_slice())
            .expect("MAC must appear within USM region");
        let auth_params_offset = usm_pos + auth_pos;

        let mut zeroed = encoded.clone();
        zeroed[auth_params_offset..auth_params_offset + embedded_mac.len()].fill(0);

        auth_protocol
            .verify_mac(&auth_key_for_verify, &zeroed, &embedded_mac)
            .expect("MAC must verify");
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
        let embedded_mac = usm_params.authentication_parameters.to_vec();

        // Mirrors the production two-step search to independently verify the offset logic.
        let usm_raw = decoded.security_parameters.as_ref();
        let usm_pos = encoded
            .windows(usm_raw.len())
            .position(|w| w == usm_raw)
            .expect("USM bytes must appear in encoded message");
        let auth_pos = encoded[usm_pos..usm_pos + usm_raw.len()]
            .windows(embedded_mac.len())
            .position(|w| w == embedded_mac.as_slice())
            .expect("MAC must appear within USM region");
        let auth_params_offset = usm_pos + auth_pos;

        let mut zeroed = encoded.clone();
        zeroed[auth_params_offset..auth_params_offset + embedded_mac.len()].fill(0);

        auth_protocol
            .verify_mac(&auth_key_for_verify, &zeroed, &embedded_mac)
            .expect("MAC must verify");
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
        let usm_raw = v3_msg.security_parameters.as_ref();
        let embedded_mac = usm_params.authentication_parameters.to_vec();
        let usm_pos = encoded
            .windows(usm_raw.len())
            .position(|w| w == usm_raw)
            .expect("USM bytes must appear in encoded message");
        let auth_pos = encoded[usm_pos..usm_pos + usm_raw.len()]
            .windows(embedded_mac.len())
            .position(|w| w == embedded_mac.as_slice())
            .expect("MAC must appear within USM region");
        let auth_params_offset = usm_pos + auth_pos;
        let mut zeroed = encoded.clone();
        zeroed[auth_params_offset..auth_params_offset + embedded_mac.len()].fill(0);
        auth_protocol
            .verify_mac(&auth_key_for_verify, &zeroed, &embedded_mac)
            .expect("HMAC over encrypted message must verify");
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
    fn given_valid_inputs_when_encode_v3_report_then_returns_non_empty_bytes() {
        // Verifies: REQ-0093
        let engine_id = b"\x80\x00\x1f\x88\x04test";
        let oid: Oid = "1.3.6.1.6.3.15.1.1.4.0".parse().unwrap();
        let result = encode_v3_report(42, engine_id, 3, 100, &oid, 7);
        assert!(result.is_ok(), "encode_v3_report should succeed");
        assert!(!result.unwrap().is_empty());
    }

    #[test]
    fn given_encode_v3_report_when_decoded_then_security_params_contain_engine_state() {
        // Verifies: REQ-0093, REQ-0099
        let engine_id = b"\x80\x00\x1f\x88\x04test";
        let oid: Oid = "1.3.6.1.6.3.15.1.1.4.0".parse().unwrap();
        let encoded = encode_v3_report(42, engine_id, 3, 100, &oid, 7).unwrap();

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
    }
}
