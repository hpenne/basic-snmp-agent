use rasn_smi::v2::{ApplicationSyntax, ObjectSyntax, SimpleSyntax};
use rasn_snmp::v2::{
    GetBulkRequest as RasnGetBulkRequest, GetNextRequest as RasnGetNextRequest,
    GetRequest as RasnGetRequest, Pdus, SetRequest as RasnSetRequest, VarBind,
    VarBindValue as RasnVarBindValue,
};
use rasn_snmp::v3::{Message as V3Message, ScopedPduData, USMSecurityParameters};

use super::types::{
    DecodeError, DecodeErrorKind, GetBulkRequest, GetNextRequest, GetRequest, InboundPdu,
    SetRequest, UsmSecurityFields, V3InboundMessage, Varbind, VarbindValue,
};
use crate::codec::{Oid, Value};

/// Converts a `rasn` `ObjectIdentifier` into our `Oid`.
fn oid_from_rasn(oid: &rasn::types::ObjectIdentifier) -> Result<Oid, DecodeError> {
    let components: Vec<u32> = oid.as_ref().to_vec();
    Oid::try_from(components)
        .map_err(|e| DecodeError::new(DecodeErrorKind::InvalidOid, format!("invalid OID: {e}")))
}

/// Converts a rasn-snmp wire type `ObjectSyntax` into our public [`Value`].
// pub(super) rather than private: used by the cross-module round-trip test in mod.rs.
pub(super) fn value_from_object_syntax(syntax: ObjectSyntax) -> Result<Value, DecodeError> {
    match syntax {
        ObjectSyntax::Simple(SimpleSyntax::Integer(raw_integer)) => {
            let integer_value: i32 = raw_integer
                .try_into()
                .map_err(|_| DecodeError::new(DecodeErrorKind::Ber, "Integer32 out of range"))?;
            Ok(Value::Integer32(integer_value))
        }
        ObjectSyntax::Simple(SimpleSyntax::String(bytes)) => Ok(Value::OctetString(bytes.to_vec())),
        ObjectSyntax::Simple(SimpleSyntax::ObjectId(oid)) => {
            Ok(Value::ObjectIdentifier(oid_from_rasn(&oid)?))
        }
        ObjectSyntax::ApplicationWide(ApplicationSyntax::Address(ip)) => {
            Ok(Value::IpAddress(*ip.0))
        }
        ObjectSyntax::ApplicationWide(ApplicationSyntax::Counter(c)) => Ok(Value::Counter32(c.0)),
        ObjectSyntax::ApplicationWide(ApplicationSyntax::BigCounter(c)) => {
            Ok(Value::Counter64(c.0))
        }
        ObjectSyntax::ApplicationWide(ApplicationSyntax::Unsigned(u)) => Ok(Value::Gauge32(u.0)),
        ObjectSyntax::ApplicationWide(ApplicationSyntax::Ticks(t)) => Ok(Value::TimeTicks(t.0)),
        ObjectSyntax::ApplicationWide(ApplicationSyntax::Arbitrary(o)) => {
            Ok(Value::Opaque(o.as_ref().to_vec()))
        }
    }
}

/// Converts a rasn-snmp wire `VarBindValue` into our [`VarbindValue`].
///
/// `Unspecified` (the Null placeholder used in `GetRequest` varbinds) is mapped
/// to [`VarbindValue::Unspecified`], which the agent's event loop can
/// distinguish from the `NoSuchObject` response exception.
fn varbind_value_from_rasn(value: RasnVarBindValue) -> Result<VarbindValue, DecodeError> {
    match value {
        RasnVarBindValue::Value(syntax) => {
            Ok(VarbindValue::Value(value_from_object_syntax(syntax)?))
        }
        RasnVarBindValue::Unspecified => Ok(VarbindValue::Unspecified),
        RasnVarBindValue::NoSuchObject => Ok(VarbindValue::NoSuchObject),
        RasnVarBindValue::NoSuchInstance => Ok(VarbindValue::NoSuchInstance),
        RasnVarBindValue::EndOfMibView => Ok(VarbindValue::EndOfMibView),
    }
}

/// Converts a rasn-snmp wire `VarBind` to our [`Varbind`].
fn varbind_from_rasn(varbind: VarBind) -> Result<Varbind, DecodeError> {
    Ok(Varbind {
        oid: oid_from_rasn(&varbind.name)?,
        value: varbind_value_from_rasn(varbind.value)?,
    })
}

/// Converts a list of rasn-snmp `VarBind`s into our `Vec<Varbind>`.
fn varbinds_from_rasn(list: Vec<VarBind>) -> Result<Vec<Varbind>, DecodeError> {
    list.into_iter().map(varbind_from_rasn).collect()
}

// Implements: REQ-0021, REQ-0068
/// Maps a decoded `Pdus` variant to our `InboundPdu`.
///
/// Shared between `decode_pdu` and `decode_v3_message` to avoid duplicating
/// the match arms for the four inbound PDU types.
fn pdus_to_inbound_pdu(pdus: Pdus) -> Result<InboundPdu, DecodeError> {
    match pdus {
        Pdus::GetRequest(RasnGetRequest(pdu)) => Ok(InboundPdu::GetRequest(GetRequest {
            request_id: pdu.request_id,
            varbinds: varbinds_from_rasn(pdu.variable_bindings)?,
        })),
        Pdus::GetNextRequest(RasnGetNextRequest(pdu)) => {
            Ok(InboundPdu::GetNextRequest(GetNextRequest {
                request_id: pdu.request_id,
                varbinds: varbinds_from_rasn(pdu.variable_bindings)?,
            }))
        }
        Pdus::GetBulkRequest(RasnGetBulkRequest(bulk)) => {
            // RFC 3416 §4.2.3 (REQ-0028): if the wire INTEGER for non-repeaters
            // or max-repetitions is negative, treat it as zero.  BER INTEGER is
            // signed, but rasn decodes into u32 by reinterpreting the sign bit,
            // so a negative value arrives here as a number greater than i32::MAX.
            let non_repeaters = if bulk.non_repeaters > i32::MAX as u32 {
                0
            } else {
                bulk.non_repeaters
            };
            let max_repetitions = if bulk.max_repetitions > i32::MAX as u32 {
                0
            } else {
                bulk.max_repetitions
            };
            Ok(InboundPdu::GetBulkRequest(GetBulkRequest {
                request_id: bulk.request_id,
                non_repeaters,
                max_repetitions,
                varbinds: varbinds_from_rasn(bulk.variable_bindings)?,
            }))
        }
        Pdus::SetRequest(RasnSetRequest(pdu)) => Ok(InboundPdu::SetRequest(SetRequest {
            request_id: pdu.request_id,
            varbinds: varbinds_from_rasn(pdu.variable_bindings)?,
        })),
        other => Err(DecodeError::new(
            DecodeErrorKind::UnsupportedPduType,
            format!("unexpected outbound PDU type: {other:?}"),
        )),
    }
}

/// BER-decode a raw SNMP PDU byte slice into an [`InboundPdu`].
///
/// The bytes must contain a BER-encoded `Pdus` value as defined in RFC 3416.
/// Only inbound PDU types (`GetRequest`, `GetNextRequest`, `GetBulkRequest`,
/// `SetRequest`) are accepted; any other PDU type yields a [`DecodeError`].
///
/// # Errors
///
/// Returns a [`DecodeError`] if the bytes are not valid BER, contain an
/// unrecognised PDU type, or contain malformed OID or value data.
///
/// # Examples
///
/// ```no_run
/// use basic_snmp_agent::codec::decode_pdu;
///
/// let bytes: &[u8] = &[/* raw BER PDU bytes */];
/// match decode_pdu(bytes) {
///     Ok(pdu) => println!("{pdu:?}"),
///     Err(e) => eprintln!("decode failed: {e}"),
/// }
/// ```
pub fn decode_pdu(bytes: &[u8]) -> Result<InboundPdu, DecodeError> {
    let pdus: Pdus = rasn::ber::decode(bytes)
        .map_err(|e| DecodeError::new(DecodeErrorKind::Ber, format!("BER decode failed: {e}")))?;

    pdus_to_inbound_pdu(pdus)
}

/// BER-decode an inbound `SNMPv3` message into a [`V3InboundMessage`].
///
/// Accepts only cleartext `SNMPv3` messages (noAuthNoPriv and authNoPriv); encrypted
/// PDUs (`ScopedPduData::EncryptedPdu`) are rejected because privacy (authPriv)
/// decryption is not yet implemented in the decode layer.
///
/// The inner `Pdus` variant must be an inbound request type; response and trap
/// PDUs are rejected.
///
/// The `raw_message` field of the returned struct is a reference to the input
/// `bytes` slice, so the returned value borrows from `bytes`.
///
/// # Errors
///
/// Returns a [`DecodeError`] if:
/// - The bytes are not valid BER.
/// - The message version is not 3 ([`DecodeErrorKind::WrongVersion`]).
/// - The scoped PDU is encrypted ([`DecodeErrorKind::EncryptedPdu`]).
/// - The inner PDU type is not a recognised inbound type.
/// - An OID or value in a varbind cannot be decoded.
///
/// # Panics
///
/// Panics if the successfully decoded USM security parameters or `auth_params`
/// bytes cannot be located within the raw message bytes. This is a decode
/// invariant violation: if the BER decode succeeded, the bytes must be present.
///
/// # Requirements
/// Implements: REQ-0068, REQ-0069, REQ-0071, REQ-0073, REQ-0100
///
/// # Examples
///
/// ```no_run
/// use basic_snmp_agent::codec::decode_v3_message;
///
/// let bytes: &[u8] = &[/* raw BER SNMPv3 message bytes */];
/// match decode_v3_message(bytes) {
///     Ok(msg) => println!("engine_id={:?} pdu={:?}", msg.engine_id, msg.pdu),
///     Err(e) => eprintln!("decode failed: {e}"),
/// }
/// ```
pub fn decode_v3_message(bytes: &[u8]) -> Result<V3InboundMessage<'_>, DecodeError> {
    let v3_message: V3Message = rasn::ber::decode(bytes)
        .map_err(|e| DecodeError::new(DecodeErrorKind::Ber, format!("BER decode failed: {e}")))?;

    // Verify this is indeed version 3; version 1 or 2c messages are not accepted here.
    let version_number: i64 = v3_message.version.try_into().map_err(|_| {
        DecodeError::new(
            DecodeErrorKind::WrongVersion,
            "version field too large for i64",
        )
    })?;
    if version_number != 3 {
        return Err(DecodeError::new(
            DecodeErrorKind::WrongVersion,
            format!("expected SNMPv3 (version 3), got version {version_number}"),
        ));
    }

    let msg_id: i32 =
        v3_message.global_data.message_id.try_into().map_err(|_| {
            DecodeError::new(DecodeErrorKind::Ber, "msgID field does not fit in i32")
        })?;

    let scoped_pdu = match v3_message.scoped_data {
        ScopedPduData::CleartextPdu(pdu) => pdu,
        // Encrypted PDUs require privacy support that this agent does not implement.
        ScopedPduData::EncryptedPdu(_) => {
            return Err(DecodeError::new(
                DecodeErrorKind::EncryptedPdu,
                "encrypted (privacy-protected) PDUs are not supported",
            ));
        }
    };

    // Extract the USM security parameters:
    // - user_name is echoed in the response (RFC 3414 §8.2.4).
    // - auth_engine_id is empty for engine-ID discovery probes (REQ-0093).
    // - auth_engine_boots / auth_engine_time are used for time-window validation (REQ-0098, REQ-0099).
    // - auth_params carries the received MAC for HMAC verification (REQ-0100).
    // Failure to decode the security parameters is treated as a BER error.
    let usm_params: USMSecurityParameters =
        rasn::ber::decode(v3_message.security_parameters.as_ref()).map_err(|e| {
            DecodeError::new(DecodeErrorKind::Ber, format!("USM decode failed: {e}"))
        })?;
    let user_name = usm_params.user_name.to_vec();
    let auth_params = usm_params.authentication_parameters.to_vec();
    // Values outside the u32 range are clamped to u32::MAX; they will fail
    // time-window validation and trigger a Report PDU rather than causing a panic.
    let usm = UsmSecurityFields {
        auth_engine_id: usm_params.authoritative_engine_id.to_vec(),
        auth_engine_boots: u32::try_from(&usm_params.authoritative_engine_boots)
            .unwrap_or(u32::MAX),
        auth_engine_time: u32::try_from(&usm_params.authoritative_engine_time).unwrap_or(u32::MAX),
        security_flags: v3_message.global_data.flags.first().copied().unwrap_or(0),
        auth_params,
    };

    let engine_id = scoped_pdu.engine_id.to_vec();
    let context_name = scoped_pdu.name.to_vec();
    let pdu = pdus_to_inbound_pdu(scoped_pdu.data)?;

    // Find auth_params_offset using a two-step restricted search.
    // Step 1: locate the USM security parameters bytes within raw_message.
    //   (These ~50+ bytes include the engine_id which is agent-controlled,
    //   making a false match in the ScopedPDU region astronomically unlikely.)
    // Step 2: find auth_params within that restricted region.
    //   (Only attacker-controlled bytes within USM are user_name — validated to
    //   match the configured user — and auth_params itself.)
    // This avoids false matches against attacker-controlled varbind data in the ScopedPDU.
    let usm_raw = v3_message.security_parameters.as_ref();
    let auth_params_offset = if usm.auth_params.is_empty() {
        None
    } else {
        let usm_pos = bytes
            .windows(usm_raw.len())
            .position(|w| w == usm_raw)
            // Decoded from bytes, so it must be present.
            .expect("USM security parameters must appear in raw_message");
        let auth_pos = bytes[usm_pos..usm_pos + usm_raw.len()]
            .windows(usm.auth_params.len())
            .position(|w| w == usm.auth_params.as_slice())
            // Decoded from USM params, so auth_params must be within the USM region.
            .expect("auth_params must appear within the USM security parameters region");
        Some(usm_pos + auth_pos)
    };

    Ok(V3InboundMessage {
        msg_id,
        engine_id,
        context_name,
        user_name,
        pdu,
        usm,
        raw_message: bytes,
        auth_params_offset,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::pdu::{DecodeErrorKind, InboundPdu, VarbindValue};
    use crate::codec::{Oid, Value};

    #[test]
    fn decode_pdu_get_request() {
        use rasn_snmp::v2::{GetRequest as RasnGetRequest, Pdu, VarBind, VarBindValue};

        // Encode a GetRequest using rasn-snmp directly, then decode via our function.
        let oid = "1.3.6.1.2.1.1.1.0".parse::<Oid>().unwrap();
        let rasn_oid = rasn::types::ObjectIdentifier::new_unchecked(std::borrow::Cow::Owned(
            oid.as_slice().to_vec(),
        ));
        let get_req = RasnGetRequest(Pdu {
            request_id: 42,
            error_status: 0,
            error_index: 0,
            variable_bindings: vec![VarBind {
                name: rasn_oid,
                value: VarBindValue::Unspecified,
            }],
        });
        let raw_ber = rasn::ber::encode(&get_req).unwrap();
        let decode_result = decode_pdu(&raw_ber).unwrap();

        match decode_result {
            InboundPdu::GetRequest(req) => {
                assert_eq!(req.request_id, 42);
                assert_eq!(req.varbinds.len(), 1);
                assert_eq!(req.varbinds[0].oid, oid);
                // Unspecified (Null) on inbound requests decodes to VarbindValue::Unspecified.
                assert_eq!(req.varbinds[0].value, VarbindValue::Unspecified);
            }
            other => panic!("expected GetRequest, got {other:?}"),
        }
    }

    #[test]
    fn decode_pdu_get_next_request() {
        use rasn_snmp::v2::{GetNextRequest as RasnGetNextRequest, Pdu, VarBind, VarBindValue};

        let oid = "1.3.6.1.2.1.1.1.0".parse::<Oid>().unwrap();
        let rasn_oid = rasn::types::ObjectIdentifier::new_unchecked(std::borrow::Cow::Owned(
            oid.as_slice().to_vec(),
        ));
        let req = RasnGetNextRequest(Pdu {
            request_id: 7,
            error_status: 0,
            error_index: 0,
            variable_bindings: vec![VarBind {
                name: rasn_oid,
                value: VarBindValue::Unspecified,
            }],
        });
        let encoded_response = rasn::ber::encode(&req).unwrap();
        let pdu = decode_pdu(&encoded_response).unwrap();

        assert!(matches!(pdu, InboundPdu::GetNextRequest(_)));
    }

    #[test]
    fn decode_pdu_get_bulk_request() {
        use rasn_snmp::v2::{BulkPdu, GetBulkRequest as RasnGetBulkRequest, VarBind, VarBindValue};

        let oid = "1.3.6.1.2.1.1.1.0".parse::<Oid>().unwrap();
        let rasn_oid = rasn::types::ObjectIdentifier::new_unchecked(std::borrow::Cow::Owned(
            oid.as_slice().to_vec(),
        ));
        let req = RasnGetBulkRequest(BulkPdu {
            request_id: 3,
            non_repeaters: 1,
            max_repetitions: 10,
            variable_bindings: vec![VarBind {
                name: rasn_oid,
                value: VarBindValue::Unspecified,
            }],
        });
        let encoded_response = rasn::ber::encode(&req).unwrap();
        let pdu = decode_pdu(&encoded_response).unwrap();

        match pdu {
            InboundPdu::GetBulkRequest(bulk) => {
                assert_eq!(bulk.non_repeaters, 1);
                assert_eq!(bulk.max_repetitions, 10);
            }
            other => panic!("expected GetBulkRequest, got {other:?}"),
        }
    }

    #[test]
    fn decode_pdu_set_request() {
        use rasn_smi::v2::{ObjectSyntax, SimpleSyntax};
        use rasn_snmp::v2::{Pdu, SetRequest as RasnSetRequest, VarBind, VarBindValue};

        let oid = "1.3.6.1.2.1.1.4.0".parse::<Oid>().unwrap();
        let rasn_oid = rasn::types::ObjectIdentifier::new_unchecked(std::borrow::Cow::Owned(
            oid.as_slice().to_vec(),
        ));
        let req = RasnSetRequest(Pdu {
            request_id: 55,
            error_status: 0,
            error_index: 0,
            variable_bindings: vec![VarBind {
                name: rasn_oid,
                value: VarBindValue::Value(ObjectSyntax::Simple(SimpleSyntax::String(
                    b"admin@example.com".to_vec().into(),
                ))),
            }],
        });
        let encoded_response = rasn::ber::encode(&req).unwrap();
        let pdu = decode_pdu(&encoded_response).unwrap();

        match pdu {
            InboundPdu::SetRequest(set) => {
                assert_eq!(set.request_id, 55);
                assert_eq!(
                    set.varbinds[0].value,
                    VarbindValue::Value(Value::OctetString(b"admin@example.com".to_vec()))
                );
            }
            other => panic!("expected SetRequest, got {other:?}"),
        }
    }

    #[test]
    fn decode_pdu_invalid_bytes_returns_error() {
        let decode_result = decode_pdu(&[0xFF, 0xFF, 0xFF]);
        assert!(decode_result.is_err());
        assert_eq!(decode_result.unwrap_err().kind(), &DecodeErrorKind::Ber);
    }

    #[test]
    fn decode_pdu_rejects_outbound_pdu_type() {
        use rasn_snmp::v2::{Pdu as RasnPdu, Response};

        // Encode a Response (outbound), expect decode_pdu to reject it.
        let resp = Response(RasnPdu {
            request_id: 1,
            error_status: 0,
            error_index: 0,
            variable_bindings: vec![],
        });
        let encoded_response = rasn::ber::encode(&resp).unwrap();
        let decode_result = decode_pdu(&encoded_response);
        assert!(decode_result.is_err());
        assert_eq!(
            decode_result.unwrap_err().kind(),
            &DecodeErrorKind::UnsupportedPduType
        );
    }

    #[test]
    fn given_valid_v3_get_request_when_decode_then_fields_extracted() {
        // Verifies: REQ-0068, REQ-0069, REQ-0070
        let engine_id = b"\x80\x00\x1f\x88\x04test";
        let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        let encoded = snmpv3_frames::encode_get_request(engine_id, b"", 42, 7, oid.as_slice());

        let msg = decode_v3_message(&encoded).unwrap();

        assert_eq!(msg.msg_id, 42);
        assert_eq!(msg.engine_id, engine_id);
        assert_eq!(msg.context_name, b"");
        assert!(matches!(msg.pdu, InboundPdu::GetRequest(ref req) if req.request_id == 7));
    }

    #[test]
    fn given_wrong_version_message_when_decode_v3_then_wrong_version_error() {
        // Verifies: REQ-0073
        // Build a structurally valid V3Message but with version=1 (SNMPv1).
        // rasn decodes it successfully at the BER level, then our version check fires.
        let usm_params = USMSecurityParameters {
            authoritative_engine_id: rasn::types::OctetString::from(vec![]),
            authoritative_engine_boots: 0.into(),
            authoritative_engine_time: 0.into(),
            user_name: rasn::types::OctetString::from(vec![]),
            authentication_parameters: rasn::types::OctetString::from(vec![]),
            privacy_parameters: rasn::types::OctetString::from(vec![]),
        };
        let security_params = rasn::ber::encode(&usm_params).unwrap();
        let scoped_pdu = rasn_snmp::v3::ScopedPdu {
            engine_id: rasn::types::OctetString::from(vec![]),
            name: rasn::types::OctetString::from(vec![]),
            data: Pdus::GetRequest(RasnGetRequest(rasn_snmp::v2::Pdu {
                request_id: 1,
                error_status: 0,
                error_index: 0,
                variable_bindings: vec![],
            })),
        };
        let v3_msg_version_1 = V3Message {
            version: 1.into(),
            global_data: rasn_snmp::v3::HeaderData {
                message_id: 1.into(),
                max_size: 65535.into(),
                flags: rasn::types::OctetString::from(vec![0x04]),
                security_model: 3.into(),
            },
            security_parameters: security_params.into(),
            scoped_data: ScopedPduData::CleartextPdu(scoped_pdu),
        };
        let encoded = rasn::ber::encode(&v3_msg_version_1).unwrap();

        let decode_result = decode_v3_message(&encoded);

        assert!(decode_result.is_err());
        assert_eq!(
            decode_result.unwrap_err().kind(),
            &DecodeErrorKind::WrongVersion
        );
    }

    #[test]
    fn given_encrypted_scoped_pdu_when_decode_v3_then_encrypted_pdu_error() {
        // Verifies: REQ-0073
        let usm_params = USMSecurityParameters {
            authoritative_engine_id: rasn::types::OctetString::from(vec![]),
            authoritative_engine_boots: 0.into(),
            authoritative_engine_time: 0.into(),
            user_name: rasn::types::OctetString::from(vec![]),
            authentication_parameters: rasn::types::OctetString::from(vec![]),
            privacy_parameters: rasn::types::OctetString::from(vec![]),
        };
        let security_params = rasn::ber::encode(&usm_params).unwrap();
        let v3_msg = V3Message {
            version: 3.into(),
            global_data: rasn_snmp::v3::HeaderData {
                message_id: 1.into(),
                max_size: 65535.into(),
                flags: rasn::types::OctetString::from(vec![0x03]),
                security_model: 3.into(),
            },
            security_parameters: security_params.into(),
            scoped_data: ScopedPduData::EncryptedPdu(rasn::types::OctetString::from(
                b"fake-encrypted".to_vec(),
            )),
        };
        let encoded = rasn::ber::encode(&v3_msg).unwrap();

        let decode_result = decode_v3_message(&encoded);

        assert!(decode_result.is_err());
        assert_eq!(
            decode_result.unwrap_err().kind(),
            &DecodeErrorKind::EncryptedPdu
        );
    }

    #[test]
    fn given_invalid_bytes_when_decode_v3_then_ber_error() {
        // Verifies: REQ-0073
        let decode_result = decode_v3_message(&[0xFF, 0xFE, 0xFD]);
        assert!(decode_result.is_err());
        assert_eq!(decode_result.unwrap_err().kind(), &DecodeErrorKind::Ber);
    }

    #[test]
    fn given_getbulk_with_out_of_range_max_repetitions_when_decode_v3_then_treated_as_zero() {
        // Verifies: REQ-0028
        // max_repetitions values outside the SNMP protocol range (0..2147483647
        // per RFC 3416 §4.2.3) must be treated as zero.  Such values arise from
        // negative BER INTEGER wire values whose sign bit rasn reinterprets as a
        // magnitude bit, yielding a u32 value greater than i32::MAX.
        let encoded = snmpv3_frames::encode_get_bulk_request(
            b"\x80\x00\x1f\x88\x04test",
            b"",
            5,
            42,
            0,
            i32::MAX as u32 + 1,
            &[1, 3, 6, 1, 2, 1, 1, 1, 0],
        );
        let result = decode_v3_message(&encoded).expect("message must decode");
        match result.pdu {
            InboundPdu::GetBulkRequest(bulk) => {
                assert_eq!(
                    bulk.max_repetitions, 0,
                    "out-of-range max_repetitions must be clamped to 0"
                );
            }
            other => panic!("expected GetBulkRequest, got {other:?}"),
        }
    }

    #[test]
    fn given_getbulk_with_max_repetitions_at_boundary_when_decode_then_passes_through() {
        // Verifies: REQ-0028
        // i32::MAX (2147483647) is the maximum valid value per RFC 3416 §4.2.3
        // and must pass through unclamped.
        let encoded = snmpv3_frames::encode_get_bulk_request(
            b"\x80\x00\x1f\x88\x04test",
            b"",
            5,
            42,
            0,
            i32::MAX as u32,
            &[1, 3, 6, 1, 2, 1, 1, 1, 0],
        );
        let result = decode_v3_message(&encoded).expect("message must decode");
        match result.pdu {
            InboundPdu::GetBulkRequest(bulk) => {
                assert_eq!(
                    bulk.max_repetitions,
                    i32::MAX as u32,
                    "max_repetitions at i32::MAX must not be clamped"
                );
            }
            other => panic!("expected GetBulkRequest, got {other:?}"),
        }
    }

    #[test]
    fn given_getbulk_with_out_of_range_non_repeaters_when_decode_v3_then_treated_as_zero() {
        // Verifies: REQ-0028
        // non_repeaters values outside the SNMP protocol range (0..2147483647
        // per RFC 3416 §4.2.3) must be treated as zero — same clamping as
        // max_repetitions.
        let encoded = snmpv3_frames::encode_get_bulk_request(
            b"\x80\x00\x1f\x88\x04test",
            b"",
            5,
            42,
            i32::MAX as u32 + 1,
            0,
            &[1, 3, 6, 1, 2, 1, 1, 1, 0],
        );
        let result = decode_v3_message(&encoded).expect("message must decode");
        match result.pdu {
            InboundPdu::GetBulkRequest(bulk) => {
                assert_eq!(
                    bulk.non_repeaters, 0,
                    "out-of-range non_repeaters must be clamped to 0"
                );
            }
            other => panic!("expected GetBulkRequest, got {other:?}"),
        }
    }

    #[test]
    fn given_getbulk_with_non_repeaters_at_boundary_when_decode_then_passes_through() {
        // Verifies: REQ-0028
        // non_repeaters at i32::MAX (2147483647) is at the valid boundary and
        // must pass through unclamped.
        let encoded = snmpv3_frames::encode_get_bulk_request(
            b"\x80\x00\x1f\x88\x04test",
            b"",
            5,
            42,
            i32::MAX as u32,
            0,
            &[1, 3, 6, 1, 2, 1, 1, 1, 0],
        );
        let result = decode_v3_message(&encoded).expect("message must decode");
        match result.pdu {
            InboundPdu::GetBulkRequest(bulk) => {
                assert_eq!(
                    bulk.non_repeaters,
                    i32::MAX as u32,
                    "non_repeaters at i32::MAX must not be clamped"
                );
            }
            other => panic!("expected GetBulkRequest, got {other:?}"),
        }
    }

    #[test]
    fn given_v3_request_when_encode_then_decode_round_trip_succeeds() {
        // Verifies: REQ-0068, REQ-0069, REQ-0070
        // Encode a v3 GetRequest, decode it, check all fields survive.
        let engine_id = b"\x80\x00\x1f\x88\x04roundtrip";
        let oid: Oid = "1.3.6.1.2.1.1.5.0".parse().unwrap();
        let encoded =
            snmpv3_frames::encode_get_request(engine_id, b"ctx", 100, 200, oid.as_slice());

        let msg = decode_v3_message(&encoded).unwrap();

        assert_eq!(msg.msg_id, 100);
        assert_eq!(msg.engine_id, engine_id);
        assert_eq!(msg.context_name, b"ctx");
        match &msg.pdu {
            InboundPdu::GetRequest(req) => {
                assert_eq!(req.request_id, 200);
                assert_eq!(req.varbinds.len(), 1);
                assert_eq!(req.varbinds[0].oid, oid);
            }
            other => panic!("expected GetRequest, got {other:?}"),
        }
    }

    #[test]
    fn given_normal_request_when_decode_v3_then_auth_engine_id_matches_engine_id() {
        // Verifies: REQ-0093, REQ-0098, REQ-0099
        // The snmpv3_frames helper sets authoritative_engine_id = engine_id for normal requests.
        let engine_id = b"\x80\x00\x1f\x88\x04test";
        let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        let encoded = snmpv3_frames::encode_get_request(engine_id, b"", 42, 7, oid.as_slice());

        let msg = decode_v3_message(&encoded).unwrap();

        assert_eq!(msg.usm.auth_engine_id, engine_id);
        assert_eq!(msg.usm.auth_engine_boots, 0);
        assert_eq!(msg.usm.auth_engine_time, 0);
        assert_eq!(msg.usm.security_flags, 0x04); // reportableFlag set by encode_get_request
        assert!(
            msg.usm.auth_params.is_empty(),
            "noAuthNoPriv messages must have empty auth_params"
        );
    }

    #[test]
    fn given_v3_message_with_auth_params_when_decode_then_auth_params_preserved() {
        // Verifies: REQ-0100 — auth params are preserved for HMAC verification
        use rasn_snmp::v2::{
            GetRequest as RasnGetRequest2, Pdu, Pdus as V2Pdus, VarBind, VarBindValue,
        };
        use rasn_snmp::v3::{HeaderData, ScopedPdu, ScopedPduData as V3ScopedPduData};
        use std::borrow::Cow;

        let engine_id = b"\x80\x00\x1f\x88\x04test";
        let expected_auth_params: Vec<u8> = vec![0xABu8; 24]; // 24 bytes as for SHA-256

        let rasn_oid = rasn::types::ObjectIdentifier::new_unchecked(Cow::Owned(vec![
            1, 3, 6, 1, 2, 1, 1, 1, 0,
        ]));
        let get_request = RasnGetRequest2(Pdu {
            request_id: 1,
            error_status: 0,
            error_index: 0,
            variable_bindings: vec![VarBind {
                name: rasn_oid,
                value: VarBindValue::Unspecified,
            }],
        });
        let usm_params = USMSecurityParameters {
            authoritative_engine_id: engine_id.to_vec().into(),
            authoritative_engine_boots: 1.into(),
            authoritative_engine_time: 0.into(),
            user_name: rasn::types::OctetString::from(b"alice".to_vec()),
            authentication_parameters: rasn::types::OctetString::from(expected_auth_params.clone()),
            privacy_parameters: rasn::types::OctetString::from(vec![]),
        };
        let security_params = rasn::ber::encode(&usm_params).unwrap();
        let scoped_pdu = ScopedPdu {
            engine_id: engine_id.to_vec().into(),
            name: vec![].into(),
            data: V2Pdus::GetRequest(get_request),
        };
        let v3_msg = V3Message {
            version: 3.into(),
            global_data: HeaderData {
                message_id: 42.into(),
                max_size: 65535.into(),
                flags: rasn::types::OctetString::from(vec![0x05u8]), // authNoPriv + reportable
                security_model: 3.into(),
            },
            security_parameters: security_params.into(),
            scoped_data: V3ScopedPduData::CleartextPdu(scoped_pdu),
        };
        let encoded = rasn::ber::encode(&v3_msg).unwrap();

        let msg = decode_v3_message(&encoded).unwrap();

        assert_eq!(
            msg.usm.auth_params, expected_auth_params,
            "auth_params must be preserved from msgAuthenticationParameters"
        );
        assert_eq!(
            msg.raw_message,
            encoded.as_slice(),
            "raw_message must be the input bytes slice"
        );
    }

    #[test]
    fn given_v3_message_when_decode_then_raw_message_matches_input_bytes() {
        // Verifies: REQ-0100 — raw_message is preserved for HMAC verification
        let engine_id = b"\x80\x00\x1f\x88\x04test";
        let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        let encoded = snmpv3_frames::encode_get_request(engine_id, b"", 1, 2, oid.as_slice());

        let msg = decode_v3_message(&encoded).unwrap();

        assert_eq!(
            msg.raw_message, encoded,
            "raw_message must reference the input bytes"
        );
    }

    #[test]
    fn given_v3_message_with_auth_params_when_decode_then_offset_points_to_auth_params() {
        // Verifies: REQ-0100 — auth_params_offset enables secure HMAC zeroing in dispatch
        use rasn_snmp::v2::{
            GetRequest as RasnGetRequest2, Pdu, Pdus as V2Pdus, VarBind, VarBindValue,
        };
        use rasn_snmp::v3::{HeaderData, ScopedPdu, ScopedPduData as V3ScopedPduData};
        use std::borrow::Cow;

        let engine_id = b"\x80\x00\x1f\x88\x04test";
        let expected_auth_params: Vec<u8> = vec![0xABu8; 24];

        let rasn_oid = rasn::types::ObjectIdentifier::new_unchecked(Cow::Owned(vec![
            1, 3, 6, 1, 2, 1, 1, 1, 0,
        ]));
        let get_request = RasnGetRequest2(Pdu {
            request_id: 1,
            error_status: 0,
            error_index: 0,
            variable_bindings: vec![VarBind {
                name: rasn_oid,
                value: VarBindValue::Unspecified,
            }],
        });
        let usm_params = USMSecurityParameters {
            authoritative_engine_id: engine_id.to_vec().into(),
            authoritative_engine_boots: 1.into(),
            authoritative_engine_time: 0.into(),
            user_name: rasn::types::OctetString::from(b"alice".to_vec()),
            authentication_parameters: rasn::types::OctetString::from(expected_auth_params.clone()),
            privacy_parameters: rasn::types::OctetString::from(vec![]),
        };
        let security_params = rasn::ber::encode(&usm_params).unwrap();
        let scoped_pdu = ScopedPdu {
            engine_id: engine_id.to_vec().into(),
            name: vec![].into(),
            data: V2Pdus::GetRequest(get_request),
        };
        let v3_msg = V3Message {
            version: 3.into(),
            global_data: HeaderData {
                message_id: 42.into(),
                max_size: 65535.into(),
                flags: rasn::types::OctetString::from(vec![0x05u8]),
                security_model: 3.into(),
            },
            security_parameters: security_params.into(),
            scoped_data: V3ScopedPduData::CleartextPdu(scoped_pdu),
        };
        let encoded = rasn::ber::encode(&v3_msg).unwrap();

        let msg = decode_v3_message(&encoded).unwrap();

        let offset = msg
            .auth_params_offset
            .expect("authenticated message must have an auth_params_offset");
        assert_eq!(
            &msg.raw_message[offset..offset + expected_auth_params.len()],
            expected_auth_params.as_slice(),
            "raw_message at auth_params_offset must contain the auth_params bytes"
        );
    }

    #[test]
    fn given_noauthnopri_v3_message_when_decode_then_auth_params_offset_is_none() {
        // Verifies: REQ-0100 — noAuthNoPriv messages have no auth_params offset
        let engine_id = b"\x80\x00\x1f\x88\x04test";
        let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        let encoded = snmpv3_frames::encode_get_request(engine_id, b"", 1, 2, oid.as_slice());

        let msg = decode_v3_message(&encoded).unwrap();

        assert!(
            msg.auth_params_offset.is_none(),
            "noAuthNoPriv messages must have auth_params_offset = None"
        );
    }
}
