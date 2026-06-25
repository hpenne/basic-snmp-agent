use super::types::{
    DecodeError, DecodeErrorKind, DecodedScopedPdu, GetBulkRequest, GetNextRequest, GetRequest,
    InboundPdu, MessageId, RequestId, SecurityModel, SetRequest, UsmSecurityFields,
    V3InboundMessage, V3ScopedData, Varbind,
};
use crate::codec::ber;
use crate::codec::ber::{TAG_GET_NEXT_REQUEST, TAG_GET_REQUEST, TAG_SET_REQUEST};
use crate::usm::security_params::{AuthenticationParams, PrivacySalt};

// Implements: REQ-0021, REQ-0068
// Converts a [`ber::pdu::DecodedPdu`] into an [`InboundPdu`].
//
// Shared between `decode_pdu`, `decode_v3_message`, and `decode_scoped_pdu`
// to avoid duplicating the match arms for the four inbound PDU types.
fn decoded_pdu_to_inbound(decoded: ber::pdu::DecodedPdu) -> Result<InboundPdu, DecodeError> {
    match decoded {
        ber::pdu::DecodedPdu::Standard {
            tag: TAG_GET_REQUEST,
            request_id,
            raw_varbind_list,
        } => {
            let varbinds = decode_varbind_list_to_varbinds(&raw_varbind_list)?;
            Ok(InboundPdu::GetRequest(GetRequest {
                request_id: RequestId::from(request_id),
                varbinds,
            }))
        }
        ber::pdu::DecodedPdu::Standard {
            tag: TAG_GET_NEXT_REQUEST,
            request_id,
            raw_varbind_list,
        } => {
            let varbinds = decode_varbind_list_to_varbinds(&raw_varbind_list)?;
            Ok(InboundPdu::GetNextRequest(GetNextRequest {
                request_id: RequestId::from(request_id),
                varbinds,
            }))
        }
        ber::pdu::DecodedPdu::Standard {
            tag: TAG_SET_REQUEST,
            request_id,
            raw_varbind_list,
        } => {
            let varbinds = decode_varbind_list_to_varbinds(&raw_varbind_list)?;
            Ok(InboundPdu::SetRequest(SetRequest {
                request_id: RequestId::from(request_id),
                varbinds,
            }))
        }
        ber::pdu::DecodedPdu::Standard { tag, .. } => Err(DecodeError::new(
            DecodeErrorKind::UnsupportedPduType,
            format!("unexpected outbound PDU type: tag 0x{tag:02X}"),
        )),
        ber::pdu::DecodedPdu::Bulk {
            request_id,
            non_repeaters,
            max_repetitions,
            raw_varbind_list,
        } => {
            // RFC 3416 §4.2.3 (REQ-0028): negative wire values are clamped to 0.
            // The BER integer is i32; u32::try_from fails for negative values, which
            // we treat as 0 per the RFC.
            let non_repeaters_u32 = u32::try_from(non_repeaters).unwrap_or(0);
            let max_repetitions_u32 = u32::try_from(max_repetitions).unwrap_or(0);
            let varbinds = decode_varbind_list_to_varbinds(&raw_varbind_list)?;
            Ok(InboundPdu::GetBulkRequest(GetBulkRequest {
                request_id: RequestId::from(request_id),
                non_repeaters: non_repeaters_u32,
                max_repetitions: max_repetitions_u32,
                varbinds,
            }))
        }
    }
}

// Decodes a raw `VarBindList` SEQUENCE into a `Vec<Varbind>`.
// Implements: REQ-0021
fn decode_varbind_list_to_varbinds(raw_varbind_list: &[u8]) -> Result<Vec<Varbind>, DecodeError> {
    let decoded_varbinds = ber::varbind::decode_varbind_list(raw_varbind_list).map_err(|e| {
        DecodeError::new(DecodeErrorKind::Ber, format!("VarBind decode failed: {e}"))
    })?;
    decoded_varbinds
        .into_iter()
        .map(|decoded| {
            let value =
                ber::varbind::decode_varbind_value_to_value(&decoded.value).map_err(|e| {
                    DecodeError::new(
                        DecodeErrorKind::Ber,
                        format!("VarBind value decode failed: {e}"),
                    )
                })?;
            Ok(Varbind {
                oid: decoded.name,
                value,
            })
        })
        .collect()
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
    let decoded = ber::pdu::decode_pdu(bytes)
        .map_err(|e| DecodeError::new(DecodeErrorKind::Ber, format!("BER decode failed: {e}")))?;
    decoded_pdu_to_inbound(decoded)
}

/// BER-decode an inbound `SNMPv3` message into a [`V3InboundMessage`].
///
/// Accepts both cleartext (noAuthNoPriv and authNoPriv) and encrypted (authPriv)
/// `SNMPv3` messages. Encrypted PDUs are preserved as raw ciphertext in
/// [`V3ScopedData::Encrypted`]; decryption is performed by the dispatch layer before PDU processing.
///
/// The inner `Pdus` variant for cleartext messages must be an inbound request type;
/// response and trap PDUs are rejected.
///
/// The `raw_message` field of the returned struct is a reference to the input
/// `bytes` slice, so the returned value borrows from `bytes`.
///
/// # Errors
///
/// Returns a [`DecodeError`] if:
/// - The bytes are not valid BER.
/// - The message version is not 3 ([`DecodeErrorKind::WrongVersion`]).
/// - The inner PDU type is not a recognised inbound type.
/// - An OID or value in a varbind cannot be decoded.
///
/// # Requirements
/// Implements: REQ-0068, REQ-0069, REQ-0071, REQ-0073, REQ-0100, REQ-0101
///
/// # Examples
///
/// ```no_run
/// use basic_snmp_agent::codec::{decode_v3_message, V3ScopedData};
///
/// let bytes: &[u8] = &[/* raw BER SNMPv3 message bytes */];
/// match decode_v3_message(bytes) {
///     Ok(msg) => match msg.scoped_data {
///         V3ScopedData::Plaintext(pdu) => println!("cleartext pdu={pdu:?}"),
///         V3ScopedData::Encrypted(_) => println!("encrypted PDU, needs decryption"),
///     },
///     Err(e) => eprintln!("decode failed: {e}"),
/// }
/// ```
pub fn decode_v3_message(bytes: &[u8]) -> Result<V3InboundMessage<'_>, DecodeError> {
    // Map version-related errors to WrongVersion; all other BER errors to Ber.
    let envelope = ber::snmp::decode_v3_envelope(bytes).map_err(|e| {
        if e.is_wrong_version() {
            DecodeError::new(DecodeErrorKind::WrongVersion, e.to_string())
        } else {
            DecodeError::new(DecodeErrorKind::Ber, format!("BER decode failed: {e}"))
        }
    })?;

    let msg_id = MessageId::from(envelope.msg_id);
    let security_model = SecurityModel::from_wire(envelope.security_model);
    let auth_params_offset = envelope.auth_params_offset;
    // Convert the raw BER wire byte to a MsgFlags newtype at the codec boundary.
    let security_flags = crate::usm::user::MsgFlags::from(envelope.security_flags);

    // Destructure the entire UsmFields struct upfront to avoid a partial-move
    // error: priv_params would be moved into usm_fields while engine_id is also
    // needed in the Encrypted arm, and user_name is needed in the return value.
    let ber::snmp::UsmFields {
        engine_id: usm_engine_id,
        engine_boots,
        engine_time,
        user_name,
        auth_params,
        priv_params,
    } = envelope.usm;

    // Values outside the non-negative i32 range are clamped to u32::MAX; they
    // will fail time-window validation and trigger a Report PDU rather than panicking.
    let auth_engine_boots = u32::try_from(engine_boots).unwrap_or(u32::MAX);
    let auth_engine_time = u32::try_from(engine_time).unwrap_or(u32::MAX);
    let usm_fields = UsmSecurityFields {
        auth_engine_id: usm_engine_id.clone(),
        auth_engine_boots,
        auth_engine_time,
        security_flags,
        auth_params: AuthenticationParams::try_from(auth_params).ok(),
        priv_params: PrivacySalt::try_from(priv_params).ok(),
    };

    let (engine_id, context_name, scoped_data) = match envelope.scoped_data {
        ber::snmp::ScopedData::Plaintext {
            context_engine_id,
            context_name,
            raw_pdu,
        } => {
            let decoded_pdu = ber::pdu::decode_pdu(&raw_pdu).map_err(|e| {
                DecodeError::new(DecodeErrorKind::Ber, format!("BER decode failed: {e}"))
            })?;
            let pdu = decoded_pdu_to_inbound(decoded_pdu)?;
            (
                context_engine_id,
                context_name,
                V3ScopedData::Plaintext(pdu),
            )
        }
        ber::snmp::ScopedData::Encrypted(ciphertext) => {
            // contextEngineID is inside the encrypted blob; use authoritativeEngineID from the
            // USM header as a proxy — they identify the same authoritative engine (RFC 3414 §3.1).
            // context_name is empty; it is extracted after AES decryption in dispatch.
            (usm_engine_id, vec![], V3ScopedData::Encrypted(ciphertext))
        }
    };

    Ok(V3InboundMessage {
        msg_id,
        max_size: envelope.max_size,
        security_model,
        engine_id,
        context_name,
        user_name,
        scoped_data,
        usm: usm_fields,
        raw_message: bytes,
        auth_params_offset,
    })
}

/// BER-decode raw bytes as a `ScopedPdu` and return a [`DecodedScopedPdu`].
///
/// Used by the dispatch layer after AES decryption of authPriv messages.
///
/// # Errors
///
/// Returns a [`DecodeError`] if the bytes are not a valid BER-encoded `ScopedPDU` or
/// the inner PDU type is not a recognised inbound type.
///
/// # Requirements
/// Implements: REQ-0101
pub fn decode_scoped_pdu(bytes: &[u8]) -> Result<DecodedScopedPdu, DecodeError> {
    let scoped = ber::snmp::decode_scoped_pdu(bytes).map_err(|e| {
        DecodeError::new(
            DecodeErrorKind::Ber,
            format!("ScopedPDU decode failed: {e}"),
        )
    })?;
    let decoded = ber::pdu::decode_pdu(&scoped.raw_pdu)
        .map_err(|e| DecodeError::new(DecodeErrorKind::Ber, format!("PDU decode failed: {e}")))?;
    let pdu = decoded_pdu_to_inbound(decoded)?;
    Ok(DecodedScopedPdu {
        context_engine_id: scoped.context_engine_id,
        context_name: scoped.context_name,
        pdu,
    })
}

#[cfg(test)]
pub(super) fn value_from_object_syntax(
    syntax: rasn_smi::v2::ObjectSyntax,
) -> Result<crate::codec::Value, DecodeError> {
    use rasn_smi::v2::{ApplicationSyntax, SimpleSyntax};

    fn oid_from_rasn(
        oid: &rasn::types::ObjectIdentifier,
    ) -> Result<crate::codec::Oid, DecodeError> {
        let components: Vec<u32> = oid.as_ref().to_vec();
        crate::codec::Oid::try_from(components)
            .map_err(|e| DecodeError::new(DecodeErrorKind::InvalidOid, format!("invalid OID: {e}")))
    }

    match syntax {
        rasn_smi::v2::ObjectSyntax::Simple(SimpleSyntax::Integer(raw_integer)) => {
            let integer_value: i32 = raw_integer
                .try_into()
                .map_err(|_| DecodeError::new(DecodeErrorKind::Ber, "Integer32 out of range"))?;
            Ok(crate::codec::Value::Integer32(integer_value))
        }
        rasn_smi::v2::ObjectSyntax::Simple(SimpleSyntax::String(bytes)) => {
            Ok(crate::codec::Value::OctetString(bytes.to_vec()))
        }
        rasn_smi::v2::ObjectSyntax::Simple(SimpleSyntax::ObjectId(oid)) => {
            Ok(crate::codec::Value::ObjectIdentifier(oid_from_rasn(&oid)?))
        }
        rasn_smi::v2::ObjectSyntax::ApplicationWide(ApplicationSyntax::Address(ip)) => {
            Ok(crate::codec::Value::IpAddress(*ip.0))
        }
        rasn_smi::v2::ObjectSyntax::ApplicationWide(ApplicationSyntax::Counter(c)) => {
            Ok(crate::codec::Value::Counter32(c.0))
        }
        rasn_smi::v2::ObjectSyntax::ApplicationWide(ApplicationSyntax::BigCounter(c)) => {
            Ok(crate::codec::Value::Counter64(c.0))
        }
        rasn_smi::v2::ObjectSyntax::ApplicationWide(ApplicationSyntax::Unsigned(u)) => {
            Ok(crate::codec::Value::Gauge32(u.0))
        }
        rasn_smi::v2::ObjectSyntax::ApplicationWide(ApplicationSyntax::Ticks(t)) => {
            Ok(crate::codec::Value::TimeTicks(t.0))
        }
        rasn_smi::v2::ObjectSyntax::ApplicationWide(ApplicationSyntax::Arbitrary(o)) => {
            Ok(crate::codec::Value::Opaque(o.as_ref().to_vec()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::pdu::{DecodeErrorKind, InboundPdu, V3ScopedData, VarbindValue};
    use crate::codec::{Oid, Value};

    #[test]
    fn decode_pdu_get_request() {
        // Verifies: REQ-0021
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
                assert_eq!(req.request_id, RequestId::from(42));
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
        // Verifies: REQ-0021
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

        match pdu {
            InboundPdu::GetNextRequest(req) => {
                assert_eq!(req.request_id, RequestId::from(7));
                assert_eq!(req.varbinds.len(), 1);
                assert_eq!(req.varbinds[0].oid, oid);
                assert_eq!(req.varbinds[0].value, VarbindValue::Unspecified);
            }
            other => panic!("expected GetNextRequest, got {other:?}"),
        }
    }

    #[test]
    fn decode_pdu_get_bulk_request() {
        // Verifies: REQ-0021
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
        // Verifies: REQ-0021
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
                assert_eq!(set.request_id, RequestId::from(55));
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
        // Verifies: REQ-0021
        let decode_result = decode_pdu(&[0xFF, 0xFF, 0xFF]);
        assert!(decode_result.is_err());
        assert_eq!(decode_result.unwrap_err().kind(), &DecodeErrorKind::Ber);
    }

    #[test]
    fn decode_pdu_rejects_outbound_pdu_type() {
        // Verifies: REQ-0021
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

    // ── decode_scoped_pdu tests (REQ-0101) ────────────────────────────────────

    /// Build BER-encoded `ScopedPdu` bytes for use in `decode_scoped_pdu` tests.
    fn encode_scoped_pdu_get_request(
        engine_id: &[u8],
        context_name: &[u8],
        request_id: i32,
        oid_arcs: &[u32],
    ) -> Vec<u8> {
        use rasn_snmp::v2::Pdus;
        use rasn_snmp::v2::{GetRequest as RasnGetRequest2, Pdu, VarBind, VarBindValue};
        use rasn_snmp::v3::ScopedPdu;
        use std::borrow::Cow;

        let rasn_oid = rasn::types::ObjectIdentifier::new_unchecked(Cow::Owned(oid_arcs.to_vec()));
        let get_request = RasnGetRequest2(Pdu {
            request_id,
            error_status: 0,
            error_index: 0,
            variable_bindings: vec![VarBind {
                name: rasn_oid,
                value: VarBindValue::Unspecified,
            }],
        });
        let scoped_pdu = ScopedPdu {
            engine_id: engine_id.to_vec().into(),
            name: context_name.to_vec().into(),
            data: Pdus::GetRequest(get_request),
        };
        rasn::ber::encode(&scoped_pdu).unwrap()
    }

    #[test]
    fn given_valid_scoped_pdu_bytes_when_decode_then_fields_extracted() {
        // Verifies: REQ-0101
        let engine_id = b"\x80\x00\x1f\x88\x04test";
        let context_name = b"";
        let oid_arcs = [1_u32, 3, 6, 1, 2, 1, 1, 1, 0];
        let encoded = encode_scoped_pdu_get_request(engine_id, context_name, 42, &oid_arcs);

        let decoded = decode_scoped_pdu(&encoded).expect("must decode valid ScopedPdu");

        assert_eq!(
            decoded.context_engine_id, engine_id,
            "context_engine_id must match ScopedPdu engine_id"
        );
        assert!(
            decoded.context_name.is_empty(),
            "context_name must be empty"
        );
        match decoded.pdu {
            InboundPdu::GetRequest(req) => {
                assert_eq!(
                    req.request_id,
                    RequestId::from(42),
                    "request_id must be preserved"
                );
                assert_eq!(req.varbinds.len(), 1);
                assert_eq!(req.varbinds[0].oid.as_slice(), &oid_arcs);
            }
            other => panic!("expected GetRequest, got {other:?}"),
        }
    }

    #[test]
    fn given_invalid_ber_bytes_when_decode_scoped_pdu_then_ber_error() {
        // Verifies: REQ-0101
        let decode_result = decode_scoped_pdu(&[0xDE, 0xAD, 0xBE, 0xEF]);

        assert!(decode_result.is_err());
        assert_eq!(
            decode_result.unwrap_err().kind(),
            &DecodeErrorKind::Ber,
            "garbage bytes must yield a Ber error"
        );
    }

    #[test]
    fn given_outbound_pdu_type_when_decode_scoped_pdu_then_unsupported_pdu_type() {
        // Verifies: REQ-0101 — outbound PDU types inside a ScopedPdu are rejected
        use rasn_snmp::v2::{Pdu as RasnPdu, Pdus as V2Pdus, Response};
        use rasn_snmp::v3::ScopedPdu;

        let response_pdu = Response(RasnPdu {
            request_id: 1,
            error_status: 0,
            error_index: 0,
            variable_bindings: vec![],
        });
        let scoped_pdu = ScopedPdu {
            engine_id: vec![].into(),
            name: vec![].into(),
            data: V2Pdus::Response(response_pdu),
        };
        let encoded = rasn::ber::encode(&scoped_pdu).unwrap();

        let decode_result = decode_scoped_pdu(&encoded);

        assert!(decode_result.is_err());
        assert_eq!(
            decode_result.unwrap_err().kind(),
            &DecodeErrorKind::UnsupportedPduType,
            "outbound PDU type must yield UnsupportedPduType error"
        );
    }

    #[test]
    fn given_valid_v3_get_request_when_decode_then_fields_extracted() {
        // Verifies: REQ-0068, REQ-0069, REQ-0070
        let engine_id = b"\x80\x00\x1f\x88\x04test";
        let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        let encoded = snmpv3_frames::encode_get_request(engine_id, b"", 42, 7, oid.as_slice());

        let msg = decode_v3_message(&encoded).unwrap();

        assert_eq!(msg.msg_id, MessageId::from(42));
        assert_eq!(msg.engine_id, engine_id);
        assert_eq!(msg.context_name, b"");
        match &msg.scoped_data {
            V3ScopedData::Plaintext(InboundPdu::GetRequest(req)) => {
                assert_eq!(req.request_id, RequestId::from(7));
            }
            other => panic!("expected Plaintext(GetRequest), got {other:?}"),
        }
    }

    #[test]
    fn given_wrong_version_message_when_decode_v3_then_wrong_version_error() {
        // Verifies: REQ-0073
        // Build a structurally valid V3Message but with version=1 (SNMPv1).
        // The BER codec rejects it with an error message containing "version".
        use rasn_snmp::v2::{GetRequest as RasnGetRequest2, Pdu, Pdus};
        use rasn_snmp::v3::{Message as V3Message, ScopedPduData, USMSecurityParameters};

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
            data: Pdus::GetRequest(RasnGetRequest2(Pdu {
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
                max_size: 0xFFFF.into(),
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
    fn given_encrypted_pdu_when_decode_v3_then_ciphertext_preserved() {
        // Verifies: REQ-0101
        let ciphertext = b"fake-encrypted-payload".to_vec();
        let usm_params = rasn_snmp::v3::USMSecurityParameters {
            authoritative_engine_id: rasn::types::OctetString::from(vec![]),
            authoritative_engine_boots: 0.into(),
            authoritative_engine_time: 0.into(),
            user_name: rasn::types::OctetString::from(vec![]),
            authentication_parameters: rasn::types::OctetString::from(vec![]),
            privacy_parameters: rasn::types::OctetString::from(vec![]),
        };
        let security_params = rasn::ber::encode(&usm_params).unwrap();
        let v3_msg = rasn_snmp::v3::Message {
            version: 3.into(),
            global_data: rasn_snmp::v3::HeaderData {
                message_id: 1.into(),
                max_size: 0xFFFF.into(),
                flags: rasn::types::OctetString::from(vec![0x03]),
                security_model: 3.into(),
            },
            security_parameters: security_params.into(),
            scoped_data: rasn_snmp::v3::ScopedPduData::EncryptedPdu(
                rasn::types::OctetString::from(ciphertext.clone()),
            ),
        };
        let encoded = rasn::ber::encode(&v3_msg).unwrap();

        let decode_result = decode_v3_message(&encoded);

        assert!(
            decode_result.is_ok(),
            "encrypted PDU must decode without error"
        );
        let msg = decode_result.unwrap();
        assert_eq!(
            msg.scoped_data,
            V3ScopedData::Encrypted(ciphertext),
            "ciphertext must be preserved in scoped_data"
        );
        // authoritative_engine_id is empty in this test message, so engine_id must also be empty.
        assert_eq!(
            msg.engine_id,
            Vec::<u8>::new(),
            "engine_id must match auth_engine_id for encrypted messages"
        );
        assert!(
            msg.context_name.is_empty(),
            "context_name must be empty for encrypted messages pending decryption"
        );
    }

    #[test]
    fn given_authpriv_message_when_decode_v3_then_priv_params_preserved() {
        // Verifies: REQ-0101
        let expected_priv_params: Vec<u8> = vec![0xAB_u8; 8];
        let usm_params = rasn_snmp::v3::USMSecurityParameters {
            authoritative_engine_id: rasn::types::OctetString::from(vec![]),
            authoritative_engine_boots: 0.into(),
            authoritative_engine_time: 0.into(),
            user_name: rasn::types::OctetString::from(vec![]),
            authentication_parameters: rasn::types::OctetString::from(vec![]),
            privacy_parameters: rasn::types::OctetString::from(expected_priv_params.clone()),
        };
        let security_params = rasn::ber::encode(&usm_params).unwrap();
        let v3_msg = rasn_snmp::v3::Message {
            version: 3.into(),
            global_data: rasn_snmp::v3::HeaderData {
                message_id: 2.into(),
                max_size: 0xFFFF.into(),
                flags: rasn::types::OctetString::from(vec![0x03]),
                security_model: 3.into(),
            },
            security_parameters: security_params.into(),
            scoped_data: rasn_snmp::v3::ScopedPduData::EncryptedPdu(
                rasn::types::OctetString::from(b"some-ciphertext".to_vec()),
            ),
        };
        let encoded = rasn::ber::encode(&v3_msg).unwrap();

        let msg = decode_v3_message(&encoded).expect("must decode");

        assert_eq!(
            msg.msg_id,
            MessageId::from(2),
            "msg_id must be decoded correctly from the header"
        );
        assert_eq!(
            msg.usm.priv_params.as_ref().map(AsRef::as_ref),
            Some(expected_priv_params.as_slice()),
            "priv_params must be preserved from msgPrivacyParameters"
        );
    }

    #[test]
    fn given_noauthnopriv_message_when_decode_v3_then_priv_params_empty() {
        // Verifies: REQ-0101
        let engine_id = b"\x80\x00\x1f\x88\x04test";
        let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        // encode_get_request produces a noAuthNoPriv cleartext message with empty privacy_parameters.
        let encoded = snmpv3_frames::encode_get_request(engine_id, b"", 1, 2, oid.as_slice());

        let msg = decode_v3_message(&encoded).expect("must decode");

        assert!(
            msg.usm.priv_params.is_none(),
            "noAuthNoPriv messages must have no priv_params (empty on wire)"
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
    fn given_getbulk_with_out_of_range_max_repetitions_when_decode_v3_then_ber_error() {
        // Verifies: REQ-0028
        // max_repetitions values outside the i32 range (i32::MAX+1 = 2147483648)
        // require 5 bytes of BER INTEGER representation, which read_integer() rejects
        // as it cannot fit in i32.
        let encoded = snmpv3_frames::encode_get_bulk_request(
            b"\x80\x00\x1f\x88\x04test",
            b"",
            5,
            42,
            0,
            u32::try_from(i32::MAX).expect("i32::MAX fits in u32") + 1,
            &[1, 3, 6, 1, 2, 1, 1, 1, 0],
        );
        let result = decode_v3_message(&encoded);
        assert!(
            result.is_err(),
            "out-of-range max_repetitions must fail at BER level"
        );
        assert_eq!(result.unwrap_err().kind(), &DecodeErrorKind::Ber);
    }

    #[test]
    fn given_getbulk_with_negative_max_repetitions_when_decode_v3_then_clamped_to_zero() {
        // Verifies: REQ-0028
        // Negative wire values for max_repetitions must be clamped to 0 per RFC 3416 §4.2.3.
        // We encode the PDU directly with our BER codec to pass a negative i32.
        let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        let null_value = ber::varbind::encode_null_value();
        let varbind_bytes = ber::varbind::encode_varbind(&oid, &null_value);
        let varbind_list = ber::varbind::encode_varbind_list(&[&varbind_bytes]);
        let bulk_pdu = ber::pdu::encode_bulk_pdu(42, 0, -1, &varbind_list);
        let scoped_pdu = ber::snmp::encode_scoped_pdu(b"\x80\x00\x1f\x88\x04test", b"", &bulk_pdu);
        let (frame, _) = ber::snmp::encode_v3_message(
            5,
            0xFFFF,
            0x04,
            3,
            b"\x80\x00\x1f\x88\x04test",
            0,
            0,
            b"",
            &[],
            &[],
            &scoped_pdu,
            false,
        )
        .unwrap();

        let result = decode_v3_message(&frame).unwrap();
        match result.scoped_data {
            V3ScopedData::Plaintext(InboundPdu::GetBulkRequest(bulk)) => {
                assert_eq!(
                    bulk.max_repetitions, 0,
                    "negative max_repetitions must be clamped to 0"
                );
            }
            other => panic!("expected Plaintext(GetBulkRequest), got {other:?}"),
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
            u32::try_from(i32::MAX).expect("i32::MAX fits in u32"),
            &[1, 3, 6, 1, 2, 1, 1, 1, 0],
        );
        let result = decode_v3_message(&encoded).expect("message must decode");
        match result.scoped_data {
            V3ScopedData::Plaintext(InboundPdu::GetBulkRequest(bulk)) => {
                assert_eq!(
                    bulk.max_repetitions,
                    u32::try_from(i32::MAX).expect("i32::MAX fits in u32"),
                    "max_repetitions at i32::MAX must not be clamped"
                );
            }
            other => panic!("expected Plaintext(GetBulkRequest), got {other:?}"),
        }
    }

    #[test]
    fn given_getbulk_with_out_of_range_non_repeaters_when_decode_v3_then_ber_error() {
        // Verifies: REQ-0028
        // non_repeaters values outside the i32 range fail at the BER parse level.
        let encoded = snmpv3_frames::encode_get_bulk_request(
            b"\x80\x00\x1f\x88\x04test",
            b"",
            5,
            42,
            u32::try_from(i32::MAX).expect("i32::MAX fits in u32") + 1,
            0,
            &[1, 3, 6, 1, 2, 1, 1, 1, 0],
        );
        let result = decode_v3_message(&encoded);
        assert!(
            result.is_err(),
            "out-of-range non_repeaters must fail at BER level"
        );
        assert_eq!(result.unwrap_err().kind(), &DecodeErrorKind::Ber);
    }

    #[test]
    fn given_getbulk_with_negative_non_repeaters_when_decode_v3_then_clamped_to_zero() {
        // Verifies: REQ-0028
        // Negative wire values for non_repeaters must be clamped to 0 per RFC 3416 §4.2.3.
        let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        let null_value = ber::varbind::encode_null_value();
        let varbind_bytes = ber::varbind::encode_varbind(&oid, &null_value);
        let varbind_list = ber::varbind::encode_varbind_list(&[&varbind_bytes]);
        let bulk_pdu = ber::pdu::encode_bulk_pdu(42, -1, 10, &varbind_list);
        let scoped_pdu = ber::snmp::encode_scoped_pdu(b"\x80\x00\x1f\x88\x04test", b"", &bulk_pdu);
        let (frame, _) = ber::snmp::encode_v3_message(
            5,
            0xFFFF,
            0x04,
            3,
            b"\x80\x00\x1f\x88\x04test",
            0,
            0,
            b"",
            &[],
            &[],
            &scoped_pdu,
            false,
        )
        .unwrap();

        let result = decode_v3_message(&frame).unwrap();
        match result.scoped_data {
            V3ScopedData::Plaintext(InboundPdu::GetBulkRequest(bulk)) => {
                assert_eq!(
                    bulk.non_repeaters, 0,
                    "negative non_repeaters must be clamped to 0"
                );
            }
            other => panic!("expected Plaintext(GetBulkRequest), got {other:?}"),
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
            u32::try_from(i32::MAX).expect("i32::MAX fits in u32"),
            0,
            &[1, 3, 6, 1, 2, 1, 1, 1, 0],
        );
        let result = decode_v3_message(&encoded).expect("message must decode");
        match result.scoped_data {
            V3ScopedData::Plaintext(InboundPdu::GetBulkRequest(bulk)) => {
                assert_eq!(
                    bulk.non_repeaters,
                    u32::try_from(i32::MAX).expect("i32::MAX fits in u32"),
                    "non_repeaters at i32::MAX must not be clamped"
                );
            }
            other => panic!("expected Plaintext(GetBulkRequest), got {other:?}"),
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

        assert_eq!(msg.msg_id, MessageId::from(100));
        assert_eq!(msg.engine_id, engine_id);
        assert_eq!(msg.context_name, b"ctx");
        match &msg.scoped_data {
            V3ScopedData::Plaintext(InboundPdu::GetRequest(req)) => {
                assert_eq!(req.request_id, RequestId::from(200));
                assert_eq!(req.varbinds.len(), 1);
                assert_eq!(req.varbinds[0].oid, oid);
            }
            other => panic!("expected Plaintext(GetRequest), got {other:?}"),
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
        assert_eq!(
            msg.usm.security_flags,
            crate::usm::user::MsgFlags::from(0x04_u8)
        ); // reportableFlag set by encode_get_request
        assert!(
            msg.usm.auth_params.is_none(),
            "noAuthNoPriv messages must have no auth_params (empty on wire)"
        );
    }

    #[test]
    fn given_v3_message_with_auth_params_when_decode_then_auth_params_preserved() {
        // Verifies: REQ-0100 — auth params are preserved for HMAC verification
        use rasn_snmp::v2::{
            GetRequest as RasnGetRequest2, Pdu, Pdus as V2Pdus, VarBind, VarBindValue,
        };
        use rasn_snmp::v3::{
            HeaderData, ScopedPdu, ScopedPduData as V3ScopedPduData, USMSecurityParameters,
        };
        use std::borrow::Cow;

        let engine_id = b"\x80\x00\x1f\x88\x04test";
        let expected_auth_params: Vec<u8> = vec![0xAB_u8; 24]; // 24 bytes as for SHA-256

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
        let v3_msg = rasn_snmp::v3::Message {
            version: 3.into(),
            global_data: HeaderData {
                message_id: 42.into(),
                max_size: 0xFFFF.into(),
                flags: rasn::types::OctetString::from(vec![0x05_u8]), // authNoPriv + reportable
                security_model: 3.into(),
            },
            security_parameters: security_params.into(),
            scoped_data: V3ScopedPduData::CleartextPdu(scoped_pdu),
        };
        let encoded = rasn::ber::encode(&v3_msg).unwrap();

        let msg = decode_v3_message(&encoded).unwrap();

        assert_eq!(
            msg.usm.auth_params.as_ref().map(AsRef::as_ref),
            Some(expected_auth_params.as_slice()),
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
        use rasn_snmp::v3::{
            HeaderData, ScopedPdu, ScopedPduData as V3ScopedPduData, USMSecurityParameters,
        };
        use std::borrow::Cow;

        let engine_id = b"\x80\x00\x1f\x88\x04test";
        let expected_auth_params: Vec<u8> = vec![0xAB_u8; 24];

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
        let v3_msg = rasn_snmp::v3::Message {
            version: 3.into(),
            global_data: HeaderData {
                message_id: 42.into(),
                max_size: 0xFFFF.into(),
                flags: rasn::types::OctetString::from(vec![0x05_u8]),
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

    #[test]
    fn given_constructed_security_params_octet_string_when_decode_v3_then_ber_error() {
        // Verifies: REQ-0100
        // BER permits constructed encoding for OCTET STRING fields. When the
        // security_parameters OCTET STRING uses constructed form, the new BER
        // codec's read_octet_string() rejects it at the BER parse level.
        use rasn_snmp::v2::{
            GetRequest as RasnGetRequest2, Pdu, Pdus as V2Pdus, VarBind, VarBindValue,
        };
        use rasn_snmp::v3::{
            HeaderData, ScopedPdu, ScopedPduData as V3ScopedPduData, USMSecurityParameters,
        };
        use std::borrow::Cow;

        let engine_id = b"\x80\x00\x1f\x88\x04";
        let auth_params: Vec<u8> = vec![0xab; 12];
        let usm_params = USMSecurityParameters {
            authoritative_engine_id: engine_id.to_vec().into(),
            authoritative_engine_boots: 0.into(),
            authoritative_engine_time: 0.into(),
            user_name: rasn::types::OctetString::from(b"alice".to_vec()),
            authentication_parameters: rasn::types::OctetString::from(auth_params),
            privacy_parameters: rasn::types::OctetString::from(vec![]),
        };
        let usm_bytes = rasn::ber::encode(&usm_params).unwrap();
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
        let scoped_pdu = ScopedPdu {
            engine_id: engine_id.to_vec().into(),
            name: vec![].into(),
            data: V2Pdus::GetRequest(get_request),
        };
        let v3_msg = rasn_snmp::v3::Message {
            version: 3.into(),
            global_data: HeaderData {
                message_id: 1.into(),
                max_size: 0xFFFF.into(),
                flags: rasn::types::OctetString::from(vec![0x05_u8]),
                security_model: 3.into(),
            },
            security_parameters: usm_bytes.clone().into(),
            scoped_data: V3ScopedPduData::CleartextPdu(scoped_pdu),
        };
        let valid_encoded = rasn::ber::encode(&v3_msg).unwrap();
        assert!(
            decode_v3_message(&valid_encoded).is_ok(),
            "original message with primitive security_params must decode successfully"
        );

        let tampered = make_security_params_constructed_form(&valid_encoded, &usm_bytes);

        let result = decode_v3_message(&tampered);

        assert!(
            result.is_err(),
            "constructed security_params OCTET STRING must yield an error"
        );
        assert_eq!(
            result.unwrap_err().kind(),
            &DecodeErrorKind::Ber,
            "constructed security_params OCTET STRING must yield a Ber error"
        );
    }

    #[test]
    fn given_constructed_auth_params_in_usm_when_decode_v3_then_ber_error() {
        // Verifies: REQ-0100
        // When the authentication_parameters OCTET STRING within the USM uses BER
        // constructed encoding, the new BER codec's read_octet_string() rejects it
        // at the BER parse level (constructed OCTET STRINGs are not permitted).
        use rasn_snmp::v2::{
            GetRequest as RasnGetRequest2, Pdu, Pdus as V2Pdus, VarBind, VarBindValue,
        };
        use rasn_snmp::v3::{HeaderData, ScopedPdu, ScopedPduData as V3ScopedPduData};
        use std::borrow::Cow;

        let engine_id = b"\x80\x00\x1f\x88\x04";

        // Hand-crafted USM bytes: authentication_parameters (tag 0x24) uses constructed
        // encoding split into two 6-byte chunks. The new BER codec rejects tag 0x24
        // because read_octet_string() expects tag 0x04 (primitive OCTET STRING).
        let usm_with_constructed_auth_params: Vec<u8> = vec![
            0x30, 0x28, // SEQUENCE, length=40
            0x04, 0x05, 0x80, 0x00, 0x1f, 0x88, 0x04, // engine_id (5 bytes)
            0x02, 0x01, 0x00, // boots=0
            0x02, 0x01, 0x00, // time=0
            0x04, 0x05, 0x61, 0x6c, 0x69, 0x63, 0x65, // user_name="alice"
            0x24, 0x10, // constructed OCTET STRING, length=16
            0x04, 0x06, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, // chunk 1: 6 bytes
            0x04, 0x06, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, // chunk 2: 6 bytes
            0x04, 0x00, // priv_params (empty)
        ];

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
        let scoped_pdu = ScopedPdu {
            engine_id: engine_id.to_vec().into(),
            name: vec![].into(),
            data: V2Pdus::GetRequest(get_request),
        };
        let v3_msg = rasn_snmp::v3::Message {
            version: 3.into(),
            global_data: HeaderData {
                message_id: 1.into(),
                max_size: 0xFFFF.into(),
                flags: rasn::types::OctetString::from(vec![0x05_u8]),
                security_model: 3.into(),
            },
            security_parameters: usm_with_constructed_auth_params.into(),
            scoped_data: V3ScopedPduData::CleartextPdu(scoped_pdu),
        };
        let encoded = rasn::ber::encode(&v3_msg).unwrap();

        let result = decode_v3_message(&encoded);

        assert!(
            result.is_err(),
            "constructed auth_params OCTET STRING in USM must yield an error"
        );
        assert_eq!(
            result.unwrap_err().kind(),
            &DecodeErrorKind::Ber,
            "constructed auth_params OCTET STRING must yield a Ber error"
        );
    }

    // Converts the security_parameters primitive OCTET STRING in an encoded V3 message
    // to BER constructed form by splitting the USM content into two equal chunks.
    // Constructed-form OCTET STRINGs are valid in BER but not DER; the new hand-written
    // BER codec rejects them immediately at the read_octet_string() level.
    //
    // Preconditions: the USM bytes appear exactly once as a contiguous substring of
    // encoded; the preceding TLV uses 1-byte length encoding; the outer SEQUENCE length
    // fits in one byte and does not exceed 251 (so adding 4 remains within u8 range).
    fn make_security_params_constructed_form(encoded: &[u8], usm_bytes: &[u8]) -> Vec<u8> {
        let usm_start = encoded
            .windows(usm_bytes.len())
            .position(|w| w == usm_bytes)
            .expect("usm_bytes must appear as a contiguous substring of encoded");
        assert_eq!(
            encoded[usm_start - 2],
            0x04,
            "expected OCTET STRING tag (0x04) two bytes before usm_bytes"
        );
        assert_eq!(
            encoded[usm_start - 1],
            u8::try_from(usm_bytes.len()).expect("usm_bytes.len() fits in u8"),
            "expected 1-byte length before usm_bytes"
        );
        let sp_start = usm_start - 2;
        let sp_end = usm_start + usm_bytes.len();

        let mid = usm_bytes.len() / 2;
        let rest = usm_bytes.len() - mid;
        // inner_len: two primitive TLV headers at 2 bytes each, plus their payloads.
        let inner_len = 4 + usm_bytes.len();
        let mut constructed: Vec<u8> = Vec::with_capacity(6 + usm_bytes.len());
        constructed.push(0x24); // constructed OCTET STRING tag (0x04 | 0x20)
        constructed.push(
            u8::try_from(inner_len).expect("inner_len fits in u8 for test-sized USM parameters"),
        );
        constructed.push(0x04);
        constructed.push(u8::try_from(mid).expect("mid fits in u8"));
        constructed.extend_from_slice(&usm_bytes[..mid]);
        constructed.push(0x04);
        constructed.push(u8::try_from(rest).expect("rest fits in u8"));
        constructed.extend_from_slice(&usm_bytes[mid..]);

        // The constructed TLV is 4 bytes larger than the original primitive TLV:
        // two additional inner TLV headers at 2 bytes each.
        let new_outer_len = encoded[1]
            .checked_add(4)
            .expect("outer SEQUENCE length + 4 does not overflow u8");

        let mut modified = Vec::with_capacity(encoded.len() + 4);
        modified.push(encoded[0]); // outer SEQUENCE tag (0x30)
        modified.push(new_outer_len);
        modified.extend_from_slice(&encoded[2..sp_start]);
        modified.extend_from_slice(&constructed);
        modified.extend_from_slice(&encoded[sp_end..]);
        modified
    }
}
