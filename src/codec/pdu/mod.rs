//! SNMP PDU types and BER encode/decode for SNMPv2/v3 agents (RFC 3416).
//!
//! This module provides:
//!
//! - Clean public PDU types decoupled from the `rasn`/`rasn-snmp` wire types.
//! - [`decode_pdu`]: BER-decode inbound SNMP PDU bytes into an [`InboundPdu`].
//! - [`decode_v3_message`]: BER-decode an inbound `SNMPv3` message into a [`V3InboundMessage`].
//! - [`encode_response`]: BER-encode a [`GetResponse`] for sending.
//! - [`encode_v3_response`]: BER-encode a [`GetResponse`] inside an `SNMPv3` message envelope.
//! - [`encode_v3_report`]: BER-encode an `SNMPv3` Report PDU for engine-ID discovery.
//! - [`encode_trap`]: BER-encode a [`WireTrapPdu`] for sending.

mod decode;
mod encode;
mod types;

pub use decode::{decode_pdu, decode_v3_message};
pub use encode::{encode_response, encode_trap, encode_v3_report, encode_v3_response};
pub use types::{
    DecodeError, DecodeErrorKind, EncodeError, ErrorStatus, GetBulkRequest, GetNextRequest,
    GetRequest, GetResponse, InboundPdu, SetRequest, UsmSecurityFields, V3InboundMessage,
    V3ScopedData, Varbind, VarbindValue, WireTrapPdu,
};

// Cross-module round-trip tests that exercise both encode and decode.
#[cfg(test)]
mod tests {
    use super::decode::value_from_object_syntax;
    use super::*;
    use crate::codec::{Oid, Value};
    use rasn_snmp::v2::{Pdus, Response, VarBindValue as RasnVarBindValue};

    #[test]
    fn encode_decode_empty_varbinds() {
        use rasn_snmp::v2::{GetRequest as RasnGetRequest, Pdu};

        let pdu = GetResponse {
            request_id: 100,
            error_status: ErrorStatus::NoError,
            error_index: 0,
            varbinds: vec![],
        };
        let encoded_response = encode_response(&pdu).unwrap();
        assert!(
            !encoded_response.is_empty(),
            "encoded bytes must not be empty even with no varbinds"
        );

        let decoded: Pdus = rasn::ber::decode(&encoded_response).expect("must decode");
        match decoded {
            Pdus::Response(Response(inner)) => {
                assert_eq!(inner.variable_bindings.len(), 0);
            }
            other => panic!("expected Response, got {other:?}"),
        }

        let get_req = RasnGetRequest(Pdu {
            request_id: 200,
            error_status: 0,
            error_index: 0,
            variable_bindings: vec![],
        });
        let raw_ber = rasn::ber::encode(&get_req).unwrap();
        let decode_result = decode_pdu(&raw_ber).unwrap();
        match decode_result {
            InboundPdu::GetRequest(req) => {
                assert_eq!(req.request_id, 200);
                assert_eq!(req.varbinds.len(), 0);
            }
            other => panic!("expected GetRequest, got {other:?}"),
        }
    }

    #[test]
    fn all_value_types_survive_response_encode_decode() {
        let oid_base = "1.3.6.1.2.1.1";
        let values = vec![
            Value::Integer32(-42),
            Value::OctetString(b"test".to_vec()),
            Value::Counter32(1_000_000),
            Value::Counter64(u64::MAX / 2),
            Value::Gauge32(500),
            Value::TimeTicks(99_999),
            Value::IpAddress([192, 168, 0, 1]),
            Value::Opaque(vec![0xAB, 0xCD]),
            Value::ObjectIdentifier("1.3.6.1.2.1.1.1.0".parse().unwrap()),
        ];
        for (i, value) in values.into_iter().enumerate() {
            let oid: Oid = format!("{oid_base}.{i}.0").parse().unwrap();
            let pdu = GetResponse {
                request_id: i32::try_from(i).expect("loop index fits i32"),
                error_status: ErrorStatus::NoError,
                error_index: 0,
                varbinds: vec![Varbind {
                    oid: oid.clone(),
                    value: VarbindValue::Value(value.clone()),
                }],
            };
            let encoded_response = encode_response(&pdu).unwrap();
            let decoded: Pdus = rasn::ber::decode(&encoded_response).expect("must decode");
            match decoded {
                Pdus::Response(Response(inner)) => {
                    let vb = &inner.variable_bindings[0];
                    assert_eq!(vb.name.as_ref(), oid.as_slice());
                    if let RasnVarBindValue::Value(syntax) = vb.value.clone() {
                        let recovered =
                            value_from_object_syntax(syntax).expect("should convert back");
                        assert_eq!(recovered, value, "round-trip failed for {value:?}");
                    } else {
                        panic!("expected Value variant in VarBindValue");
                    }
                }
                other => panic!("expected Response, got {other:?}"),
            }
        }
    }
}
