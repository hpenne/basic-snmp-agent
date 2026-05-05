//! BER encode/decode for SNMP PDU structures (RFC 3416 §3).
//!
//! This module handles the PDU structure layer. It encodes and decodes the
//! context-tagged PDU TLVs that sit inside the `ScopedPdu`. `VarBind` parsing
//! is a separate concern — this layer returns the `VarBindList` as raw bytes.

use super::{
    BerError, BerReader, BerWriter, TAG_GET_BULK_REQUEST, TAG_GET_NEXT_REQUEST, TAG_GET_REQUEST,
    TAG_INFORM_REQUEST, TAG_REPORT, TAG_RESPONSE, TAG_SET_REQUEST, TAG_TRAP,
};

// ── Decoded PDU ───────────────────────────────────────────────────────────────

/// Decoded PDU content. `VarBindList` is left as raw bytes for later parsing.
///
/// # Requirements
/// Implements: REQ-0000
#[derive(Debug)]
pub(crate) enum DecodedPdu {
    /// Standard PDU (`GetRequest`, `GetNextRequest`, `Response`, `SetRequest`,
    /// `InformRequest`, Trap, Report).
    Standard {
        /// The context tag identifying the PDU type (0xA0–0xA8, excluding 0xA5).
        tag: u8,
        /// PDU request identifier.
        request_id: i32,
        /// Error status (0 = `noError`).
        error_status: i32,
        /// 1-based index of the first errored varbind, or 0.
        error_index: i32,
        /// Raw `SEQUENCE OF VarBind` bytes (the full SEQUENCE TLV).
        raw_varbind_list: Vec<u8>,
    },
    /// `GetBulkRequest` PDU (tag 0xA5, RFC 3416 §3 `BulkPDU`).
    Bulk {
        /// PDU request identifier.
        request_id: i32,
        /// Number of non-repeating varbinds at the head of the list.
        non_repeaters: i32,
        /// Maximum number of repetitions requested per repeating varbind.
        max_repetitions: i32,
        /// Raw `SEQUENCE OF VarBind` bytes (the full SEQUENCE TLV).
        raw_varbind_list: Vec<u8>,
    },
}

// ── Decode ────────────────────────────────────────────────────────────────────

/// Decodes raw PDU TLV bytes into a [`DecodedPdu`].
///
/// `raw_pdu_bytes` is the complete context-tagged PDU TLV (tag + length +
/// content) as returned by `decode_v3_envelope` in `ScopedData::Plaintext::raw_pdu`.
///
/// The `VarBindList` is **not** parsed — it is returned as raw SEQUENCE bytes
/// for the caller to parse in a subsequent step.
///
/// # Errors
///
/// Returns a [`BerError`] if:
/// - `raw_pdu_bytes` is truncated or malformed.
/// - The outer tag is not a recognised SNMP PDU context tag (0xA0–0xA8,
///   excluding 0xA4 / `SNMPv1` Trap).
/// - There are trailing bytes after the PDU TLV.
/// - The `VarBindList` field is absent.
///
/// # Requirements
/// Implements: REQ-0000
pub(crate) fn decode_pdu(raw_pdu_bytes: &[u8]) -> Result<DecodedPdu, BerError> {
    let mut outer_reader = BerReader::new(raw_pdu_bytes);
    let pdu_tag = outer_reader.peek_tag()?;
    // read_constructed validates the tag and returns a sub-reader over the contents.
    let mut pdu_reader = outer_reader.read_constructed(pdu_tag)?;

    // Trailing bytes after the PDU TLV indicate a malformed message.
    if !outer_reader.is_empty() {
        return Err(BerError::new("BER: trailing bytes after PDU TLV"));
    }

    let request_id = pdu_reader.read_integer()?;

    match pdu_tag {
        TAG_GET_BULK_REQUEST => {
            let non_repeaters = pdu_reader.read_integer()?;
            let max_repetitions = pdu_reader.read_integer()?;
            let raw_varbind_list = read_validated_varbind_list(&mut pdu_reader)?;
            Ok(DecodedPdu::Bulk {
                request_id,
                non_repeaters,
                max_repetitions,
                raw_varbind_list,
            })
        }
        TAG_GET_REQUEST | TAG_GET_NEXT_REQUEST | TAG_RESPONSE | TAG_SET_REQUEST
        | TAG_INFORM_REQUEST | TAG_TRAP | TAG_REPORT => {
            let error_status = pdu_reader.read_integer()?;
            let error_index = pdu_reader.read_integer()?;
            let raw_varbind_list = read_validated_varbind_list(&mut pdu_reader)?;
            Ok(DecodedPdu::Standard {
                tag: pdu_tag,
                request_id,
                error_status,
                error_index,
                raw_varbind_list,
            })
        }
        _ => Err(BerError::new(format!(
            "BER: unrecognised PDU tag 0x{pdu_tag:02X}"
        ))),
    }
}

// Validates that the VarBindList is present, captures its raw bytes, and
// confirms there are no trailing bytes after it inside the PDU envelope.
// Implements: REQ-0000
fn read_validated_varbind_list(pdu_reader: &mut BerReader) -> Result<Vec<u8>, BerError> {
    // VarBindList is mandatory per RFC 3416 §3.
    if pdu_reader.is_empty() {
        return Err(BerError::new("BER: PDU missing VarBindList"));
    }
    // Capture raw bytes before read_sequence() advances the cursor.
    // The trailing-bytes check below ensures this is exactly the SEQUENCE TLV.
    let raw_varbind_list = pdu_reader.remaining().to_vec();
    let _varbind_list_reader = pdu_reader.read_sequence()?;
    if !pdu_reader.is_empty() {
        return Err(BerError::new(
            "BER: trailing bytes after VarBindList in PDU",
        ));
    }
    Ok(raw_varbind_list)
}

// ── Valid standard PDU tags ───────────────────────────────────────────────────

// TAG_GET_BULK_REQUEST is intentionally excluded: bulk PDUs must use encode_bulk_pdu.
const VALID_STANDARD_PDU_TAGS: &[u8] = &[
    TAG_GET_REQUEST,
    TAG_GET_NEXT_REQUEST,
    TAG_RESPONSE,
    TAG_SET_REQUEST,
    TAG_INFORM_REQUEST,
    TAG_TRAP,
    TAG_REPORT,
];

// ── Encode ────────────────────────────────────────────────────────────────────

/// Encodes a standard PDU (Response, Trap, Report, etc.) with the given context tag.
///
/// `raw_varbind_list` is a pre-encoded `VarBindList` SEQUENCE (including the
/// SEQUENCE TLV wrapper).
///
/// # Errors
///
/// Returns a [`BerError`] if `tag` is not one of the valid standard PDU tags.
/// Use [`encode_bulk_pdu`] for `GetBulkRequest` (tag 0xA5).
///
/// # Requirements
/// Implements: REQ-0000
pub(crate) fn encode_pdu(
    tag: u8,
    request_id: i32,
    error_status: i32,
    error_index: i32,
    raw_varbind_list: &[u8],
) -> Result<Vec<u8>, BerError> {
    if !VALID_STANDARD_PDU_TAGS.contains(&tag) {
        return Err(BerError::new(format!(
            "BER: invalid standard PDU tag 0x{tag:02X}"
        )));
    }
    let mut inner = BerWriter::new();
    inner.write_integer(request_id);
    inner.write_integer(error_status);
    inner.write_integer(error_index);
    inner.write_raw(raw_varbind_list);

    let mut outer = BerWriter::new();
    outer.write_constructed(tag, inner.as_bytes());
    Ok(outer.into_vec())
}

/// Encodes a `GetBulkRequest` PDU with tag 0xA5.
///
/// `raw_varbind_list` is a pre-encoded `VarBindList` SEQUENCE (including the
/// SEQUENCE TLV wrapper).
///
/// # Requirements
/// Implements: REQ-0000
pub(crate) fn encode_bulk_pdu(
    request_id: i32,
    non_repeaters: i32,
    max_repetitions: i32,
    raw_varbind_list: &[u8],
) -> Vec<u8> {
    let mut inner = BerWriter::new();
    inner.write_integer(request_id);
    inner.write_integer(non_repeaters);
    inner.write_integer(max_repetitions);
    inner.write_raw(raw_varbind_list);

    let mut outer = BerWriter::new();
    outer.write_constructed(TAG_GET_BULK_REQUEST, inner.as_bytes());
    outer.into_vec()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::ber::{
        TAG_GET_BULK_REQUEST, TAG_GET_NEXT_REQUEST, TAG_GET_REQUEST, TAG_INFORM_REQUEST,
        TAG_REPORT, TAG_RESPONSE, TAG_SET_REQUEST, TAG_TRAP,
    };

    // ── Test 1: GetRequest encode/decode ────────────────────────────────────

    // GetRequest: request_id=42, error_status=0, error_index=0, empty VarBindList.
    //
    // Inner TLVs:
    //   INTEGER 42:          02 01 2A   (3 bytes)
    //   INTEGER 0:           02 01 00   (3 bytes)
    //   INTEGER 0:           02 01 00   (3 bytes)
    //   VarBindList (empty): 30 00      (2 bytes)
    // Total inner = 11 bytes
    // Outer: A0 0B [11 bytes]
    const GET_REQUEST_WIRE: &[u8] = &[
        0xA0, 0x0B, // GetRequest-PDU, length 11
        0x02, 0x01, 0x2A, // INTEGER 42
        0x02, 0x01, 0x00, // INTEGER 0
        0x02, 0x01, 0x00, // INTEGER 0
        0x30, 0x00, // SEQUENCE {} (empty VarBindList)
    ];

    #[test]
    fn given_get_request_fields_when_encoded_then_matches_wire_vector() {
        // Verifies: REQ-0000
        let encoded = encode_pdu(TAG_GET_REQUEST, 42, 0, 0, &[0x30, 0x00]).expect("must encode");
        assert_eq!(encoded, GET_REQUEST_WIRE);
    }

    #[test]
    fn given_get_request_wire_when_decoded_then_fields_match() {
        // Verifies: REQ-0000
        let decoded = decode_pdu(GET_REQUEST_WIRE).expect("must decode");
        match decoded {
            DecodedPdu::Standard {
                tag,
                request_id,
                error_status,
                error_index,
                raw_varbind_list,
            } => {
                assert_eq!(tag, TAG_GET_REQUEST);
                assert_eq!(request_id, 42);
                assert_eq!(error_status, 0);
                assert_eq!(error_index, 0);
                assert_eq!(raw_varbind_list, &[0x30, 0x00]);
            }
            DecodedPdu::Bulk { .. } => panic!("expected Standard variant"),
        }
    }

    // ── Test 2: Response PDU encode/decode ──────────────────────────────────

    // Response: tag=0xA2, request_id=42, error_status=0, error_index=0, empty VarBindList.
    const RESPONSE_WIRE: &[u8] = &[
        0xA2, 0x0B, // Response-PDU, length 11
        0x02, 0x01, 0x2A, // INTEGER 42
        0x02, 0x01, 0x00, // INTEGER 0
        0x02, 0x01, 0x00, // INTEGER 0
        0x30, 0x00, // SEQUENCE {} (empty VarBindList)
    ];

    #[test]
    fn given_response_fields_when_encoded_then_matches_wire_vector() {
        // Verifies: REQ-0000
        let encoded = encode_pdu(TAG_RESPONSE, 42, 0, 0, &[0x30, 0x00]).expect("must encode");
        assert_eq!(encoded, RESPONSE_WIRE);
    }

    #[test]
    fn given_response_wire_when_decoded_then_tag_is_response() {
        // Verifies: REQ-0000
        let decoded = decode_pdu(RESPONSE_WIRE).expect("must decode");
        match decoded {
            DecodedPdu::Standard {
                tag,
                request_id,
                error_status,
                error_index,
                raw_varbind_list,
            } => {
                assert_eq!(tag, TAG_RESPONSE);
                assert_eq!(request_id, 42);
                assert_eq!(error_status, 0);
                assert_eq!(error_index, 0);
                assert_eq!(raw_varbind_list, &[0x30, 0x00]);
            }
            DecodedPdu::Bulk { .. } => panic!("expected Standard variant"),
        }
    }

    // ── Test 3: GetBulkRequest encode/decode ────────────────────────────────

    // GetBulkRequest: request_id=7, non_repeaters=1, max_repetitions=10, empty VarBindList.
    //
    // Inner TLVs:
    //   INTEGER 7:   02 01 07   (3 bytes)
    //   INTEGER 1:   02 01 01   (3 bytes)
    //   INTEGER 10:  02 01 0A   (3 bytes)
    //   SEQUENCE {}: 30 00      (2 bytes)
    // Total inner = 11 bytes
    // Outer: A5 0B [11 bytes]
    const GET_BULK_WIRE: &[u8] = &[
        0xA5, 0x0B, // GetBulkRequest-PDU, length 11
        0x02, 0x01, 0x07, // INTEGER 7
        0x02, 0x01, 0x01, // INTEGER 1
        0x02, 0x01, 0x0A, // INTEGER 10
        0x30, 0x00, // SEQUENCE {} (empty VarBindList)
    ];

    #[test]
    fn given_bulk_fields_when_encoded_then_matches_wire_vector() {
        // Verifies: REQ-0000
        let encoded = encode_bulk_pdu(7, 1, 10, &[0x30, 0x00]);
        assert_eq!(encoded, GET_BULK_WIRE);
    }

    #[test]
    fn given_bulk_wire_when_decoded_then_fields_match() {
        // Verifies: REQ-0000
        let decoded = decode_pdu(GET_BULK_WIRE).expect("must decode");
        match decoded {
            DecodedPdu::Bulk {
                request_id,
                non_repeaters,
                max_repetitions,
                raw_varbind_list,
            } => {
                assert_eq!(request_id, 7);
                assert_eq!(non_repeaters, 1);
                assert_eq!(max_repetitions, 10);
                assert_eq!(raw_varbind_list, &[0x30, 0x00]);
            }
            DecodedPdu::Standard { .. } => panic!("expected Bulk variant"),
        }
    }

    // ── Test 4: SNMPv2-Trap PDU encode/decode ───────────────────────────────

    // Trap: tag=0xA7, request_id=1, error_status=0, error_index=0, empty VarBindList.
    const TRAP_WIRE: &[u8] = &[
        0xA7, 0x0B, // SNMPv2-Trap-PDU, length 11
        0x02, 0x01, 0x01, // INTEGER 1
        0x02, 0x01, 0x00, // INTEGER 0
        0x02, 0x01, 0x00, // INTEGER 0
        0x30, 0x00, // SEQUENCE {} (empty VarBindList)
    ];

    #[test]
    fn given_trap_fields_when_encoded_then_matches_wire_vector() {
        // Verifies: REQ-0000
        let encoded = encode_pdu(TAG_TRAP, 1, 0, 0, &[0x30, 0x00]).expect("must encode");
        assert_eq!(encoded, TRAP_WIRE);
    }

    #[test]
    fn given_trap_wire_when_decoded_then_tag_is_trap() {
        // Verifies: REQ-0000
        let decoded = decode_pdu(TRAP_WIRE).expect("must decode");
        match decoded {
            DecodedPdu::Standard {
                tag,
                request_id,
                error_status,
                error_index,
                raw_varbind_list,
            } => {
                assert_eq!(tag, TAG_TRAP);
                assert_eq!(request_id, 1);
                assert_eq!(error_status, 0);
                assert_eq!(error_index, 0);
                assert_eq!(raw_varbind_list, &[0x30, 0x00]);
            }
            DecodedPdu::Bulk { .. } => panic!("expected Standard variant"),
        }
    }

    // ── Test 5: Report PDU encode/decode ────────────────────────────────────

    // Report: tag=0xA8, request_id=99, error_status=0, error_index=0, empty VarBindList.
    //
    // Inner TLVs:
    //   INTEGER 99:  02 01 63   (3 bytes)
    //   INTEGER 0:   02 01 00   (3 bytes)
    //   INTEGER 0:   02 01 00   (3 bytes)
    //   SEQUENCE {}: 30 00      (2 bytes)
    // Total inner = 11 bytes
    // Outer: A8 0B [11 bytes]
    const REPORT_WIRE: &[u8] = &[
        0xA8, 0x0B, // Report-PDU, length 11
        0x02, 0x01, 0x63, // INTEGER 99
        0x02, 0x01, 0x00, // INTEGER 0
        0x02, 0x01, 0x00, // INTEGER 0
        0x30, 0x00, // SEQUENCE {} (empty VarBindList)
    ];

    #[test]
    fn given_report_fields_when_encoded_then_matches_wire_vector() {
        // Verifies: REQ-0000
        let encoded = encode_pdu(TAG_REPORT, 99, 0, 0, &[0x30, 0x00]).expect("must encode");
        assert_eq!(encoded, REPORT_WIRE);
    }

    #[test]
    fn given_report_wire_when_decoded_then_tag_is_report() {
        // Verifies: REQ-0000
        let decoded = decode_pdu(REPORT_WIRE).expect("must decode");
        match decoded {
            DecodedPdu::Standard {
                tag,
                request_id,
                error_status,
                error_index,
                raw_varbind_list,
            } => {
                assert_eq!(tag, TAG_REPORT);
                assert_eq!(request_id, 99);
                assert_eq!(error_status, 0);
                assert_eq!(error_index, 0);
                assert_eq!(raw_varbind_list, &[0x30, 0x00]);
            }
            DecodedPdu::Bulk { .. } => panic!("expected Standard variant"),
        }
    }

    // ── Test 6: Round-trip with non-empty VarBindList ───────────────────────

    // VarBind: SEQUENCE { OID 1.3.6.1, NULL }
    //   OID 1.3.6.1: tag=06, len=03, value=[2B 06 01]
    //     combined first arc = 40*1+3 = 43 = 0x2B, then 6, then 1
    //   NULL:         05 00
    //   VarBind SEQUENCE: 30 07 [7 bytes]
    //
    // VarBindList: SEQUENCE containing the one VarBind
    //   30 09 30 07 06 03 2B 06 01 05 00
    //
    // GetNextRequest (0xA1): request_id=100, error_status=0, error_index=0
    //   Inner:
    //     INTEGER 100: 02 01 64   (3 bytes)
    //     INTEGER 0:   02 01 00   (3 bytes)
    //     INTEGER 0:   02 01 00   (3 bytes)
    //     VarBindList: 30 09 ...  (11 bytes)
    //   Total inner = 3+3+3+11 = 20 bytes
    //   Outer: A1 14 [20 bytes]
    const VARBIND_LIST_WIRE: &[u8] = &[
        0x30, 0x09, // SEQUENCE, length 9
        0x30, 0x07, // VarBind SEQUENCE, length 7
        0x06, 0x03, 0x2B, 0x06, 0x01, // OID 1.3.6.1
        0x05, 0x00, // NULL
    ];

    const GET_NEXT_WITH_VARBIND_WIRE: &[u8] = &[
        0xA1, 0x14, // GetNextRequest-PDU, length 20
        0x02, 0x01, 0x64, // INTEGER 100
        0x02, 0x01, 0x00, // INTEGER 0
        0x02, 0x01, 0x00, // INTEGER 0
        // VarBindList (11 bytes):
        0x30, 0x09, 0x30, 0x07, 0x06, 0x03, 0x2B, 0x06, 0x01, 0x05, 0x00,
    ];

    #[test]
    fn given_get_next_with_varbind_when_encoded_then_matches_wire_vector() {
        // Verifies: REQ-0000
        let encoded =
            encode_pdu(TAG_GET_NEXT_REQUEST, 100, 0, 0, VARBIND_LIST_WIRE).expect("must encode");
        assert_eq!(encoded, GET_NEXT_WITH_VARBIND_WIRE);
    }

    #[test]
    fn given_get_next_with_varbind_wire_when_decoded_then_raw_varbind_list_preserved() {
        // Verifies: REQ-0000
        let decoded = decode_pdu(GET_NEXT_WITH_VARBIND_WIRE).expect("must decode");
        match decoded {
            DecodedPdu::Standard {
                tag,
                request_id,
                error_status,
                error_index,
                raw_varbind_list,
            } => {
                assert_eq!(tag, TAG_GET_NEXT_REQUEST);
                assert_eq!(request_id, 100);
                assert_eq!(error_status, 0);
                assert_eq!(error_index, 0);
                assert_eq!(raw_varbind_list, VARBIND_LIST_WIRE);
            }
            DecodedPdu::Bulk { .. } => panic!("expected Standard variant"),
        }
    }

    // ── Test 7: Unrecognised tag returns error ───────────────────────────────

    #[test]
    fn given_unrecognised_pdu_tag_when_decoded_then_error_mentions_unrecognised() {
        // Verifies: REQ-0000
        // 0xBF is context class constructed with tag number 31 — not a valid SNMP PDU tag.
        // We construct a minimal TLV with 11-byte inner to give read_constructed something valid.
        let raw_bytes = [
            0xBF, 0x0B, // invalid context tag
            0x02, 0x01, 0x01, // INTEGER 1
            0x02, 0x01, 0x00, // INTEGER 0
            0x02, 0x01, 0x00, // INTEGER 0
            0x30, 0x00, // empty VarBindList
        ];
        let ber_error = decode_pdu(&raw_bytes).unwrap_err();
        assert!(
            ber_error.to_string().contains("unrecognised"),
            "error must mention unrecognised, got: {ber_error}"
        );
    }

    // ── Test: SNMPv1 Trap tag (0xA4) is rejected ────────────────────────────

    #[test]
    fn given_snmpv1_trap_tag_when_decoded_then_error_mentions_unrecognised() {
        // Verifies: REQ-0000
        // 0xA4 is the SNMPv1 Trap-PDU tag, excluded from SNMPv2c/v3 processing.
        let raw_bytes = [
            0xA4, 0x0B, // SNMPv1 Trap-PDU tag
            0x02, 0x01, 0x01, // INTEGER 1
            0x02, 0x01, 0x00, // INTEGER 0
            0x02, 0x01, 0x00, // INTEGER 0
            0x30, 0x00, // empty VarBindList
        ];
        let ber_error = decode_pdu(&raw_bytes).unwrap_err();
        assert!(
            ber_error.to_string().contains("unrecognised"),
            "error must mention unrecognised, got: {ber_error}"
        );
    }

    // ── Test 8: Truncated PDU returns error ──────────────────────────────────

    #[test]
    fn given_truncated_pdu_when_decoded_then_returns_error() {
        // Verifies: REQ-0000
        // Only 3 bytes — not enough to form a valid PDU TLV.
        let truncated = [0xA0_u8, 0x0B, 0x02];
        let ber_error = decode_pdu(&truncated).unwrap_err();
        assert!(
            ber_error.to_string().to_lowercase().contains("truncated")
                || ber_error
                    .to_string()
                    .to_lowercase()
                    .contains("unexpected end"),
            "error must indicate truncation, got: {ber_error}"
        );
    }

    // ── Test: Trailing bytes after PDU TLV returns error ────────────────────

    #[test]
    fn given_pdu_with_trailing_bytes_when_decoded_then_returns_error() {
        // Verifies: REQ-0000
        // A valid GetRequest TLV followed by an extra byte.
        let mut raw_bytes = GET_REQUEST_WIRE.to_vec();
        raw_bytes.push(0x00);
        let ber_error = decode_pdu(&raw_bytes).unwrap_err();
        assert!(
            ber_error.to_string().contains("trailing bytes"),
            "error must mention trailing bytes, got: {ber_error}"
        );
    }

    // ── Test: PDU missing VarBindList returns error ──────────────────────────

    #[test]
    fn given_pdu_missing_varbind_list_when_decoded_then_returns_error() {
        // Verifies: REQ-0000
        // GetRequest with only three INTEGER fields and no VarBindList.
        //   Inner: INTEGER 1, INTEGER 0, INTEGER 0 = 9 bytes
        //   Outer: A0 09 [9 bytes]
        let raw_bytes = [
            0xA0, 0x09, // GetRequest-PDU, length 9
            0x02, 0x01, 0x01, // INTEGER 1
            0x02, 0x01, 0x00, // INTEGER 0
            0x02, 0x01, 0x00, // INTEGER 0
                  // no VarBindList
        ];
        let ber_error = decode_pdu(&raw_bytes).unwrap_err();
        assert!(
            ber_error.to_string().contains("missing VarBindList"),
            "error must mention missing VarBindList, got: {ber_error}"
        );
    }

    // ── Test: encode_pdu rejects bulk tag ────────────────────────────────────

    #[test]
    fn given_bulk_tag_when_encode_pdu_called_then_returns_error() {
        // Verifies: REQ-0000
        // TAG_GET_BULK_REQUEST must be rejected; callers must use encode_bulk_pdu.
        let ber_error = encode_pdu(TAG_GET_BULK_REQUEST, 1, 0, 0, &[0x30, 0x00]).unwrap_err();
        assert!(
            ber_error.to_string().contains("invalid standard PDU tag"),
            "error must mention invalid tag, got: {ber_error}"
        );
    }

    // ── Test 9: SetRequest round-trip ───────────────────────────────────────

    #[test]
    fn given_set_request_when_round_tripped_then_tag_is_set_request() {
        // Verifies: REQ-0000
        let encoded = encode_pdu(TAG_SET_REQUEST, 55, 0, 0, &[0x30, 0x00]).expect("must encode");
        let decoded = decode_pdu(&encoded).expect("must decode");
        match decoded {
            DecodedPdu::Standard {
                tag,
                request_id,
                error_status,
                error_index,
                raw_varbind_list,
            } => {
                assert_eq!(tag, TAG_SET_REQUEST);
                assert_eq!(request_id, 55);
                assert_eq!(error_status, 0);
                assert_eq!(error_index, 0);
                assert_eq!(raw_varbind_list, &[0x30, 0x00]);
            }
            DecodedPdu::Bulk { .. } => panic!("expected Standard variant"),
        }
    }

    // ── Test 10: InformRequest round-trip ───────────────────────────────────

    #[test]
    fn given_inform_request_when_round_tripped_then_tag_is_inform_request() {
        // Verifies: REQ-0000
        let encoded =
            encode_pdu(TAG_INFORM_REQUEST, 200, 0, 0, &[0x30, 0x00]).expect("must encode");
        let decoded = decode_pdu(&encoded).expect("must decode");
        match decoded {
            DecodedPdu::Standard {
                tag,
                request_id,
                error_status,
                error_index,
                raw_varbind_list,
            } => {
                assert_eq!(tag, TAG_INFORM_REQUEST);
                assert_eq!(request_id, 200);
                assert_eq!(error_status, 0);
                assert_eq!(error_index, 0);
                assert_eq!(raw_varbind_list, &[0x30, 0x00]);
            }
            DecodedPdu::Bulk { .. } => panic!("expected Standard variant"),
        }
    }

    // ── Extra: encode_bulk_pdu round-trip ───────────────────────────────────

    #[test]
    fn given_bulk_pdu_when_round_tripped_then_all_fields_preserved() {
        // Verifies: REQ-0000
        let encoded = encode_bulk_pdu(999, 3, 20, VARBIND_LIST_WIRE);
        let decoded = decode_pdu(&encoded).expect("must decode");
        match decoded {
            DecodedPdu::Bulk {
                request_id,
                non_repeaters,
                max_repetitions,
                raw_varbind_list,
            } => {
                assert_eq!(request_id, 999);
                assert_eq!(non_repeaters, 3);
                assert_eq!(max_repetitions, 20);
                assert_eq!(raw_varbind_list, VARBIND_LIST_WIRE);
            }
            DecodedPdu::Standard { .. } => panic!("expected Bulk variant"),
        }
    }

    // ── Test: Trailing bytes inside PDU after VarBindList (Standard) ─────────

    #[test]
    fn given_pdu_with_trailing_bytes_after_varbindlist_when_decoded_then_returns_error() {
        // Verifies: REQ-0000
        // GetRequest-PDU with valid VarBindList followed by a trailing byte
        // still inside the PDU envelope.
        let raw_bytes = [
            0xA0, 0x0C, // GetRequest-PDU, length 12
            0x02, 0x01, 0x01, // INTEGER 1
            0x02, 0x01, 0x00, // INTEGER 0
            0x02, 0x01, 0x00, // INTEGER 0
            0x30, 0x00, // empty VarBindList
            0xFF, // trailing byte inside PDU
        ];
        let ber_error = decode_pdu(&raw_bytes).unwrap_err();
        assert_eq!(
            ber_error.to_string(),
            "BER: trailing bytes after VarBindList in PDU"
        );
    }

    #[test]
    fn given_bulk_pdu_with_trailing_bytes_after_varbindlist_when_decoded_then_returns_error() {
        // Verifies: REQ-0000
        let raw_bytes = [
            0xA5, 0x0C, // GetBulkRequest-PDU, length 12
            0x02, 0x01, 0x01, // INTEGER 1
            0x02, 0x01, 0x00, // INTEGER 0
            0x02, 0x01, 0x00, // INTEGER 0
            0x30, 0x00, // empty VarBindList
            0xFF, // trailing byte inside PDU
        ];
        let ber_error = decode_pdu(&raw_bytes).unwrap_err();
        assert_eq!(
            ber_error.to_string(),
            "BER: trailing bytes after VarBindList in PDU"
        );
    }
}
