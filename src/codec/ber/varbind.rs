//! BER encode/decode for SNMP `VarBind` and `VarBindList` (RFC 3416 §3).
//!
//! A `VarBindList` is a SEQUENCE OF `VarBind`. Each `VarBind` is a SEQUENCE
//! containing an OID (the `name`) followed by a CHOICE value. The value can
//! be a universal type (INTEGER, OCTET STRING, OID, NULL), one of the three
//! SNMP exception tags (noSuchObject, noSuchInstance, endOfMibView), or an
//! APPLICATION-tagged `SMIv2` type.
//!
//! This module handles both the structural layer and `SMIv2` type interpretation.
//! Universal and exception types are decoded inline; APPLICATION-tagged values
//! (Counter32, Gauge32, etc.) are stored as [`DecodedVarbindValue::Raw`] at the
//! structural layer and promoted to typed `Value` variants by
//! [`decode_varbind_value_to_value`].

use super::{
    BerError, BerWriter, TAG_COUNTER32, TAG_COUNTER64, TAG_END_OF_MIB_VIEW, TAG_GAUGE32,
    TAG_INTEGER, TAG_IP_ADDRESS, TAG_NO_SUCH_INSTANCE, TAG_NO_SUCH_OBJECT, TAG_NULL,
    TAG_OCTET_STRING, TAG_OID, TAG_OPAQUE, TAG_TIMETICKS,
};
use crate::codec::Oid;
use crate::codec::Value;
use crate::codec::pdu::VarbindValue;

// ----- Value CHOICE ----------------------------------------------------------

/// The decoded value CHOICE of a single `VarBind` (RFC 3416 §3).
///
/// Universal types (INTEGER, OCTET STRING, OID) are decoded inline. The three
/// SNMP exception tags are decoded into the dedicated variants. All
/// APPLICATION-tagged types (Counter32, Gauge32, etc.) are stored as
/// [`Raw`][DecodedVarbindValue::Raw] for interpretation in a higher layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DecodedVarbindValue {
    /// `unSpecified NULL` — value placeholder in GetRequest/GetNext/GetBulk.
    Unspecified,
    /// `noSuchObject` exception `[0] IMPLICIT NULL` (tag 0x80).
    NoSuchObject,
    /// `noSuchInstance` exception `[1] IMPLICIT NULL` (tag 0x81).
    NoSuchInstance,
    /// `endOfMibView` exception `[2] IMPLICIT NULL` (tag 0x82).
    EndOfMibView,
    /// INTEGER (universal tag 0x02).
    ///
    /// Specifically represents the `Integer32` / universal INTEGER value from
    /// `SMIv2`, not arbitrary ASN.1 INTEGER widths.
    Integer(i32),
    /// OCTET STRING (universal tag 0x04).
    OctetString(Vec<u8>),
    /// OBJECT IDENTIFIER (universal tag 0x06).
    ObjectIdentifier(Oid),
    /// APPLICATION-tagged or other unrecognised value — raw bytes retained for
    /// the APPLICATION-type layer to interpret.
    Raw { tag: u8, value_bytes: Vec<u8> },
}

// ----- DecodedVarbind --------------------------------------------------------

/// A single decoded `VarBind`: an OID name and its associated value CHOICE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DecodedVarbind {
    /// The variable name (RFC 3416 §3: `name ObjectName`).
    pub(crate) name: Oid,
    /// The decoded value CHOICE.
    pub(crate) value: DecodedVarbindValue,
}

// ----- Decoding --------------------------------------------------------------

/// Decodes a complete `VarBindList` SEQUENCE TLV into a vector of [`DecodedVarbind`].
///
/// The input must be the full `VarBindList` SEQUENCE TLV (tag + length + contents),
/// as produced by the PDU decoder's `raw_varbind_list` field.
///
/// # Errors
///
/// Returns a [`BerError`] when:
/// - The outer tag is not a SEQUENCE (0x30).
/// - Any inner `VarBind` SEQUENCE is structurally invalid.
/// - Trailing bytes remain after the outer SEQUENCE TLV.
/// - Trailing bytes remain after the last `VarBind` within the outer SEQUENCE.
pub(crate) fn decode_varbind_list(
    raw_varbind_list_bytes: &[u8],
) -> Result<Vec<DecodedVarbind>, BerError> {
    let mut outer_reader = super::BerReader::new(raw_varbind_list_bytes);
    let mut list_reader = outer_reader.read_sequence()?;
    if !outer_reader.is_empty() {
        return Err(BerError::new(
            "BER: trailing bytes after VarBindList SEQUENCE",
        ));
    }

    let mut varbinds = Vec::new();
    while !list_reader.is_empty() {
        let mut varbind_reader = list_reader.read_sequence()?;
        let name = varbind_reader.read_oid()?;
        let value = decode_varbind_value(&mut varbind_reader)?;
        varbinds.push(DecodedVarbind { name, value });
    }

    Ok(varbinds)
}

/// Decodes the value CHOICE from the remaining bytes of a `VarBind` sub-reader.
///
/// The reader must be positioned at the start of the value TLV. After reading
/// the value, no bytes must remain in the `VarBind` reader — trailing bytes
/// indicate a malformed `VarBind` and cause an error.
fn decode_varbind_value(
    varbind_reader: &mut super::BerReader,
) -> Result<DecodedVarbindValue, BerError> {
    let tag = varbind_reader.peek_tag()?;

    let value = match tag {
        TAG_NULL => {
            varbind_reader.read_null()?;
            DecodedVarbindValue::Unspecified
        }
        TAG_NO_SUCH_OBJECT | TAG_NO_SUCH_INSTANCE | TAG_END_OF_MIB_VIEW => {
            let (_exception_tag, exception_bytes) = varbind_reader.read_tlv()?;
            if !exception_bytes.is_empty() {
                return Err(BerError::new(format!(
                    "BER: exception tag 0x{tag:02X} must have length 0, got {}",
                    exception_bytes.len()
                )));
            }
            // `tag` is already matched to exactly these three values by the outer match arm.
            match tag {
                TAG_NO_SUCH_OBJECT => DecodedVarbindValue::NoSuchObject,
                TAG_NO_SUCH_INSTANCE => DecodedVarbindValue::NoSuchInstance,
                TAG_END_OF_MIB_VIEW => DecodedVarbindValue::EndOfMibView,
                _ => {
                    return Err(BerError::new(format!(
                        "BER: unexpected exception tag 0x{tag:02X}"
                    )));
                }
            }
        }
        TAG_INTEGER => {
            let integer_value = varbind_reader.read_integer()?;
            DecodedVarbindValue::Integer(integer_value)
        }
        TAG_OCTET_STRING => {
            let string_bytes = varbind_reader.read_octet_string()?;
            DecodedVarbindValue::OctetString(string_bytes.to_vec())
        }
        TAG_OID => {
            let oid_value = varbind_reader.read_oid()?;
            DecodedVarbindValue::ObjectIdentifier(oid_value)
        }
        _ => {
            let (raw_tag, raw_value) = varbind_reader.read_tlv()?;
            DecodedVarbindValue::Raw {
                tag: raw_tag,
                value_bytes: raw_value.to_vec(),
            }
        }
    };

    // No bytes must remain inside the VarBind SEQUENCE after the value.
    if !varbind_reader.is_empty() {
        return Err(BerError::new(format!(
            "BER: trailing bytes in VarBind SEQUENCE: {} byte(s) remain after value",
            varbind_reader.remaining().len()
        )));
    }

    Ok(value)
}

/// Converts a decoded `VarBind` value into the production `VarbindValue` type.
///
/// APPLICATION-tagged `Raw` values are decoded into the corresponding `SMIv2`
/// `Value` variant. Unknown APPLICATION tags produce an error.
///
// Returns Result for forward compatibility: Value is #[non_exhaustive], and future
// variants might have encoding constraints that can fail.
pub(crate) fn decode_varbind_value_to_value(
    decoded: &DecodedVarbindValue,
) -> Result<VarbindValue, BerError> {
    match decoded {
        DecodedVarbindValue::Unspecified => Ok(VarbindValue::Unspecified),
        DecodedVarbindValue::NoSuchObject => Ok(VarbindValue::NoSuchObject),
        DecodedVarbindValue::NoSuchInstance => Ok(VarbindValue::NoSuchInstance),
        DecodedVarbindValue::EndOfMibView => Ok(VarbindValue::EndOfMibView),
        DecodedVarbindValue::Integer(integer_value) => {
            Ok(VarbindValue::Value(Value::Integer32(*integer_value)))
        }
        DecodedVarbindValue::OctetString(string_bytes) => Ok(VarbindValue::Value(
            Value::OctetString(string_bytes.clone()),
        )),
        DecodedVarbindValue::ObjectIdentifier(oid) => {
            Ok(VarbindValue::Value(Value::ObjectIdentifier(oid.clone())))
        }
        DecodedVarbindValue::Raw {
            tag: TAG_IP_ADDRESS,
            value_bytes,
        } => {
            let octets: [u8; 4] = value_bytes.as_slice().try_into().map_err(|_| {
                BerError::new(format!(
                    "BER: IpAddress must be exactly 4 bytes, got {}",
                    value_bytes.len()
                ))
            })?;
            Ok(VarbindValue::Value(Value::IpAddress(octets)))
        }
        DecodedVarbindValue::Raw {
            tag: TAG_COUNTER32,
            value_bytes,
        } => {
            let counter_value = super::decode_unsigned_u32(value_bytes, 0)?;
            Ok(VarbindValue::Value(Value::Counter32(counter_value)))
        }
        DecodedVarbindValue::Raw {
            tag: TAG_GAUGE32,
            value_bytes,
        } => {
            let gauge_value = super::decode_unsigned_u32(value_bytes, 0)?;
            Ok(VarbindValue::Value(Value::Gauge32(gauge_value)))
        }
        DecodedVarbindValue::Raw {
            tag: TAG_TIMETICKS,
            value_bytes,
        } => {
            let timeticks_value = super::decode_unsigned_u32(value_bytes, 0)?;
            Ok(VarbindValue::Value(Value::TimeTicks(timeticks_value)))
        }
        DecodedVarbindValue::Raw {
            tag: TAG_OPAQUE,
            value_bytes,
        } => Ok(VarbindValue::Value(Value::Opaque(value_bytes.clone()))),
        DecodedVarbindValue::Raw {
            tag: TAG_COUNTER64,
            value_bytes,
        } => {
            let counter64_value = super::decode_unsigned_u64(value_bytes, 0)?;
            Ok(VarbindValue::Value(Value::Counter64(counter64_value)))
        }
        DecodedVarbindValue::Raw { tag: other_tag, .. } => Err(BerError::new(format!(
            "BER: unsupported APPLICATION tag 0x{other_tag:02X} in VarBind value"
        ))),
    }
}

// ----- Encoding --------------------------------------------------------------

/// Wraps a slice of pre-encoded `VarBind` byte slices in a `VarBindList` SEQUENCE TLV.
///
/// The caller prepares each `VarBind` with [`encode_varbind`] and passes the
/// resulting slices here. The function concatenates them and wraps the result
/// in a SEQUENCE TLV (tag 0x30).
pub(crate) fn encode_varbind_list(encoded_varbinds: &[&[u8]]) -> Vec<u8> {
    let mut inner_writer = BerWriter::new();
    for encoded_varbind in encoded_varbinds {
        inner_writer.write_raw(encoded_varbind);
    }
    let mut outer_writer = BerWriter::new();
    outer_writer.write_sequence(inner_writer.as_bytes());
    outer_writer.into_vec()
}

/// Encodes a single `VarBind` as a SEQUENCE TLV containing the OID name and
/// a pre-encoded value TLV.
///
/// The `encoded_value_tlv` must be a complete TLV (tag + length + value bytes)
/// for the desired value type. Use the `encode_*_value` helpers or
/// [`encode_exception`] to produce this.
pub(crate) fn encode_varbind(oid: &Oid, encoded_value_tlv: &[u8]) -> Vec<u8> {
    let mut inner_writer = BerWriter::new();
    inner_writer.write_oid(oid);
    inner_writer.write_raw(encoded_value_tlv);

    let mut outer_writer = BerWriter::new();
    outer_writer.write_sequence(inner_writer.as_bytes());
    outer_writer.into_vec()
}

/// Encodes a `VarbindValue` into raw TLV bytes for use with [`encode_varbind`].
///
/// The returned bytes are a complete TLV (tag + length + value) suitable for
/// passing as the `encoded_value_tlv` argument to [`encode_varbind`].
///
// Returns Result for forward compatibility: Value is #[non_exhaustive], and future
// variants might have encoding constraints that can fail.
pub(crate) fn encode_varbind_value(value: &VarbindValue) -> Result<Vec<u8>, BerError> {
    match value {
        VarbindValue::Unspecified => Ok(encode_null_value()),
        VarbindValue::NoSuchObject => encode_exception(TAG_NO_SUCH_OBJECT),
        VarbindValue::NoSuchInstance => encode_exception(TAG_NO_SUCH_INSTANCE),
        VarbindValue::EndOfMibView => encode_exception(TAG_END_OF_MIB_VIEW),
        VarbindValue::Value(Value::Integer32(integer_value)) => {
            Ok(encode_integer_value(*integer_value))
        }
        VarbindValue::Value(Value::OctetString(string_bytes)) => {
            Ok(encode_octet_string_value(string_bytes))
        }
        VarbindValue::Value(Value::ObjectIdentifier(oid)) => Ok(encode_oid_value(oid)),
        VarbindValue::Value(Value::IpAddress(octets)) => {
            let mut writer = BerWriter::new();
            writer.write_tlv(TAG_IP_ADDRESS, octets);
            Ok(writer.into_vec())
        }
        VarbindValue::Value(Value::Counter32(counter_value)) => {
            let mut writer = BerWriter::new();
            writer.write_tagged_unsigned32(TAG_COUNTER32, *counter_value);
            Ok(writer.into_vec())
        }
        VarbindValue::Value(Value::Gauge32(gauge_value)) => {
            let mut writer = BerWriter::new();
            writer.write_tagged_unsigned32(TAG_GAUGE32, *gauge_value);
            Ok(writer.into_vec())
        }
        VarbindValue::Value(Value::TimeTicks(timeticks_value)) => {
            let mut writer = BerWriter::new();
            writer.write_tagged_unsigned32(TAG_TIMETICKS, *timeticks_value);
            Ok(writer.into_vec())
        }
        VarbindValue::Value(Value::Opaque(opaque_bytes)) => {
            let mut writer = BerWriter::new();
            writer.write_tlv(TAG_OPAQUE, opaque_bytes);
            Ok(writer.into_vec())
        }
        VarbindValue::Value(Value::Counter64(counter64_value)) => {
            let mut writer = BerWriter::new();
            writer.write_tagged_unsigned64(TAG_COUNTER64, *counter64_value);
            Ok(writer.into_vec())
        }
    }
}

/// Encodes a NULL value TLV (tag 0x05, length 0x00).
///
/// Used as the value in GetRequest/GetNext/GetBulk `VarBinds` where the value
/// field is the `unSpecified` CHOICE.
pub(crate) fn encode_null_value() -> Vec<u8> {
    vec![TAG_NULL, 0x00]
}

/// Encodes a signed INTEGER value TLV.
pub(crate) fn encode_integer_value(value: i32) -> Vec<u8> {
    let mut writer = BerWriter::new();
    writer.write_integer(value);
    writer.into_vec()
}

/// Encodes an OCTET STRING value TLV.
pub(crate) fn encode_octet_string_value(bytes: &[u8]) -> Vec<u8> {
    let mut writer = BerWriter::new();
    writer.write_octet_string(bytes);
    writer.into_vec()
}

/// Encodes an OBJECT IDENTIFIER value TLV.
pub(crate) fn encode_oid_value(oid: &Oid) -> Vec<u8> {
    let mut writer = BerWriter::new();
    writer.write_oid(oid);
    writer.into_vec()
}

/// Encodes an SNMP exception value TLV (noSuchObject, noSuchInstance,
/// endOfMibView) with the given context-tagged primitive tag and a zero-length
/// value, per RFC 3416 §3.
///
/// Pass one of [`TAG_NO_SUCH_OBJECT`], [`TAG_NO_SUCH_INSTANCE`], or
/// [`TAG_END_OF_MIB_VIEW`]. Any other tag value is rejected with an error.
///
/// # Errors
///
/// Returns a [`BerError`] when `tag` is not one of the three valid exception tags.
pub(crate) fn encode_exception(tag: u8) -> Result<Vec<u8>, BerError> {
    if tag != TAG_NO_SUCH_OBJECT && tag != TAG_NO_SUCH_INSTANCE && tag != TAG_END_OF_MIB_VIEW {
        return Err(BerError::new(format!(
            "BER: invalid exception tag 0x{tag:02X}"
        )));
    }
    Ok(vec![tag, 0x00])
}

// ----- Tests -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Value;
    use crate::codec::ber::{
        TAG_COUNTER32, TAG_COUNTER64, TAG_GAUGE32, TAG_IP_ADDRESS, TAG_OPAQUE, TAG_TIMETICKS,
    };
    use crate::codec::pdu::VarbindValue;

    // Wire constants shared across multiple tests.
    //
    // OID 1.3.6.1:
    //   combined first arc: 40*1+3 = 43 = 0x2B; remaining: 6=0x06, 1=0x01
    //   TLV: 06 03 2B 06 01  (5 bytes)
    //
    // OID 1.3.6.1.2.1:
    //   combined first arc: 0x2B; remaining: 6, 1, 2, 1
    //   TLV: 06 05 2B 06 01 02 01  (7 bytes)
    //
    // NULL:              05 00  (2 bytes)
    // INTEGER 42:        02 01 2A  (3 bytes)
    // INTEGER 7:         02 01 07  (3 bytes)
    // OCTET STRING "Hi": 04 02 48 69  (4 bytes)

    // Test 1: empty VarBindList — outer SEQUENCE with empty contents.
    const EMPTY_VARBIND_LIST: &[u8] = &[0x30, 0x00];

    // Test 2: VarBindList { VarBind { OID 1.3.6.1, NULL } }
    //   VarBind inner: OID(5) + NULL(2) = 7  → 30 07 06 03 2B 06 01 05 00
    //   VarBindList:   inner(9 bytes)         → 30 09 30 07 06 03 2B 06 01 05 00
    const VARBIND_LIST_OID1361_NULL: &[u8] = &[
        0x30, 0x09, // VarBindList SEQUENCE, length 9
        0x30, 0x07, // VarBind SEQUENCE, length 7
        0x06, 0x03, 0x2B, 0x06, 0x01, // OID 1.3.6.1
        0x05, 0x00, // NULL
    ];

    // Test 3: VarBindList { VarBind { OID 1.3.6.1, INTEGER 42 } }
    //   VarBind inner: OID(5) + INTEGER(3) = 8  → 30 08 06 03 2B 06 01 02 01 2A
    //   VarBindList:   inner(10 bytes)            → 30 0A 30 08 06 03 2B 06 01 02 01 2A
    const VARBIND_LIST_OID1361_INT42: &[u8] = &[
        0x30, 0x0A, // VarBindList SEQUENCE, length 10
        0x30, 0x08, // VarBind SEQUENCE, length 8
        0x06, 0x03, 0x2B, 0x06, 0x01, // OID 1.3.6.1
        0x02, 0x01, 0x2A, // INTEGER 42
    ];

    // Test 4: VarBindList { VarBind { OID 1.3.6.1, OCTET STRING "Hi" } }
    //   VarBind inner: OID(5) + OCTET STRING(4) = 9  → 30 09 06 03 2B 06 01 04 02 48 69
    //   VarBindList:   inner(11 bytes)                 → 30 0B 30 09 06 03 2B 06 01 04 02 48 69
    const VARBIND_LIST_OID1361_HI: &[u8] = &[
        0x30, 0x0B, // VarBindList SEQUENCE, length 11
        0x30, 0x09, // VarBind SEQUENCE, length 9
        0x06, 0x03, 0x2B, 0x06, 0x01, // OID 1.3.6.1
        0x04, 0x02, 0x48, 0x69, // OCTET STRING "Hi"
    ];

    // Test 5: VarBindList { VarBind { OID 1.3.6.1, OID 1.3.6.1.2.1 } }
    //   OID value 1.3.6.1.2.1:  06 05 2B 06 01 02 01  (7 bytes)
    //   VarBind inner: OID(5) + OID(7) = 12  → 30 0C 06 03 2B 06 01 06 05 2B 06 01 02 01
    //   VarBindList:   inner(14 bytes)         → 30 0E 30 0C 06 03 2B 06 01 06 05 2B 06 01 02 01
    const VARBIND_LIST_OID1361_OID136121: &[u8] = &[
        0x30, 0x0E, // VarBindList SEQUENCE, length 14
        0x30, 0x0C, // VarBind SEQUENCE, length 12
        0x06, 0x03, 0x2B, 0x06, 0x01, // OID 1.3.6.1 (name)
        0x06, 0x05, 0x2B, 0x06, 0x01, 0x02, 0x01, // OID 1.3.6.1.2.1 (value)
    ];

    // Test 6: VarBindList with two VarBinds:
    //   VarBind 1: OID 1.3.6.1, NULL          → 30 07 06 03 2B 06 01 05 00  (9 bytes)
    //   VarBind 2: OID 1.3.6.1.2.1, INTEGER 7 → 30 0A 06 05 2B 06 01 02 01 02 01 07  (12 bytes)
    //   VarBindList: 9+12 = 21 bytes of content → 30 15 ...
    const VARBIND_LIST_TWO_VARBINDS: &[u8] = &[
        0x30, 0x15, // VarBindList SEQUENCE, length 21
        0x30, 0x07, // VarBind 1 SEQUENCE, length 7
        0x06, 0x03, 0x2B, 0x06, 0x01, // OID 1.3.6.1
        0x05, 0x00, // NULL
        0x30, 0x0A, // VarBind 2 SEQUENCE, length 10
        0x06, 0x05, 0x2B, 0x06, 0x01, 0x02, 0x01, // OID 1.3.6.1.2.1
        0x02, 0x01, 0x07, // INTEGER 7
    ];

    // Test 7: VarBind with noSuchObject exception (tag 0x80, length 0)
    //   VarBind inner: OID(5) + exception(2) = 7  → 30 07 06 03 2B 06 01 80 00
    //   VarBindList:   inner(9 bytes)              → 30 09 30 07 06 03 2B 06 01 80 00
    const VARBIND_LIST_NO_SUCH_OBJECT: &[u8] = &[
        0x30, 0x09, // VarBindList SEQUENCE, length 9
        0x30, 0x07, // VarBind SEQUENCE, length 7
        0x06, 0x03, 0x2B, 0x06, 0x01, // OID 1.3.6.1
        0x80, 0x00, // noSuchObject
    ];

    // Test 8: noSuchInstance (tag 0x81, length 0)
    //   VarBind inner: OID(5) + exception(2) = 7  → 30 07 06 03 2B 06 01 81 00
    //   VarBindList:   inner(9 bytes)              → 30 09 30 07 06 03 2B 06 01 81 00
    const VARBIND_LIST_NO_SUCH_INSTANCE: &[u8] = &[
        0x30, 0x09, // VarBindList SEQUENCE, length 9
        0x30, 0x07, // VarBind SEQUENCE, length 7
        0x06, 0x03, 0x2B, 0x06, 0x01, // OID 1.3.6.1
        0x81, 0x00, // noSuchInstance
    ];

    // Test 9: endOfMibView (tag 0x82, length 0)
    //   VarBind inner: OID(5) + exception(2) = 7  → 30 07 06 03 2B 06 01 82 00
    //   VarBindList:   inner(9 bytes)              → 30 09 30 07 06 03 2B 06 01 82 00
    const VARBIND_LIST_END_OF_MIB_VIEW: &[u8] = &[
        0x30, 0x09, // VarBindList SEQUENCE, length 9
        0x30, 0x07, // VarBind SEQUENCE, length 7
        0x06, 0x03, 0x2B, 0x06, 0x01, // OID 1.3.6.1
        0x82, 0x00, // endOfMibView
    ];

    // Test 10: APPLICATION-tagged Counter32 (tag 0x41, value 0x03 0xE8 = 1000)
    //   Counter32 TLV: 41 02 03 E8  (4 bytes)
    //   VarBind inner: OID(5) + Counter32(4) = 9  → 30 09 06 03 2B 06 01 41 02 03 E8
    //   VarBindList:   inner(11 bytes)              → 30 0B 30 09 06 03 2B 06 01 41 02 03 E8
    const VARBIND_LIST_COUNTER32_1000: &[u8] = &[
        0x30, 0x0B, // VarBindList SEQUENCE, length 11
        0x30, 0x09, // VarBind SEQUENCE, length 9
        0x06, 0x03, 0x2B, 0x06, 0x01, // OID 1.3.6.1
        0x41, 0x02, 0x03, 0xE8, // Counter32 (APPLICATION tag 0x41), value 1000
    ];

    // APPLICATION-tagged wire constants for SMIv2 type tests.
    //
    // IpAddress TLV: 40 04 0A 00 00 01
    const IP_ADDRESS_TLV: &[u8] = &[0x40, 0x04, 0x0A, 0x00, 0x00, 0x01];

    // Counter32(1000): 41 02 03 E8
    const COUNTER32_1000_TLV: &[u8] = &[0x41, 0x02, 0x03, 0xE8];

    // Counter32(u32::MAX): 41 05 00 FF FF FF FF  (leading 0x00 sign byte)
    const COUNTER32_MAX_TLV: &[u8] = &[0x41, 0x05, 0x00, 0xFF, 0xFF, 0xFF, 0xFF];

    // Gauge32(500): 42 02 01 F4
    const GAUGE32_500_TLV: &[u8] = &[0x42, 0x02, 0x01, 0xF4];

    // TimeTicks(360000 = 0x057E40): 43 03 05 7E 40
    const TIMETICKS_360000_TLV: &[u8] = &[0x43, 0x03, 0x05, 0x7E, 0x40];

    // Opaque([0xDE, 0xAD]): 44 02 DE AD
    const OPAQUE_DEAD_TLV: &[u8] = &[0x44, 0x02, 0xDE, 0xAD];

    // Counter64(1000): 46 02 03 E8
    const COUNTER64_1000_TLV: &[u8] = &[0x46, 0x02, 0x03, 0xE8];

    // Counter64(u64::MAX): 46 09 00 FF FF FF FF FF FF FF FF
    const COUNTER64_MAX_TLV: &[u8] = &[
        0x46, 0x09, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ];

    // --- Decode: empty VarBindList ---

    #[test]
    fn given_empty_varbind_list_bytes_when_decoded_then_returns_empty_vec() {
        let varbinds =
            decode_varbind_list(EMPTY_VARBIND_LIST).expect("empty VarBindList should decode");
        assert_eq!(varbinds, vec![]);
    }

    // --- Decode: single VarBind with NULL ---

    #[test]
    fn given_single_varbind_with_null_when_decoded_then_returns_unspecified() {
        let varbinds = decode_varbind_list(VARBIND_LIST_OID1361_NULL)
            .expect("VarBindList with NULL should decode");
        assert_eq!(varbinds.len(), 1);
        let expected_oid: Oid = "1.3.6.1".parse().unwrap();
        assert_eq!(varbinds[0].name, expected_oid);
        assert_eq!(varbinds[0].value, DecodedVarbindValue::Unspecified);
    }

    // --- Decode: single VarBind with INTEGER ---

    #[test]
    fn given_single_varbind_with_integer_42_when_decoded_then_returns_integer_42() {
        let varbinds = decode_varbind_list(VARBIND_LIST_OID1361_INT42)
            .expect("VarBindList with INTEGER should decode");
        assert_eq!(varbinds.len(), 1);
        let expected_oid: Oid = "1.3.6.1".parse().unwrap();
        assert_eq!(varbinds[0].name, expected_oid);
        assert_eq!(varbinds[0].value, DecodedVarbindValue::Integer(42));
    }

    // --- Decode: single VarBind with OCTET STRING ---

    #[test]
    fn given_single_varbind_with_octet_string_hi_when_decoded_then_returns_hi_bytes() {
        let varbinds = decode_varbind_list(VARBIND_LIST_OID1361_HI)
            .expect("VarBindList with OCTET STRING should decode");
        assert_eq!(varbinds.len(), 1);
        let expected_oid: Oid = "1.3.6.1".parse().unwrap();
        assert_eq!(varbinds[0].name, expected_oid);
        assert_eq!(
            varbinds[0].value,
            DecodedVarbindValue::OctetString(b"Hi".to_vec())
        );
    }

    // --- Decode: single VarBind with OID value ---

    #[test]
    fn given_single_varbind_with_oid_value_when_decoded_then_returns_oid() {
        let varbinds = decode_varbind_list(VARBIND_LIST_OID1361_OID136121)
            .expect("VarBindList with OID value should decode");
        assert_eq!(varbinds.len(), 1);
        let expected_name: Oid = "1.3.6.1".parse().unwrap();
        let expected_value_oid: Oid = "1.3.6.1.2.1".parse().unwrap();
        assert_eq!(varbinds[0].name, expected_name);
        assert_eq!(
            varbinds[0].value,
            DecodedVarbindValue::ObjectIdentifier(expected_value_oid)
        );
    }

    // --- Decode: multiple VarBinds ---

    #[test]
    fn given_two_varbinds_when_decoded_then_returns_both() {
        let varbinds = decode_varbind_list(VARBIND_LIST_TWO_VARBINDS)
            .expect("VarBindList with two VarBinds should decode");
        assert_eq!(varbinds.len(), 2);
        let oid_1361: Oid = "1.3.6.1".parse().unwrap();
        let oid_136121: Oid = "1.3.6.1.2.1".parse().unwrap();
        assert_eq!(varbinds[0].name, oid_1361);
        assert_eq!(varbinds[0].value, DecodedVarbindValue::Unspecified);
        assert_eq!(varbinds[1].name, oid_136121);
        assert_eq!(varbinds[1].value, DecodedVarbindValue::Integer(7));
    }

    // --- Decode: exception values ---

    #[test]
    fn given_varbind_with_no_such_object_when_decoded_then_returns_no_such_object() {
        let varbinds = decode_varbind_list(VARBIND_LIST_NO_SUCH_OBJECT)
            .expect("noSuchObject VarBind should decode");
        assert_eq!(varbinds.len(), 1);
        assert_eq!(varbinds[0].value, DecodedVarbindValue::NoSuchObject);
    }

    #[test]
    fn given_varbind_with_no_such_instance_when_decoded_then_returns_no_such_instance() {
        let varbinds = decode_varbind_list(VARBIND_LIST_NO_SUCH_INSTANCE)
            .expect("noSuchInstance VarBind should decode");
        assert_eq!(varbinds.len(), 1);
        assert_eq!(varbinds[0].value, DecodedVarbindValue::NoSuchInstance);
    }

    #[test]
    fn given_varbind_with_end_of_mib_view_when_decoded_then_returns_end_of_mib_view() {
        let varbinds = decode_varbind_list(VARBIND_LIST_END_OF_MIB_VIEW)
            .expect("endOfMibView VarBind should decode");
        assert_eq!(varbinds.len(), 1);
        assert_eq!(varbinds[0].value, DecodedVarbindValue::EndOfMibView);
    }

    // --- Decode: APPLICATION-tagged value ---

    #[test]
    fn given_varbind_with_counter32_when_decoded_then_returns_raw_with_tag_and_bytes() {
        let varbinds = decode_varbind_list(VARBIND_LIST_COUNTER32_1000)
            .expect("Counter32 VarBind should decode");
        assert_eq!(varbinds.len(), 1);
        assert_eq!(
            varbinds[0].value,
            DecodedVarbindValue::Raw {
                tag: TAG_COUNTER32,
                value_bytes: vec![0x03, 0xE8],
            }
        );
    }

    // --- Encode: empty VarBindList ---

    #[test]
    fn given_empty_encoded_varbinds_when_encoded_as_list_then_matches_empty_wire() {
        let encoded = encode_varbind_list(&[]);
        assert_eq!(encoded, EMPTY_VARBIND_LIST);
    }

    // --- Encode: single VarBind with NULL ---

    #[test]
    fn given_oid_and_null_value_when_encoded_as_varbind_then_matches_wire() {
        let oid: Oid = "1.3.6.1".parse().unwrap();
        let null_tlv = encode_null_value();
        let varbind_bytes = encode_varbind(&oid, &null_tlv);
        let list_bytes = encode_varbind_list(&[&varbind_bytes]);
        assert_eq!(list_bytes, VARBIND_LIST_OID1361_NULL);
    }

    // --- Encode: single VarBind with INTEGER ---

    #[test]
    fn given_oid_and_integer_value_when_encoded_then_matches_wire() {
        let oid: Oid = "1.3.6.1".parse().unwrap();
        let integer_tlv = encode_integer_value(42);
        let varbind_bytes = encode_varbind(&oid, &integer_tlv);
        let list_bytes = encode_varbind_list(&[&varbind_bytes]);
        assert_eq!(list_bytes, VARBIND_LIST_OID1361_INT42);
    }

    // --- Encode: single VarBind with OCTET STRING ---

    #[test]
    fn given_oid_and_octet_string_value_when_encoded_then_matches_wire() {
        let oid: Oid = "1.3.6.1".parse().unwrap();
        let octet_string_tlv = encode_octet_string_value(b"Hi");
        let varbind_bytes = encode_varbind(&oid, &octet_string_tlv);
        let list_bytes = encode_varbind_list(&[&varbind_bytes]);
        assert_eq!(list_bytes, VARBIND_LIST_OID1361_HI);
    }

    // --- Encode: single VarBind with OID value ---

    #[test]
    fn given_oid_name_and_oid_value_when_encoded_then_matches_wire() {
        let name_oid: Oid = "1.3.6.1".parse().unwrap();
        let value_oid: Oid = "1.3.6.1.2.1".parse().unwrap();
        let oid_tlv = encode_oid_value(&value_oid);
        let varbind_bytes = encode_varbind(&name_oid, &oid_tlv);
        let list_bytes = encode_varbind_list(&[&varbind_bytes]);
        assert_eq!(list_bytes, VARBIND_LIST_OID1361_OID136121);
    }

    // --- Encode: exception values ---

    #[test]
    fn given_no_such_object_exception_when_encoded_then_matches_wire() {
        let oid: Oid = "1.3.6.1".parse().unwrap();
        let exception_tlv = encode_exception(TAG_NO_SUCH_OBJECT).expect("must encode");
        let varbind_bytes = encode_varbind(&oid, &exception_tlv);
        let list_bytes = encode_varbind_list(&[&varbind_bytes]);
        assert_eq!(list_bytes, VARBIND_LIST_NO_SUCH_OBJECT);
    }

    #[test]
    fn given_no_such_instance_exception_when_encoded_then_matches_wire() {
        let oid: Oid = "1.3.6.1".parse().unwrap();
        let exception_tlv = encode_exception(TAG_NO_SUCH_INSTANCE).expect("must encode");
        let varbind_bytes = encode_varbind(&oid, &exception_tlv);
        let list_bytes = encode_varbind_list(&[&varbind_bytes]);
        assert_eq!(list_bytes, VARBIND_LIST_NO_SUCH_INSTANCE);
    }

    #[test]
    fn given_end_of_mib_view_exception_when_encoded_then_matches_wire() {
        let oid: Oid = "1.3.6.1".parse().unwrap();
        let exception_tlv = encode_exception(TAG_END_OF_MIB_VIEW).expect("must encode");
        let varbind_bytes = encode_varbind(&oid, &exception_tlv);
        let list_bytes = encode_varbind_list(&[&varbind_bytes]);
        assert_eq!(list_bytes, VARBIND_LIST_END_OF_MIB_VIEW);
    }

    // --- Encode: invalid exception tag ---

    #[test]
    fn given_invalid_exception_tag_when_encoded_then_returns_error() {
        let ber_error = encode_exception(0x05).unwrap_err();
        assert!(
            ber_error.to_string().contains("invalid exception tag"),
            "unexpected error: {ber_error}"
        );
    }

    // --- Round-trip tests ---

    #[test]
    fn given_varbind_with_null_when_round_tripped_then_recovers_identical_varbind() {
        let oid: Oid = "1.3.6.1".parse().unwrap();
        let null_tlv = encode_null_value();
        let varbind_bytes = encode_varbind(&oid, &null_tlv);
        let list_bytes = encode_varbind_list(&[&varbind_bytes]);

        let decoded = decode_varbind_list(&list_bytes).expect("round-trip should decode");
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].name, oid);
        assert_eq!(decoded[0].value, DecodedVarbindValue::Unspecified);
    }

    #[test]
    fn given_varbind_with_integer_when_round_tripped_then_recovers_identical_varbind() {
        let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        let integer_tlv = encode_integer_value(-42);
        let varbind_bytes = encode_varbind(&oid, &integer_tlv);
        let list_bytes = encode_varbind_list(&[&varbind_bytes]);

        let decoded = decode_varbind_list(&list_bytes).expect("round-trip should decode");
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].name, oid);
        assert_eq!(decoded[0].value, DecodedVarbindValue::Integer(-42));
    }

    #[test]
    fn given_varbind_with_octet_string_when_round_tripped_then_recovers_identical_varbind() {
        let oid: Oid = "1.3.6.1".parse().unwrap();
        let octet_string_tlv = encode_octet_string_value(b"hello world");
        let varbind_bytes = encode_varbind(&oid, &octet_string_tlv);
        let list_bytes = encode_varbind_list(&[&varbind_bytes]);

        let decoded = decode_varbind_list(&list_bytes).expect("round-trip should decode");
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].name, oid);
        assert_eq!(
            decoded[0].value,
            DecodedVarbindValue::OctetString(b"hello world".to_vec())
        );
    }

    #[test]
    fn given_varbind_with_oid_value_when_round_tripped_then_recovers_identical_varbind() {
        let name_oid: Oid = "1.3.6.1".parse().unwrap();
        let value_oid: Oid = "1.3.6.1.2.1".parse().unwrap();
        let oid_tlv = encode_oid_value(&value_oid);
        let varbind_bytes = encode_varbind(&name_oid, &oid_tlv);
        let list_bytes = encode_varbind_list(&[&varbind_bytes]);

        let decoded = decode_varbind_list(&list_bytes).expect("round-trip should decode");
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].name, name_oid);
        assert_eq!(
            decoded[0].value,
            DecodedVarbindValue::ObjectIdentifier(value_oid)
        );
    }

    #[test]
    fn given_varbind_with_no_such_object_when_round_tripped_then_recovers_exception() {
        let oid: Oid = "1.3.6.1".parse().unwrap();
        let exception_tlv = encode_exception(TAG_NO_SUCH_OBJECT).expect("must encode");
        let varbind_bytes = encode_varbind(&oid, &exception_tlv);
        let list_bytes = encode_varbind_list(&[&varbind_bytes]);

        let decoded = decode_varbind_list(&list_bytes).expect("round-trip should decode");
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].name, oid);
        assert_eq!(decoded[0].value, DecodedVarbindValue::NoSuchObject);
    }

    #[test]
    fn given_varbind_with_raw_counter32_when_round_tripped_then_recovers_raw_tag_and_bytes() {
        // Counter32 (APPLICATION tag 0x41) with value 1000 = 0x03E8
        let oid: Oid = "1.3.6.1".parse().unwrap();
        // Manually construct a Counter32 TLV: tag 0x41, length 2, value 0x03 0xE8
        let counter32_tlv: &[u8] = &[0x41, 0x02, 0x03, 0xE8];
        let varbind_bytes = encode_varbind(&oid, counter32_tlv);
        let list_bytes = encode_varbind_list(&[&varbind_bytes]);

        let decoded = decode_varbind_list(&list_bytes).expect("round-trip should decode");
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].name, oid);
        assert_eq!(
            decoded[0].value,
            DecodedVarbindValue::Raw {
                tag: TAG_COUNTER32,
                value_bytes: vec![0x03, 0xE8],
            }
        );
    }

    #[test]
    fn given_multiple_varbinds_when_round_tripped_then_recovers_all() {
        let oid1: Oid = "1.3.6.1".parse().unwrap();
        let oid2: Oid = "1.3.6.1.2.1".parse().unwrap();
        let vb1 = encode_varbind(&oid1, &encode_null_value());
        let vb2 = encode_varbind(&oid2, &encode_integer_value(99));
        let list_bytes = encode_varbind_list(&[&vb1, &vb2]);

        let decoded = decode_varbind_list(&list_bytes).expect("round-trip should decode");
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].name, oid1);
        assert_eq!(decoded[0].value, DecodedVarbindValue::Unspecified);
        assert_eq!(decoded[1].name, oid2);
        assert_eq!(decoded[1].value, DecodedVarbindValue::Integer(99));
    }

    // --- Error: truncated VarBind ---

    #[test]
    fn given_truncated_varbind_when_decoded_then_returns_error() {
        // VarBindList SEQUENCE containing a truncated VarBind (declares length 7
        // but only 4 bytes of content follow).
        // 30 06  — VarBindList SEQUENCE, length 6
        // 30 07  — VarBind SEQUENCE, declares length 7 but only 4 bytes remain
        // 06 03 2B 06  — OID TLV truncated (declares length 3, only 2 bytes)
        const TRUNCATED: &[u8] = &[0x30, 0x06, 0x30, 0x07, 0x06, 0x03, 0x2B, 0x06];
        let ber_error = decode_varbind_list(TRUNCATED).unwrap_err();
        assert!(
            ber_error.to_string().contains("truncated"),
            "unexpected error: {ber_error}"
        );
    }

    // --- Error: non-SEQUENCE outer tag ---

    #[test]
    fn given_non_sequence_outer_tag_when_decoded_then_returns_error() {
        // Tag 0x31 is SET, not SEQUENCE.
        const NOT_A_SEQUENCE: &[u8] = &[0x31, 0x00];
        let ber_error = decode_varbind_list(NOT_A_SEQUENCE).unwrap_err();
        assert!(
            ber_error.to_string().contains("0x30"),
            "unexpected error: {ber_error}"
        );
    }

    // --- Error: trailing bytes in VarBind SEQUENCE ---

    #[test]
    fn given_trailing_bytes_in_varbind_when_decoded_then_returns_error() {
        // VarBind SEQUENCE contains OID + NULL + extra junk byte 0xFF.
        // VarBind inner: OID(5) + NULL(2) + junk(1) = 8 → 30 08 06 03 2B 06 01 05 00 FF
        // VarBindList: 10 bytes → 30 0A 30 08 06 03 2B 06 01 05 00 FF
        const WITH_TRAILING: &[u8] = &[
            0x30, 0x0A, 0x30, 0x08, 0x06, 0x03, 0x2B, 0x06, 0x01, 0x05, 0x00,
            0xFF, // junk trailing byte inside the VarBind SEQUENCE
        ];
        let ber_error = decode_varbind_list(WITH_TRAILING).unwrap_err();
        assert!(
            ber_error.to_string().contains("trailing bytes"),
            "unexpected error: {ber_error}"
        );
    }

    // --- Error: trailing bytes after VarBindList SEQUENCE ---

    #[test]
    fn given_trailing_bytes_after_varbindlist_sequence_when_decoded_then_returns_error() {
        // VARBIND_LIST_OID1361_NULL with an extra 0xFF byte appended after the outer SEQUENCE.
        let mut with_trailing = VARBIND_LIST_OID1361_NULL.to_vec();
        with_trailing.push(0xFF);
        let ber_error = decode_varbind_list(&with_trailing).unwrap_err();
        assert!(
            ber_error.to_string().contains("trailing bytes"),
            "unexpected error: {ber_error}"
        );
    }

    // --- Error: exception tag with non-zero length ---

    #[test]
    fn given_exception_with_non_zero_length_when_decoded_then_returns_error() {
        // noSuchObject (0x80) with length 1 instead of 0: the decoder must reject it.
        // VarBind inner: OID 1.3.6.1 (5 bytes) + 0x80 0x01 0xFF (3 bytes) = 8 bytes
        // VarBindList: 30 0A 30 08 06 03 2B 06 01 80 01 FF
        const NONZERO_EXCEPTION: &[u8] = &[
            0x30, 0x0A, // VarBindList SEQUENCE, length 10
            0x30, 0x08, // VarBind SEQUENCE, length 8
            0x06, 0x03, 0x2B, 0x06, 0x01, // OID 1.3.6.1
            0x80, 0x01, 0xFF, // noSuchObject with length 1 (malformed)
        ];
        let ber_error = decode_varbind_list(NONZERO_EXCEPTION).unwrap_err();
        assert!(
            ber_error.to_string().contains("length 0"),
            "unexpected error: {ber_error}"
        );
    }

    // --- encode_varbind_value / decode_varbind_value_to_value: IpAddress ---

    #[test]
    fn given_ip_address_value_when_encoded_then_matches_wire() {
        let varbind_value = VarbindValue::Value(Value::IpAddress([10, 0, 0, 1]));
        let encoded_tlv = encode_varbind_value(&varbind_value).expect("must encode");
        assert_eq!(encoded_tlv, IP_ADDRESS_TLV);
    }

    #[test]
    fn given_raw_ip_address_when_decoded_to_value_then_returns_ip_address() {
        let raw = DecodedVarbindValue::Raw {
            tag: TAG_IP_ADDRESS,
            value_bytes: vec![10, 0, 0, 1],
        };
        let varbind_value = decode_varbind_value_to_value(&raw).expect("must decode");
        assert_eq!(
            varbind_value,
            VarbindValue::Value(Value::IpAddress([10, 0, 0, 1]))
        );
    }

    #[test]
    fn given_raw_ip_address_with_wrong_length_when_decoded_then_returns_error() {
        let raw_three_bytes = DecodedVarbindValue::Raw {
            tag: TAG_IP_ADDRESS,
            value_bytes: vec![10, 0, 0],
        };
        let ber_error = decode_varbind_value_to_value(&raw_three_bytes).unwrap_err();
        assert!(
            ber_error.to_string().contains("4 bytes"),
            "unexpected error: {ber_error}"
        );

        let raw_five_bytes = DecodedVarbindValue::Raw {
            tag: TAG_IP_ADDRESS,
            value_bytes: vec![10, 0, 0, 1, 2],
        };
        let ber_error = decode_varbind_value_to_value(&raw_five_bytes).unwrap_err();
        assert!(
            ber_error.to_string().contains("4 bytes"),
            "unexpected error: {ber_error}"
        );
    }

    #[test]
    fn given_raw_ip_address_with_zero_length_when_decoded_then_returns_error() {
        let raw_empty = DecodedVarbindValue::Raw {
            tag: TAG_IP_ADDRESS,
            value_bytes: vec![],
        };
        let ber_error = decode_varbind_value_to_value(&raw_empty).unwrap_err();
        assert!(
            ber_error.to_string().contains("4 bytes"),
            "unexpected error: {ber_error}"
        );
    }

    // --- encode_varbind_value / decode_varbind_value_to_value: Counter32 ---

    #[test]
    fn given_counter32_1000_when_encoded_then_matches_wire() {
        let varbind_value = VarbindValue::Value(Value::Counter32(1000));
        let encoded_tlv = encode_varbind_value(&varbind_value).expect("must encode");
        assert_eq!(encoded_tlv, COUNTER32_1000_TLV);
    }

    #[test]
    fn given_counter32_max_when_encoded_then_matches_wire() {
        let varbind_value = VarbindValue::Value(Value::Counter32(u32::MAX));
        let encoded_tlv = encode_varbind_value(&varbind_value).expect("must encode");
        assert_eq!(encoded_tlv, COUNTER32_MAX_TLV);
    }

    #[test]
    fn given_raw_counter32_1000_when_decoded_to_value_then_returns_counter32_1000() {
        let raw = DecodedVarbindValue::Raw {
            tag: TAG_COUNTER32,
            value_bytes: vec![0x03, 0xE8],
        };
        let varbind_value = decode_varbind_value_to_value(&raw).expect("must decode");
        assert_eq!(varbind_value, VarbindValue::Value(Value::Counter32(1000)));
    }

    #[test]
    fn given_raw_counter32_max_when_decoded_to_value_then_returns_counter32_max() {
        // u32::MAX = 0xFFFFFFFF, encoded with leading sign byte: 00 FF FF FF FF
        let raw = DecodedVarbindValue::Raw {
            tag: TAG_COUNTER32,
            value_bytes: vec![0x00, 0xFF, 0xFF, 0xFF, 0xFF],
        };
        let varbind_value = decode_varbind_value_to_value(&raw).expect("must decode");
        assert_eq!(
            varbind_value,
            VarbindValue::Value(Value::Counter32(u32::MAX))
        );
    }

    // --- encode_varbind_value / decode_varbind_value_to_value: Gauge32 ---

    #[test]
    fn given_gauge32_500_when_encoded_then_matches_wire() {
        let varbind_value = VarbindValue::Value(Value::Gauge32(500));
        let encoded_tlv = encode_varbind_value(&varbind_value).expect("must encode");
        assert_eq!(encoded_tlv, GAUGE32_500_TLV);
    }

    #[test]
    fn given_raw_gauge32_500_when_decoded_to_value_then_returns_gauge32_500() {
        let raw = DecodedVarbindValue::Raw {
            tag: TAG_GAUGE32,
            value_bytes: vec![0x01, 0xF4],
        };
        let varbind_value = decode_varbind_value_to_value(&raw).expect("must decode");
        assert_eq!(varbind_value, VarbindValue::Value(Value::Gauge32(500)));
    }

    // --- encode_varbind_value / decode_varbind_value_to_value: TimeTicks ---

    #[test]
    fn given_timeticks_360000_when_encoded_then_matches_wire() {
        let varbind_value = VarbindValue::Value(Value::TimeTicks(360_000));
        let encoded_tlv = encode_varbind_value(&varbind_value).expect("must encode");
        assert_eq!(encoded_tlv, TIMETICKS_360000_TLV);
    }

    #[test]
    fn given_raw_timeticks_360000_when_decoded_to_value_then_returns_timeticks_360000() {
        let raw = DecodedVarbindValue::Raw {
            tag: TAG_TIMETICKS,
            value_bytes: vec![0x05, 0x7E, 0x40],
        };
        let varbind_value = decode_varbind_value_to_value(&raw).expect("must decode");
        assert_eq!(
            varbind_value,
            VarbindValue::Value(Value::TimeTicks(360_000))
        );
    }

    // --- encode_varbind_value / decode_varbind_value_to_value: Opaque ---

    #[test]
    fn given_opaque_dead_when_encoded_then_matches_wire() {
        let varbind_value = VarbindValue::Value(Value::Opaque(vec![0xDE, 0xAD]));
        let encoded_tlv = encode_varbind_value(&varbind_value).expect("must encode");
        assert_eq!(encoded_tlv, OPAQUE_DEAD_TLV);
    }

    #[test]
    fn given_raw_opaque_dead_when_decoded_to_value_then_returns_opaque_dead() {
        let raw = DecodedVarbindValue::Raw {
            tag: TAG_OPAQUE,
            value_bytes: vec![0xDE, 0xAD],
        };
        let varbind_value = decode_varbind_value_to_value(&raw).expect("must decode");
        assert_eq!(
            varbind_value,
            VarbindValue::Value(Value::Opaque(vec![0xDE, 0xAD]))
        );
    }

    // --- encode_varbind_value / decode_varbind_value_to_value: Counter64 ---

    #[test]
    fn given_counter64_1000_when_encoded_then_matches_wire() {
        let varbind_value = VarbindValue::Value(Value::Counter64(1000));
        let encoded_tlv = encode_varbind_value(&varbind_value).expect("must encode");
        assert_eq!(encoded_tlv, COUNTER64_1000_TLV);
    }

    #[test]
    fn given_counter64_max_when_encoded_then_matches_wire() {
        let varbind_value = VarbindValue::Value(Value::Counter64(u64::MAX));
        let encoded_tlv = encode_varbind_value(&varbind_value).expect("must encode");
        assert_eq!(encoded_tlv, COUNTER64_MAX_TLV);
    }

    #[test]
    fn given_raw_counter64_1000_when_decoded_to_value_then_returns_counter64_1000() {
        let raw = DecodedVarbindValue::Raw {
            tag: TAG_COUNTER64,
            value_bytes: vec![0x03, 0xE8],
        };
        let varbind_value = decode_varbind_value_to_value(&raw).expect("must decode");
        assert_eq!(varbind_value, VarbindValue::Value(Value::Counter64(1000)));
    }

    // --- decode_varbind_value_to_value: unknown APPLICATION tag ---

    #[test]
    fn given_raw_with_unknown_tag_when_decoded_to_value_then_returns_error() {
        // Tag 0x45 (APPLICATION 5) is not a defined SMIv2 type.
        let raw = DecodedVarbindValue::Raw {
            tag: 0x45,
            value_bytes: vec![0x01],
        };
        let ber_error = decode_varbind_value_to_value(&raw).unwrap_err();
        assert!(
            ber_error
                .to_string()
                .contains("unsupported APPLICATION tag"),
            "unexpected error: {ber_error}"
        );
        assert!(
            ber_error.to_string().contains("0x45"),
            "error should include the unknown tag: {ber_error}"
        );
    }

    // --- decode_varbind_value_to_value: passthrough variants ---

    #[test]
    fn given_unspecified_when_decoded_to_value_then_returns_unspecified() {
        let decoded = DecodedVarbindValue::Unspecified;
        let varbind_value = decode_varbind_value_to_value(&decoded).expect("must decode");
        assert_eq!(varbind_value, VarbindValue::Unspecified);
    }

    #[test]
    fn given_no_such_object_when_decoded_to_value_then_returns_no_such_object() {
        let decoded = DecodedVarbindValue::NoSuchObject;
        let varbind_value = decode_varbind_value_to_value(&decoded).expect("must decode");
        assert_eq!(varbind_value, VarbindValue::NoSuchObject);
    }

    #[test]
    fn given_no_such_instance_when_decoded_to_value_then_returns_no_such_instance() {
        let decoded = DecodedVarbindValue::NoSuchInstance;
        let varbind_value = decode_varbind_value_to_value(&decoded).expect("must decode");
        assert_eq!(varbind_value, VarbindValue::NoSuchInstance);
    }

    #[test]
    fn given_end_of_mib_view_when_decoded_to_value_then_returns_end_of_mib_view() {
        let decoded = DecodedVarbindValue::EndOfMibView;
        let varbind_value = decode_varbind_value_to_value(&decoded).expect("must decode");
        assert_eq!(varbind_value, VarbindValue::EndOfMibView);
    }

    #[test]
    fn given_integer_42_when_decoded_to_value_then_returns_integer32_42() {
        let decoded = DecodedVarbindValue::Integer(42);
        let varbind_value = decode_varbind_value_to_value(&decoded).expect("must decode");
        assert_eq!(varbind_value, VarbindValue::Value(Value::Integer32(42)));
    }

    #[test]
    fn given_octet_string_when_decoded_to_value_then_returns_octet_string() {
        let decoded = DecodedVarbindValue::OctetString(b"hello".to_vec());
        let varbind_value = decode_varbind_value_to_value(&decoded).expect("must decode");
        assert_eq!(
            varbind_value,
            VarbindValue::Value(Value::OctetString(b"hello".to_vec()))
        );
    }

    #[test]
    fn given_object_identifier_when_decoded_to_value_then_returns_object_identifier() {
        let oid: Oid = "1.3.6.1.2.1".parse().unwrap();
        let decoded = DecodedVarbindValue::ObjectIdentifier(oid.clone());
        let varbind_value = decode_varbind_value_to_value(&decoded).expect("must decode");
        assert_eq!(
            varbind_value,
            VarbindValue::Value(Value::ObjectIdentifier(oid))
        );
    }

    // --- encode_varbind_value: passthrough/non-APPLICATION variants ---

    #[test]
    fn given_passthrough_variants_when_encoded_then_produce_expected_tlvs() {
        // Unspecified → NULL TLV
        assert_eq!(
            encode_varbind_value(&VarbindValue::Unspecified).expect("unspecified"),
            &[0x05, 0x00]
        );
        // NoSuchObject → exception tag 0x80
        assert_eq!(
            encode_varbind_value(&VarbindValue::NoSuchObject).expect("nso"),
            &[0x80, 0x00]
        );
        // NoSuchInstance → exception tag 0x81
        assert_eq!(
            encode_varbind_value(&VarbindValue::NoSuchInstance).expect("nsi"),
            &[0x81, 0x00]
        );
        // EndOfMibView → exception tag 0x82
        assert_eq!(
            encode_varbind_value(&VarbindValue::EndOfMibView).expect("eomv"),
            &[0x82, 0x00]
        );
        // Integer32(42) → INTEGER TLV
        assert_eq!(
            encode_varbind_value(&VarbindValue::Value(Value::Integer32(42))).expect("int"),
            &[0x02, 0x01, 0x2A]
        );
        // OctetString("Hi") → OCTET STRING TLV
        assert_eq!(
            encode_varbind_value(&VarbindValue::Value(Value::OctetString(b"Hi".to_vec())))
                .expect("oct"),
            &[0x04, 0x02, 0x48, 0x69]
        );
        // ObjectIdentifier(1.3.6.1) → OID TLV
        let oid: Oid = "1.3.6.1".parse().unwrap();
        assert_eq!(
            encode_varbind_value(&VarbindValue::Value(Value::ObjectIdentifier(oid))).expect("oid"),
            &[0x06, 0x03, 0x2B, 0x06, 0x01]
        );
    }

    // --- Full end-to-end pipeline round-trip: all APPLICATION types ---

    fn assert_full_pipeline_round_trip(original: &VarbindValue) {
        let oid: Oid = "1.3.6.1".parse().unwrap();
        let encoded_tlv = encode_varbind_value(original).expect("encode_varbind_value");
        let varbind_sequence = encode_varbind(&oid, &encoded_tlv);
        let varbind_list_bytes = encode_varbind_list(&[&varbind_sequence]);
        let decoded_varbinds =
            decode_varbind_list(&varbind_list_bytes).expect("decode_varbind_list");
        assert_eq!(decoded_varbinds.len(), 1);
        let recovered =
            decode_varbind_value_to_value(&decoded_varbinds[0].value).expect("decode_to_value");
        assert_eq!(recovered, *original);
    }

    #[test]
    fn given_application_tagged_values_when_full_pipeline_round_tripped_then_recover_all() {
        assert_full_pipeline_round_trip(&VarbindValue::Value(Value::IpAddress([192, 168, 1, 1])));
        assert_full_pipeline_round_trip(&VarbindValue::Value(Value::Counter32(1000)));
        assert_full_pipeline_round_trip(&VarbindValue::Value(Value::Counter32(u32::MAX)));
        assert_full_pipeline_round_trip(&VarbindValue::Value(Value::Gauge32(500)));
        assert_full_pipeline_round_trip(&VarbindValue::Value(Value::TimeTicks(360_000)));
        assert_full_pipeline_round_trip(&VarbindValue::Value(Value::Opaque(vec![0xDE, 0xAD])));
        assert_full_pipeline_round_trip(&VarbindValue::Value(Value::Counter64(1000)));
        assert_full_pipeline_round_trip(&VarbindValue::Value(Value::Counter64(u64::MAX)));
    }
}
