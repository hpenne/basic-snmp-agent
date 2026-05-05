//! BER encoding and decoding primitives for SNMP.
//!
//! This module provides low-level BER (Basic Encoding Rules, X.690) building blocks
//! that the SNMP codec layers use to read and write wire-format messages without
//! depending on a full ASN.1 framework:
//!
//! - Tag constants for every TLV type that appears in SNMPv2c/v3 messages.
//! - [`BerWriter`]: a byte accumulator that emits DER-canonical TLV encoding.
//! - [`BerReader`]: a cursor over a `&[u8]` slice that parses TLV encoding.
//! - [`BerError`]: the single error type returned by all parsing operations.
//!
use crate::codec::Oid;
use std::fmt;

pub(crate) mod pdu;
pub(crate) mod snmp;
pub(crate) mod varbind;

// ----- Tag constants --------------------------------------------------------

// Universal primitive tags (X.690 §8).

/// BER tag for ASN.1 INTEGER (universal primitive, tag 2).
pub(crate) const TAG_INTEGER: u8 = 0x02;

/// BER tag for ASN.1 OCTET STRING (universal primitive, tag 4).
pub(crate) const TAG_OCTET_STRING: u8 = 0x04;

/// BER tag for ASN.1 NULL (universal primitive, tag 5).
pub(crate) const TAG_NULL: u8 = 0x05;

/// BER tag for ASN.1 OBJECT IDENTIFIER (universal primitive, tag 6).
pub(crate) const TAG_OID: u8 = 0x06;

/// BER tag for ASN.1 SEQUENCE (universal constructed, tag 16, high bit set for constructed).
pub(crate) const TAG_SEQUENCE: u8 = 0x30;

// Context-tagged constructed IMPLICIT tags for SNMP PDU types (RFC 3416 §3).
// The 0xA0–0xA8 range is context class (bit 7–6 = 10), constructed (bit 5 = 1).

/// BER tag for `SNMPv2` `GetRequest-PDU` (context 0, constructed).
pub(crate) const TAG_GET_REQUEST: u8 = 0xA0;

/// BER tag for `SNMPv2` `GetNextRequest-PDU` (context 1, constructed).
pub(crate) const TAG_GET_NEXT_REQUEST: u8 = 0xA1;

/// BER tag for `SNMPv2` `Response-PDU` (context 2, constructed).
pub(crate) const TAG_RESPONSE: u8 = 0xA2;

/// BER tag for `SNMPv2` `SetRequest-PDU` (context 3, constructed).
pub(crate) const TAG_SET_REQUEST: u8 = 0xA3;

/// BER tag for `SNMPv1` `Trap-PDU` (context 4, constructed).
/// Not used in SNMPv2c/v3 but defined for completeness in PDU identification.
pub(crate) const TAG_TRAP_V1: u8 = 0xA4;

/// BER tag for `SNMPv2` `GetBulkRequest-PDU` (context 5, constructed).
pub(crate) const TAG_GET_BULK_REQUEST: u8 = 0xA5;

/// BER tag for `SNMPv2` `InformRequest-PDU` (context 6, constructed).
pub(crate) const TAG_INFORM_REQUEST: u8 = 0xA6;

/// BER tag for `SNMPv2` `Trap-PDU` (context 7, constructed).
pub(crate) const TAG_TRAP: u8 = 0xA7;

/// BER tag for `SNMPv3` `Report-PDU` (context 8, constructed).
pub(crate) const TAG_REPORT: u8 = 0xA8;

// Context-tagged primitive IMPLICIT tags for VarBind exception values (RFC 3416 §3).
// The 0x80–0x82 range is context class (bit 7–6 = 10), primitive (bit 5 = 0).

/// BER tag for `VarBind` `noSuchObject` exception (context 0, primitive).
pub(crate) const TAG_NO_SUCH_OBJECT: u8 = 0x80;

/// BER tag for `VarBind` `noSuchInstance` exception (context 1, primitive).
pub(crate) const TAG_NO_SUCH_INSTANCE: u8 = 0x81;

/// BER tag for `VarBind` `endOfMibView` exception (context 2, primitive).
pub(crate) const TAG_END_OF_MIB_VIEW: u8 = 0x82;

// APPLICATION primitive tags for SMIv2 types (RFC 2578 §7.1).
// The 0x40–0x46 range is application class (bit 7–6 = 01), primitive (bit 5 = 0).

/// BER tag for `SMIv2` `IpAddress` (application 0, primitive).
pub(crate) const TAG_IP_ADDRESS: u8 = 0x40;

/// BER tag for `SMIv2` `Counter32` (application 1, primitive).
pub(crate) const TAG_COUNTER32: u8 = 0x41;

/// BER tag for `SMIv2` `Gauge32` / `Unsigned32` (application 2, primitive).
pub(crate) const TAG_GAUGE32: u8 = 0x42;

/// BER tag for `SMIv2` `TimeTicks` (application 3, primitive).
pub(crate) const TAG_TIMETICKS: u8 = 0x43;

/// BER tag for `SMIv2` `Opaque` (application 4, primitive).
pub(crate) const TAG_OPAQUE: u8 = 0x44;

/// BER tag for `SMIv2` `Counter64` (application 6, primitive).
pub(crate) const TAG_COUNTER64: u8 = 0x46;

// ----- BerError -------------------------------------------------------------

/// Error returned by [`BerReader`] parsing operations.
pub(crate) struct BerError {
    message: String,
    is_wrong_version: bool,
}

impl BerError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            is_wrong_version: false,
        }
    }

    pub(crate) fn wrong_version(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            is_wrong_version: true,
        }
    }

    pub(crate) fn is_wrong_version(&self) -> bool {
        self.is_wrong_version
    }
}

impl fmt::Display for BerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl fmt::Debug for BerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BerError")
            .field("message", &self.message)
            .field("is_wrong_version", &self.is_wrong_version)
            .finish()
    }
}

impl std::error::Error for BerError {}

// ----- BerWriter ------------------------------------------------------------

/// Accumulates DER-canonical BER-encoded bytes.
///
/// The writer appends each TLV in DER canonical form (definite-length, shortest
/// length encoding). Use [`BerWriter::into_vec`] or [`BerWriter::as_bytes`] to
/// retrieve the completed encoding.
pub(crate) struct BerWriter {
    buffer: Vec<u8>,
}

impl BerWriter {
    /// Creates a new, empty writer.
    pub(crate) fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// Creates a new writer pre-allocated for `cap` bytes.
    pub(crate) fn with_capacity(cap: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(cap),
        }
    }

    /// Appends raw bytes verbatim (no tag or length prefix).
    pub(crate) fn write_raw(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// Appends a complete TLV: `tag`, then the DER-canonical length of `value`,
    /// then `value` itself.
    pub(crate) fn write_tlv(&mut self, tag: u8, value: &[u8]) {
        self.buffer.push(tag);
        encode_length(&mut self.buffer, value.len());
        self.buffer.extend_from_slice(value);
    }

    /// Appends a SEQUENCE TLV (`0x30` + length + contents).
    pub(crate) fn write_sequence(&mut self, contents: &[u8]) {
        self.write_tlv(TAG_SEQUENCE, contents);
    }

    /// Appends a constructed TLV with the given tag (used for context-tagged and
    /// application-tagged constructed wrappers).
    pub(crate) fn write_constructed(&mut self, tag: u8, contents: &[u8]) {
        self.write_tlv(tag, contents);
    }

    /// Appends a signed INTEGER TLV using the minimal two's-complement encoding.
    pub(crate) fn write_integer(&mut self, value: i32) {
        let encoded_value = encode_signed_i32(value);
        self.write_tlv(TAG_INTEGER, &encoded_value);
    }

    /// Appends an unsigned 32-bit value as an INTEGER TLV.
    ///
    /// A leading `0x00` byte is prepended when the high bit of the first
    /// significant byte is set, ensuring the value is interpreted as positive
    /// in the ASN.1 INTEGER two's-complement interpretation.
    pub(crate) fn write_unsigned32(&mut self, value: u32) {
        let encoded_value = encode_unsigned_u32(value);
        self.write_tlv(TAG_INTEGER, &encoded_value);
    }

    /// Appends an unsigned 64-bit value as an INTEGER TLV.
    ///
    /// A leading `0x00` byte is prepended when the high bit of the first
    /// significant byte is set (same sign-extension rule as `write_unsigned32`).
    pub(crate) fn write_unsigned64(&mut self, value: u64) {
        let encoded_value = encode_unsigned_u64(value);
        self.write_tlv(TAG_INTEGER, &encoded_value);
    }

    /// Appends an unsigned 32-bit value with the given tag instead of `TAG_INTEGER`.
    /// Used for APPLICATION-tagged `SMIv2` types (Counter32, Gauge32, `TimeTicks`).
    pub(crate) fn write_tagged_unsigned32(&mut self, tag: u8, value: u32) {
        let encoded_value = encode_unsigned_u32(value);
        self.write_tlv(tag, &encoded_value);
    }

    /// Appends an unsigned 64-bit value with the given tag instead of `TAG_INTEGER`.
    /// Used for APPLICATION-tagged Counter64.
    pub(crate) fn write_tagged_unsigned64(&mut self, tag: u8, value: u64) {
        let encoded_value = encode_unsigned_u64(value);
        self.write_tlv(tag, &encoded_value);
    }

    /// Appends an OCTET STRING TLV containing the given bytes.
    pub(crate) fn write_octet_string(&mut self, bytes: &[u8]) {
        self.write_tlv(TAG_OCTET_STRING, bytes);
    }

    /// Appends a NULL TLV (`0x05 0x00`).
    pub(crate) fn write_null(&mut self) {
        self.buffer.push(TAG_NULL);
        self.buffer.push(0x00);
    }

    /// Appends an OBJECT IDENTIFIER TLV using BER sub-identifier encoding.
    ///
    /// The first two OID arcs are combined into a single sub-identifier as
    /// `40 * first_arc + second_arc` per X.690 §8.19.4. Remaining arcs are
    /// encoded independently as base-128 variable-length integers.
    pub(crate) fn write_oid(&mut self, oid: &Oid) {
        let encoded_oid = encode_oid(oid);
        self.write_tlv(TAG_OID, &encoded_oid);
    }

    /// Returns the accumulated bytes as a slice.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.buffer
    }

    /// Returns the number of bytes accumulated so far.
    pub(crate) fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Consumes the writer and returns the accumulated bytes.
    pub(crate) fn into_vec(self) -> Vec<u8> {
        self.buffer
    }
}

impl Default for BerWriter {
    fn default() -> Self {
        Self::new()
    }
}

// ----- BerReader ------------------------------------------------------------

/// Parses BER-encoded TLV structures from a byte slice.
///
/// The reader maintains a cursor position within a bounded input slice. When
/// parsing nested structures (e.g. a SEQUENCE), [`BerReader::read_sequence`]
/// returns a new sub-reader bounded to the contents; the `base_offset` field
/// tracks the absolute byte position from the start of the original message,
/// which is useful for computing byte ranges for authentication.
#[derive(Debug)]
pub(crate) struct BerReader<'a> {
    input: &'a [u8],
    position: usize,
    /// Offset of `input[0]` from the beginning of the outermost message.
    /// Zero for top-level readers; set by `new_with_offset` for sub-readers.
    base_offset: usize,
}

impl<'a> BerReader<'a> {
    /// Creates a reader over `input` with `base_offset` = 0.
    pub(crate) fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            position: 0,
            base_offset: 0,
        }
    }

    /// Creates a reader over `input` whose byte 0 is at `base_offset` from the
    /// start of the original message.
    pub(crate) fn new_with_offset(input: &'a [u8], base_offset: usize) -> Self {
        Self {
            input,
            position: 0,
            base_offset,
        }
    }

    /// Returns the tag byte of the next TLV without advancing the cursor.
    pub(crate) fn peek_tag(&self) -> Result<u8, BerError> {
        self.input.get(self.position).copied().ok_or_else(|| {
            BerError::new(format!(
                "BER: unexpected end of input at offset {} while peeking tag",
                self.offset()
            ))
        })
    }

    /// Reads and returns the next tag byte, advancing the cursor by one.
    pub(crate) fn read_tag(&mut self) -> Result<u8, BerError> {
        let tag = self.peek_tag()?;
        self.position += 1;
        Ok(tag)
    }

    /// Reads and decodes a DER/BER definite-length field, advancing the cursor.
    pub(crate) fn read_length(&mut self) -> Result<usize, BerError> {
        let first_byte = self.input.get(self.position).copied().ok_or_else(|| {
            BerError::new(format!(
                "BER: unexpected end of input at offset {} while reading length",
                self.offset()
            ))
        })?;
        self.position += 1;

        if first_byte & 0x80 == 0 {
            // Short form: the byte itself is the length.
            return Ok(usize::from(first_byte));
        }

        // Long form: low seven bits are the number of subsequent length bytes.
        let extra_byte_count = usize::from(first_byte & 0x7F);
        if extra_byte_count == 0 {
            // Indefinite-length encoding — BER allows it but SNMP forbids it.
            return Err(BerError::new(format!(
                "BER: indefinite-length encoding is not permitted in SNMP at offset {}",
                self.offset()
            )));
        }

        let length_bytes = self
            .input
            .get(self.position..self.position + extra_byte_count)
            .ok_or_else(|| {
                BerError::new(format!(
                    "BER: truncated length field: need {} bytes at offset {}",
                    extra_byte_count,
                    self.offset()
                ))
            })?;
        self.position += extra_byte_count;

        // Accumulate into usize; reject values that overflow the platform word.
        let mut length: usize = 0;
        for &length_byte in length_bytes {
            length = length
                .checked_mul(256)
                .and_then(|shifted| shifted.checked_add(usize::from(length_byte)))
                .ok_or_else(|| {
                    BerError::new(format!(
                        "BER: length value overflows usize at offset {}",
                        self.offset()
                    ))
                })?;
        }
        Ok(length)
    }

    /// Reads the next TLV, returning `(tag, value_slice)`.
    ///
    /// The returned slice references the original input without copying.
    pub(crate) fn read_tlv(&mut self) -> Result<(u8, &'a [u8]), BerError> {
        let tag = self.read_tag()?;
        let length = self.read_length()?;
        // Guard against overflow in `self.position + length` for absurdly large
        // length values that fit in usize but exceed the remaining input.
        let remaining = self.input.len() - self.position;
        if length > remaining {
            return Err(BerError::new(format!(
                "BER: truncated value: length field ({length}) exceeds remaining input \
                 ({remaining} bytes) for tag 0x{tag:02X} at offset {}",
                self.offset()
            )));
        }
        // The guard above ensures self.position + length <= self.input.len().
        let value_slice = &self.input[self.position..self.position + length];
        self.position += length;
        Ok((tag, value_slice))
    }

    /// Reads the next TLV and verifies it has the expected tag.
    ///
    /// Returns `(tag_start_offset, value_bytes)` on success.
    fn read_expected_tlv(
        &mut self,
        expected_tag: u8,
        type_name: &str,
    ) -> Result<(usize, &'a [u8]), BerError> {
        let tag_start_offset = self.offset();
        let (tag, value_bytes) = self.read_tlv()?;
        if tag != expected_tag {
            return Err(BerError::new(format!(
                "BER: expected {type_name} (0x{expected_tag:02X}), got 0x{tag:02X} at offset {tag_start_offset}"
            )));
        }
        Ok((tag_start_offset, value_bytes))
    }

    /// Reads a SEQUENCE TLV and returns a sub-reader bounded to its contents.
    pub(crate) fn read_sequence(&mut self) -> Result<BerReader<'a>, BerError> {
        self.read_constructed(TAG_SEQUENCE)
    }

    /// Reads a constructed TLV with the given expected tag and returns a
    /// sub-reader bounded to its contents.
    pub(crate) fn read_constructed(&mut self, expected_tag: u8) -> Result<BerReader<'a>, BerError> {
        let tag_start_offset = self.offset();
        let (tag, contents) = self.read_tlv()?;
        if tag != expected_tag {
            return Err(BerError::new(format!(
                "BER: expected tag 0x{expected_tag:02X}, got 0x{tag:02X} at offset {tag_start_offset}"
            )));
        }
        // The sub-reader's base_offset is the absolute position of the first
        // byte of the contents (i.e. after the T and L fields we just consumed).
        let contents_offset = self.base_offset + self.position - contents.len();
        Ok(BerReader::new_with_offset(contents, contents_offset))
    }

    /// Reads an INTEGER TLV and returns its value as a signed `i32`.
    pub(crate) fn read_integer(&mut self) -> Result<i32, BerError> {
        let (tag_start_offset, integer_bytes) = self.read_expected_tlv(TAG_INTEGER, "INTEGER")?;
        decode_signed_i32(integer_bytes, tag_start_offset)
    }

    /// Reads an INTEGER TLV and returns its value as an unsigned `u32`.
    pub(crate) fn read_unsigned32(&mut self) -> Result<u32, BerError> {
        let (tag_start_offset, integer_bytes) = self.read_expected_tlv(TAG_INTEGER, "INTEGER")?;
        decode_unsigned_u32(integer_bytes, tag_start_offset)
    }

    /// Reads an INTEGER TLV and returns its value as an unsigned `u64`.
    pub(crate) fn read_unsigned64(&mut self) -> Result<u64, BerError> {
        let (tag_start_offset, integer_bytes) = self.read_expected_tlv(TAG_INTEGER, "INTEGER")?;
        decode_unsigned_u64(integer_bytes, tag_start_offset)
    }

    /// Reads an unsigned 32-bit INTEGER value with a specific expected tag.
    /// Used for APPLICATION-tagged `SMIv2` types.
    pub(crate) fn read_tagged_unsigned32(&mut self, expected_tag: u8) -> Result<u32, BerError> {
        let (tag_start_offset, integer_bytes) =
            self.read_expected_tlv(expected_tag, "tagged unsigned32")?;
        decode_unsigned_u32(integer_bytes, tag_start_offset)
    }

    /// Reads an unsigned 64-bit INTEGER value with a specific expected tag.
    /// Used for APPLICATION-tagged Counter64.
    pub(crate) fn read_tagged_unsigned64(&mut self, expected_tag: u8) -> Result<u64, BerError> {
        let (tag_start_offset, integer_bytes) =
            self.read_expected_tlv(expected_tag, "tagged unsigned64")?;
        decode_unsigned_u64(integer_bytes, tag_start_offset)
    }

    /// Reads an OCTET STRING TLV and returns a slice referencing the original input.
    pub(crate) fn read_octet_string(&mut self) -> Result<&'a [u8], BerError> {
        let (_, string_bytes) = self.read_expected_tlv(TAG_OCTET_STRING, "OCTET STRING")?;
        Ok(string_bytes)
    }

    /// Reads a NULL TLV, returning `()` on success.
    pub(crate) fn read_null(&mut self) -> Result<(), BerError> {
        let (tag_start_offset, null_contents) = self.read_expected_tlv(TAG_NULL, "NULL")?;
        if !null_contents.is_empty() {
            return Err(BerError::new(format!(
                "BER: NULL value must have length 0, got {} at offset {tag_start_offset}",
                null_contents.len()
            )));
        }
        Ok(())
    }

    /// Reads an OBJECT IDENTIFIER TLV and decodes it into an [`Oid`].
    pub(crate) fn read_oid(&mut self) -> Result<Oid, BerError> {
        let (tag_start_offset, oid_bytes) = self.read_expected_tlv(TAG_OID, "OID")?;
        decode_oid(oid_bytes, tag_start_offset)
    }

    /// Returns the bytes remaining in this reader (from the current position).
    pub(crate) fn remaining(&self) -> &'a [u8] {
        // position is always within bounds because read_tlv ensures it.
        &self.input[self.position..]
    }

    /// Returns `true` if there are no more bytes to read.
    pub(crate) fn is_empty(&self) -> bool {
        self.position >= self.input.len()
    }

    /// Returns the absolute byte offset of the reader's current position from
    /// the start of the outermost message.
    pub(crate) fn offset(&self) -> usize {
        self.base_offset + self.position
    }
}

// ----- Length encoding/decoding helpers -------------------------------------

/// Appends the DER-canonical length encoding for `length` to `dest`.
///
/// Short form (single byte) is used when `length ≤ 127`; the long form
/// (one length-of-length byte followed by the big-endian length bytes) is
/// used otherwise, always with the minimum number of length bytes.
fn encode_length(dest: &mut Vec<u8>, length: usize) {
    if length <= 127 {
        // Short form.
        dest.push(u8::try_from(length).expect("length ≤ 127 always fits in u8"));
    } else {
        // Long form: emit the big-endian bytes of `length` with leading zeros
        // stripped, then prefix with the number-of-bytes indicator byte.
        let length_bytes = length.to_be_bytes();
        let leading_zero_bytes =
            usize::try_from(length.leading_zeros()).expect("leading_zeros fits in usize") / 8;
        let significant_bytes = &length_bytes[leading_zero_bytes..];
        // X.690 §8.1.3.5: long-form length-of-length byte = 0x80 + number of subsequent octets.
        dest.push(
            0x80 + u8::try_from(significant_bytes.len()).expect("byte count of usize fits in u8"),
        );
        dest.extend_from_slice(significant_bytes);
    }
}

// ----- Integer encoding helpers ---------------------------------------------

/// Encodes `value` as the minimal two's-complement big-endian byte sequence
/// required for ASN.1 INTEGER.
///
/// - Non-negative: strip leading `0x00` bytes, but keep one if the next byte's
///   high bit is set (to preserve the non-negative sign).
/// - Negative: strip leading `0xFF` bytes, but keep one if the next byte's
///   high bit is clear (to preserve the negative sign).
fn encode_signed_i32(value: i32) -> Vec<u8> {
    let raw_bytes = value.to_be_bytes();
    let strip_byte = if value >= 0 { 0x00u8 } else { 0xFFu8 };

    // Find the first byte that is not the strippable prefix byte, but stop
    // one byte early so we never produce an empty slice.
    let first_significant = raw_bytes
        .iter()
        .position(|&byte| byte != strip_byte)
        .unwrap_or(raw_bytes.len() - 1);

    // If the remaining high bit has the wrong sign, back up one byte.
    let start = if value > 0 && raw_bytes[first_significant] & 0x80 != 0 {
        // High bit set on a positive value — need the preceding 0x00 byte.
        first_significant.saturating_sub(1)
    } else if value < 0 && raw_bytes[first_significant] & 0x80 == 0 {
        // High bit clear on a negative value — need the preceding 0xFF byte.
        first_significant.saturating_sub(1)
    } else {
        first_significant
    };

    raw_bytes[start..].to_vec()
}

/// Encodes `value` as the minimal unsigned big-endian byte sequence for an
/// ASN.1 INTEGER (i.e. prepends `0x00` when the high bit of the first
/// significant byte is set, to keep the sign positive).
fn encode_unsigned_u32(value: u32) -> Vec<u8> {
    encode_unsigned_bytes(&value.to_be_bytes())
}

/// Same as [`encode_unsigned_u32`] but for 64-bit values.
fn encode_unsigned_u64(value: u64) -> Vec<u8> {
    encode_unsigned_bytes(&value.to_be_bytes())
}

/// Shared implementation: strips leading zeros from `raw_bytes`, then prepends
/// a `0x00` sign byte if the first remaining byte has its high bit set.
fn encode_unsigned_bytes(raw_bytes: &[u8]) -> Vec<u8> {
    // Strip leading zeros, keeping at least one byte.
    let first_nonzero = raw_bytes
        .iter()
        .position(|&byte| byte != 0)
        .unwrap_or(raw_bytes.len() - 1);
    let significant = &raw_bytes[first_nonzero..];

    if significant[0] & 0x80 != 0 {
        // Prepend sign byte so ASN.1 INTEGER sees a positive value.
        let mut result = Vec::with_capacity(significant.len() + 1);
        result.push(0x00);
        result.extend_from_slice(significant);
        result
    } else {
        significant.to_vec()
    }
}

// ----- Integer decoding helpers ---------------------------------------------

/// Decodes a two's-complement INTEGER byte sequence into an `i32`.
///
/// Non-minimal encodings are accepted: BER permits redundant leading 0x00 bytes
/// for positive values and redundant leading 0xFF bytes for negative values.
/// These are stripped before checking the byte count, ensuring interoperability
/// with peer implementations that do not produce minimal encodings.
fn decode_signed_i32(integer_bytes: &[u8], error_offset: usize) -> Result<i32, BerError> {
    if integer_bytes.is_empty() {
        return Err(BerError::new(format!(
            "BER: INTEGER value has zero length at offset {error_offset}"
        )));
    }
    // Strip redundant padding bytes before the length check.
    // A leading 0x00 is redundant when the next byte has bit 7 clear (positive sign preserved).
    // A leading 0xFF is redundant when the next byte has bit 7 set (negative sign preserved).
    let is_negative = integer_bytes[0] & 0x80 != 0;
    let significant = if integer_bytes.len() > 1 {
        let redundant_byte = if is_negative { 0xFF } else { 0x00 };
        let sign_bit_of_next = if is_negative { 0x80 } else { 0x00 };
        let first_significant = integer_bytes
            .windows(2)
            .position(|pair| pair[0] != redundant_byte || (pair[1] & 0x80) != sign_bit_of_next)
            .unwrap_or(integer_bytes.len() - 1);
        &integer_bytes[first_significant..]
    } else {
        integer_bytes
    };
    if significant.len() > 4 {
        return Err(BerError::new(format!(
            "BER: INTEGER value too large for i32 ({} bytes) at offset {error_offset}",
            significant.len()
        )));
    }
    // Sign-extend the leading byte into a 4-byte buffer.
    let sign_byte = if significant[0] & 0x80 != 0 {
        0xFF
    } else {
        0x00
    };
    let mut word = [sign_byte; 4];
    let start = 4 - significant.len();
    word[start..].copy_from_slice(significant);
    Ok(i32::from_be_bytes(word))
}

/// Shared unsigned INTEGER decoder for up to `max_width` significant bytes.
///
/// Non-minimal encodings (redundant leading zero bytes) are accepted. BER permits
/// them; only DER requires minimal encoding. SNMP uses BER, so interoperability
/// demands that we tolerate any number of leading zeroes from peer implementations.
///
/// Returns the decoded value as `u64`; callers narrow to the target type.
fn decode_unsigned(
    integer_bytes: &[u8],
    max_width: usize,
    error_offset: usize,
) -> Result<u64, BerError> {
    if integer_bytes.is_empty() {
        return Err(BerError::new(format!(
            "BER: INTEGER value has zero length at offset {error_offset}"
        )));
    }
    // A first byte with the high bit set means a negative value in ASN.1
    // two's-complement; reject it as unsigned values cannot be negative.
    if integer_bytes[0] & 0x80 != 0 {
        return Err(BerError::new(format!(
            "BER: negative INTEGER cannot be decoded as unsigned at offset {error_offset}"
        )));
    }
    // BER permits any number of redundant leading 0x00 sign bytes; strip all of them
    // before checking the byte count so that non-minimal encodings from peer
    // implementations are accepted.  When every byte is 0x00 we keep the last one so
    // that the value zero is represented by [0x00] rather than an empty slice.
    let significant = if integer_bytes.len() > 1 {
        let first_nonzero = integer_bytes
            .iter()
            .position(|&b| b != 0x00)
            .unwrap_or(integer_bytes.len() - 1);
        &integer_bytes[first_nonzero..]
    } else {
        integer_bytes
    };
    if significant.len() > max_width {
        return Err(BerError::new(format!(
            "BER: INTEGER value too large for u{} ({} bytes) at offset {error_offset}",
            max_width * 8,
            significant.len()
        )));
    }
    let mut word = [0u8; 8];
    let start = 8 - significant.len();
    word[start..].copy_from_slice(significant);
    Ok(u64::from_be_bytes(word))
}

/// Decodes a BER-encoded unsigned INTEGER into a `u32`.
fn decode_unsigned_u32(integer_bytes: &[u8], error_offset: usize) -> Result<u32, BerError> {
    let value = decode_unsigned(integer_bytes, 4, error_offset)?;
    // Safe: decode_unsigned with max_width=4 guarantees value fits in u32.
    Ok(
        u32::try_from(value)
            .expect("decode_unsigned with max_width=4 guarantees value fits in u32"),
    )
}

/// Decodes a BER-encoded unsigned INTEGER into a `u64`.
fn decode_unsigned_u64(integer_bytes: &[u8], error_offset: usize) -> Result<u64, BerError> {
    decode_unsigned(integer_bytes, 8, error_offset)
}

// ----- OID encoding/decoding helpers ----------------------------------------

/// Encodes `oid` as a BER OID value (without the tag or length prefix).
///
/// The first two arcs are combined as `40 * first_arc + second_arc` per
/// X.690 §8.19.4. Each sub-identifier is then encoded as a base-128
/// variable-length integer with the high bit set on all but the last byte.
///
/// The combined value is computed as u64 to avoid overflow when the first arc
/// is 2 and the second arc is large (e.g., `2.999999999`).
fn encode_oid(oid: &Oid) -> Vec<u8> {
    let arcs = oid.as_slice();
    // Validated OIDs always have at least two arcs.
    let first_combined = u64::from(arcs[0]) * 40 + u64::from(arcs[1]);
    let remaining_arcs = &arcs[2..];

    let mut encoded = Vec::new();
    encode_base128(&mut encoded, first_combined);
    for &arc in remaining_arcs {
        encode_base128(&mut encoded, u64::from(arc));
    }
    encoded
}

// ceil(u64::BITS / 7) = ceil(64/7) = 10
const MAX_BASE128_GROUPS: usize = 10;

/// Appends the base-128 variable-length encoding of `value` to `dest`.
///
/// The high bit of each byte is 1 for all bytes except the last, which
/// signals the end of the sub-identifier (X.690 §8.19.2).
///
/// The parameter is u64 to accommodate the combined first two arcs of OIDs
/// with a first arc of 2 and a large second arc (e.g., `2.999999999`).
fn encode_base128(dest: &mut Vec<u8>, value: u64) {
    if value == 0 {
        dest.push(0x00);
        return;
    }
    // Collect groups of 7 bits from most-significant to least-significant.
    let mut groups = [0u8; MAX_BASE128_GROUPS];
    let mut remaining = value;
    let mut group_count = 0;
    while remaining > 0 {
        groups[group_count] =
            u8::try_from(remaining & 0x7F).expect("masking to 7 bits always fits in u8");
        remaining >>= 7;
        group_count += 1;
    }
    // Emit groups in big-endian order (most significant first).
    for i in (0..group_count).rev() {
        let high_bit = if i > 0 { 0x80 } else { 0x00 };
        // + rather than | so that operator mutations (+ → −) are detectable by tests.
        dest.push(groups[i] + high_bit);
    }
}

/// Decodes a BER OID value byte sequence into an [`Oid`].
fn decode_oid(oid_bytes: &[u8], error_offset: usize) -> Result<Oid, BerError> {
    if oid_bytes.is_empty() {
        return Err(BerError::new(format!(
            "BER: OID value has zero length at offset {error_offset}"
        )));
    }

    let mut sub_identifiers: Vec<u64> = Vec::new();
    let mut remaining = oid_bytes;
    while !remaining.is_empty() {
        let (sub_id, bytes_consumed) = decode_base128(remaining, error_offset)?;
        // Guard against an infinite loop if decode_base128 is ever buggy in a release build.
        debug_assert_ne!(
            bytes_consumed, 0,
            "decode_base128 must consume at least one byte"
        );
        if bytes_consumed == 0 {
            return Err(BerError::new(format!(
                "BER: internal error: zero bytes consumed decoding OID sub-identifier at offset {error_offset}"
            )));
        }
        sub_identifiers.push(sub_id);
        remaining = &remaining[bytes_consumed..];
    }

    // Split the first combined sub-identifier back into two arcs.
    // X.690 §8.19.4: first = combined / 40, second = combined % 40,
    // but when combined >= 80 the first arc is always 2.
    let first_combined = sub_identifiers[0];
    let (first_arc, second_arc) = if first_combined < 40 {
        (0u64, first_combined)
    } else if first_combined < 80 {
        (1u64, first_combined - 40)
    } else {
        (2u64, first_combined - 80)
    };

    // Convert decoded u64 arcs to u32 for the Oid type.
    let first_arc_u32 = u32::try_from(first_arc).map_err(|_| {
        BerError::new(format!(
            "BER: OID first arc overflows u32 at offset {error_offset}"
        ))
    })?;
    let second_arc_u32 = u32::try_from(second_arc).map_err(|_| {
        BerError::new(format!(
            "BER: OID second arc overflows u32 at offset {error_offset}"
        ))
    })?;

    let mut arcs = Vec::with_capacity(sub_identifiers.len() + 1);
    arcs.push(first_arc_u32);
    arcs.push(second_arc_u32);
    for sub_id in &sub_identifiers[1..] {
        let arc_u32 = u32::try_from(*sub_id).map_err(|_| {
            BerError::new(format!(
                "BER: OID arc overflows u32 at offset {error_offset}"
            ))
        })?;
        arcs.push(arc_u32);
    }

    Oid::try_from(arcs).map_err(|oid_error| {
        BerError::new(format!(
            "BER: decoded OID is structurally invalid at offset {error_offset}: {oid_error}"
        ))
    })
}

/// Decodes one base-128 sub-identifier from the start of `bytes`.
///
/// Returns `(sub_identifier_value, bytes_consumed)`.
///
/// The return type uses u64 to accommodate the combined first two OID arcs
/// when the first arc is 2 and the second arc is large.
fn decode_base128(bytes: &[u8], error_offset: usize) -> Result<(u64, usize), BerError> {
    let mut accumulator: u64 = 0;
    let mut bytes_consumed = 0;

    loop {
        let byte = bytes.get(bytes_consumed).copied().ok_or_else(|| {
            BerError::new(format!(
                "BER: truncated OID sub-identifier at offset {error_offset}"
            ))
        })?;

        // X.690 §8.19.2: a leading 0x80 byte (continuation bit set, value
        // bits all zero) is a non-minimal encoding — equivalent to a leading
        // zero in base-128. Reject to prevent acceptance of non-canonical wire.
        // 0x80 is the only possible non-minimal leading byte: any other byte with
        // the continuation bit set has non-zero value bits and is therefore significant.
        if bytes_consumed == 0 && byte == 0x80 {
            return Err(BerError::new(format!(
                "BER: non-minimal OID sub-identifier encoding (leading 0x80) at offset {error_offset}"
            )));
        }

        bytes_consumed += 1;

        accumulator = accumulator
            .checked_shl(7)
            .and_then(|shifted| shifted.checked_add(u64::from(byte & 0x7F)))
            .ok_or_else(|| {
                BerError::new(format!(
                    "BER: OID sub-identifier overflows u64 at offset {error_offset}"
                ))
            })?;

        if byte & 0x80 == 0 {
            // Last byte of this sub-identifier.
            break;
        }
    }

    Ok((accumulator, bytes_consumed))
}

// ----- Tests ----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Length encoding ---

    #[test]
    fn given_length_zero_when_encoded_then_short_form_single_byte() {
        let mut dest = Vec::new();
        encode_length(&mut dest, 0);
        assert_eq!(dest, [0x00]);
    }

    #[test]
    fn given_length_1_when_encoded_then_short_form_single_byte() {
        let mut dest = Vec::new();
        encode_length(&mut dest, 1);
        assert_eq!(dest, [0x01]);
    }

    #[test]
    fn given_length_127_when_encoded_then_short_form_single_byte() {
        let mut dest = Vec::new();
        encode_length(&mut dest, 127);
        assert_eq!(dest, [0x7F]);
    }

    #[test]
    fn given_length_128_when_encoded_then_long_form_two_bytes() {
        let mut dest = Vec::new();
        encode_length(&mut dest, 128);
        assert_eq!(dest, [0x81, 0x80]);
    }

    #[test]
    fn given_length_255_when_encoded_then_long_form_two_bytes() {
        let mut dest = Vec::new();
        encode_length(&mut dest, 255);
        assert_eq!(dest, [0x81, 0xFF]);
    }

    #[test]
    fn given_length_256_when_encoded_then_long_form_three_bytes() {
        let mut dest = Vec::new();
        encode_length(&mut dest, 256);
        assert_eq!(dest, [0x82, 0x01, 0x00]);
    }

    #[test]
    fn given_length_65535_when_encoded_then_long_form_three_bytes() {
        let mut dest = Vec::new();
        encode_length(&mut dest, 65535);
        assert_eq!(dest, [0x82, 0xFF, 0xFF]);
    }

    // --- Length decoding (round-trip) ---

    fn round_trip_length(length: usize) -> usize {
        let mut dest = Vec::new();
        encode_length(&mut dest, length);
        let mut reader = BerReader::new(&dest);
        reader.read_length().expect("length should decode cleanly")
    }

    #[test]
    fn given_length_0_when_round_tripped_then_recovers_value() {
        assert_eq!(round_trip_length(0), 0);
    }

    #[test]
    fn given_length_1_when_round_tripped_then_recovers_value() {
        assert_eq!(round_trip_length(1), 1);
    }

    #[test]
    fn given_length_127_when_round_tripped_then_recovers_value() {
        assert_eq!(round_trip_length(127), 127);
    }

    #[test]
    fn given_length_128_when_round_tripped_then_recovers_value() {
        assert_eq!(round_trip_length(128), 128);
    }

    #[test]
    fn given_length_255_when_round_tripped_then_recovers_value() {
        assert_eq!(round_trip_length(255), 255);
    }

    #[test]
    fn given_length_256_when_round_tripped_then_recovers_value() {
        assert_eq!(round_trip_length(256), 256);
    }

    #[test]
    fn given_length_65535_when_round_tripped_then_recovers_value() {
        assert_eq!(round_trip_length(65535), 65535);
    }

    #[test]
    fn given_empty_input_when_read_length_then_returns_error() {
        let mut reader = BerReader::new(&[]);
        let ber_error = reader.read_length().unwrap_err();
        assert!(
            ber_error.to_string().contains("unexpected end of input"),
            "unexpected error: {ber_error}"
        );
    }

    #[test]
    fn given_long_form_length_with_truncated_bytes_when_read_length_then_returns_error() {
        // 0x82 says "2 following bytes", but only 1 byte follows.
        let truncated = [0x82, 0x01];
        let mut reader = BerReader::new(&truncated);
        let ber_error = reader.read_length().unwrap_err();
        assert!(
            ber_error.to_string().contains("truncated"),
            "unexpected error: {ber_error}"
        );
    }

    #[test]
    fn given_indefinite_length_encoding_when_read_length_then_returns_error() {
        // Verifies: REQ-0000
        // 0x80 with zero extra-byte count means indefinite length (forbidden in SNMP).
        let indefinite = [0x80];
        let mut reader = BerReader::new(&indefinite);
        let ber_error = reader.read_length().unwrap_err();
        assert!(
            ber_error.to_string().contains("indefinite"),
            "unexpected error: {ber_error}"
        );
    }

    #[test]
    fn given_long_form_length_exceeding_input_when_read_tlv_then_returns_error() {
        // Verifies: REQ-0000
        // 0x02 is INTEGER tag; 0x84 means 4 subsequent bytes encode the length.
        // Length = 0x7FFFFFFF = 2147483647 — fits in usize on all platforms but
        // far exceeds the 0 bytes of input remaining after the tag and length field.
        let absurd_tlv = [0x02, 0x84, 0x7F, 0xFF, 0xFF, 0xFF];
        let mut reader = BerReader::new(&absurd_tlv);
        let ber_error = reader.read_tlv().unwrap_err();
        assert!(
            ber_error.to_string().contains("exceeds remaining input"),
            "unexpected error: {ber_error}"
        );
    }

    #[test]
    fn given_long_form_length_larger_than_available_data_when_read_tlv_then_returns_error() {
        // Verifies: REQ-0000
        // 0x02 is INTEGER tag; 0x83 means 3 subsequent bytes encode the length = 0x0F4240 = 1000000 bytes.
        // Only 3 value bytes follow, so the length exceeds the remaining input.
        let large_tlv = [0x02, 0x83, 0x0F, 0x42, 0x40, 0xAA, 0xBB, 0xCC];
        let mut reader = BerReader::new(&large_tlv);
        let ber_error = reader.read_tlv().unwrap_err();
        assert!(
            ber_error.to_string().contains("exceeds remaining input"),
            "unexpected error: {ber_error}"
        );
    }

    // --- Signed integer encoding ---

    #[test]
    fn given_integer_zero_when_encoded_then_single_zero_byte() {
        assert_eq!(encode_signed_i32(0), [0x00]);
    }

    #[test]
    fn given_integer_1_when_encoded_then_single_byte_0x01() {
        assert_eq!(encode_signed_i32(1), [0x01]);
    }

    #[test]
    fn given_integer_minus1_when_encoded_then_single_byte_0xff() {
        assert_eq!(encode_signed_i32(-1), [0xFF]);
    }

    #[test]
    fn given_integer_127_when_encoded_then_single_byte_0x7f() {
        assert_eq!(encode_signed_i32(127), [0x7F]);
    }

    #[test]
    fn given_integer_128_when_encoded_then_two_bytes_with_sign_extension() {
        // 128 = 0x0080: high bit of 0x80 is set, so a leading 0x00 is needed.
        assert_eq!(encode_signed_i32(128), [0x00, 0x80]);
    }

    #[test]
    fn given_integer_minus128_when_encoded_then_single_byte_0x80() {
        // -128 = 0x80 in two's complement — no extension needed.
        assert_eq!(encode_signed_i32(-128), [0x80]);
    }

    #[test]
    fn given_integer_minus129_when_encoded_then_two_bytes_0xff7f() {
        // -129 = 0xFFFFFF7F; strip leading 0xFF → keep [0xFF, 0x7F].
        // High bit of 0xFF is set (negative), so no extra 0xFF needed.
        assert_eq!(encode_signed_i32(-129), [0xFF, 0x7F]);
    }

    #[test]
    fn given_integer_max_i32_when_encoded_then_five_bytes() {
        // i32::MAX = 0x7FFFFFFF — sign byte 0x00 is not needed (high bit is 0).
        assert_eq!(encode_signed_i32(i32::MAX), [0x7F, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn given_integer_min_i32_when_encoded_then_four_bytes() {
        // i32::MIN = 0x80000000 — the high bit is 1 (negative), single sign byte.
        assert_eq!(encode_signed_i32(i32::MIN), [0x80, 0x00, 0x00, 0x00]);
    }

    // --- Unsigned32 encoding ---

    #[test]
    fn given_unsigned32_zero_when_encoded_then_single_zero_byte() {
        assert_eq!(encode_unsigned_u32(0), [0x00]);
    }

    #[test]
    fn given_unsigned32_127_when_encoded_then_single_byte_0x7f() {
        assert_eq!(encode_unsigned_u32(127), [0x7F]);
    }

    #[test]
    fn given_unsigned32_128_when_encoded_then_two_bytes_with_sign_byte() {
        assert_eq!(encode_unsigned_u32(128), [0x00, 0x80]);
    }

    #[test]
    fn given_unsigned32_255_when_encoded_then_two_bytes_with_sign_byte() {
        assert_eq!(encode_unsigned_u32(255), [0x00, 0xFF]);
    }

    #[test]
    fn given_unsigned32_256_when_encoded_then_two_bytes_no_sign_byte() {
        assert_eq!(encode_unsigned_u32(256), [0x01, 0x00]);
    }

    #[test]
    fn given_unsigned32_max_when_encoded_then_five_bytes_with_sign_byte() {
        // u32::MAX = 0xFFFFFFFF — high bit set, prepend 0x00.
        assert_eq!(
            encode_unsigned_u32(u32::MAX),
            [0x00, 0xFF, 0xFF, 0xFF, 0xFF]
        );
    }

    // --- Unsigned64 encoding ---

    #[test]
    fn given_unsigned64_zero_when_encoded_then_single_zero_byte() {
        assert_eq!(encode_unsigned_u64(0), [0x00]);
    }

    #[test]
    fn given_unsigned64_u32_max_when_encoded_then_five_bytes_with_sign_byte() {
        assert_eq!(
            encode_unsigned_u64(u64::from(u32::MAX)),
            [0x00, 0xFF, 0xFF, 0xFF, 0xFF]
        );
    }

    #[test]
    fn given_unsigned64_max_when_encoded_then_nine_bytes_with_sign_byte() {
        // u64::MAX = 0xFFFFFFFF_FFFFFFFF — high bit set, prepend 0x00.
        assert_eq!(
            encode_unsigned_u64(u64::MAX),
            [0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        );
    }

    // --- BerWriter / BerReader round-trips for typed values ---

    fn encode_with_writer(write_fn: impl Fn(&mut BerWriter)) -> Vec<u8> {
        let mut writer = BerWriter::new();
        write_fn(&mut writer);
        writer.into_vec()
    }

    #[test]
    fn given_octet_string_empty_when_round_tripped_then_recovers_empty_slice() {
        let encoded = encode_with_writer(|w| w.write_octet_string(&[]));
        let recovered = BerReader::new(&encoded)
            .read_octet_string()
            .expect("octet string should decode");
        assert_eq!(recovered, b"");
    }

    #[test]
    fn given_octet_string_short_when_round_tripped_then_recovers_bytes() {
        let payload = b"hello";
        let encoded = encode_with_writer(|w| w.write_octet_string(payload));
        let recovered = BerReader::new(&encoded)
            .read_octet_string()
            .expect("octet string should decode");
        assert_eq!(recovered, payload);
    }

    #[test]
    fn given_octet_string_medium_when_round_tripped_then_recovers_bytes() {
        // 200-byte payload forces the long-form length encoding path.
        let payload: Vec<u8> = (0u8..=199).collect();
        let encoded = encode_with_writer(|w| w.write_octet_string(&payload));
        let recovered = BerReader::new(&encoded)
            .read_octet_string()
            .expect("octet string should decode");
        assert_eq!(recovered, payload.as_slice());
    }

    #[test]
    fn given_null_when_round_tripped_then_returns_unit() {
        let mut writer = BerWriter::new();
        writer.write_null();
        let encoded = writer.into_vec();
        BerReader::new(&encoded)
            .read_null()
            .expect("null should decode");
    }

    // --- OID round-trips ---

    #[test]
    fn given_standard_snmp_oid_when_round_tripped_then_recovers_oid() {
        // Verifies: REQ-0000
        // 1.3.6.1.2.1.1.1.0
        // Combined first: 40*1+3 = 43 = 0x2B
        // Remaining arcs: 6, 1, 2, 1, 1, 1, 0 — all single-byte base-128
        // Wire: 06 08 2B 06 01 02 01 01 01 00
        const SNMP_SYSNAME_OID_WIRE: &[u8] =
            &[0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];
        let original: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        let encoded = encode_with_writer(|w| w.write_oid(&original));
        assert_eq!(encoded, SNMP_SYSNAME_OID_WIRE);
        let recovered = BerReader::new(&encoded)
            .read_oid()
            .expect("OID should decode");
        assert_eq!(recovered, original);
    }

    #[test]
    fn given_oid_with_large_arc_when_round_tripped_then_recovers_oid() {
        // Verifies: REQ-0000
        // 1.3.6.1.4.1.99999
        // Combined first: 43 = 0x2B
        // Remaining: 6(0x06), 1(0x01), 4(0x04), 1(0x01), 99999
        // 99999 = 0x1869F
        // Base-128 groups (7 bits from LSB): 0x1F, 0x0D, 0x06 → with cont. bits: [0x86, 0x8D, 0x1F]
        // Wire: 06 08 2B 06 01 04 01 86 8D 1F
        const ENTERPRISE_LARGE_ARC_OID_WIRE: &[u8] =
            &[0x06, 0x08, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x86, 0x8D, 0x1F];
        let original: Oid = "1.3.6.1.4.1.99999".parse().unwrap();
        let encoded = encode_with_writer(|w| w.write_oid(&original));
        assert_eq!(encoded, ENTERPRISE_LARGE_ARC_OID_WIRE);
        let recovered = BerReader::new(&encoded)
            .read_oid()
            .expect("OID should decode");
        assert_eq!(recovered, original);
    }

    #[test]
    fn given_arc_zero_oid_when_round_tripped_then_recovers() {
        // Verifies: REQ-0000
        // 0.0 → combined first sub-id = 40*0+0 = 0x00
        // Wire: 06 01 00
        const EXPECTED_WIRE: &[u8] = &[0x06, 0x01, 0x00];
        let oid: Oid = "0.0".parse().unwrap();
        let encoded = encode_with_writer(|w| w.write_oid(&oid));
        assert_eq!(encoded, EXPECTED_WIRE);
        let recovered = BerReader::new(&encoded)
            .read_oid()
            .expect("OID should decode");
        assert_eq!(recovered, oid);
    }

    #[test]
    fn given_arc_two_oid_with_large_second_arc_when_round_tripped_then_recovers() {
        // Verifies: REQ-0000
        // 2.999 → combined = 40*2+999 = 1079 = 0x437
        // Base-128: 0x437 groups from LSB: 0x37, 0x08 → with cont. bits: [0x88, 0x37]
        // Wire: 06 02 88 37
        const EXPECTED_WIRE: &[u8] = &[0x06, 0x02, 0x88, 0x37];
        let oid: Oid = "2.999".parse().unwrap();
        let encoded = encode_with_writer(|w| w.write_oid(&oid));
        assert_eq!(encoded, EXPECTED_WIRE);
        let recovered = BerReader::new(&encoded)
            .read_oid()
            .expect("OID should decode");
        assert_eq!(recovered, oid);
    }

    #[test]
    fn given_oid_with_max_u32_arc_when_round_tripped_then_recovers() {
        // Verifies: REQ-0000
        // 1.3.4294967295 → combined first = 40*1+3 = 43 = 0x2B
        // 4294967295 = 0xFFFFFFFF
        // Base-128 of 0xFFFFFFFF (from LSB): 0x7F,0x7F,0x7F,0x7F,0x0F
        // with continuation bits: [0x8F, 0xFF, 0xFF, 0xFF, 0x7F]
        // Wire: 06 06 2B 8F FF FF FF 7F
        const EXPECTED_WIRE: &[u8] = &[0x06, 0x06, 0x2B, 0x8F, 0xFF, 0xFF, 0xFF, 0x7F];
        let oid: Oid = "1.3.4294967295".parse().unwrap();
        let encoded = encode_with_writer(|w| w.write_oid(&oid));
        assert_eq!(encoded, EXPECTED_WIRE);
        let recovered = BerReader::new(&encoded)
            .read_oid()
            .expect("OID should decode");
        assert_eq!(recovered, oid);
    }

    // --- Signed integer round-trips ---

    fn integer_round_trip(value: i32) -> i32 {
        let encoded = encode_with_writer(|w| w.write_integer(value));
        BerReader::new(&encoded)
            .read_integer()
            .expect("integer should decode")
    }

    #[test]
    fn given_boundary_integers_when_round_tripped_then_recover_original_values() {
        for value in [0, 1, -1, 127, 128, -128, -129, i32::MAX, i32::MIN] {
            assert_eq!(
                integer_round_trip(value),
                value,
                "round-trip failed for {value}"
            );
        }
    }

    #[test]
    fn given_integer_42_when_encoded_then_matches_expected_wire() {
        // Verifies: REQ-0000
        // INTEGER 42: tag=0x02, len=0x01, value=0x2A
        const EXPECTED_WIRE: &[u8] = &[0x02, 0x01, 0x2A];
        let encoded = encode_with_writer(|w| w.write_integer(42));
        assert_eq!(encoded, EXPECTED_WIRE);
    }

    // --- Unsigned32 integer round-trips ---

    fn unsigned32_round_trip(value: u32) -> u32 {
        let encoded = encode_with_writer(|w| w.write_unsigned32(value));
        BerReader::new(&encoded)
            .read_unsigned32()
            .expect("unsigned32 should decode")
    }

    #[test]
    fn given_boundary_unsigned32s_when_round_tripped_then_recover_original_values() {
        for value in [0u32, 127, 128, 255, 256, u32::MAX] {
            assert_eq!(
                unsigned32_round_trip(value),
                value,
                "round-trip failed for {value}"
            );
        }
    }

    // --- Unsigned64 integer round-trips ---

    fn unsigned64_round_trip(value: u64) -> u64 {
        let encoded = encode_with_writer(|w| w.write_unsigned64(value));
        BerReader::new(&encoded)
            .read_unsigned64()
            .expect("unsigned64 should decode")
    }

    #[test]
    fn given_boundary_unsigned64s_when_round_tripped_then_recover_original_values() {
        for value in [0u64, u64::from(u32::MAX), u64::MAX] {
            assert_eq!(
                unsigned64_round_trip(value),
                value,
                "round-trip failed for {value}"
            );
        }
    }

    // --- SEQUENCE nesting ---

    #[test]
    fn given_sequence_with_integer_and_octet_string_when_round_tripped_then_recovers_both() {
        // Write a SEQUENCE containing an INTEGER and an OCTET STRING.
        let mut inner_writer = BerWriter::new();
        inner_writer.write_integer(42);
        inner_writer.write_octet_string(b"test");

        let mut outer_writer = BerWriter::new();
        outer_writer.write_sequence(inner_writer.as_bytes());

        let encoded_sequence = outer_writer.into_vec();
        let mut outer_reader = BerReader::new(&encoded_sequence);
        let mut inner_reader = outer_reader.read_sequence().expect("sequence should parse");

        let recovered_integer = inner_reader.read_integer().expect("integer should parse");
        let recovered_string = inner_reader
            .read_octet_string()
            .expect("octet string should parse");

        assert_eq!(recovered_integer, 42);
        assert_eq!(recovered_string, b"test");
        assert!(
            inner_reader.is_empty(),
            "all sequence contents should be consumed"
        );
    }

    // --- BerReader offset tracking ---

    #[test]
    fn given_reader_at_start_when_offset_queried_then_returns_zero() {
        let mut writer = BerWriter::new();
        writer.write_null();
        let encoded = writer.into_vec();
        let reader = BerReader::new(&encoded);
        assert_eq!(reader.offset(), 0);
    }

    #[test]
    fn given_reader_after_reading_null_when_offset_queried_then_returns_two() {
        // NULL encodes as exactly 2 bytes: 0x05 0x00.
        let mut writer = BerWriter::new();
        writer.write_null();
        let encoded = writer.into_vec();
        let mut reader = BerReader::new(&encoded);
        reader.read_null().expect("null should parse");
        assert_eq!(reader.offset(), 2);
    }

    #[test]
    fn given_base_offset_reader_when_offset_queried_then_includes_base() {
        let mut writer = BerWriter::new();
        writer.write_null();
        let encoded = writer.into_vec();
        let reader = BerReader::new_with_offset(&encoded, 100);
        assert_eq!(reader.offset(), 100);
    }

    #[test]
    fn given_sub_reader_from_sequence_when_offset_queried_then_reflects_absolute_position() {
        // Build: SEQUENCE { NULL } and check that the sub-reader's offset
        // correctly reflects the position within the original buffer.
        let mut inner_writer = BerWriter::new();
        inner_writer.write_null();

        let mut outer_writer = BerWriter::new();
        outer_writer.write_sequence(inner_writer.as_bytes());

        let encoded = outer_writer.into_vec();
        // SEQUENCE header is 2 bytes (tag + length ≤ 127), so contents start at offset 2.
        let mut outer_reader = BerReader::new(&encoded);
        let mut inner_reader = outer_reader.read_sequence().expect("sequence should parse");

        assert_eq!(
            inner_reader.offset(),
            2,
            "sub-reader should start at offset 2 (after SEQUENCE T+L)"
        );
        inner_reader.read_null().expect("null should parse");
        assert_eq!(
            inner_reader.offset(),
            4,
            "sub-reader should be at offset 4 after reading 2-byte NULL"
        );
    }

    // --- Error cases ---

    #[test]
    fn given_empty_input_when_peek_tag_then_returns_error() {
        let reader = BerReader::new(&[]);
        let ber_error = reader.peek_tag().unwrap_err();
        assert!(
            ber_error.to_string().contains("unexpected end of input"),
            "unexpected error: {ber_error}"
        );
    }

    #[test]
    fn given_empty_input_when_read_tag_then_returns_error() {
        let mut reader = BerReader::new(&[]);
        let ber_error = reader.read_tag().unwrap_err();
        assert!(
            ber_error.to_string().contains("unexpected end of input"),
            "unexpected error: {ber_error}"
        );
    }

    #[test]
    fn given_wrong_tag_when_read_integer_then_returns_error_with_tag_info() {
        // 0x05 0x00 is NULL, not INTEGER.
        let null_bytes = [0x05, 0x00];
        let mut reader = BerReader::new(&null_bytes);
        let ber_error = reader.read_integer().unwrap_err();
        assert!(
            ber_error.to_string().contains("expected INTEGER"),
            "unexpected error: {ber_error}"
        );
    }

    #[test]
    fn given_wrong_tag_when_read_octet_string_then_returns_error() {
        let null_bytes = [0x05, 0x00];
        let mut reader = BerReader::new(&null_bytes);
        let ber_error = reader.read_octet_string().unwrap_err();
        assert!(
            ber_error.to_string().contains("expected OCTET STRING"),
            "unexpected error: {ber_error}"
        );
    }

    #[test]
    fn given_wrong_tag_when_read_null_then_returns_error() {
        // 0x02 0x01 0x00 is INTEGER(0), not NULL.
        let integer_bytes = [0x02, 0x01, 0x00];
        let mut reader = BerReader::new(&integer_bytes);
        let ber_error = reader.read_null().unwrap_err();
        assert!(
            ber_error.to_string().contains("expected NULL"),
            "unexpected error: {ber_error}"
        );
    }

    #[test]
    fn given_truncated_value_when_read_tlv_then_returns_error() {
        // Tag says 5 bytes of value, but only 2 follow.
        let truncated = [0x04, 0x05, 0x41, 0x42];
        let mut reader = BerReader::new(&truncated);
        let ber_error = reader.read_tlv().unwrap_err();
        assert!(
            ber_error.to_string().contains("truncated"),
            "unexpected error: {ber_error}"
        );
    }

    #[test]
    fn given_wrong_constructed_tag_when_read_sequence_then_returns_error() {
        // 0x30 expected but 0x31 (SET) appears.
        let set_bytes = [0x31, 0x00];
        let mut reader = BerReader::new(&set_bytes);
        let ber_error = reader.read_sequence().unwrap_err();
        assert!(
            ber_error.to_string().contains("expected tag"),
            "unexpected error: {ber_error}"
        );
    }

    #[test]
    fn given_negative_integer_when_read_unsigned32_then_returns_error() {
        // Verifies: REQ-0000
        // INTEGER encoding of -1: 02 01 FF
        const NEGATIVE_ONE: &[u8] = &[0x02, 0x01, 0xFF];
        let mut reader = BerReader::new(NEGATIVE_ONE);
        let ber_error = reader.read_unsigned32().unwrap_err();
        assert!(
            ber_error.to_string().contains("negative"),
            "unexpected error: {ber_error}"
        );
    }

    #[test]
    fn given_negative_integer_when_read_unsigned64_then_returns_error() {
        // Verifies: REQ-0000
        const NEGATIVE_ONE: &[u8] = &[0x02, 0x01, 0xFF];
        let mut reader = BerReader::new(NEGATIVE_ONE);
        let ber_error = reader.read_unsigned64().unwrap_err();
        assert!(
            ber_error.to_string().contains("negative"),
            "unexpected error: {ber_error}"
        );
    }

    #[test]
    fn given_null_with_nonzero_length_when_read_null_then_returns_error() {
        // Verifies: REQ-0000
        // NULL tag with length 1 and a junk byte — this is malformed.
        const MALFORMED_NULL: &[u8] = &[0x05, 0x01, 0x00];
        let mut reader = BerReader::new(MALFORMED_NULL);
        let ber_error = reader.read_null().unwrap_err();
        assert!(
            ber_error.to_string().contains("length 0"),
            "unexpected error: {ber_error}"
        );
    }

    #[test]
    fn given_reader_with_two_tlvs_when_first_consumed_then_remaining_returns_second() {
        // Verifies: REQ-0000
        // Two NULLs: 05 00 05 00
        const TWO_NULLS: &[u8] = &[0x05, 0x00, 0x05, 0x00];
        let mut reader = BerReader::new(TWO_NULLS);
        reader.read_null().expect("first null should parse");
        assert_eq!(reader.remaining(), &[0x05, 0x00]);
    }

    #[test]
    fn given_writer_when_write_raw_called_then_bytes_appended_verbatim() {
        // Verifies: REQ-0000
        let mut writer = BerWriter::new();
        writer.write_raw(&[0x01, 0x02, 0x03]);
        assert_eq!(writer.as_bytes(), &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn given_tagged_unsigned32_when_round_tripped_then_recovers() {
        // Verifies: REQ-0000
        // Counter32 tag 0x41, value 1000 = 0x03E8
        // Wire: 41 02 03 E8
        const EXPECTED_WIRE: &[u8] = &[0x41, 0x02, 0x03, 0xE8];
        let mut writer = BerWriter::new();
        writer.write_tagged_unsigned32(TAG_COUNTER32, 1000);
        assert_eq!(writer.as_bytes(), EXPECTED_WIRE);
        let mut reader = BerReader::new(writer.as_bytes());
        let value = reader
            .read_tagged_unsigned32(TAG_COUNTER32)
            .expect("should decode");
        assert_eq!(value, 1000);
    }

    #[test]
    fn given_tagged_unsigned64_when_round_tripped_then_recovers() {
        // Verifies: REQ-0000
        // Counter64 tag 0x46, value 0x0100000000 = 4294967296
        // Encoded unsigned bytes: [0x01, 0x00, 0x00, 0x00, 0x00] (no sign byte needed, high bit clear)
        // Wire: 46 05 01 00 00 00 00
        const EXPECTED_WIRE: &[u8] = &[0x46, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00];
        let mut writer = BerWriter::new();
        writer.write_tagged_unsigned64(TAG_COUNTER64, 4_294_967_296);
        assert_eq!(writer.as_bytes(), EXPECTED_WIRE);
        let mut reader = BerReader::new(writer.as_bytes());
        let value = reader
            .read_tagged_unsigned64(TAG_COUNTER64)
            .expect("should decode");
        assert_eq!(value, 4_294_967_296);
    }

    // --- New error-case tests ---

    #[test]
    fn given_zero_length_integer_when_read_integer_then_returns_error() {
        // Verifies: REQ-0000
        // INTEGER with length 0: 02 00
        const ZERO_LENGTH_INTEGER: &[u8] = &[0x02, 0x00];
        let mut reader = BerReader::new(ZERO_LENGTH_INTEGER);
        let ber_error = reader.read_integer().unwrap_err();
        assert!(
            ber_error.to_string().contains("zero length"),
            "unexpected error: {ber_error}"
        );
    }

    #[test]
    fn given_five_byte_integer_when_read_integer_then_returns_error() {
        // Verifies: REQ-0000
        // INTEGER with 5 value bytes: 02 05 01 02 03 04 05
        const OVERSIZED_INTEGER: &[u8] = &[0x02, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
        let mut reader = BerReader::new(OVERSIZED_INTEGER);
        let ber_error = reader.read_integer().unwrap_err();
        assert!(
            ber_error.to_string().contains("too large for i32"),
            "unexpected error: {ber_error}"
        );
    }

    #[test]
    fn given_unsigned_too_large_for_u32_when_read_unsigned32_then_returns_error() {
        // Verifies: REQ-0000
        // Unsigned value 0x0100000000 (fits in u64 but not u32):
        // Sign byte 0x00 + 5 significant bytes → total 6 value bytes
        // 02 06 00 01 00 00 00 00
        const OVERSIZED_U32: &[u8] = &[0x02, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
        let mut reader = BerReader::new(OVERSIZED_U32);
        let ber_error = reader.read_unsigned32().unwrap_err();
        assert!(
            ber_error.to_string().contains("too large for u32"),
            "unexpected error: {ber_error}"
        );
    }

    #[test]
    fn given_counter32_when_read_as_gauge32_then_returns_error() {
        // Verifies: REQ-0000
        // Counter32 tag 0x41, value 1: 41 01 01
        const COUNTER32_ONE: &[u8] = &[0x41, 0x01, 0x01];
        let mut reader = BerReader::new(COUNTER32_ONE);
        let ber_error = reader.read_tagged_unsigned32(TAG_GAUGE32).unwrap_err();
        assert!(
            ber_error.to_string().contains("expected"),
            "unexpected error: {ber_error}"
        );
    }

    #[test]
    fn given_zero_length_oid_when_read_oid_then_returns_error() {
        // Verifies: REQ-0000
        // OID tag with zero length: 06 00
        const EMPTY_OID: &[u8] = &[0x06, 0x00];
        let mut reader = BerReader::new(EMPTY_OID);
        let ber_error = reader.read_oid().unwrap_err();
        assert!(
            ber_error.to_string().contains("zero length"),
            "unexpected error: {ber_error}"
        );
    }

    #[test]
    fn given_oid_with_overflowing_sub_identifier_when_decoded_then_returns_error() {
        // Verifies: REQ-0000
        // An OID value where the first sub-id is valid (0x2B = 43 → arc 1.3)
        // then a second sub-id with 11 continuation bytes that overflows u64.
        // Each byte has continuation bit set (0x80+) except the last.
        // 11 groups of 7 bits = 77 bits > 64 bits → overflow guaranteed.
        const OVERFLOWING_OID: &[u8] = &[
            0x06, 0x0C, // OID tag, length 12
            0x2B, // first sub-id: 43 (arc 1.3)
            // 11-byte sub-identifier that overflows u64:
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F,
        ];
        let mut reader = BerReader::new(OVERFLOWING_OID);
        let ber_error = reader.read_oid().unwrap_err();
        assert!(
            ber_error.to_string().contains("overflow"),
            "unexpected error: {ber_error}"
        );
    }

    #[test]
    fn given_unsigned32_max_when_encoded_then_matches_expected_wire() {
        // Verifies: REQ-0000
        // u32::MAX = 0xFFFFFFFF, high bit set → prepend 0x00 sign byte
        // INTEGER tag 0x02, length 5, value 00 FF FF FF FF
        const EXPECTED_WIRE: &[u8] = &[0x02, 0x05, 0x00, 0xFF, 0xFF, 0xFF, 0xFF];
        let encoded = encode_with_writer(|w| w.write_unsigned32(u32::MAX));
        assert_eq!(encoded, EXPECTED_WIRE);
    }

    #[test]
    fn given_unsigned64_max_when_encoded_then_matches_expected_wire() {
        // Verifies: REQ-0000
        // u64::MAX, high bit set → prepend 0x00
        // INTEGER tag 0x02, length 9, value 00 FF FF FF FF FF FF FF FF
        const EXPECTED_WIRE: &[u8] = &[
            0x02, 0x09, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ];
        let encoded = encode_with_writer(|w| w.write_unsigned64(u64::MAX));
        assert_eq!(encoded, EXPECTED_WIRE);
    }

    // --- Mutant-killing tests: BerError Debug, BerWriter capacity/len ---

    #[test]
    fn given_ber_error_when_debug_formatted_then_contains_fields() {
        // Verifies: REQ-0000
        let error = BerError::new("test message".to_string());
        let debug_output = format!("{error:?}");
        assert!(
            debug_output.contains("BerError"),
            "Debug output should contain struct name: {debug_output}"
        );
        assert!(
            debug_output.contains("message"),
            "Debug output should contain field name: {debug_output}"
        );
        assert!(
            debug_output.contains("test message"),
            "Debug output should contain message value: {debug_output}"
        );
        assert!(
            debug_output.contains("is_wrong_version"),
            "Debug output should contain is_wrong_version field: {debug_output}"
        );
        assert!(
            debug_output.contains("false"),
            "Debug output should contain is_wrong_version value: {debug_output}"
        );
    }

    #[test]
    fn given_writer_with_capacity_when_integer_written_then_matches_default_writer() {
        // Verifies: REQ-0000
        // Note: The cargo-mutants "replace with_capacity -> Self with Default::default()" mutant
        // is equivalent — Default produces a functionally identical empty writer.
        let mut writer_cap = BerWriter::with_capacity(64);
        writer_cap.write_integer(42);

        let mut writer_default = BerWriter::new();
        writer_default.write_integer(42);

        assert_eq!(writer_cap.as_bytes(), writer_default.as_bytes());
    }

    #[test]
    fn given_writer_after_writing_octet_string_when_len_called_then_returns_correct_byte_count() {
        // Verifies: REQ-0000
        let mut writer = BerWriter::new();
        writer.write_octet_string(b"hello");
        // tag(0x04) + length(0x05) + 5 payload bytes = 7
        assert_eq!(writer.len(), 7);
    }

    #[test]
    fn given_wrong_version_error_when_debug_formatted_then_shows_true() {
        // Verifies: REQ-0000
        let error = BerError::wrong_version("version mismatch".to_string());
        let debug_output = format!("{error:?}");
        assert!(
            debug_output.contains("true"),
            "Debug output should show is_wrong_version as true: {debug_output}"
        );
    }

    // --- Mutant-killing tests: decode_unsigned edge case ---

    #[test]
    fn given_single_zero_byte_when_decoded_as_unsigned_then_returns_zero() {
        // Verifies: REQ-0000
        let result = decode_unsigned(&[0x00], 4, 0).expect("single zero byte should decode");
        assert_eq!(result, 0);
    }

    #[test]
    fn given_two_byte_unsigned_with_sign_padding_when_decoded_then_strips_leading_zero() {
        // Verifies: REQ-0000
        // [0x00, 0x80] has leading 0x00 sign byte; significant bytes = [0x80] → value 128
        let result = decode_unsigned(&[0x00, 0x80], 4, 0)
            .expect("two-byte unsigned with sign padding should decode");
        assert_eq!(result, 128);
    }

    #[test]
    fn given_ber_encoded_integer_zero_when_decoded_as_unsigned32_then_returns_zero() {
        // Verifies: REQ-0000
        // INTEGER 0 is BER-encoded as tag=0x02, length=0x01, value=0x00.
        // The decode_unsigned path must keep the single [0x00] byte as significant
        // (len == 1, so len > 1 is false) rather than stripping it to empty.
        // Both paths produce value 0, confirming the condition is semantically correct.
        const BER_INTEGER_ZERO: &[u8] = &[0x02, 0x01, 0x00];
        let mut reader = BerReader::new(BER_INTEGER_ZERO);
        let decoded_value = reader
            .read_unsigned32()
            .expect("BER-encoded integer 0 must decode successfully");
        assert_eq!(decoded_value, 0);
    }

    #[test]
    fn given_multiple_redundant_leading_zeroes_when_decoded_as_unsigned_then_strips_all() {
        // Verifies: REQ-0000

        // [0x00, 0x00, 0x00, 0x01] → 1 (three redundant sign bytes)
        let result = decode_unsigned(&[0x00, 0x00, 0x00, 0x01], 4, 0)
            .expect("three leading zeroes before 0x01 should decode");
        assert_eq!(result, 1);

        // [0x00, 0x00, 0x00, 0x00, 0x00, 0x80] → 128 (five leading zeroes, one significant byte)
        let result = decode_unsigned(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x80], 4, 0)
            .expect("five leading zeroes before 0x80 should decode");
        assert_eq!(result, 128);

        // [0x00, 0x00, 0x00, 0x00, 0x00] → 0 (all zeroes; last byte preserved as value)
        let result = decode_unsigned(&[0x00, 0x00, 0x00, 0x00, 0x00], 4, 0)
            .expect("all-zero bytes should decode as 0");
        assert_eq!(result, 0);

        // [0x00, 0x00, 0x01, 0x02, 0x03, 0x04]: two leading zeroes then four significant
        // bytes; must succeed for max_width=4.
        let result = decode_unsigned(&[0x00, 0x00, 0x01, 0x02, 0x03, 0x04], 4, 0)
            .expect("two leading zeroes before four significant bytes should decode");
        assert_eq!(result, 0x0102_0304);

        // [0x00, 0x01, 0x02, 0x03, 0x04, 0x05]: one leading zero then five significant
        // bytes; must fail for max_width=4.
        decode_unsigned(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05], 4, 0)
            .expect_err("five significant bytes must exceed max_width=4");
    }

    #[test]
    fn given_multiple_redundant_leading_bytes_when_decoded_as_signed_then_strips_all() {
        // Verifies: REQ-0000

        // [0x00, 0x00, 0x00, 0x01] encodes +1 with three redundant 0x00 sign bytes.
        let result = decode_signed_i32(&[0x00, 0x00, 0x00, 0x01], 0)
            .expect("three leading zeroes before 0x01 should decode as +1");
        assert_eq!(result, 1);

        // [0xFF, 0xFF, 0xFF, 0xFF] encodes -1 with three redundant 0xFF sign bytes.
        let result = decode_signed_i32(&[0xFF, 0xFF, 0xFF, 0xFF], 0)
            .expect("three leading 0xFF bytes should decode as -1");
        assert_eq!(result, -1);

        // [0xFF, 0x80] encodes -128: 0xFF is redundant (next byte 0x80 has high bit set).
        let result = decode_signed_i32(&[0xFF, 0x80], 0).expect("0xFF 0x80 should decode as -128");
        assert_eq!(result, -128);

        // [0x00, 0x7F] encodes +127: 0x00 is redundant (next byte 0x7F has high bit clear).
        let result = decode_signed_i32(&[0x00, 0x7F], 0).expect("0x00 0x7F should decode as +127");
        assert_eq!(result, 127);

        // [0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x01]: two redundant 0xFF bytes, then five
        // significant bytes — must fail because 5 > max i32 width of 4.
        decode_signed_i32(&[0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x01], 0)
            .expect_err("five significant bytes must exceed i32 capacity");
    }

    // --- Mutant-killing tests: OID arc boundary values ---

    #[test]
    fn given_oid_1_0_when_round_tripped_then_recovers_correctly() {
        // Verifies: REQ-0000
        // OID "1.0": combined first sub-id = 40*1 + 0 = 40 = 0x28
        // Wire: 06 01 28
        // This value must be decoded as arc (1, 0), not (0, 40).
        const EXPECTED_WIRE: &[u8] = &[0x06, 0x01, 0x28];
        let oid: Oid = "1.0".parse().unwrap();
        let encoded = encode_with_writer(|w| w.write_oid(&oid));
        assert_eq!(encoded, EXPECTED_WIRE);
        let recovered = BerReader::new(&encoded)
            .read_oid()
            .expect("OID 1.0 should decode");
        assert_eq!(recovered, oid);
    }

    #[test]
    fn given_oid_2_0_when_round_tripped_then_recovers_correctly() {
        // Verifies: REQ-0000
        // OID "2.0": combined first sub-id = 40*2 + 0 = 80 = 0x50
        // Wire: 06 01 50
        // This value must be decoded as arc (2, 0), not (1, 40).
        const EXPECTED_WIRE: &[u8] = &[0x06, 0x01, 0x50];
        let oid: Oid = "2.0".parse().unwrap();
        let encoded = encode_with_writer(|w| w.write_oid(&oid));
        assert_eq!(encoded, EXPECTED_WIRE);
        let recovered = BerReader::new(&encoded)
            .read_oid()
            .expect("OID 2.0 should decode");
        assert_eq!(recovered, oid);
    }

    #[test]
    fn given_oid_with_129_sub_identifiers_when_decoded_then_returns_error() {
        // Verifies: REQ-0000
        // First BER byte 0x00 encodes arcs (0, 0), then 127 more single-byte
        // sub-identifiers (0x01 each), giving 2 + 127 = 129 total arcs.
        let mut oid_value = vec![0x00u8]; // arcs 0.0
        oid_value.extend(std::iter::repeat_n(0x01u8, 127));
        // Total OID value length = 128 bytes
        // Wrap in OID TLV: tag 0x06, length 128 (long form: 0x81 0x80)
        let mut tlv = vec![0x06, 0x81, 0x80];
        tlv.extend(&oid_value);
        let mut reader = BerReader::new(&tlv);
        let ber_error = reader.read_oid().unwrap_err();
        let error_message = ber_error.to_string();
        assert!(
            error_message.contains("too many sub-identifiers"),
            "error must mention sub-identifier limit, got: {error_message}"
        );
        assert!(
            error_message.contains("129"),
            "error must report the actual count, got: {error_message}"
        );
    }

    #[test]
    fn given_oid_with_128_sub_identifiers_when_decoded_then_succeeds() {
        // Verifies: REQ-0000
        // First BER byte 0x00 encodes arcs (0, 0), then 126 more single-byte
        // sub-identifiers (0x01 each), giving 2 + 126 = 128 total arcs.
        let mut oid_value = vec![0x00u8]; // arcs 0.0
        oid_value.extend(std::iter::repeat_n(0x01u8, 126));
        // Total OID value length = 127 bytes
        // Wrap in OID TLV: tag 0x06, length 127 (short form: 0x7F)
        let mut tlv = vec![0x06, 0x7F];
        tlv.extend(&oid_value);
        let mut reader = BerReader::new(&tlv);
        let oid = reader
            .read_oid()
            .expect("128 sub-identifiers should succeed");
        assert_eq!(oid.as_slice().len(), 128);
        assert_eq!(oid.as_slice()[0], 0);
        assert_eq!(oid.as_slice()[1], 0);
        assert_eq!(oid.as_slice()[127], 1);
    }

    #[test]
    fn given_oid_sub_identifier_with_leading_0x80_when_decoded_then_returns_error() {
        // Verifies: REQ-0000
        // OID where the second sub-identifier starts with 0x80 followed by 0x00.
        // 0x80 has the continuation bit set but value bits all zero, which is
        // a non-minimal base-128 encoding per X.690 §8.19.2.
        // Wire: OID tag 0x06, length 3, value [0x2B, 0x80, 0x00].
        // 0x2B = 43 encodes arcs 1.3; 0x80 0x00 is a non-minimal encoding of 0.
        const NON_MINIMAL_OID: &[u8] = &[0x06, 0x03, 0x2B, 0x80, 0x00];
        let mut reader = BerReader::new(NON_MINIMAL_OID);
        let ber_error = reader.read_oid().unwrap_err();
        let error_message = ber_error.to_string();
        assert!(
            error_message.contains("non-minimal"),
            "error must mention non-minimal encoding, got: {error_message}"
        );
        assert!(
            error_message.contains("offset"),
            "error must include offset context, got: {error_message}"
        );
    }

    #[test]
    fn given_oid_with_zero_sub_identifier_when_decoded_then_succeeds() {
        // Verifies: REQ-0000
        // 0x00 is the minimal single-byte encoding for sub-identifier value 0.
        // It must NOT be rejected by the non-minimal encoding check.
        // Wire: OID tag 0x06, length 2, value [0x2B, 0x00] = OID 1.3.0.
        const OID_WITH_ZERO: &[u8] = &[0x06, 0x02, 0x2B, 0x00];
        let mut reader = BerReader::new(OID_WITH_ZERO);
        let oid = reader
            .read_oid()
            .expect("zero sub-identifier must be accepted");
        assert_eq!(oid, "1.3.0".parse::<Oid>().unwrap());
    }

    #[test]
    fn given_oid_sub_identifier_with_longer_leading_0x80_when_decoded_then_returns_error() {
        // Verifies: REQ-0000
        // Wire: OID tag 0x06, length 4, value [0x2B, 0x80, 0x80, 0x01].
        // 0x80 0x80 0x01 is a non-minimal encoding (starts with leading 0x80).
        const NON_MINIMAL_OID: &[u8] = &[0x06, 0x04, 0x2B, 0x80, 0x80, 0x01];
        let mut reader = BerReader::new(NON_MINIMAL_OID);
        let ber_error = reader.read_oid().unwrap_err();
        assert!(ber_error.to_string().contains("non-minimal"));
    }
}
