//! SNMP message-level BER encode/decode layer.
//!
//! Covers both the `SNMPv3` message envelope (RFC 3412 §6 and RFC 3414 §2.4)
//! and the `SNMPv2c` message envelope (RFC 1901 §3), using the [`BerWriter`]
//! and [`BerReader`] primitives from the parent module. The inner PDU is left
//! as raw bytes and decoded by a higher layer.

use super::{BerError, BerReader, BerWriter, TAG_OCTET_STRING, TAG_SEQUENCE};

/// `SNMPv3` message version field value (RFC 3412 §6).
const SNMPV3_VERSION: i32 = 3;

/// `SNMPv2c` message version field value (RFC 1901 §3).
const SNMPV2C_VERSION: i32 = 1;

/// Maximum `SNMPv3` message size (in bytes) advertised in outbound messages.
///
/// RFC 3412 §6.4 defines `msgMaxSize` as the maximum message size the sender
/// can accept. 65535 is the conventional maximum for UDP-transported SNMP and
/// the value this agent advertises as its receive capability.
pub(crate) const MSG_MAX_SIZE_UDP: i32 = 65535;

// ── Intermediate types ────────────────────────────────────────────────────────

/// Decoded `SNMPv3` message envelope. The inner PDU is left as raw bytes.
#[derive(Debug)]
pub(crate) struct V3MessageEnvelope<'a> {
    /// Message ID from `HeaderData`; echoed in the `SNMPv3` response.
    pub msg_id: i32,
    /// Maximum message size from `HeaderData`.
    pub max_size: i32,
    /// Security flags byte from `HeaderData`.
    pub security_flags: u8,
    /// Security model from `HeaderData` (3 = USM).
    pub security_model: i32,
    /// Decoded USM security parameters.
    pub usm: UsmFields,
    /// Decoded `ScopedPduData` — either plaintext or encrypted.
    pub scoped_data: ScopedData,
    /// Reference to the raw bytes of the complete `SNMPv3` message as received.
    pub raw_message: &'a [u8],
    /// Byte offset of `msgAuthenticationParameters` VALUE within `raw_message`.
    ///
    /// `None` for noAuthNoPriv messages (empty `auth_params`). The offset is
    /// derived from the structural parse position rather than a byte-pattern
    /// search, making it immune to attacker-controlled data in the `ScopedPDU`.
    pub auth_params_offset: Option<usize>,
}

/// Decoded USM security parameters (RFC 3414 §2.4).
///
/// `engine_boots` and `engine_time` are `i32` because BER INTEGER is signed
/// and the underlying reader returns `i32`. The dispatch layer validates that
/// the values fall within the non-negative protocol range.
#[derive(Debug)]
pub(crate) struct UsmFields {
    /// `msgAuthoritativeEngineID`.
    pub engine_id: Vec<u8>,
    /// `msgAuthoritativeEngineBoots`.
    pub engine_boots: i32,
    /// `msgAuthoritativeEngineTime`.
    pub engine_time: i32,
    /// `msgUserName`.
    pub user_name: Vec<u8>,
    /// `msgAuthenticationParameters`.
    pub auth_params: Vec<u8>,
    /// `msgPrivacyParameters`.
    pub priv_params: Vec<u8>,
}

/// Decoded `ScopedPduData` — either plaintext or encrypted.
#[derive(Debug)]
pub(crate) enum ScopedData {
    /// Plaintext `ScopedPDU` containing the context fields and raw PDU bytes.
    Plaintext {
        /// `contextEngineID` from the `ScopedPdu`.
        context_engine_id: Vec<u8>,
        /// `contextName` from the `ScopedPdu`.
        context_name: Vec<u8>,
        /// Raw TLV bytes of the inner PDU (context-tagged constructed).
        raw_pdu: Vec<u8>,
    },
    /// Encrypted PDU ciphertext that requires AES decryption before use.
    Encrypted(Vec<u8>),
}

/// Decoded `ScopedPdu` fields after AES decryption (used by the dispatch layer).
#[derive(Debug)]
pub(crate) struct DecodedScopedPduFields {
    /// `contextEngineID` from the `ScopedPdu`.
    pub context_engine_id: Vec<u8>,
    /// `contextName` from the `ScopedPdu`.
    pub context_name: Vec<u8>,
    /// Raw TLV bytes of the inner PDU.
    pub raw_pdu: Vec<u8>,
}

// ── Decode functions ──────────────────────────────────────────────────────────

/// Decodes an `SNMPv3` message envelope from raw BER bytes.
///
/// The inner PDU is NOT parsed — it is returned as raw bytes in
/// `ScopedData::Plaintext::raw_pdu` or as encrypted ciphertext in
/// `ScopedData::Encrypted`.
///
/// The `auth_params_offset` in the returned envelope gives the byte position
/// of the `msgAuthenticationParameters` VALUE within `bytes`, derived from
/// structural parse offsets rather than a byte-pattern search. This allows the
/// dispatch layer to zero the field before HMAC verification without scanning
/// attacker-controlled varbind content.
///
/// # Errors
///
/// Returns a [`BerError`] if:
/// - `bytes` is not a valid BER-encoded `SNMPv3` SEQUENCE.
/// - The `msgVersion` field is not 3.
/// - Any mandatory field is absent, truncated, or has the wrong tag.
///
/// # Requirements
/// Implements: REQ-0118, REQ-0119
pub(crate) fn decode_v3_envelope(bytes: &[u8]) -> Result<V3MessageEnvelope<'_>, BerError> {
    let mut outer_reader = BerReader::new(bytes);
    let mut msg_reader = outer_reader.read_sequence()?;

    let version = msg_reader.read_integer()?;
    if version != SNMPV3_VERSION {
        return Err(BerError::wrong_version(format!(
            "BER: expected SNMPv3 (version 3), got version {version}"
        )));
    }

    let mut header_reader = msg_reader.read_sequence()?;
    let msg_id = header_reader.read_integer()?;
    // RFC 3412 §6.4: msgID is in the range [0, 2^31-1].
    if msg_id < 0 {
        return Err(BerError::new(
            "BER: msgID must be non-negative per RFC 3412 §6.4",
        ));
    }
    let max_size = header_reader.read_integer()?;
    // RFC 3412 §6.6: msgMaxSize must be at least 484.
    if max_size < 484 {
        return Err(BerError::new(
            "BER: msgMaxSize must be at least 484 per RFC 3412 §6.6",
        ));
    }
    let flags_bytes = header_reader.read_octet_string()?;
    // RFC 3412 §6.6: msgFlags must be exactly 1 byte.
    if flags_bytes.len() != 1 {
        return Err(BerError::new(format!(
            "BER: msgFlags must be exactly 1 byte, got {}",
            flags_bytes.len()
        )));
    }
    let security_flags = flags_bytes[0];
    let security_model = header_reader.read_integer()?;

    // Read the security_parameters OCTET STRING and track the absolute offset
    // of its VALUE bytes so we can hand off a correctly-offset USM reader.
    let usm_raw = msg_reader.read_octet_string()?;
    // The offset *after* reading usm_raw is the absolute end of the USM VALUE;
    // subtracting the value length gives the start of the VALUE bytes.
    let usm_value_offset = msg_reader.offset() - usm_raw.len();

    let mut usm_outer_reader = BerReader::new_with_offset(usm_raw, usm_value_offset);
    let mut usm_reader = usm_outer_reader.read_sequence()?;
    let engine_id = usm_reader.read_octet_string()?.to_vec();
    let engine_boots = usm_reader.read_integer()?;
    let engine_time = usm_reader.read_integer()?;
    let user_name = usm_reader.read_octet_string()?.to_vec();
    let auth_params = usm_reader.read_octet_string()?.to_vec();
    // auth_params_offset is the absolute offset of the auth_params VALUE bytes.
    let auth_params_offset = if auth_params.is_empty() {
        None
    } else {
        // usm_reader.offset() is positioned just after the auth_params VALUE bytes.
        Some(usm_reader.offset() - auth_params.len())
    };
    let priv_params = usm_reader.read_octet_string()?.to_vec();

    // Peek at the tag of the next element to decide whether we have a plaintext
    // ScopedPDU (SEQUENCE, 0x30) or encrypted ciphertext (OCTET STRING, 0x04).
    let scoped_data_tag = msg_reader.peek_tag()?;
    let scoped_data = if scoped_data_tag == TAG_SEQUENCE {
        let mut scoped_reader = msg_reader.read_sequence()?;
        let context_engine_id = scoped_reader.read_octet_string()?.to_vec();
        let context_name = scoped_reader.read_octet_string()?.to_vec();
        // Everything remaining in the ScopedPdu after the two OCTET STRINGs is
        // the raw TLV of the context-tagged inner PDU.
        let raw_pdu = scoped_reader.remaining().to_vec();
        ScopedData::Plaintext {
            context_engine_id,
            context_name,
            raw_pdu,
        }
    } else if scoped_data_tag == TAG_OCTET_STRING {
        let ciphertext = msg_reader.read_octet_string()?.to_vec();
        ScopedData::Encrypted(ciphertext)
    } else {
        return Err(BerError::new(format!(
            "BER: expected ScopedPduData as SEQUENCE (0x30) or OCTET STRING (0x04), \
             got tag 0x{scoped_data_tag:02X}"
        )));
    };

    Ok(V3MessageEnvelope {
        msg_id,
        max_size,
        security_flags,
        security_model,
        usm: UsmFields {
            engine_id,
            engine_boots,
            engine_time,
            user_name,
            auth_params,
            priv_params,
        },
        scoped_data,
        raw_message: bytes,
        auth_params_offset,
    })
}

/// Decodes a `ScopedPdu` from raw BER bytes (used after AES decryption).
///
/// The raw bytes must be a BER-encoded `ScopedPDU SEQUENCE { contextEngineID,
/// contextName, data }` as defined in RFC 3412 §6.
///
/// # Errors
///
/// Returns a [`BerError`] if `bytes` is not a valid BER-encoded `ScopedPdu`.
pub(crate) fn decode_scoped_pdu(bytes: &[u8]) -> Result<DecodedScopedPduFields, BerError> {
    let mut outer_reader = BerReader::new(bytes);
    let mut scoped_reader = outer_reader.read_sequence()?;
    let context_engine_id = scoped_reader.read_octet_string()?.to_vec();
    let context_name = scoped_reader.read_octet_string()?.to_vec();
    let raw_pdu = scoped_reader.remaining().to_vec();
    Ok(DecodedScopedPduFields {
        context_engine_id,
        context_name,
        raw_pdu,
    })
}

// ── Encode functions ──────────────────────────────────────────────────────────

/// Encodes a `ScopedPdu`: `SEQUENCE { contextEngineID, contextName, raw_pdu_bytes }`.
///
/// `raw_pdu_bytes` is a pre-encoded PDU TLV (context-tagged constructed).
pub(crate) fn encode_scoped_pdu(
    context_engine_id: &[u8],
    context_name: &[u8],
    raw_pdu_bytes: &[u8],
) -> Vec<u8> {
    let mut inner = BerWriter::new();
    inner.write_octet_string(context_engine_id);
    inner.write_octet_string(context_name);
    inner.write_raw(raw_pdu_bytes);

    let mut outer = BerWriter::new();
    outer.write_sequence(inner.as_bytes());
    outer.into_vec()
}

/// Encodes USM security parameters as a BER SEQUENCE (RFC 3414 §2.4).
pub(crate) fn encode_usm_params(
    engine_id: &[u8],
    engine_boots: i32,
    engine_time: i32,
    user_name: &[u8],
    auth_params: &[u8],
    priv_params: &[u8],
) -> Vec<u8> {
    let mut inner = BerWriter::new();
    inner.write_octet_string(engine_id);
    inner.write_integer(engine_boots);
    inner.write_integer(engine_time);
    inner.write_octet_string(user_name);
    inner.write_octet_string(auth_params);
    inner.write_octet_string(priv_params);

    let mut outer = BerWriter::new();
    outer.write_sequence(inner.as_bytes());
    outer.into_vec()
}

/// Encodes a `HeaderData` SEQUENCE (RFC 3412 §6).
pub(crate) fn encode_header_data(
    msg_id: i32,
    max_size: i32,
    flags_byte: u8,
    security_model: i32,
) -> Vec<u8> {
    let mut inner = BerWriter::new();
    inner.write_integer(msg_id);
    inner.write_integer(max_size);
    // msgFlags is an OCTET STRING of exactly 1 byte (RFC 3412 §6.6).
    inner.write_octet_string(&[flags_byte]);
    inner.write_integer(security_model);

    let mut outer = BerWriter::new();
    outer.write_sequence(inner.as_bytes());
    outer.into_vec()
}

/// Encodes a complete `SNMPv3` message.
///
/// Returns `(encoded_message, auth_params_offset)`.
/// `auth_params_offset` is `Some(offset)` when `auth_params` is non-empty,
/// giving the byte offset of the `auth_params` VALUE within the encoded message.
///
/// `scoped_pdu_or_ciphertext` is either:
/// - Pre-encoded `ScopedPdu` bytes (plaintext) — written verbatim (they already
///   carry the SEQUENCE tag and length).
/// - Encrypted ciphertext bytes — wrapped in an OCTET STRING.
///
/// `encrypted` controls which wrapping is used.
///
/// # Errors
///
/// Returns a [`BerError`] if re-parsing the encoded message to locate the
/// `auth_params` offset fails (should be unreachable for well-formed inputs).
#[allow(clippy::too_many_arguments)]
pub(crate) fn encode_v3_message(
    msg_id: i32,
    max_size: i32,
    flags_byte: u8,
    security_model: i32,
    engine_id: &[u8],
    engine_boots: i32,
    engine_time: i32,
    user_name: &[u8],
    auth_params: &[u8],
    priv_params: &[u8],
    scoped_pdu_or_ciphertext: &[u8],
    encrypted: bool,
) -> Result<(Vec<u8>, Option<usize>), BerError> {
    let header_bytes = encode_header_data(msg_id, max_size, flags_byte, security_model);
    let usm_bytes = encode_usm_params(
        engine_id,
        engine_boots,
        engine_time,
        user_name,
        auth_params,
        priv_params,
    );

    let mut msg_inner = BerWriter::new();
    msg_inner.write_integer(SNMPV3_VERSION);
    msg_inner.write_raw(&header_bytes);
    // security_parameters is an OCTET STRING wrapping the BER-encoded USM SEQUENCE.
    msg_inner.write_octet_string(&usm_bytes);
    if encrypted {
        msg_inner.write_octet_string(scoped_pdu_or_ciphertext);
    } else {
        // Plaintext ScopedPdu bytes already carry the SEQUENCE tag; write verbatim.
        msg_inner.write_raw(scoped_pdu_or_ciphertext);
    }

    let mut outer = BerWriter::new();
    outer.write_sequence(msg_inner.as_bytes());
    let encoded_message = outer.into_vec();

    let auth_params_offset = find_auth_params_offset(&encoded_message, auth_params.len())?;
    Ok((encoded_message, auth_params_offset))
}

/// Encodes an `SNMPv2c` message envelope (RFC 1901 §3).
///
/// Produces `SEQUENCE { INTEGER version, OCTET STRING community, <raw PDU TLV> }`.
/// `raw_pdu_tlv` must be a fully-encoded PDU TLV (e.g. the output of
/// [`super::pdu::encode_pdu`]) and is written verbatim without additional
/// wrapping. Used for plain trap delivery when no USM user is configured.
pub(crate) fn encode_v2c_message(community: &[u8], raw_pdu_tlv: &[u8]) -> Vec<u8> {
    let mut inner = BerWriter::new();
    inner.write_integer(SNMPV2C_VERSION);
    inner.write_octet_string(community);
    inner.write_raw(raw_pdu_tlv);

    let mut outer = BerWriter::new();
    outer.write_sequence(inner.as_bytes());
    outer.into_vec()
}

/// Re-parses `encoded_message` to find the byte offset of `msgAuthenticationParameters`.
///
/// Returns `None` when `auth_params_len` is zero (noAuthNoPriv). The offset is
/// derived from the structural parse position rather than a pattern search,
/// which is deterministic and immune to false matches from attacker-controlled
/// varbind data.
///
/// An alternative would be to track the offset during encoding by computing
/// byte sizes of each TLV layer. The re-parse approach is preferred because
/// it is self-verifying (a structural mismatch fails with a `BerError`) and
/// avoids duplicating TLV size arithmetic from `encode_length`.
fn find_auth_params_offset(
    encoded_message: &[u8],
    auth_params_len: usize,
) -> Result<Option<usize>, BerError> {
    if auth_params_len == 0 {
        return Ok(None);
    }
    let mut outer_reader = BerReader::new(encoded_message);
    let mut msg_reader = outer_reader.read_sequence()?;
    let _ = msg_reader.read_integer()?; // version — skip
    // Skip HeaderData: read_sequence advances the parent reader past the
    // entire SEQUENCE TLV (tag + length + value) and returns a sub-reader
    // that we discard since we only need to advance past it.
    let _ = msg_reader.read_sequence()?;
    let usm_raw = msg_reader.read_octet_string()?;
    // Absolute offset of the USM VALUE bytes (first byte of the USM SEQUENCE).
    let usm_value_offset = msg_reader.offset() - usm_raw.len();

    let mut usm_outer_reader = BerReader::new_with_offset(usm_raw, usm_value_offset);
    let mut usm_reader = usm_outer_reader.read_sequence()?;
    // Skip each USM field ahead of auth_params: read_octet_string / read_integer
    // advances the reader past the entire TLV; the returned slice is discarded.
    let _ = usm_reader.read_octet_string()?; // engine_id — skip
    let _ = usm_reader.read_integer()?; // engine_boots — skip
    let _ = usm_reader.read_integer()?; // engine_time — skip
    let _ = usm_reader.read_octet_string()?; // user_name — skip
    let auth_params_value = usm_reader.read_octet_string()?;
    // The offset just after reading auth_params_value minus its length equals
    // the absolute start offset of the VALUE bytes.
    Ok(Some(usm_reader.offset() - auth_params_value.len()))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Test 1: HeaderData encode/decode round-trip ───────────────────────────

    // Wire encoding of HeaderData { msgID: 1, maxSize: 65535, flags: 0x04, securityModel: 3 }
    //
    // Inner TLVs:
    //   INTEGER 1:      02 01 01                    (3 bytes)
    //   INTEGER 65535:  02 03 00 FF FF              (5 bytes — sign byte needed)
    //   OCTET STRING:   04 01 04                    (3 bytes)
    //   INTEGER 3:      02 01 03                    (3 bytes)
    // Total inner = 14 bytes
    // Outer: 30 0E [14 bytes]
    const HEADER_DATA_WIRE: &[u8] = &[
        0x30, 0x0E, // SEQUENCE, length 14
        0x02, 0x01, 0x01, // INTEGER 1
        0x02, 0x03, 0x00, 0xFF, 0xFF, // INTEGER 65535 (sign byte 0x00)
        0x04, 0x01, 0x04, // OCTET STRING [0x04]
        0x02, 0x01, 0x03, // INTEGER 3
    ];

    #[test]
    fn given_header_data_fields_when_encoded_then_matches_wire_vector() {
        let encoded = encode_header_data(1, MSG_MAX_SIZE_UDP, 0x04, 3);
        assert_eq!(encoded, HEADER_DATA_WIRE);
    }

    #[test]
    fn given_header_data_wire_when_decoded_then_fields_extracted() {
        let mut outer = BerReader::new(HEADER_DATA_WIRE);
        let mut reader = outer.read_sequence().expect("SEQUENCE must parse");
        let msg_id = reader.read_integer().expect("msgID must parse");
        let max_size = reader.read_integer().expect("maxSize must parse");
        let flags_bytes = reader.read_octet_string().expect("msgFlags must parse");
        let security_model = reader.read_integer().expect("securityModel must parse");

        assert_eq!(msg_id, 1);
        assert_eq!(max_size, MSG_MAX_SIZE_UDP);
        assert_eq!(flags_bytes, &[0x04]);
        assert_eq!(security_model, 3);
    }

    // ── Test 2: USM params encode/decode round-trip ───────────────────────────

    // Wire encoding of USM { engine_id: [0x80,0x00,0x01], boots: 10, time: 200,
    //                        user_name: b"admin", auth_params: [], priv_params: [] }
    //
    // Inner TLVs:
    //   OCTET STRING [80 00 01]:  04 03 80 00 01              (5 bytes)
    //   INTEGER 10:               02 01 0A                    (3 bytes)
    //   INTEGER 200:              02 02 00 C8                 (4 bytes — 0xC8 high bit set)
    //   OCTET STRING "admin":     04 05 61 64 6D 69 6E        (7 bytes)
    //   OCTET STRING []:          04 00                       (2 bytes)
    //   OCTET STRING []:          04 00                       (2 bytes)
    // Total inner = 5+3+4+7+2+2 = 23 bytes
    // Outer: 30 17 [23 bytes]
    const USM_PARAMS_WIRE: &[u8] = &[
        0x30, 0x17, // SEQUENCE, length 23
        0x04, 0x03, 0x80, 0x00, 0x01, // OCTET STRING [80 00 01]
        0x02, 0x01, 0x0A, // INTEGER 10
        0x02, 0x02, 0x00, 0xC8, // INTEGER 200 (sign byte 0x00 before 0xC8)
        0x04, 0x05, 0x61, 0x64, 0x6D, 0x69, 0x6E, // OCTET STRING "admin"
        0x04, 0x00, // OCTET STRING [] (auth_params)
        0x04, 0x00, // OCTET STRING [] (priv_params)
    ];

    #[test]
    fn given_usm_fields_when_encoded_then_matches_wire_vector() {
        let encoded = encode_usm_params(&[0x80, 0x00, 0x01], 10, 200, b"admin", &[], &[]);
        assert_eq!(encoded, USM_PARAMS_WIRE);
    }

    #[test]
    fn given_usm_wire_when_decoded_then_fields_extracted() {
        let mut outer = BerReader::new(USM_PARAMS_WIRE);
        let mut reader = outer.read_sequence().expect("SEQUENCE must parse");
        let engine_id = reader.read_octet_string().expect("engine_id must parse");
        let engine_boots = reader.read_integer().expect("engine_boots must parse");
        let engine_time = reader.read_integer().expect("engine_time must parse");
        let user_name = reader.read_octet_string().expect("user_name must parse");
        let auth_params = reader.read_octet_string().expect("auth_params must parse");
        let priv_params = reader.read_octet_string().expect("priv_params must parse");

        assert_eq!(engine_id, &[0x80, 0x00, 0x01]);
        assert_eq!(engine_boots, 10);
        assert_eq!(engine_time, 200);
        assert_eq!(user_name, b"admin");
        assert_eq!(auth_params, b"");
        assert_eq!(priv_params, b"");
    }

    // ── Test 3: ScopedPdu encode/decode round-trip ────────────────────────────

    // Wire encoding of ScopedPdu { engine_id: [0x01], context_name: b"ctx",
    //                              raw_pdu: [0xA0, 0x00] (empty GetRequest) }
    //
    // Inner TLVs:
    //   OCTET STRING [01]:   04 01 01                    (3 bytes)
    //   OCTET STRING "ctx":  04 03 63 74 78              (5 bytes)
    //   raw PDU:             A0 00                       (2 bytes, verbatim)
    // Total inner = 3+5+2 = 10 bytes
    // Outer: 30 0A [10 bytes]
    const SCOPED_PDU_WIRE: &[u8] = &[
        0x30, 0x0A, // SEQUENCE, length 10
        0x04, 0x01, 0x01, // OCTET STRING [01]
        0x04, 0x03, 0x63, 0x74, 0x78, // OCTET STRING "ctx"
        0xA0, 0x00, // raw PDU: empty GetRequest
    ];

    #[test]
    fn given_scoped_pdu_fields_when_encoded_then_matches_wire_vector() {
        let encoded = encode_scoped_pdu(&[0x01], b"ctx", &[0xA0, 0x00]);
        assert_eq!(encoded, SCOPED_PDU_WIRE);
    }

    #[test]
    fn given_scoped_pdu_wire_when_decoded_then_fields_extracted() {
        let decoded = decode_scoped_pdu(SCOPED_PDU_WIRE).expect("must decode");

        assert_eq!(decoded.context_engine_id, &[0x01]);
        assert_eq!(decoded.context_name, b"ctx");
        assert_eq!(decoded.raw_pdu, &[0xA0, 0x00]);
    }

    // ── Test 4: Full V3 message encode/decode round-trip (noAuthNoPriv) ───────

    // Discovery probe: all-empty/zero USM fields, empty context fields, minimal PDU.
    //
    // version TLV:          02 01 03                          (3 bytes)
    // HeaderData SEQUENCE:
    //   INTEGER 1:          02 01 01
    //   INTEGER 65535:      02 03 00 FF FF
    //   OCTET STRING:       04 01 04
    //   INTEGER 3:          02 01 03
    //   inner = 3+5+3+3 = 14 bytes → 30 0E [14] = 16 bytes total
    //
    // USM SEQUENCE (all-empty/zero):
    //   OCTET STRING []:    04 00  (2 bytes)
    //   INTEGER 0:          02 01 00  (3 bytes)
    //   INTEGER 0:          02 01 00  (3 bytes)
    //   OCTET STRING []:    04 00  (2 bytes)
    //   OCTET STRING []:    04 00  (2 bytes)
    //   OCTET STRING []:    04 00  (2 bytes)
    //   inner = 2+3+3+2+2+2 = 14 bytes → 30 0E [14] = 16 bytes total
    // securityParams OCTET STRING: 04 10 [16 bytes] = 18 bytes total
    //
    // ScopedPdu SEQUENCE:
    //   OCTET STRING []:    04 00  (2 bytes)
    //   OCTET STRING []:    04 00  (2 bytes)
    //   raw PDU:            A0 00  (2 bytes)
    //   inner = 2+2+2 = 6 bytes → 30 06 [6] = 8 bytes total
    //
    // Outer inner total = 3 + 16 + 18 + 8 = 45 bytes → 30 2D [45]
    const V3_DISCOVERY_WIRE: &[u8] = &[
        0x30, 0x2D, // SEQUENCE, length 45
        // version = 3
        0x02, 0x01, 0x03, // HeaderData SEQUENCE (14 bytes inner)
        0x30, 0x0E, 0x02, 0x01, 0x01, // msgID = 1
        0x02, 0x03, 0x00, 0xFF, 0xFF, // maxSize = 65535
        0x04, 0x01, 0x04, // msgFlags = [0x04]
        0x02, 0x01, 0x03, // securityModel = 3
        // securityParameters OCTET STRING wrapping USM SEQUENCE
        0x04, 0x10, // OCTET STRING, length 16
        0x30, 0x0E, // USM SEQUENCE, length 14
        0x04, 0x00, // engineID = []
        0x02, 0x01, 0x00, // engineBoots = 0
        0x02, 0x01, 0x00, // engineTime = 0
        0x04, 0x00, // userName = []
        0x04, 0x00, // authParams = []
        0x04, 0x00, // privParams = []
        // ScopedPdu SEQUENCE (6 bytes inner)
        0x30, 0x06, 0x04, 0x00, // contextEngineID = []
        0x04, 0x00, // contextName = []
        0xA0, 0x00, // raw PDU = empty GetRequest
    ];

    #[test]
    fn given_discovery_probe_fields_when_encoded_then_matches_wire_vector() {
        let scoped_pdu = encode_scoped_pdu(&[], &[], &[0xA0, 0x00]);
        let (encoded, auth_offset) = encode_v3_message(
            1,                // msg_id
            MSG_MAX_SIZE_UDP, // max_size
            0x04,             // flags_byte (reportable, noAuth, noPriv)
            3,                // security_model (USM)
            &[],              // engine_id
            0,                // engine_boots
            0,                // engine_time
            &[],              // user_name
            &[],              // auth_params
            &[],              // priv_params
            &scoped_pdu,
            false, // not encrypted
        )
        .expect("encode must succeed");

        assert_eq!(encoded, V3_DISCOVERY_WIRE);
        assert!(
            auth_offset.is_none(),
            "noAuthNoPriv must have no auth offset"
        );
    }

    #[test]
    fn given_discovery_probe_wire_when_decoded_then_all_fields_match() {
        let envelope = decode_v3_envelope(V3_DISCOVERY_WIRE).expect("must decode");

        assert_eq!(envelope.msg_id, 1);
        assert_eq!(envelope.max_size, MSG_MAX_SIZE_UDP);
        assert_eq!(envelope.security_flags, 0x04);
        assert_eq!(envelope.security_model, 3);
        assert_eq!(envelope.usm.engine_id, b"");
        assert_eq!(envelope.usm.engine_boots, 0);
        assert_eq!(envelope.usm.engine_time, 0);
        assert_eq!(envelope.usm.user_name, b"");
        assert_eq!(envelope.usm.auth_params, b"");
        assert_eq!(envelope.usm.priv_params, b"");
        assert!(envelope.auth_params_offset.is_none());
        assert_eq!(envelope.raw_message, V3_DISCOVERY_WIRE);

        match envelope.scoped_data {
            ScopedData::Plaintext {
                context_engine_id,
                context_name,
                raw_pdu,
            } => {
                assert_eq!(context_engine_id, b"");
                assert_eq!(context_name, b"");
                assert_eq!(raw_pdu, &[0xA0, 0x00]);
            }
            ScopedData::Encrypted(_) => panic!("expected plaintext scoped data"),
        }
    }

    // ── Test 5: V3 message with non-empty auth_params — verify auth_params_offset ──

    #[test]
    fn given_v3_message_with_auth_params_when_encoded_then_offset_points_into_message() {
        let auth_params = [0x00u8; 12]; // 12-byte HMAC-SHA-1 placeholder
        let scoped_pdu = encode_scoped_pdu(&[0x01], b"", &[0xA0, 0x00]);
        let (encoded, auth_offset) = encode_v3_message(
            2,
            MSG_MAX_SIZE_UDP,
            0x01, // authNoPriv
            3,
            &[0x80, 0x00, 0x01],
            5,
            100,
            b"admin",
            &auth_params,
            &[],
            &scoped_pdu,
            false,
        )
        .expect("encode must succeed");

        let offset = auth_offset.expect("authenticated message must have auth_params_offset");
        assert_eq!(
            &encoded[offset..offset + auth_params.len()],
            &auth_params,
            "bytes at auth_params_offset must equal the encoded auth_params"
        );
    }

    #[test]
    fn given_v3_message_with_auth_params_when_decoded_then_offset_points_into_message() {
        // Encode a message with non-empty auth_params, then decode and verify
        // that auth_params_offset from decode also points at the correct bytes.
        let auth_params = vec![0xABu8; 12];
        let scoped_pdu = encode_scoped_pdu(&[0x01], b"", &[0xA0, 0x00]);
        let (encoded, _) = encode_v3_message(
            3,
            MSG_MAX_SIZE_UDP,
            0x01,
            3,
            &[0x80, 0x00, 0x01],
            1,
            42,
            b"user",
            &auth_params,
            &[],
            &scoped_pdu,
            false,
        )
        .expect("encode must succeed");

        let envelope = decode_v3_envelope(&encoded).expect("must decode");
        let offset = envelope
            .auth_params_offset
            .expect("authenticated message must have auth_params_offset");
        assert_eq!(
            &encoded[offset..offset + auth_params.len()],
            auth_params.as_slice(),
            "bytes at auth_params_offset must equal the auth_params"
        );
    }

    // ── Test 6: Encrypted ScopedPduData decode ────────────────────────────────

    #[test]
    fn given_v3_message_with_encrypted_scoped_data_when_decoded_then_ciphertext_preserved() {
        let ciphertext = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02];
        let (encoded, _) = encode_v3_message(
            4,
            MSG_MAX_SIZE_UDP,
            0x03, // authPriv
            3,
            &[0x80, 0x00, 0x01],
            0,
            0,
            b"user",
            &[],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08], // priv_params
            &ciphertext,
            true, // encrypted
        )
        .expect("encode must succeed");

        let envelope = decode_v3_envelope(&encoded).expect("must decode");

        match envelope.scoped_data {
            ScopedData::Encrypted(decoded_ciphertext) => {
                assert_eq!(decoded_ciphertext, ciphertext);
            }
            ScopedData::Plaintext { .. } => panic!("expected encrypted scoped data"),
        }
    }

    // ── Test 7: authPriv message — both auth_params and priv_params non-empty ──

    #[test]
    fn given_v3_authpriv_message_when_encoded_and_decoded_then_offsets_and_params_preserved() {
        // An authPriv message has both non-empty auth_params (HMAC placeholder)
        // and non-empty priv_params (AES salt).
        let auth_params = [0x00u8; 12]; // 12-byte HMAC-SHA-1 placeholder
        let priv_params = [0xBBu8; 8]; // 8-byte AES salt
        let scoped_pdu = encode_scoped_pdu(&[0x80, 0x00, 0x01], b"", &[0xA0, 0x00]);
        let (encoded, auth_offset) = encode_v3_message(
            5,
            MSG_MAX_SIZE_UDP,
            0x03, // authPriv
            3,
            &[0x80, 0x00, 0x01],
            7,
            300,
            b"secuser",
            &auth_params,
            &priv_params,
            &scoped_pdu,
            false,
        )
        .expect("encode must succeed");

        // auth_params_offset from encoding must point at the zeroed auth_params bytes.
        let encode_offset = auth_offset.expect("authPriv message must have auth_params_offset");
        assert_eq!(
            &encoded[encode_offset..encode_offset + auth_params.len()],
            &auth_params,
            "encode offset must point to auth_params bytes"
        );

        // Decode and verify that both auth_params_offset and priv_params are correct.
        let envelope = decode_v3_envelope(&encoded).expect("must decode");
        let decode_offset = envelope
            .auth_params_offset
            .expect("decoded authPriv message must have auth_params_offset");
        assert_eq!(
            encode_offset, decode_offset,
            "encode and decode offsets must agree"
        );
        assert_eq!(
            &encoded[decode_offset..decode_offset + auth_params.len()],
            &auth_params,
            "decode offset must point to auth_params bytes"
        );
        assert_eq!(
            envelope.usm.priv_params, priv_params,
            "priv_params must be preserved through encode/decode"
        );
    }

    // ── Test 8: Version check — wrong version returns error ───────────────────

    #[test]
    fn given_snmpv2c_message_when_decoded_then_error_mentions_version() {
        // Construct a minimal message with version 1 (SNMPv2c wire value).
        // We reuse the discovery wire vector and patch version byte 3 → value 1.
        // In V3_DISCOVERY_WIRE the version INTEGER is bytes [2..5]: 02 01 03.
        // Patch the value byte at index 4 from 03 to 01.
        let mut patched = V3_DISCOVERY_WIRE.to_vec();
        patched[4] = 0x01; // version = 1 (SNMPv2c)

        match decode_v3_envelope(&patched) {
            Err(ber_error) => {
                let error_message = ber_error.to_string();
                assert!(
                    error_message.contains("version"),
                    "error message must mention version, got: {error_message}"
                );
            }
            Ok(_) => panic!("expected an error for wrong version, but decode succeeded"),
        }
    }

    // ── Test 9: decode_scoped_pdu standalone ─────────────────────────────────

    #[test]
    fn given_scoped_pdu_bytes_when_decode_scoped_pdu_called_then_fields_extracted() {
        let raw_pdu = [0xA1, 0x00]; // empty GetNextRequest
        let encoded = encode_scoped_pdu(&[0x80, 0x00, 0x02], b"public", &raw_pdu);

        let decoded = decode_scoped_pdu(&encoded).expect("must decode");

        assert_eq!(decoded.context_engine_id, &[0x80, 0x00, 0x02]);
        assert_eq!(decoded.context_name, b"public");
        assert_eq!(decoded.raw_pdu, &raw_pdu);
    }

    // ── Test 10: Error cases ──────────────────────────────────────────────────

    #[test]
    fn given_truncated_message_when_decoded_then_returns_error() {
        let truncated = &V3_DISCOVERY_WIRE[..10];
        let ber_error = decode_v3_envelope(truncated).unwrap_err();
        assert!(
            ber_error.to_string().to_lowercase().contains("truncated")
                || ber_error
                    .to_string()
                    .to_lowercase()
                    .contains("unexpected end"),
            "unexpected error: {ber_error}"
        );
    }

    #[test]
    fn given_wrong_outer_tag_when_decoded_then_returns_error() {
        // Replace the outer SEQUENCE tag (0x30) with 0x31 (SET).
        let mut wrong_tag = V3_DISCOVERY_WIRE.to_vec();
        wrong_tag[0] = 0x31;
        let ber_error = decode_v3_envelope(&wrong_tag).unwrap_err();
        assert!(
            ber_error.to_string().to_lowercase().contains("expected"),
            "unexpected error: {ber_error}"
        );
    }

    #[test]
    fn given_truncated_usm_params_when_decoded_then_returns_error() {
        // Locate the USM SEQUENCE within the wire vector and shorten its length.
        // The USM SEQUENCE starts after: outer tag+len(2) + version(3) +
        //   HeaderData(16) + secParams OCTET STRING tag+len(2) = 23 bytes.
        // So V3_DISCOVERY_WIRE[23] should be 0x30 (USM SEQUENCE tag).
        // We truncate the message at byte 25 to cut into the USM content.
        let ber_error = decode_v3_envelope(&V3_DISCOVERY_WIRE[..26]).unwrap_err();
        assert!(
            ber_error.to_string().to_lowercase().contains("truncated")
                || ber_error
                    .to_string()
                    .to_lowercase()
                    .contains("unexpected end"),
            "unexpected error: {ber_error}"
        );
    }

    // ── Test 11: Negative engine_boots/engine_time preserved by BER codec ─────

    #[test]
    fn given_negative_engine_boots_and_time_when_encoded_and_decoded_then_values_preserved() {
        // The BER codec must preserve negative values as-is; the dispatch layer
        // is responsible for validating that boots/time are non-negative.
        let scoped_pdu = encode_scoped_pdu(&[], &[], &[0xA0, 0x00]);
        let (encoded, _) = encode_v3_message(
            6,
            MSG_MAX_SIZE_UDP,
            0x04,
            3,
            &[],
            -1,  // engine_boots: negative
            -42, // engine_time: negative
            &[],
            &[],
            &[],
            &scoped_pdu,
            false,
        )
        .expect("encode must succeed");

        let envelope = decode_v3_envelope(&encoded).expect("must decode");
        assert_eq!(
            envelope.usm.engine_boots, -1,
            "negative engine_boots must survive encode/decode"
        );
        assert_eq!(
            envelope.usm.engine_time, -42,
            "negative engine_time must survive encode/decode"
        );
    }

    // ── Test 11b: Negative msgID is rejected by decode_v3_envelope ───────────

    #[test]
    fn given_negative_msg_id_when_decode_v3_envelope_then_error() {
        // Verifies: REQ-0118
        // §6.4 msgID range [0, 2^31-1]
        // encode_v3_message happily encodes any i32 including -1; the decoder
        // must then reject it because msgID must be non-negative.
        let scoped_pdu = encode_scoped_pdu(&[], &[], &[0xA0, 0x00]);
        let (encoded, _) = encode_v3_message(
            -1,               // msg_id: negative — invalid per RFC 3412 §6.4
            MSG_MAX_SIZE_UDP, // max_size
            0x04,             // flags_byte (reportable, noAuth, noPriv)
            3,                // security_model (USM)
            &[],              // engine_id
            0,                // engine_boots
            0,                // engine_time
            &[],              // user_name
            &[],              // auth_params
            &[],              // priv_params
            &scoped_pdu,
            false, // not encrypted
        )
        .expect("encoding a negative msgID must succeed (encoder does not validate)");

        let ber_error = decode_v3_envelope(&encoded).unwrap_err();
        let error_message = ber_error.to_string();
        assert!(
            error_message.contains("msgID"),
            "error must mention msgID, got: {error_message}"
        );
        assert!(
            error_message.contains("non-negative") || error_message.contains("RFC 3412"),
            "error must reference the non-negative constraint or RFC 3412, got: {error_message}"
        );
    }

    // ── Test 11c: msgMaxSize below 484 is rejected by decode_v3_envelope ──────

    #[test]
    fn given_max_size_zero_when_decode_v3_envelope_then_error() {
        // Verifies: REQ-0119
        // §6.6 msgMaxSize minimum value 484 — encode_v3_message encodes any i32
        // for max_size; the decoder must reject 0 because msgMaxSize must be at
        // least 484.
        let scoped_pdu = encode_scoped_pdu(&[], &[], &[0xA0, 0x00]);
        let (encoded, _) = encode_v3_message(
            1,    // msg_id
            0,    // max_size: 0 — invalid per RFC 3412 §6.6
            0x04, // flags_byte (reportable, noAuth, noPriv)
            3,    // security_model (USM)
            &[],  // engine_id
            0,    // engine_boots
            0,    // engine_time
            &[],  // user_name
            &[],  // auth_params
            &[],  // priv_params
            &scoped_pdu,
            false, // not encrypted
        )
        .expect("encoding max_size=0 must succeed (encoder does not validate)");

        let ber_error = decode_v3_envelope(&encoded).unwrap_err();
        let error_message = ber_error.to_string();
        assert!(
            error_message.contains("msgMaxSize"),
            "error must mention msgMaxSize, got: {error_message}"
        );
        assert!(
            error_message.contains("484") || error_message.contains("RFC 3412"),
            "error must reference 484 or RFC 3412, got: {error_message}"
        );
    }

    #[test]
    fn given_max_size_483_when_decode_v3_envelope_then_error() {
        // Verifies: REQ-0119
        // §6.6 msgMaxSize minimum value 484 — 483 is one below the minimum; the
        // decoder must reject it.
        let scoped_pdu = encode_scoped_pdu(&[], &[], &[0xA0, 0x00]);
        let (encoded, _) = encode_v3_message(
            1,    // msg_id
            483,  // max_size: 483 — one below the minimum per RFC 3412 §6.6
            0x04, // flags_byte (reportable, noAuth, noPriv)
            3,    // security_model (USM)
            &[],  // engine_id
            0,    // engine_boots
            0,    // engine_time
            &[],  // user_name
            &[],  // auth_params
            &[],  // priv_params
            &scoped_pdu,
            false, // not encrypted
        )
        .expect("encoding max_size=483 must succeed (encoder does not validate)");

        let ber_error = decode_v3_envelope(&encoded).unwrap_err();
        let error_message = ber_error.to_string();
        assert!(
            error_message.contains("msgMaxSize"),
            "error must mention msgMaxSize, got: {error_message}"
        );
        assert!(
            error_message.contains("484") || error_message.contains("RFC 3412"),
            "error must reference 484 or RFC 3412, got: {error_message}"
        );
    }

    #[test]
    fn given_max_size_484_when_decode_v3_envelope_then_accepted() {
        // Verifies: REQ-0119
        // §6.6 msgMaxSize minimum value 484 — 484 is the minimum allowed value;
        // the decoder must not reject it
        // for the max_size check (it may succeed fully or fail for other reasons).
        let scoped_pdu = encode_scoped_pdu(&[], &[], &[0xA0, 0x00]);
        let (encoded, _) = encode_v3_message(
            1,    // msg_id
            484,  // max_size: exactly the minimum per RFC 3412 §6.6
            0x04, // flags_byte (reportable, noAuth, noPriv)
            3,    // security_model (USM)
            &[],  // engine_id
            0,    // engine_boots
            0,    // engine_time
            &[],  // user_name
            &[],  // auth_params
            &[],  // priv_params
            &scoped_pdu,
            false, // not encrypted
        )
        .expect("encode must succeed");

        // The decode must either succeed completely or fail for a reason other
        // than the max_size check — never with an error mentioning msgMaxSize.
        match decode_v3_envelope(&encoded) {
            Ok(_) => {} // fully valid message — max_size check passed
            Err(ber_error) => {
                assert!(
                    !ber_error.to_string().contains("msgMaxSize"),
                    "decode must not reject max_size=484 with a msgMaxSize error, got: {ber_error}"
                );
            }
        }
    }

    // ── Test 12: msgFlags validation — wrong length returns error ─────────────

    #[test]
    fn given_msg_flags_with_wrong_length_when_decoded_then_error_mentions_msgflags() {
        // Build a HeaderData with a 2-byte msgFlags (invalid per RFC 3412 §6.6)
        // and embed it in a minimal V3 envelope to exercise the validation path.
        let mut inner = BerWriter::new();
        inner.write_integer(1); // msgID
        inner.write_integer(MSG_MAX_SIZE_UDP); // maxSize
        inner.write_octet_string(&[0x04, 0x00]); // msgFlags: 2 bytes — invalid
        inner.write_integer(3); // securityModel

        let mut header_outer = BerWriter::new();
        header_outer.write_sequence(inner.as_bytes());
        let header_bytes = header_outer.into_vec();

        let usm_bytes = encode_usm_params(&[], 0, 0, &[], &[], &[]);
        let scoped_pdu = encode_scoped_pdu(&[], &[], &[0xA0, 0x00]);

        let mut msg_inner = BerWriter::new();
        msg_inner.write_integer(SNMPV3_VERSION);
        msg_inner.write_raw(&header_bytes);
        msg_inner.write_octet_string(&usm_bytes);
        msg_inner.write_raw(&scoped_pdu);

        let mut outer = BerWriter::new();
        outer.write_sequence(msg_inner.as_bytes());
        let bad_message = outer.into_vec();

        let ber_error = decode_v3_envelope(&bad_message).unwrap_err();
        assert!(
            ber_error.to_string().to_lowercase().contains("msgflags"),
            "error must mention msgFlags, got: {ber_error}"
        );
    }

    // ── Test 13: Encode v2c with empty community ──────────────────────────────

    // Wire encoding of V2cMessage { version: 1, community: "", data: empty Trap PDU }
    //
    // Inner TLVs:
    //   INTEGER 1:           02 01 01         (3 bytes)
    //   OCTET STRING "":     04 00            (2 bytes)
    //   raw PDU:             A7 00            (2 bytes)
    // Total inner = 7 bytes
    // Outer: 30 07 [7 bytes]
    const V2C_EMPTY_COMMUNITY_WIRE: &[u8] = &[0x30, 0x07, 0x02, 0x01, 0x01, 0x04, 0x00, 0xA7, 0x00];

    #[test]
    fn given_empty_community_when_v2c_encoded_then_matches_wire_vector() {
        let encoded = encode_v2c_message(b"", &[0xA7, 0x00]);
        assert_eq!(encoded, V2C_EMPTY_COMMUNITY_WIRE);
    }

    // ── Test 14: Encode v2c with "public" community ───────────────────────────

    // Wire encoding of V2cMessage { version: 1, community: "public", data: empty Trap PDU }
    //
    // Inner TLVs:
    //   INTEGER 1:           02 01 01                        (3 bytes)
    //   OCTET STRING:        04 06 70 75 62 6C 69 63         (8 bytes — "public")
    //   raw PDU:             A7 00                           (2 bytes)
    // Total inner = 13 bytes
    // Outer: 30 0D [13 bytes]
    const V2C_PUBLIC_COMMUNITY_WIRE: &[u8] = &[
        0x30, 0x0D, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, 0xA7, 0x00,
    ];

    #[test]
    fn given_public_community_when_v2c_encoded_then_matches_wire_vector() {
        let encoded = encode_v2c_message(b"public", &[0xA7, 0x00]);
        assert_eq!(encoded, V2C_PUBLIC_COMMUNITY_WIRE);
    }

    // ── Helper: decode the three fields of a v2c message ─────────────────────

    /// Decodes a BER-encoded `SNMPv2c` message and returns `(version, community, pdu_bytes)`.
    ///
    /// Asserts that no bytes trail the outer SEQUENCE in the encoded buffer,
    /// verifying there is no trailing garbage after the message envelope.
    fn decode_v2c_fields(encoded: &[u8]) -> (i32, Vec<u8>, Vec<u8>) {
        let mut outer_reader = BerReader::new(encoded);
        let mut msg_reader = outer_reader.read_sequence().expect("SEQUENCE must parse");
        // Verify no bytes trail the outer SEQUENCE TLV in the encoded buffer.
        assert!(
            outer_reader.is_empty(),
            "no trailing bytes expected after the SNMPv2c outer SEQUENCE"
        );
        let version = msg_reader.read_integer().expect("version must parse");
        let community = msg_reader
            .read_octet_string()
            .expect("community must parse")
            .to_vec();
        let pdu_bytes = msg_reader.remaining().to_vec();
        (version, community, pdu_bytes)
    }

    // ── Test 15: Decode round-trip ────────────────────────────────────────────

    #[test]
    fn given_v2c_message_when_encoded_and_decoded_then_fields_match() {
        let community = b"test-community";
        let raw_pdu = [0xA7, 0x00]; // empty Trap PDU
        let encoded = encode_v2c_message(community, &raw_pdu);

        let (version, decoded_community, decoded_pdu) = decode_v2c_fields(&encoded);

        assert_eq!(version, 1);
        assert_eq!(decoded_community, community);
        assert_eq!(decoded_pdu, raw_pdu);
    }

    // ── Test 16: Encode with real trap PDU ───────────────────────────────────

    #[test]
    fn given_v2c_message_with_trap_pdu_when_encoded_and_decoded_then_pdu_preserved() {
        use super::super::TAG_TRAP;
        use super::super::pdu::encode_pdu;

        // Build a minimal trap PDU: request_id=1, error_status=0, error_index=0, empty varbind list
        let trap_pdu =
            encode_pdu(TAG_TRAP, 1, 0, 0, &[0x30, 0x00]).expect("encode_pdu must succeed");

        let encoded = encode_v2c_message(b"", &trap_pdu);

        let (version, community, decoded_pdu) = decode_v2c_fields(&encoded);

        assert_eq!(version, 1);
        assert_eq!(community, b"");
        assert_eq!(decoded_pdu, trap_pdu.as_slice());
    }
}
