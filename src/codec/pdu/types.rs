use std::fmt;

use crate::codec::{Oid, Value};

// ── VarbindValue ─────────────────────────────────────────────────────────────

/// The value carried by a single varbind, which may be a concrete `SMIv2`
/// value, an inbound Null placeholder, or one of the three exception sentinels
/// defined in RFC 3416.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VarbindValue {
    /// A concrete `SMIv2` value.
    Value(Value),
    /// Null placeholder used in inbound Get/GetNext/GetBulk varbinds to
    /// indicate "no value provided yet"; distinct from the `NoSuchObject`
    /// response exception.
    Unspecified,
    /// The requested object does not exist in the MIB (response exception).
    NoSuchObject,
    /// The requested object instance does not exist (response exception).
    NoSuchInstance,
    /// GETNEXT/GETBULK has walked past the end of the MIB view (response exception).
    EndOfMibView,
}

// ── Varbind ───────────────────────────────────────────────────────────────────

/// A single variable binding (OID + value/exception) in an SNMP PDU.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Varbind {
    /// The object identifier being bound.
    pub oid: Oid,
    /// The value or exception associated with the OID.
    pub value: VarbindValue,
}

// ── ErrorStatus ───────────────────────────────────────────────────────────────

/// SNMP error-status codes as defined in RFC 3416 §3.
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ErrorStatus {
    /// No error occurred.
    NoError = 0,
    /// The response PDU would have been too large.
    TooBig = 1,
    /// No such variable name in this MIB view (`SNMPv1` compat).
    NoSuchName = 2,
    /// The value supplied in a set request is of the wrong type or length.
    BadValue = 3,
    /// A variable is read-only (`SNMPv1` compat).
    ReadOnly = 4,
    /// A general error unrelated to the other categories.
    GenErr = 5,
    /// Access to the requested variable is not allowed.
    NoAccess = 6,
    /// The variable binding value has the wrong ASN.1 type.
    WrongType = 7,
    /// The variable binding value has the wrong length.
    WrongLength = 8,
    /// The variable binding value is incorrectly encoded.
    WrongEncoding = 9,
    /// The variable binding value is not consistent with the variable's definition.
    WrongValue = 10,
    /// The specified variable does not exist and cannot be created.
    NoCreation = 11,
    /// The variable binding is inconsistent with the current state.
    InconsistentValue = 12,
    /// Required resources are unavailable.
    ResourceUnavailable = 13,
    /// A prior commitment could not be undone.
    CommitFailed = 14,
    /// Undo was not possible.
    UndoFailed = 15,
    /// Access was denied for other reasons.
    AuthorizationError = 16,
    /// The variable binding cannot be written.
    NotWritable = 17,
    /// The OID in the variable binding is inconsistent with the current state.
    InconsistentName = 18,
}

impl ErrorStatus {
    /// Converts a raw RFC 3416 integer error-status code into an [`ErrorStatus`].
    ///
    /// Returns `None` if `code` is not a defined error-status value.
    #[must_use]
    pub fn from_u32(code: u32) -> Option<Self> {
        match code {
            0 => Some(Self::NoError),
            1 => Some(Self::TooBig),
            2 => Some(Self::NoSuchName),
            3 => Some(Self::BadValue),
            4 => Some(Self::ReadOnly),
            5 => Some(Self::GenErr),
            6 => Some(Self::NoAccess),
            7 => Some(Self::WrongType),
            8 => Some(Self::WrongLength),
            9 => Some(Self::WrongEncoding),
            10 => Some(Self::WrongValue),
            11 => Some(Self::NoCreation),
            12 => Some(Self::InconsistentValue),
            13 => Some(Self::ResourceUnavailable),
            14 => Some(Self::CommitFailed),
            15 => Some(Self::UndoFailed),
            16 => Some(Self::AuthorizationError),
            17 => Some(Self::NotWritable),
            18 => Some(Self::InconsistentName),
            _ => None,
        }
    }
}

impl fmt::Display for ErrorStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (name, code) = match self {
            Self::NoError => ("noError", 0u32),
            Self::TooBig => ("tooBig", 1),
            Self::NoSuchName => ("noSuchName", 2),
            Self::BadValue => ("badValue", 3),
            Self::ReadOnly => ("readOnly", 4),
            Self::GenErr => ("genErr", 5),
            Self::NoAccess => ("noAccess", 6),
            Self::WrongType => ("wrongType", 7),
            Self::WrongLength => ("wrongLength", 8),
            Self::WrongEncoding => ("wrongEncoding", 9),
            Self::WrongValue => ("wrongValue", 10),
            Self::NoCreation => ("noCreation", 11),
            Self::InconsistentValue => ("inconsistentValue", 12),
            Self::ResourceUnavailable => ("resourceUnavailable", 13),
            Self::CommitFailed => ("commitFailed", 14),
            Self::UndoFailed => ("undoFailed", 15),
            Self::AuthorizationError => ("authorizationError", 16),
            Self::NotWritable => ("notWritable", 17),
            Self::InconsistentName => ("inconsistentName", 18),
        };
        write!(f, "{name}({code})")
    }
}

// ── Inbound PDU structs ───────────────────────────────────────────────────────

/// An `SNMPv2` [`GetRequest`] PDU (inbound).
///
/// On the wire all varbind values are Null; they are decoded as
/// [`VarbindValue::Unspecified`] as a placeholder until the agent populates
/// the response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetRequest {
    /// PDU request identifier, echoed in the response.
    pub request_id: i32,
    /// Variable bindings (values are [`VarbindValue::Unspecified`] on inbound requests).
    pub varbinds: Vec<Varbind>,
}

/// An `SNMPv2` [`GetNextRequest`] PDU (inbound).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetNextRequest {
    /// PDU request identifier, echoed in the response.
    pub request_id: i32,
    /// Variable bindings identifying the OIDs whose lexicographic successors are requested.
    pub varbinds: Vec<Varbind>,
}

/// An `SNMPv2` [`GetBulkRequest`] PDU (inbound).
///
/// `non_repeaters` and `max_repetitions` are unchecked wire values.  The
/// caller (event loop) is responsible for validating that `non_repeaters` does
/// not exceed the varbind count and for capping `max_repetitions` to a
/// reasonable bound before iterating.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetBulkRequest {
    /// PDU request identifier, echoed in the response.
    pub request_id: i32,
    /// Number of varbinds at the start of the list to treat as `GetNext`
    /// (non-repeating).  This is an unchecked wire value; validate before use.
    pub non_repeaters: u32,
    /// Maximum number of repetitions to return for each repeating variable.
    /// This is an unchecked wire value; cap to a reasonable bound before use.
    pub max_repetitions: u32,
    /// Variable bindings specifying the starting OIDs for the bulk walk.
    pub varbinds: Vec<Varbind>,
}

/// An `SNMPv2` [`SetRequest`] PDU (inbound).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetRequest {
    /// PDU request identifier, echoed in the response.
    pub request_id: i32,
    /// Variable bindings containing the OID/value pairs to set.
    pub varbinds: Vec<Varbind>,
}

// ── InboundPdu ────────────────────────────────────────────────────────────────

/// Union of all PDU types that an SNMP agent may receive from a manager.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InboundPdu {
    /// A [`GetRequest`].
    GetRequest(GetRequest),
    /// A [`GetNextRequest`].
    GetNextRequest(GetNextRequest),
    /// A [`GetBulkRequest`].
    GetBulkRequest(GetBulkRequest),
    /// A [`SetRequest`].
    SetRequest(SetRequest),
}

// ── V3ScopedData ─────────────────────────────────────────────────────────────

/// The inner PDU content of an `SNMPv3` message.
///
/// # Requirements
/// Implements: REQ-0101
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum V3ScopedData {
    /// A decoded cleartext PDU ready for dispatch (noAuthNoPriv or authNoPriv).
    Plaintext(InboundPdu),
    /// Raw AES ciphertext from an authPriv message; requires decryption before dispatch.
    /// The 8-byte privacy salt is in `UsmSecurityFields::priv_params`.
    Encrypted(Vec<u8>),
}

// ── DecodedScopedPdu ──────────────────────────────────────────────────────────

/// The decoded contents of a BER-encoded `ScopedPdu`, produced by [`decode_scoped_pdu`].
///
/// # Requirements
/// Implements: REQ-0101
#[derive(Debug, PartialEq, Eq)]
pub struct DecodedScopedPdu {
    /// `contextEngineID` extracted from the `ScopedPdu`.
    pub context_engine_id: Vec<u8>,
    /// `contextName` extracted from the `ScopedPdu`.
    pub context_name: Vec<u8>,
    /// The decoded inbound PDU.
    pub pdu: InboundPdu,
}

// ── UsmSecurityFields / V3InboundMessage ─────────────────────────────────────

/// USM security parameters extracted from the inbound message header.
///
/// # Requirements
/// Implements: REQ-0093, REQ-0098, REQ-0099, REQ-0100, REQ-0101
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsmSecurityFields {
    /// `msgAuthoritativeEngineID` from USM security parameters.
    /// Empty for engine-ID discovery probes (REQ-0093).
    pub auth_engine_id: Vec<u8>,
    /// `msgAuthoritativeEngineBoots` from USM security parameters.
    pub auth_engine_boots: u32,
    /// `msgAuthoritativeEngineTime` from USM security parameters.
    pub auth_engine_time: u32,
    /// Message flags byte: bit 0 = authFlag, bit 1 = privFlag, bit 2 = reportableFlag.
    pub security_flags: u8,
    /// `msgAuthenticationParameters` from the USM security parameters.
    /// For authenticated messages, this is the received MAC (24 bytes for SHA-256,
    /// 48 bytes for SHA-512). Empty for `noAuthNoPriv` messages.
    /// Preserved here for HMAC verification in dispatch.
    pub auth_params: Vec<u8>,
    /// `msgPrivacyParameters` from the USM security parameters.
    /// For authPriv messages this is the 8-byte AES salt/IV material needed for decryption.
    /// Empty for noAuthNoPriv and authNoPriv messages.
    pub priv_params: Vec<u8>,
}

/// A decoded inbound `SNMPv3` message, containing the message-level fields
/// extracted from the `HeaderData` and `ScopedPdu` envelope, plus the inner
/// PDU or encrypted payload.
///
/// # Requirements
/// Implements: REQ-0068, REQ-0069, REQ-0070, REQ-0093, REQ-0098, REQ-0099, REQ-0100, REQ-0101
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V3InboundMessage<'a> {
    /// Message ID from `HeaderData`; echoed in the `SNMPv3` response.
    pub msg_id: i32,
    /// Security model from `HeaderData` (RFC 3412 §6.6); must be [`SecurityModel::USM`].
    pub security_model: SecurityModel,
    /// Engine ID from the `ScopedPdu`; empty for authPriv messages pending decryption.
    pub engine_id: Vec<u8>,
    /// Context name from the `ScopedPdu`; empty for authPriv messages pending decryption.
    pub context_name: Vec<u8>,
    /// Security name (user name) from USM security parameters; echoed in the response
    /// per RFC 3414 §8.2.4 so the command generator can match the response to its request.
    pub user_name: Vec<u8>,
    /// The inner PDU or encrypted payload; use [`V3ScopedData`] variants to distinguish.
    pub scoped_data: V3ScopedData,
    /// USM security parameters extracted from the message header.
    pub usm: UsmSecurityFields,
    /// A reference to the raw BER bytes of the complete `SNMPv3` message as received.
    ///
    /// Required for HMAC verification: to recompute the MAC, the
    /// `msgAuthenticationParameters` field in these bytes must be zeroed
    /// before passing the buffer to the HMAC function.
    pub raw_message: &'a [u8],
    /// Byte offset of `msgAuthenticationParameters` within `raw_message`.
    ///
    /// `None` for `noAuthNoPriv` messages (empty `auth_params`).
    /// Recorded during decode to enable secure HMAC zeroing in dispatch — the
    /// offset is derived from the structural position within the USM security
    /// parameters, not from a byte-value search.
    pub(crate) auth_params_offset: Option<usize>,
}

// ── Outbound PDU structs ──────────────────────────────────────────────────────

/// An `SNMPv2` Response PDU (outbound), used to answer Get/GetNext/GetBulk/Set requests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetResponse {
    /// Request identifier copied from the corresponding inbound PDU.
    pub request_id: i32,
    /// The error status for this response.
    pub error_status: ErrorStatus,
    /// 1-based index into `varbinds` of the first varbind that caused an error,
    /// or `0` when `error_status` is `NoError`.
    pub error_index: u32,
    /// Variable bindings containing the response values or exception sentinels.
    pub varbinds: Vec<Varbind>,
}

/// An `SNMPv2`-Trap-PDU (outbound).
///
/// The trap PDU carries the same structure as a response PDU but has zero
/// `error_status` and `error_index` on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireTrapPdu {
    /// Request identifier for correlating notifications.
    pub request_id: i32,
    /// Variable bindings describing the trap payload.
    pub varbinds: Vec<Varbind>,
}

// ── DecodeError ─────────────────────────────────────────────────────────────

/// Error returned when BER-decoding an inbound SNMP PDU fails.
#[derive(Debug)]
pub struct DecodeError {
    kind: DecodeErrorKind,
    /// Human-readable description of what went wrong.
    pub message: String,
}

impl DecodeError {
    pub(super) fn new(kind: DecodeErrorKind, msg: impl Into<String>) -> Self {
        Self {
            kind,
            message: msg.into(),
        }
    }

    /// Returns the structured kind of this decode error.
    #[must_use]
    pub fn kind(&self) -> &DecodeErrorKind {
        &self.kind
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SNMP decode error ({}): {}", self.kind, self.message)
    }
}

impl std::error::Error for DecodeError {}

/// Structured category of a [`DecodeError`], per ADR-0009 (field-level
/// parse-error granularity).
#[derive(Debug, PartialEq, Eq)]
pub enum DecodeErrorKind {
    /// BER decode failure.
    Ber,
    /// PDU type received that is not a recognised inbound type.
    UnsupportedPduType,
    /// An OID in a varbind could not be converted.
    InvalidOid,
    /// The SNMP message version is not the expected value.
    WrongVersion,
}

impl fmt::Display for DecodeErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ber => write!(f, "BER decode failure"),
            Self::UnsupportedPduType => write!(f, "unsupported PDU type"),
            Self::InvalidOid => write!(f, "invalid OID"),
            Self::WrongVersion => write!(f, "wrong SNMP version"),
        }
    }
}

impl std::error::Error for DecodeErrorKind {}

// ── EncodeError ──────────────────────────────────────────────────────────────

/// Error returned when BER-encoding an outbound SNMP PDU fails.
#[derive(Debug)]
pub struct EncodeError {
    /// Human-readable description of what went wrong.
    pub message: String,
}

impl EncodeError {
    pub(super) fn new(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
        }
    }
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SNMP encode error: {}", self.message)
    }
}

impl std::error::Error for EncodeError {}

// ── SecurityModel ──────────────────────────────────────────────────────────

/// The `msgSecurityModel` value from an `SNMPv3` `HeaderData`.
///
/// Wraps the raw wire integer to provide domain-specific semantics. The only
/// value this agent supports is [`USM`](Self::USM) (3), but the newtype
/// preserves the original wire value for diagnostic purposes.
///
/// # Requirements
/// Implements: REQ-0000
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SecurityModel(i32);

impl SecurityModel {
    /// User-Based Security Model (RFC 3414).
    pub const USM: Self = Self(3);

    /// Wrap a raw wire value.
    #[must_use]
    pub const fn from_wire(value: i32) -> Self {
        Self(value)
    }

    /// Returns `true` when this is the USM security model.
    #[must_use]
    pub const fn is_usm(self) -> bool {
        self.0 == Self::USM.0
    }
}

impl fmt::Display for SecurityModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::USM => write!(f, "USM(3)"),
            Self(value) => write!(f, "unknown({value})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Value;

    fn sysname_oid() -> Oid {
        "1.3.6.1.2.1.1.5.0".parse().unwrap()
    }

    // ── VarbindValue ──────────────────────────────────────────────────────────

    #[test]
    fn varbind_value_variants_are_distinct() {
        let varbind_value = VarbindValue::Value(Value::Integer32(42));
        let unspecified = VarbindValue::Unspecified;
        let no_obj = VarbindValue::NoSuchObject;
        let no_inst = VarbindValue::NoSuchInstance;
        let eom = VarbindValue::EndOfMibView;
        assert_ne!(varbind_value, unspecified);
        assert_ne!(unspecified, no_obj);
        assert_ne!(no_obj, no_inst);
        assert_ne!(no_inst, eom);
    }

    #[test]
    fn varbind_value_wraps_all_value_variants() {
        let cases = vec![
            VarbindValue::Value(Value::Integer32(-1)),
            VarbindValue::Value(Value::OctetString(b"hello".to_vec())),
            VarbindValue::Value(Value::Counter32(100)),
            VarbindValue::Value(Value::Counter64(u64::MAX)),
            VarbindValue::Value(Value::Gauge32(42)),
            VarbindValue::Value(Value::TimeTicks(360_000)),
            VarbindValue::Value(Value::IpAddress([10, 0, 0, 1])),
            VarbindValue::Value(Value::Opaque(vec![0xDE, 0xAD])),
            VarbindValue::Value(Value::ObjectIdentifier(sysname_oid())),
        ];
        for varbind_value in cases {
            assert!(matches!(varbind_value, VarbindValue::Value(_)));
        }
    }

    // ── Varbind ───────────────────────────────────────────────────────────────

    #[test]
    fn varbind_construction() {
        let vb = Varbind {
            oid: sysname_oid(),
            value: VarbindValue::Value(Value::OctetString(b"router".to_vec())),
        };
        assert_eq!(vb.oid.to_string(), "1.3.6.1.2.1.1.5.0");
        assert_eq!(
            vb.value,
            VarbindValue::Value(Value::OctetString(b"router".to_vec()))
        );
    }

    // ── ErrorStatus ───────────────────────────────────────────────────────────

    #[test]
    fn error_status_values_match_rfc() {
        assert_eq!(ErrorStatus::NoError as u32, 0);
        assert_eq!(ErrorStatus::TooBig as u32, 1);
        assert_eq!(ErrorStatus::NoSuchName as u32, 2);
        assert_eq!(ErrorStatus::BadValue as u32, 3);
        assert_eq!(ErrorStatus::ReadOnly as u32, 4);
        assert_eq!(ErrorStatus::GenErr as u32, 5);
        assert_eq!(ErrorStatus::NoAccess as u32, 6);
        assert_eq!(ErrorStatus::WrongType as u32, 7);
        assert_eq!(ErrorStatus::WrongLength as u32, 8);
        assert_eq!(ErrorStatus::WrongEncoding as u32, 9);
        assert_eq!(ErrorStatus::WrongValue as u32, 10);
        assert_eq!(ErrorStatus::NoCreation as u32, 11);
        assert_eq!(ErrorStatus::InconsistentValue as u32, 12);
        assert_eq!(ErrorStatus::ResourceUnavailable as u32, 13);
        assert_eq!(ErrorStatus::CommitFailed as u32, 14);
        assert_eq!(ErrorStatus::UndoFailed as u32, 15);
        assert_eq!(ErrorStatus::AuthorizationError as u32, 16);
        assert_eq!(ErrorStatus::NotWritable as u32, 17);
        assert_eq!(ErrorStatus::InconsistentName as u32, 18);
    }

    #[test]
    fn error_status_from_u32_round_trip() {
        for code in 0u32..=18 {
            let status = ErrorStatus::from_u32(code).expect("should parse");
            assert_eq!(status as u32, code);
        }
    }

    #[test]
    fn error_status_from_u32_unknown_returns_none() {
        assert!(ErrorStatus::from_u32(19).is_none());
        assert!(ErrorStatus::from_u32(u32::MAX).is_none());
    }

    #[test]
    fn error_status_display_matches_rfc_names() {
        assert_eq!(ErrorStatus::NoError.to_string(), "noError(0)");
        assert_eq!(ErrorStatus::TooBig.to_string(), "tooBig(1)");
        assert_eq!(ErrorStatus::NoSuchName.to_string(), "noSuchName(2)");
        assert_eq!(ErrorStatus::BadValue.to_string(), "badValue(3)");
        assert_eq!(ErrorStatus::ReadOnly.to_string(), "readOnly(4)");
        assert_eq!(ErrorStatus::GenErr.to_string(), "genErr(5)");
        assert_eq!(ErrorStatus::NoAccess.to_string(), "noAccess(6)");
        assert_eq!(ErrorStatus::WrongType.to_string(), "wrongType(7)");
        assert_eq!(ErrorStatus::WrongLength.to_string(), "wrongLength(8)");
        assert_eq!(ErrorStatus::WrongEncoding.to_string(), "wrongEncoding(9)");
        assert_eq!(ErrorStatus::WrongValue.to_string(), "wrongValue(10)");
        assert_eq!(ErrorStatus::NoCreation.to_string(), "noCreation(11)");
        assert_eq!(
            ErrorStatus::InconsistentValue.to_string(),
            "inconsistentValue(12)"
        );
        assert_eq!(
            ErrorStatus::ResourceUnavailable.to_string(),
            "resourceUnavailable(13)"
        );
        assert_eq!(ErrorStatus::CommitFailed.to_string(), "commitFailed(14)");
        assert_eq!(ErrorStatus::UndoFailed.to_string(), "undoFailed(15)");
        assert_eq!(
            ErrorStatus::AuthorizationError.to_string(),
            "authorizationError(16)"
        );
        assert_eq!(ErrorStatus::NotWritable.to_string(), "notWritable(17)");
        assert_eq!(
            ErrorStatus::InconsistentName.to_string(),
            "inconsistentName(18)"
        );
    }

    // ── GetResponse construction ───────────────────────────────────────────────

    #[test]
    fn get_response_construction() {
        let oid = sysname_oid();
        let resp = GetResponse {
            request_id: 42,
            error_status: ErrorStatus::NoError,
            error_index: 0,
            varbinds: vec![Varbind {
                oid,
                value: VarbindValue::Value(Value::OctetString(b"myrouter".to_vec())),
            }],
        };
        assert_eq!(resp.request_id, 42);
        assert_eq!(resp.error_status, ErrorStatus::NoError);
        assert_eq!(resp.error_index, 0);
        assert_eq!(resp.varbinds.len(), 1);
    }

    #[test]
    fn get_response_with_error_status() {
        let resp = GetResponse {
            request_id: 7,
            error_status: ErrorStatus::NoAccess,
            error_index: 1,
            varbinds: vec![],
        };
        assert_eq!(resp.error_status, ErrorStatus::NoAccess);
        assert_eq!(resp.error_index, 1);
    }

    // ── DecodeError ───────────────────────────────────────────────────────────

    #[test]
    fn decode_error_display() {
        let decode_error = DecodeError::new(DecodeErrorKind::Ber, "something went wrong");
        assert_eq!(
            decode_error.to_string(),
            "SNMP decode error (BER decode failure): something went wrong"
        );
    }

    #[test]
    fn decode_error_debug() {
        let decode_error = DecodeError::new(DecodeErrorKind::Ber, "bad bytes");
        let dbg = format!("{decode_error:?}");
        assert!(dbg.contains("bad bytes"));
    }

    #[test]
    fn decode_error_is_std_error() {
        let decode_error = DecodeError::new(DecodeErrorKind::Ber, "test");
        let _: &dyn std::error::Error = &decode_error;
    }

    #[test]
    fn decode_error_kind_ber() {
        let ber_error = DecodeError::new(DecodeErrorKind::Ber, "bad ber");
        assert_eq!(ber_error.kind(), &DecodeErrorKind::Ber);
    }

    #[test]
    fn decode_error_kind_unsupported_pdu_type() {
        let decode_error = DecodeError::new(DecodeErrorKind::UnsupportedPduType, "response pdu");
        assert_eq!(decode_error.kind(), &DecodeErrorKind::UnsupportedPduType);
    }

    #[test]
    fn decode_error_kind_invalid_oid() {
        let decode_error = DecodeError::new(DecodeErrorKind::InvalidOid, "bad oid");
        assert_eq!(decode_error.kind(), &DecodeErrorKind::InvalidOid);
    }

    // ── EncodeError Display ───────────────────────────────────────────────────

    #[test]
    fn encode_error_display_contains_message() {
        let encode_error = EncodeError::new("something failed badly");
        let error_message = encode_error.to_string();
        assert!(
            error_message.contains("SNMP encode error"),
            "missing prefix in: {error_message}"
        );
        assert!(
            error_message.contains("something failed badly"),
            "missing message in: {error_message}"
        );
    }

    #[test]
    fn encode_error_is_std_error() {
        let encode_error = EncodeError::new("test");
        let _: &dyn std::error::Error = &encode_error;
    }

    // ── SecurityModel ────────────────────────────────────────────────────────

    #[test]
    fn security_model_usm_is_usm() {
        // Verifies: REQ-0000
        assert_eq!(SecurityModel::USM, SecurityModel::from_wire(3));
        assert!(SecurityModel::USM.is_usm());
    }

    #[test]
    fn security_model_non_usm_is_not_usm() {
        // Verifies: REQ-0000
        assert_ne!(SecurityModel::from_wire(4), SecurityModel::USM);
        assert!(!SecurityModel::from_wire(4).is_usm());
    }

    #[test]
    fn security_model_display_usm() {
        // Verifies: REQ-0000
        assert_eq!(SecurityModel::USM.to_string(), "USM(3)");
    }

    #[test]
    fn security_model_display_unknown() {
        // Verifies: REQ-0000
        assert_eq!(SecurityModel::from_wire(7).to_string(), "unknown(7)");
    }
}
