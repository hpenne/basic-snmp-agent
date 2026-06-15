use std::fmt;
use std::sync::atomic::{AtomicI32, Ordering};

use crate::codec::{Oid, Value};

// ── RequestId ─────────────────────────────────────────────────────────────────

/// A PDU-level request identifier, carried in every inbound and outbound SNMP PDU.
///
/// The manager echoes the `request_id` from the inbound PDU in the corresponding
/// response PDU so it can correlate replies to outstanding requests (RFC 3416 §3).
/// The wire representation is an ASN.1 INTEGER (`i32`).
///
/// Distinct from [`MessageId`], which identifies the `SNMPv3` message envelope.
/// The two identifiers co-exist in the dispatch path; using newtypes prevents
/// silent transposition at call sites.
///
/// # Requirements
/// Implements: REQ-0039, REQ-0040, REQ-0068, REQ-0069, REQ-0070
///
/// # Examples
///
/// ```
/// use basic_snmp_agent::codec::RequestId;
///
/// let id = RequestId::from(42_i32);
/// assert_eq!(i32::from(id), 42);
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RequestId(i32);

impl RequestId {
    /// A zero-valued `RequestId`.
    ///
    /// Used in outbound messages (e.g., traps and reports) where no inbound
    /// request ID is available to echo.
    pub const ZERO: Self = Self(0);
}

impl From<i32> for RequestId {
    fn from(value: i32) -> Self {
        Self(value)
    }
}

impl From<RequestId> for i32 {
    fn from(id: RequestId) -> Self {
        id.0
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── MessageId ─────────────────────────────────────────────────────────────────

/// An `SNMPv3` message-level identifier from `HeaderData.msgID` (RFC 3412 §6.2).
///
/// The message ID identifies the `SNMPv3` message envelope, not the inner PDU.
/// Managers use it to correlate responses and detect duplicates.
///
/// Per RFC 3412 §6.2, `msgID` must be in the range `[0, 2147483647]` (i.e.,
/// non-negative). [`MessageId::next_sequential`] upholds this invariant by clearing
/// the sign bit so the counter wraps from `i32::MAX` back to 0 rather than
/// producing negative values. Values obtained via `From<i32>` are unconstrained —
/// the agent must accept whatever value the manager sends on the wire.
///
/// Distinct from [`RequestId`], which is the PDU-level correlation identifier.
///
/// # Requirements
/// Implements: REQ-0068, REQ-0069, REQ-0070, REQ-0105
///
/// # Examples
///
/// ```
/// use basic_snmp_agent::codec::MessageId;
/// use std::sync::atomic::AtomicI32;
///
/// let counter = AtomicI32::new(1);
/// let id = MessageId::next_sequential(&counter);
/// assert_eq!(i32::from(id), 1);
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MessageId(i32);

impl MessageId {
    /// Atomically increment `counter` and return the next `MessageId`.
    ///
    /// Clears the sign bit of the raw counter value so the identifier is always
    /// non-negative, as required by RFC 3412 §6.2. The counter wraps from
    /// `i32::MAX` back to 0 without ever producing a negative value.
    ///
    /// # Examples
    ///
    /// ```
    /// use basic_snmp_agent::codec::MessageId;
    /// use std::sync::atomic::AtomicI32;
    ///
    /// let counter = AtomicI32::new(i32::MAX - 1);
    /// let a = MessageId::next_sequential(&counter);
    /// let b = MessageId::next_sequential(&counter);
    /// assert_eq!(i32::from(a), i32::MAX - 1);
    /// assert_eq!(i32::from(b), i32::MAX);
    /// ```
    #[must_use]
    pub fn next_sequential(counter: &AtomicI32) -> Self {
        // Clear the sign bit so the value stays in [0, i32::MAX] and never
        // violates the RFC 3412 §6.2 non-negativity requirement.
        Self(counter.fetch_add(1, Ordering::Relaxed) & i32::MAX)
    }
}

impl From<i32> for MessageId {
    fn from(value: i32) -> Self {
        Self(value)
    }
}

impl From<MessageId> for i32 {
    fn from(id: MessageId) -> Self {
        id.0
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

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
#[repr(i32)]
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

impl fmt::Display for ErrorStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (name, code) = match self {
            Self::NoError => ("noError", 0),
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

impl From<ErrorStatus> for i32 {
    fn from(status: ErrorStatus) -> Self {
        status as Self
    }
}

/// Error returned when an `i32` does not correspond to a defined
/// [`ErrorStatus`] variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidErrorStatus(i32);

impl InvalidErrorStatus {
    /// Returns the invalid error-status code that was rejected.
    #[must_use]
    pub fn code(self) -> i32 {
        self.0
    }
}

impl fmt::Display for InvalidErrorStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid SNMP error-status code: {}", self.0)
    }
}

impl std::error::Error for InvalidErrorStatus {}

impl TryFrom<i32> for ErrorStatus {
    type Error = InvalidErrorStatus;

    fn try_from(code: i32) -> Result<Self, Self::Error> {
        match code {
            0 => Ok(Self::NoError),
            1 => Ok(Self::TooBig),
            2 => Ok(Self::NoSuchName),
            3 => Ok(Self::BadValue),
            4 => Ok(Self::ReadOnly),
            5 => Ok(Self::GenErr),
            6 => Ok(Self::NoAccess),
            7 => Ok(Self::WrongType),
            8 => Ok(Self::WrongLength),
            9 => Ok(Self::WrongEncoding),
            10 => Ok(Self::WrongValue),
            11 => Ok(Self::NoCreation),
            12 => Ok(Self::InconsistentValue),
            13 => Ok(Self::ResourceUnavailable),
            14 => Ok(Self::CommitFailed),
            15 => Ok(Self::UndoFailed),
            16 => Ok(Self::AuthorizationError),
            17 => Ok(Self::NotWritable),
            18 => Ok(Self::InconsistentName),
            _ => Err(InvalidErrorStatus(code)),
        }
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
    pub request_id: RequestId,
    /// Variable bindings (values are [`VarbindValue::Unspecified`] on inbound requests).
    pub varbinds: Vec<Varbind>,
}

/// An `SNMPv2` [`GetNextRequest`] PDU (inbound).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetNextRequest {
    /// PDU request identifier, echoed in the response.
    pub request_id: RequestId,
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
    pub request_id: RequestId,
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
    pub request_id: RequestId,
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
    ///
    /// `Some` for authenticated messages (MAC bytes, 24 bytes for SHA-256 or
    /// 48 bytes for SHA-512 per RFC 7860); `None` for `noAuthNoPriv` messages
    /// where `msgAuthenticationParameters` is empty on the wire.
    ///
    /// # Requirements
    /// Implements: REQ-0099, REQ-0100
    pub auth_params: Option<crate::usm::security_params::AuthenticationParams>,
    /// `msgPrivacyParameters` from the USM security parameters.
    ///
    /// `Some` for authPriv messages (exactly 8-byte AES salt per RFC 3826 §2.2);
    /// `None` for noAuthNoPriv and authNoPriv messages where the field is empty
    /// on the wire, or when the wire value is not exactly 8 bytes (malformed).
    ///
    /// # Requirements
    /// Implements: REQ-0101, REQ-0109
    pub priv_params: Option<crate::usm::security_params::PrivacySalt>,
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
    pub msg_id: MessageId,
    /// Maximum message size the sender can accept (from `HeaderData`).
    ///
    /// Validated by the decoder to be at least 484 per RFC 3412 §6.6.
    /// Used to bound GETBULK response sizes per REQ-0133.
    pub max_size: i32,
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
    pub request_id: RequestId,
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
    pub request_id: RequestId,
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
    fn given_all_variants_when_cast_to_i32_then_values_match_rfc() {
        assert_eq!(ErrorStatus::NoError as i32, 0);
        assert_eq!(ErrorStatus::TooBig as i32, 1);
        assert_eq!(ErrorStatus::NoSuchName as i32, 2);
        assert_eq!(ErrorStatus::BadValue as i32, 3);
        assert_eq!(ErrorStatus::ReadOnly as i32, 4);
        assert_eq!(ErrorStatus::GenErr as i32, 5);
        assert_eq!(ErrorStatus::NoAccess as i32, 6);
        assert_eq!(ErrorStatus::WrongType as i32, 7);
        assert_eq!(ErrorStatus::WrongLength as i32, 8);
        assert_eq!(ErrorStatus::WrongEncoding as i32, 9);
        assert_eq!(ErrorStatus::WrongValue as i32, 10);
        assert_eq!(ErrorStatus::NoCreation as i32, 11);
        assert_eq!(ErrorStatus::InconsistentValue as i32, 12);
        assert_eq!(ErrorStatus::ResourceUnavailable as i32, 13);
        assert_eq!(ErrorStatus::CommitFailed as i32, 14);
        assert_eq!(ErrorStatus::UndoFailed as i32, 15);
        assert_eq!(ErrorStatus::AuthorizationError as i32, 16);
        assert_eq!(ErrorStatus::NotWritable as i32, 17);
        assert_eq!(ErrorStatus::InconsistentName as i32, 18);
    }

    #[test]
    fn given_valid_code_when_try_from_i32_then_round_trips() {
        for code in 0_i32..=18 {
            let status = ErrorStatus::try_from(code).expect("should parse");
            assert_eq!(status as i32, code);
        }
    }

    #[test]
    fn given_invalid_code_when_try_from_i32_then_returns_error() {
        let result = ErrorStatus::try_from(19);
        assert_eq!(result.unwrap_err().code(), 19);

        let result = ErrorStatus::try_from(-1);
        assert_eq!(result.unwrap_err().code(), -1);

        let result = ErrorStatus::try_from(i32::MAX);
        assert_eq!(result.unwrap_err().code(), i32::MAX);

        let result = ErrorStatus::try_from(i32::MIN);
        assert_eq!(result.unwrap_err().code(), i32::MIN);
    }

    #[test]
    fn given_invalid_error_status_when_displayed_then_includes_code() {
        let error = ErrorStatus::try_from(42).unwrap_err();
        assert_eq!(error.to_string(), "invalid SNMP error-status code: 42");
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

    #[test]
    fn error_status_into_i32_boundary_and_middle_values() {
        assert_eq!(i32::from(ErrorStatus::NoError), 0);
        assert_eq!(i32::from(ErrorStatus::GenErr), 5);
        assert_eq!(i32::from(ErrorStatus::InconsistentName), 18);
    }

    // ── GetResponse construction ───────────────────────────────────────────────

    #[test]
    fn get_response_construction() {
        let oid = sysname_oid();
        let resp = GetResponse {
            request_id: RequestId::from(42),
            error_status: ErrorStatus::NoError,
            error_index: 0,
            varbinds: vec![Varbind {
                oid,
                value: VarbindValue::Value(Value::OctetString(b"myrouter".to_vec())),
            }],
        };
        assert_eq!(resp.request_id, RequestId::from(42));
        assert_eq!(resp.error_status, ErrorStatus::NoError);
        assert_eq!(resp.error_index, 0);
        assert_eq!(resp.varbinds.len(), 1);
    }

    #[test]
    fn get_response_with_error_status() {
        let resp = GetResponse {
            request_id: RequestId::from(7),
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

    // ── RequestId ─────────────────────────────────────────────────────────────

    #[test]
    fn request_id_zero_constant() {
        // Verifies: REQ-0039, REQ-0040
        assert_eq!(i32::from(RequestId::ZERO), 0);
    }

    #[test]
    fn request_id_display() {
        // Verifies: REQ-0039, REQ-0040
        assert_eq!(RequestId::from(42).to_string(), "42");
        assert_eq!(RequestId::from(-1).to_string(), "-1");
        assert_eq!(RequestId::ZERO.to_string(), "0");
    }

    #[test]
    fn request_id_from_i32_round_trips() {
        // Verifies: REQ-0039, REQ-0040
        let id = RequestId::from(99_i32);
        assert_eq!(i32::from(id), 99);
    }

    #[test]
    fn request_id_negative_value_preserved() {
        // Verifies: REQ-0039, REQ-0040
        // RFC 3416 does not constrain the sign of request-id; negative values are
        // valid on the wire and must be preserved exactly.
        let id = RequestId::from(-1_i32);
        assert_eq!(i32::from(id), -1);
    }

    #[test]
    fn request_id_equality_and_copy() {
        // Verifies: REQ-0039, REQ-0040
        let a = RequestId::from(7_i32);
        let b = a;
        assert_eq!(a, b);
        assert_ne!(a, RequestId::from(8_i32));
    }

    // ── MessageId ─────────────────────────────────────────────────────────────

    #[test]
    fn message_id_display() {
        // Verifies: REQ-0068, REQ-0105
        assert_eq!(MessageId::from(7).to_string(), "7");
        assert_eq!(MessageId::from(0).to_string(), "0");
    }

    #[test]
    fn message_id_from_i32_round_trips() {
        // Verifies: REQ-0068, REQ-0105
        let id = MessageId::from(42_i32);
        assert_eq!(i32::from(id), 42);
    }

    #[test]
    fn message_id_next_sequential_wraps_at_max_without_going_negative() {
        // Verifies: REQ-0068, REQ-0105 — RFC 3412 §6.2 non-negativity invariant.
        // The counter starts at i32::MAX - 1. After i32::MAX overflows to i32::MIN,
        // clearing the sign bit maps i32::MIN → 0, i32::MIN+1 → 1, etc.
        use std::sync::atomic::AtomicI32;
        let counter = AtomicI32::new(i32::MAX - 1);
        assert_eq!(
            MessageId::next_sequential(&counter),
            MessageId::from(i32::MAX - 1)
        );
        assert_eq!(
            MessageId::next_sequential(&counter),
            MessageId::from(i32::MAX)
        );
        assert_eq!(MessageId::next_sequential(&counter), MessageId::from(0));
        assert_eq!(MessageId::next_sequential(&counter), MessageId::from(1));
        assert_eq!(MessageId::next_sequential(&counter), MessageId::from(2));
    }

    #[test]
    fn message_id_next_sequential_produces_distinct_values() {
        // Verifies: REQ-0068, REQ-0105
        use std::sync::atomic::AtomicI32;
        let counter = AtomicI32::new(1);
        let a = MessageId::next_sequential(&counter);
        let b = MessageId::next_sequential(&counter);
        assert_eq!(a, MessageId::from(1));
        assert_eq!(b, MessageId::from(2));
    }

    #[test]
    fn message_id_negative_value_preserved() {
        // Verifies: REQ-0068, REQ-0105
        // From<i32> is unconstrained — the agent must echo whatever the manager sent,
        // including values that violate the RFC 3412 §6.2 non-negativity requirement.
        let id = MessageId::from(-1_i32);
        assert_eq!(i32::from(id), -1);
    }

    #[test]
    fn message_id_equality_and_copy() {
        // Verifies: REQ-0068, REQ-0105
        let a = MessageId::from(3_i32);
        let b = a;
        assert_eq!(a, b);
        assert_ne!(a, MessageId::from(4_i32));
    }

    // ── SecurityModel ────────────────────────────────────────────────────────

    #[test]
    fn security_model_usm_is_usm() {
        assert_eq!(SecurityModel::USM, SecurityModel::from_wire(3));
        assert!(SecurityModel::USM.is_usm());
    }

    #[test]
    fn security_model_non_usm_is_not_usm() {
        assert_ne!(SecurityModel::from_wire(4), SecurityModel::USM);
        assert!(!SecurityModel::from_wire(4).is_usm());
    }

    #[test]
    fn security_model_display_usm() {
        assert_eq!(SecurityModel::USM.to_string(), "USM(3)");
    }

    #[test]
    fn security_model_display_unknown() {
        assert_eq!(SecurityModel::from_wire(7).to_string(), "unknown(7)");
    }
}
