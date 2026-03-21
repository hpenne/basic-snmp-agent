//! SNMP PDU types and BER encode/decode for SNMPv2/v3 agents (RFC 3416).
//!
//! This module provides:
//!
//! - Clean public PDU types decoupled from the `rasn`/`rasn-snmp` wire types.
//! - [`decode_pdu`]: BER-decode inbound SNMP PDU bytes into an [`InboundPdu`].
//! - [`decode_v3_message`]: BER-decode an inbound `SNMPv3` message into a [`V3InboundMessage`].
//! - [`encode_response`]: BER-encode a [`GetResponse`] for sending.
//! - [`encode_v3_response`]: BER-encode a [`GetResponse`] inside an `SNMPv3` message envelope.
//! - [`encode_trap`]: BER-encode a [`WireTrapPdu`] for sending.

use std::fmt;

use rasn_smi::v2::{ApplicationSyntax, Counter64, ObjectSyntax, SimpleSyntax};
use rasn_snmp::v2::{
    GetBulkRequest as RasnGetBulkRequest, GetNextRequest as RasnGetNextRequest,
    GetRequest as RasnGetRequest, Pdu as RasnPdu, Pdus, Response, SetRequest as RasnSetRequest,
    Trap, VarBind, VarBindValue as RasnVarBindValue,
};
use rasn_snmp::v2c::Message as V2cMessage;
use rasn_snmp::v3::{
    HeaderData, Message as V3Message, ScopedPdu, ScopedPduData, USMSecurityParameters,
};

use super::Oid;
use super::Value;

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
    /// The variable binding value is inconsistent with the current state.
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

// ── V3InboundMessage ──────────────────────────────────────────────────────────

/// A decoded inbound `SNMPv3` message, containing the message-level fields
/// extracted from the `HeaderData` and `ScopedPdu` envelope, plus the inner
/// PDU ready for dispatch.
///
/// # Requirements
/// Implements: REQ-0068, REQ-0069, REQ-0070
#[derive(Debug)]
pub struct V3InboundMessage {
    /// Message ID from `HeaderData`; echoed in the `SNMPv3` response.
    pub msg_id: i32,
    /// Engine ID from the `ScopedPdu`; used to verify the request targets this agent.
    pub engine_id: Vec<u8>,
    /// Context name from the `ScopedPdu`; should be empty for the default context.
    pub context_name: Vec<u8>,
    /// Security name (user name) from USM security parameters; echoed in the response
    /// per RFC 3414 §8.2.4 so the command generator can match the response to its request.
    pub user_name: Vec<u8>,
    /// The inner PDU ready for dispatch to request handlers.
    pub pdu: InboundPdu,
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

// ── decode_pdu ────────────────────────────────────────────────────────────────

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

// ── decode_v3_message ─────────────────────────────────────────────────────────

/// BER-decode an inbound `SNMPv3` message into a [`V3InboundMessage`].
///
/// Accepts only cleartext (noAuthNoPriv or authNoPriv) `SNMPv3` messages; encrypted
/// PDUs (`ScopedPduData::EncryptedPdu`) are rejected because this agent implements
/// USM noAuthNoPriv only.
///
/// The inner `Pdus` variant must be an inbound request type; response and trap
/// PDUs are rejected.
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
/// # Requirements
/// Implements: REQ-0068, REQ-0069, REQ-0071, REQ-0073
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
pub fn decode_v3_message(bytes: &[u8]) -> Result<V3InboundMessage, DecodeError> {
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

    // Extract the user name from USMSecurityParameters so it can be echoed in
    // the response (RFC 3414 §8.2.4 requires msgUserName to be the same in both).
    // Failure to decode the security parameters is treated as a BER error.
    let usm_params: USMSecurityParameters =
        rasn::ber::decode(v3_message.security_parameters.as_ref()).map_err(|e| {
            DecodeError::new(DecodeErrorKind::Ber, format!("USM decode failed: {e}"))
        })?;
    let user_name = usm_params.user_name.to_vec();

    let engine_id = scoped_pdu.engine_id.to_vec();
    let context_name = scoped_pdu.name.to_vec();
    let pdu = pdus_to_inbound_pdu(scoped_pdu.data)?;

    Ok(V3InboundMessage {
        msg_id,
        engine_id,
        context_name,
        user_name,
        pdu,
    })
}

// ── encode_response ───────────────────────────────────────────────────────────

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

// ── encode_v3_response ────────────────────────────────────────────────────────

/// BER-encode a [`GetResponse`] inside a full `SNMPv3` message envelope.
///
/// Constructs a `ScopedPdu` from `engine_id` and `context_name`, wraps it in
/// `ScopedPduData::CleartextPdu`, and builds an `SNMPv3` `Message` with
/// `HeaderData` indicating USM noAuthNoPriv. The `USMSecurityParameters` include
/// the authoritative engine ID and the original `user_name` echoed back, as
/// required by RFC 3414 §8.2.4 so the command generator can match the response.
///
/// # Errors
///
/// Returns an [`EncodeError`] if `rasn` fails to BER-encode any part of the message.
///
/// # Requirements
/// Implements: REQ-0068, REQ-0070, REQ-0072
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
/// let bytes = encode_v3_response(1, b"engine", b"user", b"", &pdu).unwrap();
/// assert!(!bytes.is_empty());
/// ```
pub fn encode_v3_response(
    msg_id: i32,
    engine_id: &[u8],
    user_name: &[u8],
    context_name: &[u8],
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

    // RFC 3414 §8.2.4: the response's USMSecurityParameters must include the
    // authoritative engine ID and the original msgUserName so the command
    // generator can match the response to its pending request.
    // auth/priv parameters remain zero-length for noAuthNoPriv.
    let usm_params = USMSecurityParameters {
        authoritative_engine_id: engine_id.to_vec().into(),
        authoritative_engine_boots: 0.into(),
        authoritative_engine_time: 0.into(),
        user_name: user_name.to_vec().into(),
        authentication_parameters: rasn::types::OctetString::from(vec![]),
        privacy_parameters: rasn::types::OctetString::from(vec![]),
    };

    let security_parameters_bytes = rasn::ber::encode(&usm_params).map_err(|e| {
        EncodeError::new(format!("BER encoding of USMSecurityParameters failed: {e}"))
    })?;

    // flags byte 0x00: noAuthNoPriv, reportable bit clear (response).
    let v3_message = V3Message {
        version: 3.into(),
        global_data: HeaderData {
            message_id: msg_id.into(),
            max_size: 65535.into(),
            flags: rasn::types::OctetString::from(vec![0x00]),
            // Security model 3 = USM (RFC 3414).
            security_model: 3.into(),
        },
        security_parameters: security_parameters_bytes.into(),
        scoped_data: ScopedPduData::CleartextPdu(scoped_pdu),
    };

    rasn::ber::encode(&v3_message)
        .map_err(|e| EncodeError::new(format!("BER encoding of SNMPv3 Message failed: {e}")))
}

// ── encode_trap ───────────────────────────────────────────────────────────────

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

// ── DecodeError ─────────────────────────────────────────────────────────────

/// Error returned when BER-decoding an inbound SNMP PDU fails.
#[derive(Debug)]
pub struct DecodeError {
    kind: DecodeErrorKind,
    /// Human-readable description of what went wrong.
    pub message: String,
}

impl DecodeError {
    fn new(kind: DecodeErrorKind, msg: impl Into<String>) -> Self {
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
    /// rasn BER decode failure.
    Ber,
    /// PDU type received that is not a recognised inbound type.
    UnsupportedPduType,
    /// An OID in a varbind could not be converted.
    InvalidOid,
    /// The SNMP message version is not the expected value.
    WrongVersion,
    /// The scoped PDU is encrypted; privacy is not supported.
    EncryptedPdu,
}

impl fmt::Display for DecodeErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ber => write!(f, "BER decode failure"),
            Self::UnsupportedPduType => write!(f, "unsupported PDU type"),
            Self::InvalidOid => write!(f, "invalid OID"),
            Self::WrongVersion => write!(f, "wrong SNMP version"),
            Self::EncryptedPdu => write!(f, "encrypted PDU not supported"),
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
    fn new(msg: impl Into<String>) -> Self {
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

// ── OID conversions ──────────────────────────────────────────────────────────

/// Converts our `Oid` into a `rasn` `ObjectIdentifier`.
fn oid_to_rasn(oid: &Oid) -> rasn::types::ObjectIdentifier {
    // rasn ObjectIdentifier owns its arcs via a Cow<'static, [u32]>.
    // We clone the slice into an owned Vec wrapped in a Cow.
    let components: Vec<u32> = oid.as_slice().to_vec();
    rasn::types::ObjectIdentifier::new_unchecked(std::borrow::Cow::Owned(components))
}

/// Converts a `rasn` `ObjectIdentifier` into our `Oid`.
fn oid_from_rasn(oid: &rasn::types::ObjectIdentifier) -> Result<Oid, DecodeError> {
    let components: Vec<u32> = oid.as_ref().to_vec();
    Oid::try_from(components)
        .map_err(|e| DecodeError::new(DecodeErrorKind::InvalidOid, format!("invalid OID: {e}")))
}

// ── Opaque construction ───────────────────────────────────────────────────────

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

// ── Value ↔ ObjectSyntax conversions ─────────────────────────────────────────

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

/// Converts a rasn-snmp wire type `ObjectSyntax` into our public [`Value`].
fn value_from_object_syntax(syntax: ObjectSyntax) -> Result<Value, DecodeError> {
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

// ── VarbindValue ↔ VarBindValue conversions ───────────────────────────────────

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

// ── Varbind ↔ VarBind conversions ────────────────────────────────────────────

/// Converts our [`Varbind`] to the rasn-snmp wire type.
fn varbind_to_rasn(varbind: &Varbind) -> VarBind {
    VarBind {
        name: oid_to_rasn(&varbind.oid),
        value: varbind_value_to_rasn(&varbind.value),
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_usm_security_parameters() -> USMSecurityParameters {
        USMSecurityParameters {
            authoritative_engine_id: rasn::types::OctetString::from(vec![]),
            authoritative_engine_boots: 0.into(),
            authoritative_engine_time: 0.into(),
            user_name: rasn::types::OctetString::from(vec![]),
            authentication_parameters: rasn::types::OctetString::from(vec![]),
            privacy_parameters: rasn::types::OctetString::from(vec![]),
        }
    }

    /// Encode a `GetBulkRequest` inside a minimal V3 message, ready for `decode_v3_message`.
    /// Used by the `GetBulk` clamping tests to avoid repeating the V3 framing boilerplate.
    fn encode_getbulk_v3(non_repeaters: u32, max_repetitions: u32) -> Vec<u8> {
        use rasn_snmp::v2::{BulkPdu, GetBulkRequest as RasnGetBulkRequest, VarBind, VarBindValue};

        let engine_id = b"\x80\x00\x1f\x88\x04test";
        let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        let rasn_oid = rasn::types::ObjectIdentifier::new_unchecked(std::borrow::Cow::Owned(
            oid.as_slice().to_vec(),
        ));
        let rasn_pdu = RasnGetBulkRequest(BulkPdu {
            request_id: 42,
            non_repeaters,
            max_repetitions,
            variable_bindings: vec![VarBind {
                name: rasn_oid,
                value: VarBindValue::Unspecified,
            }],
        });
        let scoped_pdu = ScopedPdu {
            engine_id: engine_id.to_vec().into(),
            name: vec![].into(),
            data: Pdus::GetBulkRequest(rasn_pdu),
        };
        let usm_params = empty_usm_security_parameters();
        let security_params = rasn::ber::encode(&usm_params).unwrap();
        let v3_msg = V3Message {
            version: 3.into(),
            global_data: HeaderData {
                message_id: 5.into(),
                max_size: 65535.into(),
                flags: rasn::types::OctetString::from(vec![0x04]),
                security_model: 3.into(),
            },
            security_parameters: security_params.into(),
            scoped_data: ScopedPduData::CleartextPdu(scoped_pdu),
        };
        rasn::ber::encode(&v3_msg).unwrap()
    }

    fn sysname_oid() -> Oid {
        "1.3.6.1.2.1.1.5.0".parse().unwrap()
    }

    fn sysdescr_oid() -> Oid {
        "1.3.6.1.2.1.1.1.0".parse().unwrap()
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

    // ── encode_response round-trip ────────────────────────────────────────────

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

    #[test]
    fn encode_decode_empty_varbinds() {
        use rasn_snmp::v2::{GetRequest as RasnGetRequest, Pdu};

        // Encode a GetResponse with zero varbinds.
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

        // BER-decode back and check varbind count.
        let decoded: Pdus = rasn::ber::decode(&encoded_response).expect("must decode");
        match decoded {
            Pdus::Response(Response(inner)) => {
                assert_eq!(inner.variable_bindings.len(), 0);
            }
            other => panic!("expected Response, got {other:?}"),
        }

        // Encode a GetRequest with zero varbinds via rasn-snmp and decode via decode_pdu.
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
        use rasn_snmp::v2::Response;

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

    // ── bytes_to_opaque ───────────────────────────────────────────────────────

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

    // ── All SMIv2 Value types survive encode/decode ───────────────────────────

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
                    // Re-decode value back to our type to verify round-trip.
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

    // ── decode_v3_message ─────────────────────────────────────────────────────

    /// Build a minimal `SNMPv3` message wrapping a `GetRequest` for tests.
    fn encode_test_v3_get_request(
        msg_id: i32,
        engine_id: &[u8],
        context_name: &[u8],
        request_id: i32,
        oid: &Oid,
    ) -> Vec<u8> {
        let rasn_oid = rasn::types::ObjectIdentifier::new_unchecked(std::borrow::Cow::Owned(
            oid.as_slice().to_vec(),
        ));
        let rasn_pdu = RasnGetRequest(RasnPdu {
            request_id,
            error_status: 0,
            error_index: 0,
            variable_bindings: vec![VarBind {
                name: rasn_oid,
                value: RasnVarBindValue::Unspecified,
            }],
        });
        let scoped_pdu = ScopedPdu {
            engine_id: engine_id.to_vec().into(),
            name: context_name.to_vec().into(),
            data: Pdus::GetRequest(rasn_pdu),
        };
        let usm_params = empty_usm_security_parameters();
        let security_params = rasn::ber::encode(&usm_params).unwrap();
        let v3_msg = V3Message {
            version: 3.into(),
            global_data: HeaderData {
                message_id: msg_id.into(),
                max_size: 65535.into(),
                flags: rasn::types::OctetString::from(vec![0x04]),
                security_model: 3.into(),
            },
            security_parameters: security_params.into(),
            scoped_data: ScopedPduData::CleartextPdu(scoped_pdu),
        };
        rasn::ber::encode(&v3_msg).unwrap()
    }

    #[test]
    fn given_valid_v3_get_request_when_decode_then_fields_extracted() {
        // Verifies: REQ-0068, REQ-0069, REQ-0070
        let engine_id = b"\x80\x00\x1f\x88\x04test";
        let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        let encoded = encode_test_v3_get_request(42, engine_id, b"", 7, &oid);

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
        let usm_params = empty_usm_security_parameters();
        let security_params = rasn::ber::encode(&usm_params).unwrap();
        let scoped_pdu = ScopedPdu {
            engine_id: rasn::types::OctetString::from(vec![]),
            name: rasn::types::OctetString::from(vec![]),
            data: Pdus::GetRequest(RasnGetRequest(RasnPdu {
                request_id: 1,
                error_status: 0,
                error_index: 0,
                variable_bindings: vec![],
            })),
        };
        let v3_msg_version_1 = V3Message {
            version: 1.into(),
            global_data: HeaderData {
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
        let usm_params = empty_usm_security_parameters();
        let security_params = rasn::ber::encode(&usm_params).unwrap();
        let v3_msg = V3Message {
            version: 3.into(),
            global_data: HeaderData {
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
        let encoded = encode_getbulk_v3(0, i32::MAX as u32 + 1);
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
        let encoded = encode_getbulk_v3(0, i32::MAX as u32);
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
        let encoded = encode_getbulk_v3(i32::MAX as u32 + 1, 0);
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
        let encoded = encode_getbulk_v3(i32::MAX as u32, 0);
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

    // ── encode_v3_response round-trip ─────────────────────────────────────────

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

        let encoded = encode_v3_response(5, engine_id, b"testuser", b"", &pdu).unwrap();

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
    fn given_v3_request_when_encode_then_decode_round_trip_succeeds() {
        // Verifies: REQ-0068, REQ-0069, REQ-0070
        // Encode a v3 GetRequest, decode it, check all fields survive.
        let engine_id = b"\x80\x00\x1f\x88\x04roundtrip";
        let oid: Oid = "1.3.6.1.2.1.1.5.0".parse().unwrap();
        let encoded = encode_test_v3_get_request(100, engine_id, b"ctx", 200, &oid);

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
}
