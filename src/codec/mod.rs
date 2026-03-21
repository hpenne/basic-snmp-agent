//! ASN.1/BER codec primitives for SNMP.
//!
//! This module provides:
//!
//! - [`Oid`]: an SNMP Object Identifier represented as a sequence of unsigned
//!   32-bit components, with dotted-decimal [`Display`](std::fmt::Display) and
//!   [`FromStr`](std::str::FromStr) implementations.
//! - [`ParseOidError`]: the error type returned when a dotted-decimal OID
//!   string cannot be parsed, including an optional chained source error.
//! - [`Value`]: an `SMIv2` value carried in an SNMP varbind, covering all nine
//!   standard `SMIv2` types defined in RFC 2578.
//! - [`pdu`]: SNMP PDU types and BER encode/decode functions for SNMPv2/v3
//!   agents (RFC 3416).

mod oid;
mod pdu;
mod value;

pub use oid::{Oid, OidErrorCategory, ParseOidError};
pub use pdu::{
    DecodeError, DecodeErrorKind, EncodeError, ErrorStatus, GetBulkRequest, GetNextRequest,
    GetRequest, GetResponse, InboundPdu, SetRequest, V3InboundMessage, Varbind, VarbindValue,
    WireTrapPdu, decode_pdu, decode_v3_message, encode_response, encode_trap, encode_v3_response,
};
pub use value::Value;
