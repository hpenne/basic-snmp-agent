//! Minimal `SNMPv3` frame encoders for test and fuzzing use.
//!
//! Each function produces a BER-encoded `SNMPv3` message using noAuthNoPriv USM
//! security — the simplest valid framing accepted by the agent. Callers supply
//! OID arcs directly as `&[u32]` so they do not need to import `rasn` types.
//!
//! # Examples
//!
//! ```
//! let frame = snmpv3_frames::encode_get_request(
//!     b"\x80\x00\x1f\x88\x04test",
//!     b"",
//!     1,
//!     1,
//!     &[1, 3, 6, 1, 2, 1, 1, 1, 0],
//! );
//! assert!(!frame.is_empty());
//! ```

use std::borrow::Cow;

use rasn_snmp::v2::{
    BulkPdu, GetBulkRequest as RasnGetBulkRequest, GetNextRequest as RasnGetNextRequest,
    GetRequest as RasnGetRequest, Pdu as RasnPdu, Pdus, SetRequest as RasnSetRequest, VarBind,
    VarBindValue as RasnVarBindValue,
};
use rasn_snmp::v3::{
    HeaderData, Message as V3Message, ScopedPdu, ScopedPduData, USMSecurityParameters,
};

/// Encode a minimal `SNMPv3` `GetRequest` frame (noAuthNoPriv, USM).
///
/// # Examples
///
/// ```
/// let frame = snmpv3_frames::encode_get_request(
///     b"\x80\x00\x1f\x88\x04test",
///     b"",
///     1,
///     42,
///     &[1, 3, 6, 1, 2, 1, 1, 1, 0],
/// );
/// assert!(!frame.is_empty());
/// ```
#[must_use]
pub fn encode_get_request(
    engine_id: &[u8],
    context_name: &[u8],
    msg_id: i32,
    request_id: i32,
    oid_arcs: &[u32],
) -> Vec<u8> {
    let rasn_pdu = RasnGetRequest(single_varbind_pdu(request_id, oid_arcs));
    encode_v3_message(engine_id, context_name, msg_id, Pdus::GetRequest(rasn_pdu))
}

/// Encode a minimal `SNMPv3` `GetNextRequest` frame (noAuthNoPriv, USM).
///
/// # Examples
///
/// ```
/// let frame = snmpv3_frames::encode_get_next_request(
///     b"\x80\x00\x1f\x88\x04test",
///     b"",
///     2,
///     42,
///     &[1, 3, 6, 1, 2, 1, 1, 1, 0],
/// );
/// assert!(!frame.is_empty());
/// ```
#[must_use]
pub fn encode_get_next_request(
    engine_id: &[u8],
    context_name: &[u8],
    msg_id: i32,
    request_id: i32,
    oid_arcs: &[u32],
) -> Vec<u8> {
    let rasn_pdu = RasnGetNextRequest(single_varbind_pdu(request_id, oid_arcs));
    encode_v3_message(
        engine_id,
        context_name,
        msg_id,
        Pdus::GetNextRequest(rasn_pdu),
    )
}

/// Encode a minimal `SNMPv3` `GetBulkRequest` frame (noAuthNoPriv, USM).
///
/// # Examples
///
/// ```
/// let frame = snmpv3_frames::encode_get_bulk_request(
///     b"\x80\x00\x1f\x88\x04test",
///     b"",
///     3,
///     42,
///     0,
///     10,
///     &[1, 3, 6, 1, 2, 1, 1, 1, 0],
/// );
/// assert!(!frame.is_empty());
/// ```
#[must_use]
pub fn encode_get_bulk_request(
    engine_id: &[u8],
    context_name: &[u8],
    msg_id: i32,
    request_id: i32,
    non_repeaters: u32,
    max_repetitions: u32,
    oid_arcs: &[u32],
) -> Vec<u8> {
    let rasn_oid = rasn::types::ObjectIdentifier::new_unchecked(Cow::Owned(oid_arcs.to_vec()));
    let rasn_pdu = RasnGetBulkRequest(BulkPdu {
        request_id,
        non_repeaters,
        max_repetitions,
        variable_bindings: vec![VarBind {
            name: rasn_oid,
            value: RasnVarBindValue::Unspecified,
        }],
    });
    encode_v3_message(
        engine_id,
        context_name,
        msg_id,
        Pdus::GetBulkRequest(rasn_pdu),
    )
}

/// Encode a minimal `SNMPv3` `SetRequest` frame (noAuthNoPriv, USM).
///
/// # Examples
///
/// ```
/// let frame = snmpv3_frames::encode_set_request(
///     b"\x80\x00\x1f\x88\x04test",
///     b"",
///     4,
///     42,
///     &[1, 3, 6, 1, 2, 1, 1, 1, 0],
/// );
/// assert!(!frame.is_empty());
/// ```
#[must_use]
pub fn encode_set_request(
    engine_id: &[u8],
    context_name: &[u8],
    msg_id: i32,
    request_id: i32,
    oid_arcs: &[u32],
) -> Vec<u8> {
    let rasn_pdu = RasnSetRequest(single_varbind_pdu(request_id, oid_arcs));
    encode_v3_message(engine_id, context_name, msg_id, Pdus::SetRequest(rasn_pdu))
}

// Encode a complete SNMPv3 message with empty (noAuthNoPriv) USM security parameters.
// msg_id is used as the message identifier in the V3 header.
fn encode_v3_message(engine_id: &[u8], context_name: &[u8], msg_id: i32, pdus: Pdus) -> Vec<u8> {
    let scoped_pdu = ScopedPdu {
        engine_id: engine_id.to_vec().into(),
        name: context_name.to_vec().into(),
        data: pdus,
    };
    let usm_params = USMSecurityParameters {
        authoritative_engine_id: rasn::types::OctetString::from(vec![]),
        authoritative_engine_boots: 0.into(),
        authoritative_engine_time: 0.into(),
        user_name: rasn::types::OctetString::from(vec![]),
        authentication_parameters: rasn::types::OctetString::from(vec![]),
        privacy_parameters: rasn::types::OctetString::from(vec![]),
    };
    let security_parameters_bytes =
        rasn::ber::encode(&usm_params).expect("USMSecurityParameters must encode");
    let v3_message = V3Message {
        version: 3.into(),
        global_data: HeaderData {
            message_id: msg_id.into(),
            max_size: 65535.into(),
            flags: rasn::types::OctetString::from(vec![0x04]),
            security_model: 3.into(),
        },
        security_parameters: security_parameters_bytes.into(),
        scoped_data: ScopedPduData::CleartextPdu(scoped_pdu),
    };
    rasn::ber::encode(&v3_message).expect("V3Message must encode")
}

// Build a RasnPdu carrying a single null varbind for the given OID arcs.
fn single_varbind_pdu(request_id: i32, oid_arcs: &[u32]) -> RasnPdu {
    let rasn_oid = rasn::types::ObjectIdentifier::new_unchecked(Cow::Owned(oid_arcs.to_vec()));
    RasnPdu {
        request_id,
        error_status: 0,
        error_index: 0,
        variable_bindings: vec![VarBind {
            name: rasn_oid,
            value: RasnVarBindValue::Unspecified,
        }],
    }
}
