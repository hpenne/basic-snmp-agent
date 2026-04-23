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
    encode_get_request_with_user(engine_id, b"", context_name, msg_id, request_id, oid_arcs)
}

/// Encode a minimal `SNMPv3` `GetRequest` frame with a specific `msgUserName`.
///
/// This lets tests supply an explicit user name in the USM security parameters,
/// exercising user-name lookup without relying on the empty-user default.
///
/// # Examples
///
/// ```
/// let frame = snmpv3_frames::encode_get_request_with_user(
///     b"\x80\x00\x1f\x88\x04test",
///     b"alice",
///     b"",
///     1,
///     42,
///     &[1, 3, 6, 1, 2, 1, 1, 1, 0],
/// );
/// assert!(!frame.is_empty());
/// ```
#[must_use]
pub fn encode_get_request_with_user(
    engine_id: &[u8],
    user_name: &[u8],
    context_name: &[u8],
    msg_id: i32,
    request_id: i32,
    oid_arcs: &[u32],
) -> Vec<u8> {
    encode_get_request_with_user_and_flags(
        engine_id,
        user_name,
        context_name,
        msg_id,
        request_id,
        oid_arcs,
        0x04,
    )
}

/// Encode a minimal `SNMPv3` `GetRequest` frame with a specific `msgUserName` and
/// the `reportableFlag` (`0x04`) cleared in `msgFlags`.
///
/// Use this to test that the agent silently discards a user-name-mismatch response
/// when the manager has not requested a Report PDU (RFC 3412 §7.1.3a).
///
/// # Examples
///
/// ```
/// let frame = snmpv3_frames::encode_get_request_with_user_no_report(
///     b"\x80\x00\x1f\x88\x04test",
///     b"eve",
///     b"",
///     1,
///     42,
///     &[1, 3, 6, 1, 2, 1, 1, 1, 0],
/// );
/// assert!(!frame.is_empty());
/// ```
#[must_use]
pub fn encode_get_request_with_user_no_report(
    engine_id: &[u8],
    user_name: &[u8],
    context_name: &[u8],
    msg_id: i32,
    request_id: i32,
    oid_arcs: &[u32],
) -> Vec<u8> {
    encode_get_request_with_user_and_flags(
        engine_id,
        user_name,
        context_name,
        msg_id,
        request_id,
        oid_arcs,
        0x00,
    )
}

/// Encode a `SNMPv3` `GetRequest` frame with explicit `msgUserName` and `msgFlags` byte.
///
/// Use this when you need precise control over both the USM user name and the
/// security-level bits in `msgFlags`. For common cases, prefer
/// [`encode_get_request_with_user`] (`msgFlags = 0x04`) or
/// [`encode_get_request_with_user_no_report`] (`msgFlags = 0x00`).
///
/// # Examples
///
/// ```
/// // authNoPriv flags (0x05 = authFlag set, reportableFlag set):
/// let frame = snmpv3_frames::encode_get_request_with_user_and_flags(
///     b"\x80\x00\x1f\x88\x04test",
///     b"alice",
///     b"",
///     1,
///     42,
///     &[1, 3, 6, 1, 2, 1, 1, 1, 0],
///     0x05,
/// );
/// assert!(!frame.is_empty());
/// ```
#[must_use]
pub fn encode_get_request_with_user_and_flags(
    engine_id: &[u8],
    user_name: &[u8],
    context_name: &[u8],
    msg_id: i32,
    request_id: i32,
    oid_arcs: &[u32],
    msg_flags_byte: u8,
) -> Vec<u8> {
    let rasn_pdu = RasnGetRequest(single_varbind_pdu(request_id, oid_arcs));
    encode_v3_message(
        engine_id,
        user_name,
        context_name,
        msg_id,
        Pdus::GetRequest(rasn_pdu),
        msg_flags_byte,
    )
}

/// Encode a `SNMPv3` `GetRequest` frame with explicit `msgAuthenticationParameters`.
///
/// Unlike [`encode_get_request_with_user_and_flags`] (which always encodes empty `auth_params`),
/// this function places the given `auth_params` bytes into the USM security parameters.
/// Use this to build frames for HMAC verification tests: first encode with zeroed `auth_params`,
/// compute the HMAC, then encode again with the real MAC.
///
/// # Examples
///
/// ```
/// // Build with 24 zeroed auth_params (placeholder for HMAC computation)
/// let frame = snmpv3_frames::encode_get_request_with_auth_params(
///     b"\x80\x00\x1f\x88\x04test",
///     b"alice",
///     b"",
///     1,
///     42,
///     &[1, 3, 6, 1, 2, 1, 1, 1, 0],
///     0x05, // authNoPriv + reportable
///     &[0u8; 24],
/// );
/// assert!(!frame.is_empty());
/// ```
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn encode_get_request_with_auth_params(
    engine_id: &[u8],
    user_name: &[u8],
    context_name: &[u8],
    msg_id: i32,
    request_id: i32,
    oid_arcs: &[u32],
    msg_flags_byte: u8,
    auth_params: &[u8],
) -> Vec<u8> {
    let rasn_pdu = RasnGetRequest(single_varbind_pdu(request_id, oid_arcs));
    encode_v3_message_with_auth_params(
        engine_id,
        user_name,
        context_name,
        msg_id,
        Pdus::GetRequest(rasn_pdu),
        msg_flags_byte,
        auth_params,
    )
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
        b"",
        context_name,
        msg_id,
        Pdus::GetNextRequest(rasn_pdu),
        0x04,
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
        b"",
        context_name,
        msg_id,
        Pdus::GetBulkRequest(rasn_pdu),
        0x04,
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
    encode_v3_message(
        engine_id,
        b"",
        context_name,
        msg_id,
        Pdus::SetRequest(rasn_pdu),
        0x04,
    )
}

/// Encode an engine-ID discovery probe: a `GetRequest` with empty
/// `msgAuthoritativeEngineID` in the USM security parameters and the
/// `reportableFlag` (bit 2, `0x04`) set in `msgFlags`.
/// The `contextEngineID` in the `ScopedPDU` is left empty.
///
/// # Panics
///
/// Does not panic in practice; all internal BER encodings are of well-formed structures.
///
/// # Examples
///
/// ```
/// let frame = snmpv3_frames::encode_discovery_probe();
/// assert!(!frame.is_empty());
/// ```
#[must_use]
pub fn encode_discovery_probe() -> Vec<u8> {
    encode_discovery_probe_with_flags(vec![0x04])
}

/// Encode an engine-ID discovery probe with the `reportableFlag` (`0x04`) cleared in
/// `msgFlags`. Per RFC 3412 §7.1.3a the agent must silently discard such a message
/// without sending a Report PDU.
///
/// # Panics
///
/// Does not panic in practice; all internal BER encodings are of well-formed structures.
///
/// # Examples
///
/// ```
/// let frame = snmpv3_frames::encode_discovery_probe_no_report();
/// assert!(!frame.is_empty());
/// ```
#[must_use]
pub fn encode_discovery_probe_no_report() -> Vec<u8> {
    encode_discovery_probe_with_flags(vec![0x00])
}

// Build a discovery probe frame using the given raw msgFlags byte(s).
// An empty authoritative engine ID signals a discovery probe per RFC 3414.
fn encode_discovery_probe_with_flags(flags: Vec<u8>) -> Vec<u8> {
    let usm_params = USMSecurityParameters {
        authoritative_engine_id: vec![].into(), // empty = discovery probe per RFC 3414
        authoritative_engine_boots: 0.into(),
        authoritative_engine_time: 0.into(),
        user_name: rasn::types::OctetString::from(vec![]),
        authentication_parameters: rasn::types::OctetString::from(vec![]),
        privacy_parameters: rasn::types::OctetString::from(vec![]),
    };
    let security_parameters_bytes =
        rasn::ber::encode(&usm_params).expect("USMSecurityParameters must encode");

    let oid =
        rasn::types::ObjectIdentifier::new_unchecked(Cow::Owned(vec![1, 3, 6, 1, 2, 1, 1, 1, 0]));
    let get_request = RasnGetRequest(RasnPdu {
        request_id: 1,
        error_status: 0,
        error_index: 0,
        variable_bindings: vec![VarBind {
            name: oid,
            value: RasnVarBindValue::Unspecified,
        }],
    });
    let scoped_pdu = ScopedPdu {
        engine_id: vec![].into(),
        name: vec![].into(),
        data: Pdus::GetRequest(get_request),
    };
    let v3_message = V3Message {
        version: 3.into(),
        global_data: HeaderData {
            message_id: 42.into(),
            max_size: 65535.into(),
            flags: rasn::types::OctetString::from(flags),
            security_model: 3.into(),
        },
        security_parameters: security_parameters_bytes.into(),
        scoped_data: ScopedPduData::CleartextPdu(scoped_pdu),
    };
    rasn::ber::encode(&v3_message).expect("V3Message must encode")
}

// Encode a complete SNMPv3 message with noAuthNoPriv USM security parameters,
// with the authoritative engine ID set to the agent's engine_id.
// Delegates to encode_v3_message_with_auth_params with empty auth_params.
fn encode_v3_message(
    engine_id: &[u8],
    user_name: &[u8],
    context_name: &[u8],
    msg_id: i32,
    pdus: Pdus,
    msg_flags_byte: u8,
) -> Vec<u8> {
    encode_v3_message_with_auth_params(
        engine_id,
        user_name,
        context_name,
        msg_id,
        pdus,
        msg_flags_byte,
        &[],
    )
}

// Like encode_v3_message but with explicit auth_params bytes in USMSecurityParameters.
fn encode_v3_message_with_auth_params(
    engine_id: &[u8],
    user_name: &[u8],
    context_name: &[u8],
    msg_id: i32,
    pdus: Pdus,
    msg_flags_byte: u8,
    auth_params: &[u8],
) -> Vec<u8> {
    let scoped_pdu = ScopedPdu {
        engine_id: engine_id.to_vec().into(),
        name: context_name.to_vec().into(),
        data: pdus,
    };
    let usm_params = USMSecurityParameters {
        authoritative_engine_id: engine_id.to_vec().into(),
        authoritative_engine_boots: 0.into(),
        authoritative_engine_time: 0.into(),
        user_name: rasn::types::OctetString::from(user_name.to_vec()),
        authentication_parameters: rasn::types::OctetString::from(auth_params.to_vec()),
        privacy_parameters: rasn::types::OctetString::from(vec![]),
    };
    let security_parameters_bytes =
        rasn::ber::encode(&usm_params).expect("USMSecurityParameters must encode");
    let v3_message = V3Message {
        version: 3.into(),
        global_data: HeaderData {
            message_id: msg_id.into(),
            max_size: 65535.into(),
            flags: rasn::types::OctetString::from(vec![msg_flags_byte]),
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
