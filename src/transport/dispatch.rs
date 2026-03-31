//! Pure request dispatch: decode, validate, and encode a single `SNMPv3` frame.
//!
//! This module is intentionally free of I/O and side effects so that the
//! dispatch path can be exercised by fuzz targets and unit tests without
//! requiring a running event loop.

use crate::transport::event_loop::MAX_BULK_REPETITIONS;
use crate::transport::request;

/// Decode, validate, and dispatch a single RFC 3430 BER frame, returning
/// the encoded response bytes on success.
///
/// `frame` is the complete BER bytes (SEQUENCE tag + length + content).
/// Returns `Some(encoded_response)` when the frame produces a response, or
/// `None` when it should be silently discarded (invalid encoding, wrong
/// engine ID, or unsupported context name).
///
/// # Requirements
/// Implements: REQ-0011, REQ-0056, REQ-0057, REQ-0058, REQ-0066
///
/// # Examples
///
/// ```
/// use basic_snmp_agent::{mib::Store, process_snmpv3_request};
///
/// let mib = Store::new();
/// let engine_id = b"\x80\x00\x1f\x88\x80test";
/// // Garbage bytes produce no response (silently discarded).
/// let result = process_snmpv3_request(b"\x00\x01\x02", engine_id, &mib);
/// assert!(result.is_none());
/// ```
#[must_use]
pub fn process_snmpv3_request(
    frame: &[u8],
    engine_id: &[u8],
    mib: &crate::mib::Store,
) -> Option<Vec<u8>> {
    // Decode as an SNMPv3 message. Non-v3 messages are silently discarded
    // per REQ-0011.
    let v3_msg = crate::codec::decode_v3_message(frame).ok()?;

    // Verify the engine ID matches ours. Requests for other engines are
    // silently discarded per REQ-0057.
    if v3_msg.engine_id != engine_id {
        return None;
    }

    // Only the default (empty) context name is supported per REQ-0058.
    if !v3_msg.context_name.is_empty() {
        return None;
    }

    let response = match v3_msg.pdu {
        crate::codec::InboundPdu::GetRequest(req) => request::handle_get(&req, mib),
        crate::codec::InboundPdu::GetNextRequest(req) => request::handle_get_next(&req, mib),
        crate::codec::InboundPdu::GetBulkRequest(req) => {
            request::handle_get_bulk(&req, mib, MAX_BULK_REPETITIONS)
        }
        crate::codec::InboundPdu::SetRequest(req) => request::handle_set(&req),
    };

    // context_name is always empty here: non-empty values were rejected above.
    crate::codec::encode_v3_response(
        v3_msg.msg_id,
        engine_id,
        &v3_msg.user_name,
        &v3_msg.context_name,
        &response,
    )
    .ok()
}
