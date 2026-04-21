//! Pure request dispatch: decode, validate, and encode a single `SNMPv3` frame.
//!
//! This module is intentionally free of I/O and side effects so that the
//! dispatch path can be exercised by fuzz targets and unit tests without
//! requiring a running event loop.

use crate::transport::event_loop::MAX_BULK_REPETITIONS;
use crate::transport::request;

// Implements: REQ-0093
static UNKNOWN_ENGINE_IDS_OID: std::sync::LazyLock<crate::codec::Oid> =
    std::sync::LazyLock::new(|| {
        crate::usm::counters::USM_STATS_UNKNOWN_ENGINE_IDS
            .parse()
            .expect("USM_STATS_UNKNOWN_ENGINE_IDS is a valid OID constant")
    });

/// Decode, validate, and dispatch a single RFC 3430 BER frame, returning
/// the encoded response bytes on success.
///
/// `frame` is the complete BER bytes (SEQUENCE tag + length + content).
/// Returns `Some(encoded_response)` when the frame produces a response, or
/// `None` when it should be silently discarded (invalid encoding, wrong
/// engine ID, or unsupported context name).
///
/// Engine-ID discovery probes (empty `msgAuthoritativeEngineID`) always produce
/// a Report PDU response and increment `unknown_engine_ids_counter` (REQ-0093),
/// provided the `reportableFlag` (`0x04`) is set in `msgFlags`. Probes without
/// the flag set are silently discarded per RFC 3412 §7.1.3a.
///
/// # Requirements
/// Implements: REQ-0056, REQ-0057, REQ-0058, REQ-0066, REQ-0068, REQ-0073, REQ-0093
///
/// # Examples
///
/// ```
/// use basic_snmp_agent::{mib::Store, process_snmpv3_request};
///
/// let mib = Store::new();
/// let engine_id = b"\x80\x00\x1f\x88\x80test";
/// let mut counter = 0u32;
/// // Garbage bytes produce no response (silently discarded).
/// let result = process_snmpv3_request(b"\x00\x01\x02", engine_id, 1, 0, &mut counter, &mib);
/// assert!(result.is_none());
/// ```
#[must_use]
pub fn process_snmpv3_request(
    frame: &[u8],
    engine_id: &[u8],
    engine_boots: u32,
    engine_time: u32,
    unknown_engine_ids_counter: &mut u32,
    mib: &crate::mib::Store,
) -> Option<Vec<u8>> {
    // Decode as an SNMPv3 message. Non-v3 messages are silently discarded
    // per REQ-0073.
    let v3_msg = crate::codec::decode_v3_message(frame).ok()?;

    // REQ-0093: engine-ID discovery probe — the manager sent an empty
    // msgAuthoritativeEngineID. Respond with a Report PDU carrying the
    // usmStatsUnknownEngineIDs counter and our authoritative engine state
    // so the manager can learn our engine ID, boots, and approximate time.
    if v3_msg.auth_engine_id.is_empty() {
        // RFC 3412 §7.1.3a: if the reportableFlag is not set, discard without response.
        if v3_msg.security_flags & 0x04 == 0 {
            return None;
        }
        *unknown_engine_ids_counter = unknown_engine_ids_counter.saturating_add(1);
        return crate::codec::encode_v3_report(
            v3_msg.msg_id,
            engine_id,
            engine_boots,
            engine_time,
            &UNKNOWN_ENGINE_IDS_OID,
            *unknown_engine_ids_counter,
        )
        .ok();
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_engine_id() -> &'static [u8] {
        b"\x80\x00\x1f\x88\x04test"
    }

    // ── Discovery probe (REQ-0093) ────────────────────────────────────────────

    #[test]
    fn given_discovery_probe_when_process_then_returns_report_and_increments_counter() {
        // Verifies: REQ-0093
        let mib = crate::mib::Store::new();
        let probe_frame = snmpv3_frames::encode_discovery_probe();
        let mut counter = 0u32;
        let result =
            process_snmpv3_request(&probe_frame, test_engine_id(), 3, 100, &mut counter, &mib);
        assert!(
            result.is_some(),
            "discovery probe must produce a Report response"
        );
        assert_eq!(
            counter, 1,
            "counter must be incremented for discovery probe"
        );

        let response_bytes = result.unwrap();
        let v3_response = rasn::ber::decode::<rasn_snmp::v3::Message>(&response_bytes)
            .expect("response must be a valid SNMPv3 message");
        let usm_params: rasn_snmp::v3::USMSecurityParameters =
            rasn::ber::decode(v3_response.security_parameters.as_ref())
                .expect("security parameters must be valid USMSecurityParameters");
        assert_eq!(
            usm_params.authoritative_engine_id.as_ref(),
            test_engine_id(),
            "response must carry the agent's engine ID"
        );
        assert_eq!(
            u32::try_from(usm_params.authoritative_engine_boots).unwrap(),
            3u32,
            "response must carry the agent's engine boots"
        );
        assert_eq!(
            u32::try_from(usm_params.authoritative_engine_time).unwrap(),
            100u32,
            "response must carry the agent's engine time"
        );
    }

    #[test]
    fn given_two_discovery_probes_when_process_then_counter_increments_twice() {
        // Verifies: REQ-0093 — counter accumulates across calls
        let mib = crate::mib::Store::new();
        let probe_frame = snmpv3_frames::encode_discovery_probe();
        let mut counter = 5u32;
        let _ = process_snmpv3_request(&probe_frame, test_engine_id(), 3, 100, &mut counter, &mib);
        let _ = process_snmpv3_request(&probe_frame, test_engine_id(), 3, 100, &mut counter, &mib);
        assert_eq!(counter, 7);
    }

    #[test]
    fn given_normal_request_when_process_then_counter_unchanged() {
        // Verifies: REQ-0093 — only discovery probes increment the counter
        let mib = crate::mib::Store::new();
        let oid: crate::codec::Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        let frame = snmpv3_frames::encode_get_request(test_engine_id(), b"", 1, 2, oid.as_slice());
        let mut counter = 0u32;
        let _ = process_snmpv3_request(&frame, test_engine_id(), 1, 0, &mut counter, &mib);
        assert_eq!(counter, 0);
    }

    #[test]
    fn given_counter_at_max_when_discovery_probe_then_counter_does_not_overflow() {
        // Verifies: REQ-0093 — saturating_add prevents overflow
        let mib = crate::mib::Store::new();
        let probe_frame = snmpv3_frames::encode_discovery_probe();
        let mut counter = u32::MAX;
        let _ = process_snmpv3_request(&probe_frame, test_engine_id(), 1, 0, &mut counter, &mib);
        assert_eq!(counter, u32::MAX);
    }

    #[test]
    fn given_discovery_probe_without_reportable_flag_when_process_then_discarded() {
        // Verifies: REQ-0093 — non-reportable probes are silently discarded
        let mib = crate::mib::Store::new();
        let probe_frame = snmpv3_frames::encode_discovery_probe_no_report();
        let mut counter = 0u32;
        let result =
            process_snmpv3_request(&probe_frame, test_engine_id(), 3, 100, &mut counter, &mib);
        assert!(
            result.is_none(),
            "probe without reportableFlag must be silently discarded"
        );
        assert_eq!(
            counter, 0,
            "counter must not be incremented for non-reportable probe"
        );
    }
}
