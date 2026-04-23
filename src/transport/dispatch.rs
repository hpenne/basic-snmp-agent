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

// Implements: REQ-0078
static UNKNOWN_USER_NAMES_OID: std::sync::LazyLock<crate::codec::Oid> =
    std::sync::LazyLock::new(|| {
        crate::usm::counters::USM_STATS_UNKNOWN_USER_NAMES
            .parse()
            .expect("USM_STATS_UNKNOWN_USER_NAMES is a valid OID constant")
    });

/// Engine state and statistics passed to each inbound frame dispatch.
///
/// # Requirements
/// Implements: REQ-0093, REQ-0094, REQ-0078, REQ-0079, REQ-0100, REQ-0101
pub struct DispatchContext<'a> {
    /// The agent's authoritative engine ID.
    pub engine_id: &'a [u8],
    /// Current `snmpEngineBoots` value.
    pub engine_boots: u32,
    /// Current `snmpEngineTime` in seconds.
    pub engine_time: u32,
    /// Counter for `usmStatsUnknownEngineIDs` (REQ-0093).
    pub unknown_engine_ids_counter: &'a mut u32,
    /// Counter for `usmStatsUnknownUserNames` (REQ-0078).
    // Implements: REQ-0078
    pub unknown_user_names_counter: &'a mut u32,
    /// Counter for `usmStatsUnsupportedSecLevels` (REQ-0079).
    // Implements: REQ-0079
    pub unsupported_sec_levels_counter: &'a mut u32,
    /// Counter for `usmStatsWrongDigests` (REQ-0100).
    // Implements: REQ-0100
    pub wrong_digests_counter: &'a mut u32,
    /// Counter for `usmStatsDecryptionErrors` (REQ-0101).
    // Implements: REQ-0101
    pub decryption_errors_counter: &'a mut u32,
    /// Optional configured USM user; `None` when no USM user is configured (REQ-0078, REQ-0079).
    // Implements: REQ-0078, REQ-0079
    pub usm_user: Option<&'a crate::usm::user::UsmUser>,
}

/// Decode, validate, and dispatch a single RFC 3430 BER frame, returning
/// the encoded response bytes on success.
///
/// `frame` is the complete BER bytes (SEQUENCE tag + length + content).
/// Returns `Some(encoded_response)` when the frame produces a response, or
/// `None` when it should be silently discarded (invalid encoding, wrong
/// engine ID, or unsupported context name).
///
/// Engine-ID discovery probes (empty `msgAuthoritativeEngineID`) always produce
/// a Report PDU response and increment `ctx.unknown_engine_ids_counter` (REQ-0093),
/// provided the `reportableFlag` (`0x04`) is set in `msgFlags`. Probes without
/// the flag set are silently discarded per RFC 3412 §7.1.3a.
///
/// # Requirements
/// Implements: REQ-0056, REQ-0057, REQ-0058, REQ-0066, REQ-0068, REQ-0073, REQ-0078, REQ-0080, REQ-0093
///
/// # Examples
///
/// ```
/// use basic_snmp_agent::{mib::Store, process_snmpv3_request};
/// use basic_snmp_agent::transport::dispatch::DispatchContext;
///
/// let mib = Store::new();
/// let engine_id = b"\x80\x00\x1f\x88\x80test";
/// let mut counter = 0u32;
/// let mut unknown_user_names = 0u32;
/// let mut unsupported_sec_levels = 0u32;
/// let mut wrong_digests = 0u32;
/// let mut decryption_errors = 0u32;
/// let mut ctx = DispatchContext {
///     engine_id,
///     engine_boots: 1,
///     engine_time: 0,
///     unknown_engine_ids_counter: &mut counter,
///     unknown_user_names_counter: &mut unknown_user_names,
///     unsupported_sec_levels_counter: &mut unsupported_sec_levels,
///     wrong_digests_counter: &mut wrong_digests,
///     decryption_errors_counter: &mut decryption_errors,
///     usm_user: None,
/// };
/// // Garbage bytes produce no response (silently discarded).
/// let result = process_snmpv3_request(b"\x00\x01\x02", &mut ctx, &mib);
/// assert!(result.is_none());
/// ```
#[must_use]
pub fn process_snmpv3_request(
    frame: &[u8],
    ctx: &mut DispatchContext<'_>,
    mib: &crate::mib::Store,
) -> Option<Vec<u8>> {
    // Decode as an SNMPv3 message. Non-v3 messages are silently discarded
    // per REQ-0073.
    let v3_msg = crate::codec::decode_v3_message(frame).ok()?;

    // REQ-0093: engine-ID discovery probe — the manager sent an empty
    // msgAuthoritativeEngineID. Respond with a Report PDU carrying the
    // usmStatsUnknownEngineIDs counter and our authoritative engine state
    // so the manager can learn our engine ID, boots, and approximate time.
    if v3_msg.usm.auth_engine_id.is_empty() {
        // RFC 3412 §7.1.3a: if the reportableFlag is not set, discard without response.
        if v3_msg.usm.security_flags & 0x04 == 0 {
            return None;
        }
        *ctx.unknown_engine_ids_counter = ctx.unknown_engine_ids_counter.saturating_add(1);
        return crate::codec::encode_v3_report(
            v3_msg.msg_id,
            ctx.engine_id,
            ctx.engine_boots,
            ctx.engine_time,
            &UNKNOWN_ENGINE_IDS_OID,
            *ctx.unknown_engine_ids_counter,
        )
        .ok();
    }

    // Verify the engine ID matches ours. Requests for other engines are
    // silently discarded per REQ-0057.
    if v3_msg.engine_id != ctx.engine_id {
        return None;
    }

    // REQ-0078, REQ-0080: user-name lookup — discovery (above) runs before this check.
    // If a USM user is configured and the request names a different user, increment the
    // counter and respond with a Report PDU only if the reportableFlag is set
    // (RFC 3412 §7.1.3a).
    if let Some(user) = ctx.usm_user
        && v3_msg.user_name != user.name().as_bytes()
    {
        *ctx.unknown_user_names_counter = ctx.unknown_user_names_counter.saturating_add(1);
        if v3_msg.usm.security_flags & 0x04 == 0 {
            return None;
        }
        return crate::codec::encode_v3_report(
            v3_msg.msg_id,
            ctx.engine_id,
            ctx.engine_boots,
            ctx.engine_time,
            &UNKNOWN_USER_NAMES_OID,
            *ctx.unknown_user_names_counter,
        )
        .ok();
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
        ctx.engine_id,
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

    fn test_oid_arcs() -> &'static [u32] {
        &[1, 3, 6, 1, 2, 1, 1, 1, 0]
    }

    // ── Discovery probe (REQ-0093) ────────────────────────────────────────────

    #[test]
    fn given_discovery_probe_when_process_then_returns_report_and_increments_counter() {
        // Verifies: REQ-0093
        let mib = crate::mib::Store::new();
        let probe_frame = snmpv3_frames::encode_discovery_probe();
        let mut counter = 0u32;
        let mut unknown_user_names = 0u32;
        let mut unsupported_sec_levels = 0u32;
        let mut wrong_digests = 0u32;
        let mut decryption_errors = 0u32;
        let result = {
            let mut ctx = DispatchContext {
                engine_id: test_engine_id(),
                engine_boots: 3,
                engine_time: 100,
                unknown_engine_ids_counter: &mut counter,
                unknown_user_names_counter: &mut unknown_user_names,
                unsupported_sec_levels_counter: &mut unsupported_sec_levels,
                wrong_digests_counter: &mut wrong_digests,
                decryption_errors_counter: &mut decryption_errors,
                usm_user: None,
            };
            let r = process_snmpv3_request(&probe_frame, &mut ctx, &mib);
            assert_eq!(
                *ctx.unknown_engine_ids_counter, 1,
                "counter must be incremented for discovery probe"
            );
            r
        };
        assert!(
            result.is_some(),
            "discovery probe must produce a Report response"
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
        let mut unknown_user_names = 0u32;
        let mut unsupported_sec_levels = 0u32;
        let mut wrong_digests = 0u32;
        let mut decryption_errors = 0u32;
        let _ = process_snmpv3_request(
            &probe_frame,
            &mut DispatchContext {
                engine_id: test_engine_id(),
                engine_boots: 3,
                engine_time: 100,
                unknown_engine_ids_counter: &mut counter,
                unknown_user_names_counter: &mut unknown_user_names,
                unsupported_sec_levels_counter: &mut unsupported_sec_levels,
                wrong_digests_counter: &mut wrong_digests,
                decryption_errors_counter: &mut decryption_errors,
                usm_user: None,
            },
            &mib,
        );
        let _ = process_snmpv3_request(
            &probe_frame,
            &mut DispatchContext {
                engine_id: test_engine_id(),
                engine_boots: 3,
                engine_time: 100,
                unknown_engine_ids_counter: &mut counter,
                unknown_user_names_counter: &mut unknown_user_names,
                unsupported_sec_levels_counter: &mut unsupported_sec_levels,
                wrong_digests_counter: &mut wrong_digests,
                decryption_errors_counter: &mut decryption_errors,
                usm_user: None,
            },
            &mib,
        );
        assert_eq!(counter, 7);
    }

    #[test]
    fn given_normal_request_when_process_then_counter_unchanged() {
        // Verifies: REQ-0093 — only discovery probes increment the counter
        let mib = crate::mib::Store::new();
        let oid: crate::codec::Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        let frame = snmpv3_frames::encode_get_request(test_engine_id(), b"", 1, 2, oid.as_slice());
        let mut counter = 0u32;
        let mut unknown_user_names = 0u32;
        let mut unsupported_sec_levels = 0u32;
        let mut wrong_digests = 0u32;
        let mut decryption_errors = 0u32;
        let _ = process_snmpv3_request(
            &frame,
            &mut DispatchContext {
                engine_id: test_engine_id(),
                engine_boots: 1,
                engine_time: 0,
                unknown_engine_ids_counter: &mut counter,
                unknown_user_names_counter: &mut unknown_user_names,
                unsupported_sec_levels_counter: &mut unsupported_sec_levels,
                wrong_digests_counter: &mut wrong_digests,
                decryption_errors_counter: &mut decryption_errors,
                usm_user: None,
            },
            &mib,
        );
        assert_eq!(counter, 0);
    }

    #[test]
    fn given_counter_at_max_when_discovery_probe_then_counter_does_not_overflow() {
        // Verifies: REQ-0093 — saturating_add prevents overflow
        let mib = crate::mib::Store::new();
        let probe_frame = snmpv3_frames::encode_discovery_probe();
        let mut counter = u32::MAX;
        let mut unknown_user_names = 0u32;
        let mut unsupported_sec_levels = 0u32;
        let mut wrong_digests = 0u32;
        let mut decryption_errors = 0u32;
        let _ = process_snmpv3_request(
            &probe_frame,
            &mut DispatchContext {
                engine_id: test_engine_id(),
                engine_boots: 1,
                engine_time: 0,
                unknown_engine_ids_counter: &mut counter,
                unknown_user_names_counter: &mut unknown_user_names,
                unsupported_sec_levels_counter: &mut unsupported_sec_levels,
                wrong_digests_counter: &mut wrong_digests,
                decryption_errors_counter: &mut decryption_errors,
                usm_user: None,
            },
            &mib,
        );
        assert_eq!(counter, u32::MAX);
    }

    #[test]
    fn given_discovery_probe_without_reportable_flag_when_process_then_discarded() {
        // Verifies: REQ-0093 — non-reportable probes are silently discarded
        let mib = crate::mib::Store::new();
        let probe_frame = snmpv3_frames::encode_discovery_probe_no_report();
        let mut counter = 0u32;
        let mut unknown_user_names = 0u32;
        let mut unsupported_sec_levels = 0u32;
        let mut wrong_digests = 0u32;
        let mut decryption_errors = 0u32;
        let result = process_snmpv3_request(
            &probe_frame,
            &mut DispatchContext {
                engine_id: test_engine_id(),
                engine_boots: 3,
                engine_time: 100,
                unknown_engine_ids_counter: &mut counter,
                unknown_user_names_counter: &mut unknown_user_names,
                unsupported_sec_levels_counter: &mut unsupported_sec_levels,
                wrong_digests_counter: &mut wrong_digests,
                decryption_errors_counter: &mut decryption_errors,
                usm_user: None,
            },
            &mib,
        );
        assert!(
            result.is_none(),
            "probe without reportableFlag must be silently discarded"
        );
        assert_eq!(
            counter, 0,
            "counter must not be incremented for non-reportable probe"
        );
    }

    // ── User-name lookup (REQ-0078, REQ-0080) ────────────────────────────────

    #[test]
    fn given_no_usm_user_when_process_then_user_name_check_skipped() {
        // Verifies: REQ-0078 (None user → backward-compat skip)
        let mib = crate::mib::Store::new();
        // Frame with empty user name; usm_user: None means no check is performed.
        let frame = snmpv3_frames::encode_get_request(test_engine_id(), b"", 1, 2, test_oid_arcs());
        let mut unknown_engine_ids = 0u32;
        let mut unknown_user_names = 0u32;
        let mut unsupported_sec_levels = 0u32;
        let mut wrong_digests = 0u32;
        let mut decryption_errors = 0u32;
        let result = process_snmpv3_request(
            &frame,
            &mut DispatchContext {
                engine_id: test_engine_id(),
                engine_boots: 1,
                engine_time: 0,
                unknown_engine_ids_counter: &mut unknown_engine_ids,
                unknown_user_names_counter: &mut unknown_user_names,
                unsupported_sec_levels_counter: &mut unsupported_sec_levels,
                wrong_digests_counter: &mut wrong_digests,
                decryption_errors_counter: &mut decryption_errors,
                usm_user: None,
            },
            &mib,
        );
        assert!(
            result.is_some(),
            "request must pass through when no USM user is configured"
        );
        assert_eq!(unknown_user_names, 0, "counter must not be incremented");
    }

    #[test]
    fn given_matching_user_name_when_process_then_proceeds() {
        // Verifies: REQ-0078
        let mib = crate::mib::Store::new();
        let alice = crate::usm::user::UsmUser::no_auth_no_priv("alice");
        let frame = snmpv3_frames::encode_get_request_with_user(
            test_engine_id(),
            b"alice",
            b"",
            1,
            2,
            test_oid_arcs(),
        );
        let mut unknown_engine_ids = 0u32;
        let mut unknown_user_names = 0u32;
        let mut unsupported_sec_levels = 0u32;
        let mut wrong_digests = 0u32;
        let mut decryption_errors = 0u32;
        let result = process_snmpv3_request(
            &frame,
            &mut DispatchContext {
                engine_id: test_engine_id(),
                engine_boots: 1,
                engine_time: 0,
                unknown_engine_ids_counter: &mut unknown_engine_ids,
                unknown_user_names_counter: &mut unknown_user_names,
                unsupported_sec_levels_counter: &mut unsupported_sec_levels,
                wrong_digests_counter: &mut wrong_digests,
                decryption_errors_counter: &mut decryption_errors,
                usm_user: Some(&alice),
            },
            &mib,
        );
        assert!(
            result.is_some(),
            "matching user name must produce a response"
        );
        assert_eq!(
            unknown_user_names, 0,
            "counter must not be incremented on match"
        );

        // Verify the response is a normal GetResponse (Pdus::Response), not a Report.
        let response_bytes = result.unwrap();
        let v3_response = rasn::ber::decode::<rasn_snmp::v3::Message>(&response_bytes)
            .expect("response must be a valid SNMPv3 message");
        let rasn_snmp::v3::ScopedPduData::CleartextPdu(scoped_pdu) = v3_response.scoped_data else {
            panic!("response must contain a cleartext ScopedPDU");
        };
        // A Report PDU would decode as Pdus::Report; a GetResponse decodes as Pdus::Response.
        assert!(
            matches!(scoped_pdu.data, rasn_snmp::v2::Pdus::Response(_)),
            "response must be a GetResponse, not a Report"
        );
    }

    #[test]
    fn given_mismatched_user_name_when_process_then_returns_report_and_increments_counter() {
        // Verifies: REQ-0078, REQ-0080
        let mib = crate::mib::Store::new();
        let alice = crate::usm::user::UsmUser::no_auth_no_priv("alice");
        // Frame sent by "eve" but agent is configured for "alice".
        let frame = snmpv3_frames::encode_get_request_with_user(
            test_engine_id(),
            b"eve",
            b"",
            1,
            2,
            test_oid_arcs(),
        );
        let mut unknown_engine_ids = 0u32;
        let mut unknown_user_names = 0u32;
        let mut unsupported_sec_levels = 0u32;
        let mut wrong_digests = 0u32;
        let mut decryption_errors = 0u32;
        let result = process_snmpv3_request(
            &frame,
            &mut DispatchContext {
                engine_id: test_engine_id(),
                engine_boots: 1,
                engine_time: 0,
                unknown_engine_ids_counter: &mut unknown_engine_ids,
                unknown_user_names_counter: &mut unknown_user_names,
                unsupported_sec_levels_counter: &mut unsupported_sec_levels,
                wrong_digests_counter: &mut wrong_digests,
                decryption_errors_counter: &mut decryption_errors,
                usm_user: Some(&alice),
            },
            &mib,
        );
        assert!(
            result.is_some(),
            "mismatched user name must produce a Report response"
        );
        assert_eq!(
            unknown_user_names, 1,
            "counter must be incremented on mismatch"
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
            "Report response must carry the agent's engine ID"
        );
        assert_eq!(
            u32::try_from(usm_params.authoritative_engine_boots).unwrap(),
            1u32,
            "Report response must carry the agent's engine boots"
        );
        assert_eq!(
            u32::try_from(usm_params.authoritative_engine_time).unwrap(),
            0u32,
            "Report response must carry the agent's engine time"
        );
    }

    #[test]
    fn given_mismatched_user_name_without_reportable_flag_when_process_then_discarded_but_counter_incremented()
     {
        // Verifies: REQ-0078 — no Report when reportableFlag is not set, but counter still increments
        let mib = crate::mib::Store::new();
        let alice = crate::usm::user::UsmUser::no_auth_no_priv("alice");
        // Frame sent by "eve" with reportableFlag cleared — agent must not send a Report.
        let frame = snmpv3_frames::encode_get_request_with_user_no_report(
            test_engine_id(),
            b"eve",
            b"",
            1,
            2,
            test_oid_arcs(),
        );
        let mut unknown_engine_ids = 0u32;
        let mut unknown_user_names = 0u32;
        let mut unsupported_sec_levels = 0u32;
        let mut wrong_digests = 0u32;
        let mut decryption_errors = 0u32;
        let result = process_snmpv3_request(
            &frame,
            &mut DispatchContext {
                engine_id: test_engine_id(),
                engine_boots: 1,
                engine_time: 0,
                unknown_engine_ids_counter: &mut unknown_engine_ids,
                unknown_user_names_counter: &mut unknown_user_names,
                unsupported_sec_levels_counter: &mut unsupported_sec_levels,
                wrong_digests_counter: &mut wrong_digests,
                decryption_errors_counter: &mut decryption_errors,
                usm_user: Some(&alice),
            },
            &mib,
        );
        assert!(
            result.is_none(),
            "user-name mismatch without reportableFlag must be silently discarded"
        );
        assert_eq!(
            unknown_user_names, 1,
            "counter must still be incremented even when no Report is sent"
        );
    }

    #[test]
    fn given_counter_at_max_when_mismatched_user_name_then_counter_does_not_overflow() {
        // Verifies: REQ-0078 — saturating_add prevents overflow
        let mib = crate::mib::Store::new();
        let alice = crate::usm::user::UsmUser::no_auth_no_priv("alice");
        let frame = snmpv3_frames::encode_get_request_with_user(
            test_engine_id(),
            b"eve",
            b"",
            1,
            2,
            test_oid_arcs(),
        );
        let mut unknown_engine_ids = 0u32;
        let mut unknown_user_names = u32::MAX;
        let mut unsupported_sec_levels = 0u32;
        let mut wrong_digests = 0u32;
        let mut decryption_errors = 0u32;
        let _ = process_snmpv3_request(
            &frame,
            &mut DispatchContext {
                engine_id: test_engine_id(),
                engine_boots: 1,
                engine_time: 0,
                unknown_engine_ids_counter: &mut unknown_engine_ids,
                unknown_user_names_counter: &mut unknown_user_names,
                unsupported_sec_levels_counter: &mut unsupported_sec_levels,
                wrong_digests_counter: &mut wrong_digests,
                decryption_errors_counter: &mut decryption_errors,
                usm_user: Some(&alice),
            },
            &mib,
        );
        assert_eq!(unknown_user_names, u32::MAX, "counter must not overflow");
    }
}
