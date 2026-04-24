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

// Implements: REQ-0079
static UNSUPPORTED_SEC_LEVELS_OID: std::sync::LazyLock<crate::codec::Oid> =
    std::sync::LazyLock::new(|| {
        crate::usm::counters::USM_STATS_UNSUPPORTED_SEC_LEVELS
            .parse()
            .expect("USM_STATS_UNSUPPORTED_SEC_LEVELS is a valid OID constant")
    });

// Implements: REQ-0100
static WRONG_DIGESTS_OID: std::sync::LazyLock<crate::codec::Oid> = std::sync::LazyLock::new(|| {
    crate::usm::counters::USM_STATS_WRONG_DIGESTS
        .parse()
        .expect("USM_STATS_WRONG_DIGESTS is a valid OID constant")
});

// Implements: REQ-0098
static NOT_IN_TIME_WINDOWS_OID: std::sync::LazyLock<crate::codec::Oid> =
    std::sync::LazyLock::new(|| {
        crate::usm::counters::USM_STATS_NOT_IN_TIME_WINDOWS
            .parse()
            .expect("USM_STATS_NOT_IN_TIME_WINDOWS is a valid OID constant")
    });

/// Bit mask for the `reportableFlag` in `msgFlags` (RFC 3412 §7.1.3a).
const REPORTABLE_FLAG: u8 = 0x04;

/// Engine state and statistics passed to each inbound frame dispatch.
///
/// # Requirements
/// Implements: REQ-0093, REQ-0094, REQ-0078, REQ-0079, REQ-0098, REQ-0100, REQ-0101
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
    /// Counter for `usmStatsNotInTimeWindows` (REQ-0098).
    // Implements: REQ-0098
    pub not_in_time_windows_counter: &'a mut u32,
    /// Counter for `usmStatsDecryptionErrors` (REQ-0101).
    // Implements: REQ-0101
    pub decryption_errors_counter: &'a mut u32,
    /// Optional configured USM user; `None` when no USM user is configured (REQ-0078, REQ-0079).
    // Implements: REQ-0078, REQ-0079
    pub usm_user: Option<&'a crate::usm::user::UsmUser>,
}

/// Return a copy of `raw_message` with the `msgAuthenticationParameters` bytes zeroed.
///
/// `auth_params_offset` is the byte offset within `raw_message` where the MAC
/// field starts; `auth_params_len` is its length. Both are recorded during
/// decode to avoid byte-value searching, which could be misled by attacker-
/// controlled varbind data in the `ScopedPDU`.
///
/// # Requirements
/// Implements: REQ-0100
#[must_use]
fn zero_auth_params_in_message(
    raw_message: &[u8],
    auth_params_offset: usize,
    auth_params_len: usize,
) -> Vec<u8> {
    debug_assert!(
        auth_params_len > 0,
        "caller must check auth_params is non-empty"
    );
    let mut zeroed = raw_message.to_vec();
    zeroed[auth_params_offset..auth_params_offset + auth_params_len].fill(0);
    zeroed
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
/// provided the `reportableFlag` ([`REPORTABLE_FLAG`]) is set in `msgFlags`. Probes without
/// the flag set are silently discarded per RFC 3412 §7.1.3a.
///
/// # Requirements
/// Implements: REQ-0056, REQ-0057, REQ-0058, REQ-0066, REQ-0068, REQ-0073, REQ-0078, REQ-0079, REQ-0080, REQ-0093, REQ-0098, REQ-0100, REQ-0102, REQ-0103
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
/// let mut not_in_time_windows = 0u32;
/// let mut decryption_errors = 0u32;
/// let mut ctx = DispatchContext {
///     engine_id,
///     engine_boots: 1,
///     engine_time: 0,
///     unknown_engine_ids_counter: &mut counter,
///     unknown_user_names_counter: &mut unknown_user_names,
///     unsupported_sec_levels_counter: &mut unsupported_sec_levels,
///     wrong_digests_counter: &mut wrong_digests,
///     not_in_time_windows_counter: &mut not_in_time_windows,
///     decryption_errors_counter: &mut decryption_errors,
///     usm_user: None,
/// };
/// // Garbage bytes produce no response (silently discarded).
/// let result = process_snmpv3_request(b"\x00\x01\x02", &mut ctx, &mib);
/// assert!(result.is_none());
/// ```
#[must_use]
// Each branch implements a sequential RFC 3414 security check; extracting them
// into helpers would obscure the mandated processing order.
#[allow(clippy::too_many_lines)]
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
        if v3_msg.usm.security_flags & REPORTABLE_FLAG == 0 {
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
        if v3_msg.usm.security_flags & REPORTABLE_FLAG == 0 {
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

    // REQ-0079, REQ-0103: security-level enforcement — runs after user-name lookup.
    // If a USM user is configured, derive the security level from msgFlags and compare
    // against the configured user's level. The invalid combination (privFlag without
    // authFlag) is treated as a mismatch. For noAuthNoPriv messages that pass this
    // check, authentication and decryption are skipped naturally (REQ-0103).
    if let Some(user) = ctx.usm_user {
        let msg_level = crate::usm::user::SecurityLevel::from_msg_flags(v3_msg.usm.security_flags);
        if msg_level.ok() != Some(user.security_level()) {
            *ctx.unsupported_sec_levels_counter =
                ctx.unsupported_sec_levels_counter.saturating_add(1);
            if v3_msg.usm.security_flags & REPORTABLE_FLAG == 0 {
                return None;
            }
            return crate::codec::encode_v3_report(
                v3_msg.msg_id,
                ctx.engine_id,
                ctx.engine_boots,
                ctx.engine_time,
                &UNSUPPORTED_SEC_LEVELS_OID,
                *ctx.unsupported_sec_levels_counter,
            )
            .ok();
        }
    }

    // REQ-0100, REQ-0102: HMAC verification for authenticated messages.
    // Runs after security-level check per REQ-0102 processing order.
    // For noAuthNoPriv users, auth_protocol() returns None so this block is skipped (REQ-0103).
    if let Some(user) = ctx.usm_user
        && let (Some(auth_protocol), Some(auth_key)) = (user.auth_protocol(), user.auth_key())
    {
        let auth_params = &v3_msg.usm.auth_params;
        let hmac_ok = match v3_msg.auth_params_offset {
            Some(offset) => {
                let zeroed =
                    zero_auth_params_in_message(v3_msg.raw_message, offset, auth_params.len());
                auth_protocol
                    .verify_mac(auth_key, &zeroed, auth_params)
                    .is_ok()
            }
            // Empty auth_params for an auth user is always wrong.
            None => false,
        };
        if !hmac_ok {
            *ctx.wrong_digests_counter = ctx.wrong_digests_counter.saturating_add(1);
            if v3_msg.usm.security_flags & REPORTABLE_FLAG == 0 {
                return None;
            }
            return crate::codec::encode_v3_report(
                v3_msg.msg_id,
                ctx.engine_id,
                ctx.engine_boots,
                ctx.engine_time,
                &WRONG_DIGESTS_OID,
                *ctx.wrong_digests_counter,
            )
            .ok();
        }
    }

    // REQ-0098: time-window validation for authenticated messages.
    // Runs after HMAC verification per REQ-0102 processing order.
    if let Some(user) = ctx.usm_user
        && user.auth_protocol().is_some()
        && !crate::usm::time_window::is_in_time_window(
            v3_msg.usm.auth_engine_boots,
            v3_msg.usm.auth_engine_time,
            ctx.engine_boots,
            ctx.engine_time,
        )
    {
        *ctx.not_in_time_windows_counter = ctx.not_in_time_windows_counter.saturating_add(1);
        if v3_msg.usm.security_flags & REPORTABLE_FLAG == 0 {
            return None;
        }
        return crate::codec::encode_v3_report(
            v3_msg.msg_id,
            ctx.engine_id,
            ctx.engine_boots,
            ctx.engine_time,
            &NOT_IN_TIME_WINDOWS_OID,
            *ctx.not_in_time_windows_counter,
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

    /// Test helper that owns counter storage and produces a [`DispatchContext`],
    /// eliminating the repeated boilerplate of five local `u32` declarations.
    struct TestCtx {
        unknown_engine_ids: u32,
        unknown_user_names: u32,
        unsupported_sec_levels: u32,
        wrong_digests: u32,
        not_in_time_windows: u32,
        decryption_errors: u32,
        engine_boots: u32,
        engine_time: u32,
    }

    impl TestCtx {
        fn new() -> Self {
            Self {
                unknown_engine_ids: 0,
                unknown_user_names: 0,
                unsupported_sec_levels: 0,
                wrong_digests: 0,
                not_in_time_windows: 0,
                decryption_errors: 0,
                engine_boots: 1,
                engine_time: 0,
            }
        }

        fn with_unknown_engine_ids(mut self, initial_count: u32) -> Self {
            self.unknown_engine_ids = initial_count;
            self
        }

        fn with_unknown_user_names(mut self, initial_count: u32) -> Self {
            self.unknown_user_names = initial_count;
            self
        }

        fn with_unsupported_sec_levels(mut self, initial_count: u32) -> Self {
            self.unsupported_sec_levels = initial_count;
            self
        }

        fn with_wrong_digests(mut self, initial_count: u32) -> Self {
            self.wrong_digests = initial_count;
            self
        }

        fn with_not_in_time_windows(mut self, initial_count: u32) -> Self {
            self.not_in_time_windows = initial_count;
            self
        }

        fn with_boots_time(mut self, boots: u32, time: u32) -> Self {
            self.engine_boots = boots;
            self.engine_time = time;
            self
        }

        fn ctx<'a>(
            &'a mut self,
            usm_user: Option<&'a crate::usm::user::UsmUser>,
        ) -> DispatchContext<'a> {
            DispatchContext {
                engine_id: test_engine_id(),
                engine_boots: self.engine_boots,
                engine_time: self.engine_time,
                unknown_engine_ids_counter: &mut self.unknown_engine_ids,
                unknown_user_names_counter: &mut self.unknown_user_names,
                unsupported_sec_levels_counter: &mut self.unsupported_sec_levels,
                wrong_digests_counter: &mut self.wrong_digests,
                not_in_time_windows_counter: &mut self.not_in_time_windows,
                decryption_errors_counter: &mut self.decryption_errors,
                usm_user,
            }
        }
    }

    // ── Discovery probe (REQ-0093) ────────────────────────────────────────────

    #[test]
    fn given_discovery_probe_when_process_then_returns_report_and_increments_counter() {
        // Verifies: REQ-0093
        let mib = crate::mib::Store::new();
        let probe_frame = snmpv3_frames::encode_discovery_probe();
        let mut tc = TestCtx::new().with_boots_time(3, 100);
        let result = {
            let mut ctx = tc.ctx(None);
            process_snmpv3_request(&probe_frame, &mut ctx, &mib)
        };
        assert_eq!(
            tc.unknown_engine_ids, 1,
            "counter must be incremented for discovery probe"
        );
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
        let mut tc = TestCtx::new()
            .with_unknown_engine_ids(5)
            .with_boots_time(3, 100);
        {
            let mut ctx = tc.ctx(None);
            let _ = process_snmpv3_request(&probe_frame, &mut ctx, &mib);
        }
        {
            let mut ctx = tc.ctx(None);
            let _ = process_snmpv3_request(&probe_frame, &mut ctx, &mib);
        }
        assert_eq!(tc.unknown_engine_ids, 7);
    }

    #[test]
    fn given_normal_request_when_process_then_counter_unchanged() {
        // Verifies: REQ-0093 — only discovery probes increment the counter
        let mib = crate::mib::Store::new();
        let oid: crate::codec::Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        let frame = snmpv3_frames::encode_get_request(test_engine_id(), b"", 1, 2, oid.as_slice());
        let mut tc = TestCtx::new();
        let _ = {
            let mut ctx = tc.ctx(None);
            process_snmpv3_request(&frame, &mut ctx, &mib)
        };
        assert_eq!(tc.unknown_engine_ids, 0);
    }

    #[test]
    fn given_counter_at_max_when_discovery_probe_then_counter_does_not_overflow() {
        // Verifies: REQ-0093 — saturating_add prevents overflow
        let mib = crate::mib::Store::new();
        let probe_frame = snmpv3_frames::encode_discovery_probe();
        let mut tc = TestCtx::new().with_unknown_engine_ids(u32::MAX);
        {
            let mut ctx = tc.ctx(None);
            let _ = process_snmpv3_request(&probe_frame, &mut ctx, &mib);
        }
        assert_eq!(tc.unknown_engine_ids, u32::MAX);
    }

    #[test]
    fn given_discovery_probe_without_reportable_flag_when_process_then_discarded() {
        // Verifies: REQ-0093 — non-reportable probes are silently discarded
        let mib = crate::mib::Store::new();
        let probe_frame = snmpv3_frames::encode_discovery_probe_no_report();
        let mut tc = TestCtx::new().with_boots_time(3, 100);
        let result = {
            let mut ctx = tc.ctx(None);
            process_snmpv3_request(&probe_frame, &mut ctx, &mib)
        };
        assert!(
            result.is_none(),
            "probe without reportableFlag must be silently discarded"
        );
        assert_eq!(
            tc.unknown_engine_ids, 0,
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
        let mut tc = TestCtx::new();
        let result = {
            let mut ctx = tc.ctx(None);
            process_snmpv3_request(&frame, &mut ctx, &mib)
        };
        assert!(
            result.is_some(),
            "request must pass through when no USM user is configured"
        );
        assert_eq!(tc.unknown_user_names, 0, "counter must not be incremented");
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
        let mut tc = TestCtx::new();
        let result = {
            let mut ctx = tc.ctx(Some(&alice));
            process_snmpv3_request(&frame, &mut ctx, &mib)
        };
        assert!(
            result.is_some(),
            "matching user name must produce a response"
        );
        assert_eq!(
            tc.unknown_user_names, 0,
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
        let mut tc = TestCtx::new();
        let result = {
            let mut ctx = tc.ctx(Some(&alice));
            process_snmpv3_request(&frame, &mut ctx, &mib)
        };
        assert!(
            result.is_some(),
            "mismatched user name must produce a Report response"
        );
        assert_eq!(
            tc.unknown_user_names, 1,
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
        let mut tc = TestCtx::new();
        let result = {
            let mut ctx = tc.ctx(Some(&alice));
            process_snmpv3_request(&frame, &mut ctx, &mib)
        };
        assert!(
            result.is_none(),
            "user-name mismatch without reportableFlag must be silently discarded"
        );
        assert_eq!(
            tc.unknown_user_names, 1,
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
        let mut tc = TestCtx::new().with_unknown_user_names(u32::MAX);
        {
            let mut ctx = tc.ctx(Some(&alice));
            let _ = process_snmpv3_request(&frame, &mut ctx, &mib);
        }
        assert_eq!(tc.unknown_user_names, u32::MAX, "counter must not overflow");
    }

    // ── Security-level enforcement (REQ-0079, REQ-0103) ──────────────────────

    #[test]
    fn given_matching_security_level_when_process_then_proceeds() {
        // Verifies: REQ-0079, REQ-0103
        let mib = crate::mib::Store::new();
        let alice = crate::usm::user::UsmUser::no_auth_no_priv("alice");
        // flags 0x04 = reportableFlag only → noAuthNoPriv security level
        let frame = snmpv3_frames::encode_get_request_with_user(
            test_engine_id(),
            b"alice",
            b"",
            1,
            2,
            test_oid_arcs(),
        );
        let mut tc = TestCtx::new();
        let result = {
            let mut ctx = tc.ctx(Some(&alice));
            process_snmpv3_request(&frame, &mut ctx, &mib)
        };
        assert!(
            result.is_some(),
            "matching security level must produce a response"
        );
        assert_eq!(
            tc.unsupported_sec_levels, 0,
            "counter must not be incremented on match"
        );
        let response_bytes = result.unwrap();
        let v3_response = rasn::ber::decode::<rasn_snmp::v3::Message>(&response_bytes)
            .expect("response must be a valid SNMPv3 message");
        let rasn_snmp::v3::ScopedPduData::CleartextPdu(scoped_pdu) = v3_response.scoped_data else {
            panic!("response must contain a cleartext ScopedPDU");
        };
        assert!(
            matches!(scoped_pdu.data, rasn_snmp::v2::Pdus::Response(_)),
            "response must be a GetResponse, not a Report"
        );
    }

    #[test]
    fn given_mismatched_security_level_when_process_then_returns_report_and_increments_counter() {
        // Verifies: REQ-0079
        let mib = crate::mib::Store::new();
        let alice = crate::usm::user::UsmUser::no_auth_no_priv("alice");
        // flags 0x05 = authFlag + reportableFlag → authNoPriv; configured user is noAuthNoPriv
        let frame = snmpv3_frames::encode_get_request_with_user_and_flags(
            test_engine_id(),
            b"alice",
            b"",
            1,
            2,
            test_oid_arcs(),
            0x05, // authFlag set, reportableFlag set → authNoPriv, reportable
        );
        let mut tc = TestCtx::new();
        let result = {
            let mut ctx = tc.ctx(Some(&alice));
            process_snmpv3_request(&frame, &mut ctx, &mib)
        };
        assert!(
            result.is_some(),
            "security-level mismatch must produce a Report response"
        );
        assert_eq!(
            tc.unsupported_sec_levels, 1,
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
            1u32
        );
        assert_eq!(
            u32::try_from(usm_params.authoritative_engine_time).unwrap(),
            0u32
        );

        // Verify the Report PDU contains the correct varbind (usmStatsUnsupportedSecLevels).
        let rasn_snmp::v3::ScopedPduData::CleartextPdu(scoped_pdu) = v3_response.scoped_data else {
            panic!("Report response must contain a cleartext ScopedPDU");
        };
        let rasn_snmp::v2::Pdus::Report(report_pdu) = scoped_pdu.data else {
            panic!("response must be a Report PDU, not a GetResponse");
        };
        assert_eq!(
            report_pdu.0.variable_bindings.len(),
            1,
            "Report PDU must contain exactly one varbind"
        );
        let varbind = &report_pdu.0.variable_bindings[0];
        let expected_oid: crate::codec::Oid =
            crate::usm::counters::USM_STATS_UNSUPPORTED_SEC_LEVELS
                .parse()
                .unwrap();
        assert_eq!(
            varbind.name.as_ref(),
            expected_oid.as_slice(),
            "Report varbind OID must be usmStatsUnsupportedSecLevels"
        );
        // Counter32(1) encodes on the wire as ObjectSyntax::ApplicationWide(ApplicationSyntax::Counter).
        let rasn_snmp::v2::VarBindValue::Value(rasn_smi::v2::ObjectSyntax::ApplicationWide(
            rasn_smi::v2::ApplicationSyntax::Counter(ref counter),
        )) = varbind.value
        else {
            panic!("Report varbind value must be a Counter32");
        };
        assert_eq!(counter.0, 1u32, "Report varbind must carry counter value 1");
    }

    #[test]
    fn given_mismatched_security_level_without_reportable_flag_when_process_then_discarded_but_counter_incremented()
     {
        // Verifies: REQ-0079
        let mib = crate::mib::Store::new();
        let alice = crate::usm::user::UsmUser::no_auth_no_priv("alice");
        // flags 0x01 = authFlag only (no reportableFlag) → authNoPriv, not reportable
        let frame = snmpv3_frames::encode_get_request_with_user_and_flags(
            test_engine_id(),
            b"alice",
            b"",
            1,
            2,
            test_oid_arcs(),
            0x01,
        );
        let mut tc = TestCtx::new();
        let result = {
            let mut ctx = tc.ctx(Some(&alice));
            process_snmpv3_request(&frame, &mut ctx, &mib)
        };
        assert!(
            result.is_none(),
            "security-level mismatch without reportableFlag must be silently discarded"
        );
        assert_eq!(
            tc.unsupported_sec_levels, 1,
            "counter must still be incremented even when no Report is sent"
        );
    }

    #[test]
    fn given_no_usm_user_when_process_then_security_level_check_skipped() {
        // Verifies: REQ-0079 (None user → backward-compat skip)
        let mib = crate::mib::Store::new();
        // authNoPriv flags, but no configured user → no check
        let frame = snmpv3_frames::encode_get_request_with_user_and_flags(
            test_engine_id(),
            b"",
            b"",
            1,
            2,
            test_oid_arcs(),
            0x05,
        );
        let mut tc = TestCtx::new();
        let result = {
            let mut ctx = tc.ctx(None);
            process_snmpv3_request(&frame, &mut ctx, &mib)
        };
        assert!(
            result.is_some(),
            "request must pass through when no USM user is configured"
        );
        assert_eq!(
            tc.unsupported_sec_levels, 0,
            "counter must not be incremented"
        );
    }

    #[test]
    fn given_counter_at_max_when_mismatched_security_level_then_counter_does_not_overflow() {
        // Verifies: REQ-0079 — saturating_add prevents overflow
        let mib = crate::mib::Store::new();
        let alice = crate::usm::user::UsmUser::no_auth_no_priv("alice");
        let frame = snmpv3_frames::encode_get_request_with_user_and_flags(
            test_engine_id(),
            b"alice",
            b"",
            1,
            2,
            test_oid_arcs(),
            0x05,
        );
        let mut tc = TestCtx::new().with_unsupported_sec_levels(u32::MAX);
        {
            let mut ctx = tc.ctx(Some(&alice));
            let _ = process_snmpv3_request(&frame, &mut ctx, &mib);
        }
        assert_eq!(
            tc.unsupported_sec_levels,
            u32::MAX,
            "counter must not overflow"
        );
    }

    #[test]
    fn given_invalid_priv_without_auth_flags_when_process_then_returns_report_and_increments_counter()
     {
        // Verifies: REQ-0079 — privFlag=1, authFlag=0 (0x06) is invalid and treated as a mismatch
        let mib = crate::mib::Store::new();
        let alice = crate::usm::user::UsmUser::no_auth_no_priv("alice");
        // flags 0x06 = privFlag set, reportableFlag set, authFlag clear → invalid combination
        let frame = snmpv3_frames::encode_get_request_with_user_and_flags(
            test_engine_id(),
            b"alice",
            b"",
            1,
            2,
            test_oid_arcs(),
            0x06,
        );
        let mut tc = TestCtx::new();
        let result = {
            let mut ctx = tc.ctx(Some(&alice));
            process_snmpv3_request(&frame, &mut ctx, &mib)
        };
        assert!(
            result.is_some(),
            "invalid msgFlags combination must produce a Report response"
        );
        assert_eq!(
            tc.unsupported_sec_levels, 1,
            "counter must be incremented for invalid msgFlags"
        );
    }

    // ── HMAC verification (REQ-0100, REQ-0102) ───────────────────────────────

    /// Build a `GetRequest` frame authenticated with HMAC-SHA-256 using the given key bytes.
    /// Uses boots=1 and time=0 to match the default `TestCtx::new()` engine state, ensuring
    /// the time-window check passes for HMAC verification tests.
    /// The frame is addressed to `test_engine_id()` with user "alice", flags 0x05 (authNoPriv + reportable).
    fn build_authenticated_frame(auth_key_bytes: &[u8]) -> Vec<u8> {
        // boots=1 matches TestCtx::new() engine_boots=1 so the time-window check passes.
        build_authenticated_frame_with_time(auth_key_bytes, 1, 0)
    }

    #[test]
    fn given_correct_hmac_when_process_then_proceeds() {
        // Verifies: REQ-0100, REQ-0102
        use crate::usm::auth::AuthProtocol;
        use crate::usm::keys::SecretKey;

        let mib = crate::mib::Store::new();
        let auth_key_bytes = [0x42u8; 32];
        let alice = crate::usm::user::UsmUser::auth_no_priv(
            "alice",
            AuthProtocol::HmacSha256,
            SecretKey::new(auth_key_bytes.to_vec()),
        );
        let authenticated_frame = build_authenticated_frame(&auth_key_bytes);
        let mut tc = TestCtx::new();
        let result = {
            let mut ctx = tc.ctx(Some(&alice));
            process_snmpv3_request(&authenticated_frame, &mut ctx, &mib)
        };
        assert!(
            result.is_some(),
            "correct HMAC must produce a normal response"
        );
        assert_eq!(
            tc.wrong_digests, 0,
            "counter must not be incremented on correct HMAC"
        );
        // Verify it's a GetResponse (not a Report)
        let v3_response = rasn::ber::decode::<rasn_snmp::v3::Message>(&result.unwrap())
            .expect("response must be a valid SNMPv3 message");
        let rasn_snmp::v3::ScopedPduData::CleartextPdu(scoped_pdu) = v3_response.scoped_data else {
            panic!("response must contain a cleartext ScopedPDU");
        };
        assert!(
            matches!(scoped_pdu.data, rasn_snmp::v2::Pdus::Response(_)),
            "response must be a GetResponse, not a Report"
        );
    }

    #[test]
    fn given_wrong_hmac_when_process_then_returns_report_and_increments_counter() {
        // Verifies: REQ-0100, REQ-0102
        use crate::usm::auth::AuthProtocol;
        use crate::usm::keys::SecretKey;

        let mib = crate::mib::Store::new();
        let alice = crate::usm::user::UsmUser::auth_no_priv(
            "alice",
            AuthProtocol::HmacSha256,
            SecretKey::new(vec![0x42u8; 32]),
        );
        // Build frame with an incorrect MAC (all-0xBB bytes)
        let frame_with_wrong_mac = snmpv3_frames::encode_get_request_with_auth_params(
            test_engine_id(),
            b"alice",
            b"",
            1,
            2,
            test_oid_arcs(),
            0x05,
            &[0xBBu8; 24],
        );
        let mut tc = TestCtx::new();
        let result = {
            let mut ctx = tc.ctx(Some(&alice));
            process_snmpv3_request(&frame_with_wrong_mac, &mut ctx, &mib)
        };
        assert!(
            result.is_some(),
            "wrong HMAC must produce a Report response"
        );
        assert_eq!(
            tc.wrong_digests, 1,
            "counter must be incremented on wrong HMAC"
        );
        // Verify the Report carries usmStatsWrongDigests
        let v3_response = rasn::ber::decode::<rasn_snmp::v3::Message>(&result.unwrap())
            .expect("response must be a valid SNMPv3 message");
        let rasn_snmp::v3::ScopedPduData::CleartextPdu(scoped_pdu) = v3_response.scoped_data else {
            panic!("Report response must contain a cleartext ScopedPDU");
        };
        let rasn_snmp::v2::Pdus::Report(report_pdu) = scoped_pdu.data else {
            panic!("response must be a Report PDU, not a GetResponse");
        };
        assert_eq!(
            report_pdu.0.variable_bindings.len(),
            1,
            "Report must contain exactly one varbind"
        );
        let varbind = &report_pdu.0.variable_bindings[0];
        let expected_oid: crate::codec::Oid = crate::usm::counters::USM_STATS_WRONG_DIGESTS
            .parse()
            .unwrap();
        assert_eq!(
            varbind.name.as_ref(),
            expected_oid.as_slice(),
            "Report varbind OID must be usmStatsWrongDigests"
        );
        let rasn_snmp::v2::VarBindValue::Value(rasn_smi::v2::ObjectSyntax::ApplicationWide(
            rasn_smi::v2::ApplicationSyntax::Counter(ref counter),
        )) = varbind.value
        else {
            panic!("Report varbind value must be a Counter32");
        };
        assert_eq!(counter.0, 1u32, "Report varbind must carry counter value 1");
    }

    #[test]
    fn given_empty_auth_params_with_auth_user_when_process_then_returns_report() {
        // Verifies: REQ-0100 — empty auth_params for an authenticated user is rejected
        use crate::usm::auth::AuthProtocol;
        use crate::usm::keys::SecretKey;

        let mib = crate::mib::Store::new();
        let alice = crate::usm::user::UsmUser::auth_no_priv(
            "alice",
            AuthProtocol::HmacSha256,
            SecretKey::new(vec![0x42u8; 32]),
        );
        // Build frame with authFlag but empty auth_params (malformed)
        let frame = snmpv3_frames::encode_get_request_with_auth_params(
            test_engine_id(),
            b"alice",
            b"",
            1,
            2,
            test_oid_arcs(),
            0x05,
            &[],
        );
        let mut tc = TestCtx::new();
        let result = {
            let mut ctx = tc.ctx(Some(&alice));
            process_snmpv3_request(&frame, &mut ctx, &mib)
        };
        assert!(
            result.is_some(),
            "empty auth_params must produce a Report response"
        );
        assert_eq!(
            tc.wrong_digests, 1,
            "counter must be incremented for empty auth_params"
        );
    }

    #[test]
    fn given_wrong_hmac_without_reportable_flag_when_process_then_discarded_but_counter_incremented()
     {
        // Verifies: REQ-0100 — no Report when reportableFlag not set, counter still increments
        use crate::usm::auth::AuthProtocol;
        use crate::usm::keys::SecretKey;

        let mib = crate::mib::Store::new();
        let alice = crate::usm::user::UsmUser::auth_no_priv(
            "alice",
            AuthProtocol::HmacSha256,
            SecretKey::new(vec![0x42u8; 32]),
        );
        // flags 0x01 = authFlag only (no reportableFlag)
        let frame = snmpv3_frames::encode_get_request_with_auth_params(
            test_engine_id(),
            b"alice",
            b"",
            1,
            2,
            test_oid_arcs(),
            0x01,
            &[0xBBu8; 24],
        );
        let mut tc = TestCtx::new();
        let result = {
            let mut ctx = tc.ctx(Some(&alice));
            process_snmpv3_request(&frame, &mut ctx, &mib)
        };
        assert!(
            result.is_none(),
            "wrong HMAC without reportableFlag must be silently discarded"
        );
        assert_eq!(
            tc.wrong_digests, 1,
            "counter must still be incremented even when no Report is sent"
        );
    }

    #[test]
    fn given_counter_at_max_when_wrong_hmac_then_counter_does_not_overflow() {
        // Verifies: REQ-0100 — saturating_add prevents overflow
        use crate::usm::auth::AuthProtocol;
        use crate::usm::keys::SecretKey;

        let mib = crate::mib::Store::new();
        let alice = crate::usm::user::UsmUser::auth_no_priv(
            "alice",
            AuthProtocol::HmacSha256,
            SecretKey::new(vec![0x42u8; 32]),
        );
        let frame = snmpv3_frames::encode_get_request_with_auth_params(
            test_engine_id(),
            b"alice",
            b"",
            1,
            2,
            test_oid_arcs(),
            0x05,
            &[0xBBu8; 24],
        );
        let mut tc = TestCtx::new().with_wrong_digests(u32::MAX);
        {
            let mut ctx = tc.ctx(Some(&alice));
            let _ = process_snmpv3_request(&frame, &mut ctx, &mib);
        }
        assert_eq!(tc.wrong_digests, u32::MAX, "counter must not overflow");
    }

    // ── zero_auth_params_in_message ──────────────────────────────────────────────

    #[test]
    fn given_offset_and_len_when_zero_auth_params_then_bytes_at_offset_are_zeroed() {
        // Verifies: REQ-0100 — correct region is zeroed
        let message = b"hello MAC-goes-here world";
        let zeroed = zero_auth_params_in_message(message, 6, 12);
        assert_eq!(&zeroed[..6], b"hello ");
        assert_eq!(&zeroed[6..18], &[0u8; 12]);
        assert_eq!(&zeroed[18..], b"e world");
    }

    #[test]
    fn given_offset_at_start_when_zero_auth_params_then_prefix_zeroed() {
        // Verifies: REQ-0100 — boundary at start
        let message = b"MACxxxxrest";
        let zeroed = zero_auth_params_in_message(message, 0, 3);
        assert_eq!(&zeroed[..3], &[0u8; 3]);
        assert_eq!(&zeroed[3..], b"xxxxrest");
    }

    #[test]
    fn given_offset_at_end_when_zero_auth_params_then_suffix_zeroed() {
        // Verifies: REQ-0100 — boundary at end
        let message = b"prefixMAC";
        let zeroed = zero_auth_params_in_message(message, 6, 3);
        assert_eq!(&zeroed[..6], b"prefix");
        assert_eq!(&zeroed[6..], &[0u8; 3]);
    }

    #[test]
    fn given_input_when_zero_auth_params_then_original_message_is_not_modified() {
        // Verifies: REQ-0100 — original raw_message is not mutated
        let message = b"prefix MAC suffix";
        let zeroed = zero_auth_params_in_message(message, 7, 3);
        assert_eq!(message, b"prefix MAC suffix", "original must be unchanged");
        assert_eq!(&zeroed[7..10], &[0u8; 3]);
    }

    // ── Time-window validation (REQ-0098) ──────────────────────────────────────

    /// Build an authenticated `GetRequest` frame with explicit USM boots, time, and msgFlags.
    /// The frame is addressed to `test_engine_id()` with user "alice".
    fn build_authenticated_frame_with_time_and_flags(
        auth_key_bytes: &[u8],
        boots: u32,
        time: u32,
        msg_flags_byte: u8,
    ) -> Vec<u8> {
        use crate::usm::auth::AuthProtocol;
        use crate::usm::keys::SecretKey;

        let mac_len = AuthProtocol::HmacSha256.mac_len();
        let engine_id = test_engine_id();
        let oid = test_oid_arcs();

        let zeroed_auth_params = vec![0u8; mac_len];
        let frame_with_zeros = snmpv3_frames::encode_get_request_with_auth_params_and_time(
            engine_id,
            b"alice",
            b"",
            1,
            2,
            oid,
            msg_flags_byte,
            &zeroed_auth_params,
            boots,
            time,
        );

        let key = SecretKey::new(auth_key_bytes.to_vec());
        let mac = AuthProtocol::HmacSha256
            .compute_mac(&key, &frame_with_zeros)
            .unwrap();

        let pos = frame_with_zeros
            .windows(mac_len)
            .position(|w| w == zeroed_auth_params.as_slice())
            .unwrap();
        let mut frame = frame_with_zeros;
        frame[pos..pos + mac_len].copy_from_slice(&mac);
        frame
    }

    /// Build an authenticated `GetRequest` frame with explicit USM boots and time parameters.
    /// Uses flags 0x05 (authNoPriv + reportable).
    /// The frame is addressed to `test_engine_id()` with user "alice".
    fn build_authenticated_frame_with_time(
        auth_key_bytes: &[u8],
        boots: u32,
        time: u32,
    ) -> Vec<u8> {
        build_authenticated_frame_with_time_and_flags(auth_key_bytes, boots, time, 0x05)
    }

    #[test]
    fn given_in_time_window_when_process_then_proceeds() {
        // Verifies: REQ-0098
        use crate::usm::auth::AuthProtocol;
        use crate::usm::keys::SecretKey;

        let mib = crate::mib::Store::new();
        let auth_key_bytes = [0x42u8; 32];
        let alice = crate::usm::user::UsmUser::auth_no_priv(
            "alice",
            AuthProtocol::HmacSha256,
            SecretKey::new(auth_key_bytes.to_vec()),
        );
        // boots=1 matches engine_boots=1; time=0 matches engine_time=0 (within 150s window)
        let frame = build_authenticated_frame_with_time(&auth_key_bytes, 1, 0);
        let mut tc = TestCtx::new().with_boots_time(1, 0);
        let result = {
            let mut ctx = tc.ctx(Some(&alice));
            process_snmpv3_request(&frame, &mut ctx, &mib)
        };
        assert!(
            result.is_some(),
            "in-window message must produce a normal response"
        );
        assert_eq!(
            tc.not_in_time_windows, 0,
            "counter must not be incremented for in-window message"
        );
        let v3_response = rasn::ber::decode::<rasn_snmp::v3::Message>(&result.unwrap())
            .expect("response must be a valid SNMPv3 message");
        let rasn_snmp::v3::ScopedPduData::CleartextPdu(scoped_pdu) = v3_response.scoped_data else {
            panic!("response must contain a cleartext ScopedPDU");
        };
        assert!(
            matches!(scoped_pdu.data, rasn_snmp::v2::Pdus::Response(_)),
            "response must be a GetResponse, not a Report"
        );
    }

    #[test]
    fn given_out_of_time_window_when_process_then_returns_report_and_increments_counter() {
        // Verifies: REQ-0098
        use crate::usm::auth::AuthProtocol;
        use crate::usm::keys::SecretKey;

        let mib = crate::mib::Store::new();
        let auth_key_bytes = [0x42u8; 32];
        let alice = crate::usm::user::UsmUser::auth_no_priv(
            "alice",
            AuthProtocol::HmacSha256,
            SecretKey::new(auth_key_bytes.to_vec()),
        );
        // boots=2 does not match engine_boots=1 → out of window
        let frame = build_authenticated_frame_with_time(&auth_key_bytes, 2, 0);
        let mut tc = TestCtx::new().with_boots_time(1, 0);
        let result = {
            let mut ctx = tc.ctx(Some(&alice));
            process_snmpv3_request(&frame, &mut ctx, &mib)
        };
        assert!(
            result.is_some(),
            "out-of-window message must produce a Report response"
        );
        assert_eq!(
            tc.not_in_time_windows, 1,
            "counter must be incremented for out-of-window message"
        );
        let v3_response = rasn::ber::decode::<rasn_snmp::v3::Message>(&result.unwrap())
            .expect("response must be a valid SNMPv3 message");
        assert_eq!(
            i32::try_from(v3_response.global_data.message_id).unwrap(),
            1i32,
            "Report response must echo the request msg_id"
        );
        let usm_params: rasn_snmp::v3::USMSecurityParameters =
            rasn::ber::decode(v3_response.security_parameters.as_ref())
                .expect("security parameters must be valid USMSecurityParameters");
        let rasn_snmp::v3::ScopedPduData::CleartextPdu(scoped_pdu) = v3_response.scoped_data else {
            panic!("Report response must contain a cleartext ScopedPDU");
        };
        let rasn_snmp::v2::Pdus::Report(report_pdu) = scoped_pdu.data else {
            panic!("response must be a Report PDU, not a GetResponse");
        };
        assert_eq!(
            report_pdu.0.variable_bindings.len(),
            1,
            "Report must contain exactly one varbind"
        );
        let varbind = &report_pdu.0.variable_bindings[0];
        let expected_oid: crate::codec::Oid = crate::usm::counters::USM_STATS_NOT_IN_TIME_WINDOWS
            .parse()
            .unwrap();
        assert_eq!(
            varbind.name.as_ref(),
            expected_oid.as_slice(),
            "Report varbind OID must be usmStatsNotInTimeWindows"
        );
        let rasn_snmp::v2::VarBindValue::Value(rasn_smi::v2::ObjectSyntax::ApplicationWide(
            rasn_smi::v2::ApplicationSyntax::Counter(ref counter),
        )) = varbind.value
        else {
            panic!("Report varbind value must be a Counter32");
        };
        assert_eq!(counter.0, 1u32, "Report varbind must carry counter value 1");
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
    fn given_out_of_time_window_without_reportable_flag_when_process_then_discarded_but_counter_incremented()
     {
        // Verifies: REQ-0098
        use crate::usm::auth::AuthProtocol;
        use crate::usm::keys::SecretKey;

        let mib = crate::mib::Store::new();
        let auth_key_bytes = [0x42u8; 32];
        let alice = crate::usm::user::UsmUser::auth_no_priv(
            "alice",
            AuthProtocol::HmacSha256,
            SecretKey::new(auth_key_bytes.to_vec()),
        );

        // boots=2 does not match engine_boots=1 → out of window; flags=0x01 = authFlag only,
        // reportableFlag cleared, so agent must discard silently (no Report sent).
        let frame = build_authenticated_frame_with_time_and_flags(&auth_key_bytes, 2, 0, 0x01);

        let mut tc = TestCtx::new().with_boots_time(1, 0);
        let result = {
            let mut ctx = tc.ctx(Some(&alice));
            process_snmpv3_request(&frame, &mut ctx, &mib)
        };
        assert!(
            result.is_none(),
            "out-of-window without reportableFlag must be silently discarded"
        );
        assert_eq!(
            tc.not_in_time_windows, 1,
            "counter must still be incremented even when no Report is sent"
        );
    }

    #[test]
    fn given_counter_at_max_when_out_of_time_window_then_counter_does_not_overflow() {
        // Verifies: REQ-0098
        use crate::usm::auth::AuthProtocol;
        use crate::usm::keys::SecretKey;

        let mib = crate::mib::Store::new();
        let auth_key_bytes = [0x42u8; 32];
        let alice = crate::usm::user::UsmUser::auth_no_priv(
            "alice",
            AuthProtocol::HmacSha256,
            SecretKey::new(auth_key_bytes.to_vec()),
        );
        let frame = build_authenticated_frame_with_time(&auth_key_bytes, 2, 0);
        let mut tc = TestCtx::new()
            .with_not_in_time_windows(u32::MAX)
            .with_boots_time(1, 0);
        {
            let mut ctx = tc.ctx(Some(&alice));
            let _ = process_snmpv3_request(&frame, &mut ctx, &mib);
        }
        assert_eq!(
            tc.not_in_time_windows,
            u32::MAX,
            "counter must not overflow"
        );
    }

    #[test]
    fn given_no_auth_user_when_process_then_time_window_check_skipped() {
        // Verifies: REQ-0098
        let mib = crate::mib::Store::new();
        let alice = crate::usm::user::UsmUser::no_auth_no_priv("alice");
        // noAuthNoPriv user: time-window check must be skipped regardless of boots/time
        let frame = snmpv3_frames::encode_get_request_with_user(
            test_engine_id(),
            b"alice",
            b"",
            1,
            2,
            test_oid_arcs(),
        );
        // engine_boots=5 but message has boots=0 (from encode_get_request_with_user default)
        // If the check were applied, this would fail. It must be skipped.
        let mut tc = TestCtx::new().with_boots_time(5, 100);
        let result = {
            let mut ctx = tc.ctx(Some(&alice));
            process_snmpv3_request(&frame, &mut ctx, &mib)
        };
        assert!(
            result.is_some(),
            "noAuthNoPriv message must pass through regardless of boots/time"
        );
        assert_eq!(
            tc.not_in_time_windows, 0,
            "counter must not be incremented for noAuthNoPriv messages"
        );
    }

    #[test]
    fn given_time_difference_out_of_window_when_process_then_returns_report() {
        // Verifies: REQ-0098 — time-based (not boots-based) out-of-window rejection
        use crate::usm::auth::AuthProtocol;
        use crate::usm::keys::SecretKey;

        let mib = crate::mib::Store::new();
        let auth_key_bytes = [0x42u8; 32];
        let alice = crate::usm::user::UsmUser::auth_no_priv(
            "alice",
            AuthProtocol::HmacSha256,
            SecretKey::new(auth_key_bytes.to_vec()),
        );
        // boots=1 matches engine_boots=1, but msg_time=200, engine_time=0 → diff=200 > 150
        let frame = build_authenticated_frame_with_time(&auth_key_bytes, 1, 200);
        let mut tc = TestCtx::new().with_boots_time(1, 0);
        let result = {
            let mut ctx = tc.ctx(Some(&alice));
            process_snmpv3_request(&frame, &mut ctx, &mib)
        };
        assert!(
            result.is_some(),
            "time-difference out-of-window message must produce a Report response"
        );
        assert_eq!(
            tc.not_in_time_windows, 1,
            "counter must be incremented for time-difference out-of-window message"
        );
        let v3_response = rasn::ber::decode::<rasn_snmp::v3::Message>(&result.unwrap())
            .expect("response must be a valid SNMPv3 message");
        let rasn_snmp::v3::ScopedPduData::CleartextPdu(scoped_pdu) = v3_response.scoped_data else {
            panic!("Report response must contain a cleartext ScopedPDU");
        };
        let rasn_snmp::v2::Pdus::Report(_) = scoped_pdu.data else {
            panic!("response must be a Report PDU, not a GetResponse");
        };
    }
}
