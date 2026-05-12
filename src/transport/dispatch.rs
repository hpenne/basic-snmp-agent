//! Pure request dispatch: decode, validate, and encode a single `SNMPv3` frame.
//!
//! This module is intentionally free of I/O and side effects so that the
//! dispatch path can be exercised by fuzz targets and unit tests without
//! requiring a running event loop.

use crate::transport::event_loop::MAX_BULK_REPETITIONS;
use crate::transport::request;
// Implements: [[RFC-0009:C-FACADE]]
use log::{debug, trace};

// Implements: REQ-0093, REQ-0104
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

// Implements: REQ-0101
static DECRYPTION_ERRORS_OID: std::sync::LazyLock<crate::codec::Oid> =
    std::sync::LazyLock::new(|| {
        crate::usm::counters::USM_STATS_DECRYPTION_ERRORS
            .parse()
            .expect("USM_STATS_DECRYPTION_ERRORS is a valid OID constant")
    });

/// OID for `snmpUnknownSecurityModels.0` (RFC 3412, SNMP-MPD-MIB).
// Implements: REQ-0115
const SNMP_UNKNOWN_SECURITY_MODELS_OID: &str = "1.3.6.1.6.3.11.2.1.1.0";

// Implements: REQ-0115
static UNKNOWN_SECURITY_MODELS_OID: std::sync::LazyLock<crate::codec::Oid> =
    std::sync::LazyLock::new(|| {
        SNMP_UNKNOWN_SECURITY_MODELS_OID
            .parse()
            .expect("SNMP_UNKNOWN_SECURITY_MODELS_OID is a valid OID constant")
    });

/// Bit mask for the `reportableFlag` in `msgFlags` (RFC 3412 §7.1.3a).
const REPORTABLE_FLAG: u8 = 0x04;

/// Engine state and statistics passed to each inbound frame dispatch.
///
/// # Requirements
/// Implements: REQ-0078, REQ-0079, REQ-0093, REQ-0094, REQ-0098, REQ-0100, REQ-0101, REQ-0104, REQ-0115
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
    /// Counter for `snmpUnknownSecurityModels` (RFC 3412 §7.1).
    // Implements: REQ-0115
    pub unknown_security_models_counter: &'a mut u32,
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
/// Implements: REQ-0100, REQ-0111
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
    // A crafted packet could supply an out-of-range offset/length; if the
    // range is invalid the zeroing is skipped and the downstream HMAC check
    // will reject the message harmlessly.
    if let Some(end) = auth_params_offset.checked_add(auth_params_len)
        && let Some(target) = zeroed.get_mut(auth_params_offset..end)
    {
        target.fill(0);
    }
    zeroed
}

/// Increment `decryption_errors_counter` and, if `reportableFlag` is set, return a
/// `usmStatsDecryptionErrors` Report PDU; otherwise return `None` (silent discard).
///
/// # Requirements
/// Implements: REQ-0101
fn emit_decryption_error_response(
    ctx: &mut DispatchContext<'_>,
    msg_id: i32,
    security_flags: u8,
) -> Option<Vec<u8>> {
    *ctx.decryption_errors_counter = ctx.decryption_errors_counter.saturating_add(1);
    if security_flags & REPORTABLE_FLAG == 0 {
        trace!("decryption error with reportableFlag unset, discarding silently");
        return None;
    }
    crate::codec::encode_v3_report(
        msg_id,
        ctx.engine_id,
        ctx.engine_boots,
        ctx.engine_time,
        &DECRYPTION_ERRORS_OID,
        *ctx.decryption_errors_counter,
    )
    .inspect_err(|encode_error| debug!("failed to encode decryption-error report: {encode_error}"))
    .ok()
}

/// Increment `unknown_engine_ids_counter` unconditionally (RFC 3414 §4.2.4) and, if
/// `reportableFlag` is set, return a `usmStatsUnknownEngineIDs` Report PDU; otherwise
/// return `None` (silent discard).
///
/// # Requirements
/// Implements: REQ-0104
fn emit_unknown_engine_id_response(
    ctx: &mut DispatchContext<'_>,
    msg_id: i32,
    security_flags: u8,
) -> Option<Vec<u8>> {
    *ctx.unknown_engine_ids_counter = ctx.unknown_engine_ids_counter.saturating_add(1);
    if security_flags & REPORTABLE_FLAG == 0 {
        trace!("unknown engine ID with reportableFlag unset, discarding silently");
        return None;
    }
    crate::codec::encode_v3_report(
        msg_id,
        ctx.engine_id,
        ctx.engine_boots,
        ctx.engine_time,
        &UNKNOWN_ENGINE_IDS_OID,
        *ctx.unknown_engine_ids_counter,
    )
    .inspect_err(|encode_error| debug!("failed to encode unknown-engine-id report: {encode_error}"))
    .ok()
}

/// Increment `unknown_security_models_counter` and, if `reportableFlag` is set, return a
/// `snmpUnknownSecurityModels` Report PDU; otherwise return `None` (silent discard).
///
/// # Requirements
/// Implements: REQ-0115
fn emit_unknown_security_model_response(
    ctx: &mut DispatchContext<'_>,
    msg_id: i32,
    security_flags: u8,
) -> Option<Vec<u8>> {
    *ctx.unknown_security_models_counter = ctx.unknown_security_models_counter.saturating_add(1);
    if security_flags & REPORTABLE_FLAG == 0 {
        trace!("unknown security model with reportableFlag unset, discarding silently");
        return None;
    }
    crate::codec::encode_v3_report(
        msg_id,
        ctx.engine_id,
        ctx.engine_boots,
        ctx.engine_time,
        &UNKNOWN_SECURITY_MODELS_OID,
        *ctx.unknown_security_models_counter,
    )
    .inspect_err(|encode_error| {
        debug!("failed to encode unknown-security-model report: {encode_error}");
    })
    .ok()
}

/// Decode, validate, and dispatch a single RFC 3430 BER frame, returning
/// the encoded response bytes on success.
///
/// `frame` is the complete BER bytes (SEQUENCE tag + length + content).
/// Returns `Some(encoded_response)` when the frame produces a response, or
/// `None` when it should be silently discarded (invalid encoding, or
/// unsupported context name).
///
/// Engine-ID discovery probes (empty `msgAuthoritativeEngineID`) always produce
/// a Report PDU response and increment `ctx.unknown_engine_ids_counter` (REQ-0093),
/// provided the `reportableFlag` ([`REPORTABLE_FLAG`]) is set in `msgFlags`. Probes without
/// the flag set are silently discarded per RFC 3412 §7.1.3a.
///
/// # Requirements
/// Implements: REQ-0056, REQ-0058, REQ-0066, REQ-0068, REQ-0073, REQ-0078, REQ-0079, REQ-0080, REQ-0093, REQ-0098, REQ-0100, REQ-0101, REQ-0102, REQ-0103, REQ-0104, REQ-0107, REQ-0109, REQ-0115
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
/// let mut unknown_security_models = 0u32;
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
///     unknown_security_models_counter: &mut unknown_security_models,
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
    let v3_msg = crate::codec::decode_v3_message(frame)
        .inspect_err(|decode_error| debug!("failed to decode SNMPv3 message: {decode_error}"))
        .ok()?;

    // RFC 3412 §7.2 step 2: reject messages with unsupported security models.
    // Implements: REQ-0115
    if !v3_msg.security_model.is_usm() {
        return emit_unknown_security_model_response(ctx, v3_msg.msg_id, v3_msg.usm.security_flags);
    }

    // REQ-0093: engine-ID discovery probe — the manager sent an empty
    // msgAuthoritativeEngineID. Respond with a Report PDU carrying the
    // usmStatsUnknownEngineIDs counter and our authoritative engine state
    // so the manager can learn our engine ID, boots, and approximate time.
    if v3_msg.usm.auth_engine_id.is_empty() {
        *ctx.unknown_engine_ids_counter = ctx.unknown_engine_ids_counter.saturating_add(1);
        // RFC 3412 §7.1.3a: if the reportableFlag is not set, discard without response.
        if v3_msg.usm.security_flags & REPORTABLE_FLAG == 0 {
            trace!("engine-ID discovery probe with reportableFlag unset, discarding silently");
            return None;
        }
        return crate::codec::encode_v3_report(
            v3_msg.msg_id,
            ctx.engine_id,
            ctx.engine_boots,
            ctx.engine_time,
            &UNKNOWN_ENGINE_IDS_OID,
            *ctx.unknown_engine_ids_counter,
        )
        .inspect_err(|encode_error| {
            debug!("failed to encode engine-id discovery report: {encode_error}");
        })
        .ok();
    }

    // REQ-0104: contextEngineID mismatch — the ScopedPDU's contextEngineID does not
    // match the agent's snmpEngineID. Respond with a Report PDU carrying
    // usmStatsUnknownEngineIDs.
    if v3_msg.engine_id != ctx.engine_id {
        return emit_unknown_engine_id_response(ctx, v3_msg.msg_id, v3_msg.usm.security_flags);
    }

    // REQ-0078, REQ-0080: user-name lookup — discovery (above) runs before this check.
    // If a USM user is configured and the request names a different user, increment the
    // counter and respond with a Report PDU only if the reportableFlag is set
    // (RFC 3412 §7.1.3a).
    // Non-constant-time comparison is acceptable: user names are transmitted in cleartext
    // on the wire (RFC 3414 §2.4), so they are not secret.
    if let Some(user) = ctx.usm_user
        && v3_msg.user_name != user.name().as_bytes()
    {
        *ctx.unknown_user_names_counter = ctx.unknown_user_names_counter.saturating_add(1);
        if v3_msg.usm.security_flags & REPORTABLE_FLAG == 0 {
            trace!("unknown user name with reportableFlag unset, discarding silently");
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
        .inspect_err(|encode_error| {
            debug!("failed to encode unknown-user-name report: {encode_error}");
        })
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
                trace!("unsupported security level with reportableFlag unset, discarding silently");
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
            .inspect_err(|encode_error| {
                debug!("failed to encode unsupported-sec-level report: {encode_error}");
            })
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
        let hmac_ok = if let Some(offset) = v3_msg.auth_params_offset {
            let zeroed = zero_auth_params_in_message(v3_msg.raw_message, offset, auth_params.len());
            auth_protocol
                .verify_mac(auth_key, &zeroed, auth_params)
                .is_ok()
        } else {
            trace!("auth_params_offset absent, treating as HMAC failure");
            false
        };
        if !hmac_ok {
            *ctx.wrong_digests_counter = ctx.wrong_digests_counter.saturating_add(1);
            if v3_msg.usm.security_flags & REPORTABLE_FLAG == 0 {
                trace!("wrong digest with reportableFlag unset, discarding silently");
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
            .inspect_err(|encode_error| {
                debug!("failed to encode wrong-digest report: {encode_error}");
            })
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
            trace!("not-in-time-window with reportableFlag unset, discarding silently");
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
        .inspect_err(|encode_error| {
            debug!("failed to encode not-in-time-window report: {encode_error}");
        })
        .ok();
    }

    // Only the default (empty) context name is supported per REQ-0058.
    // For authPriv messages the context_name is inside the encrypted blob and is validated
    // after decryption below. For cleartext messages it is already decoded.
    if !v3_msg.context_name.is_empty() {
        debug!("unsupported context name (plaintext), discarding");
        return None;
    }

    // REQ-0101, REQ-0102: decrypt authPriv ScopedPDU ciphertext after HMAC and
    // time-window validation pass (processing order mandated by REQ-0102).
    // Returns (inbound_pdu, effective_context_name) so the correct context name
    // flows to the response encoder regardless of whether it came from the outer
    // message envelope (cleartext) or the decrypted ScopedPdu (authPriv).
    let (inbound_pdu, response_context_name) = match v3_msg.scoped_data {
        crate::codec::V3ScopedData::Plaintext(pdu) => (pdu, v3_msg.context_name),
        crate::codec::V3ScopedData::Encrypted(ciphertext) => {
            // Security-level enforcement (REQ-0079) already verified the configured user
            // is authPriv, so priv_protocol/priv_key must be Some here.
            let Some((priv_protocol, priv_key)) = ctx
                .usm_user
                .and_then(|user| user.priv_protocol().zip(user.priv_key()))
            else {
                // No configured user or no privacy credentials — can't decrypt, discard.
                debug!("encrypted message but no privacy credentials configured, discarding");
                return None;
            };

            // msgPrivacyParameters must be exactly 8 bytes (the AES salt per RFC 3826 §2.2).
            let priv_params = &v3_msg.usm.priv_params;
            if priv_params.len() != 8 {
                debug!("msgPrivacyParameters length {} != 8", priv_params.len());
                return emit_decryption_error_response(
                    ctx,
                    v3_msg.msg_id,
                    v3_msg.usm.security_flags,
                );
            }

            // Implements: REQ-0109
            // IV = engineBoots (4 BE) || engineTime (4 BE) || salt (8 bytes) per RFC 3826 §2.2.
            let mut aes_iv = [0u8; 16];
            aes_iv[0..4].copy_from_slice(&v3_msg.usm.auth_engine_boots.to_be_bytes());
            aes_iv[4..8].copy_from_slice(&v3_msg.usm.auth_engine_time.to_be_bytes());
            aes_iv[8..16].copy_from_slice(priv_params);

            let Ok(scoped_pdu_bytes) = priv_protocol.decrypt(priv_key, &aes_iv, &ciphertext) else {
                debug!("AES-CFB128 decryption failed");
                return emit_decryption_error_response(
                    ctx,
                    v3_msg.msg_id,
                    v3_msg.usm.security_flags,
                );
            };

            let Ok(decoded) = crate::codec::decode_scoped_pdu(&scoped_pdu_bytes) else {
                debug!("failed to decode decrypted ScopedPDU");
                return emit_decryption_error_response(
                    ctx,
                    v3_msg.msg_id,
                    v3_msg.usm.security_flags,
                );
            };

            // REQ-0104: contextEngineID validation — the decrypted ScopedPDU's contextEngineID
            // must match the agent's snmpEngineID per RFC 3412 §7.2 step 9d.
            if decoded.context_engine_id != ctx.engine_id {
                return emit_unknown_engine_id_response(
                    ctx,
                    v3_msg.msg_id,
                    v3_msg.usm.security_flags,
                );
            }

            // Context name validated after decryption; only the default (empty) context is supported.
            if !decoded.context_name.is_empty() {
                debug!("unsupported context name (decrypted), discarding");
                return None;
            }

            (decoded.pdu, decoded.context_name)
        }
    };
    let response = match inbound_pdu {
        crate::codec::InboundPdu::GetRequest(req) => request::handle_get(&req, mib),
        crate::codec::InboundPdu::GetNextRequest(req) => request::handle_get_next(&req, mib),
        crate::codec::InboundPdu::GetBulkRequest(req) => {
            request::handle_get_bulk(&req, mib, MAX_BULK_REPETITIONS)
        }
        crate::codec::InboundPdu::SetRequest(req) => request::handle_set(&req),
    };

    // Implements: REQ-0107 — response security level must match the request.
    let response_auth = ctx
        .usm_user
        .and_then(|user| user.auth_protocol().zip(user.auth_key()));
    // Implements: REQ-0101, REQ-0107
    let response_priv = ctx
        .usm_user
        .and_then(|user| user.priv_protocol().zip(user.priv_key()));
    crate::codec::encode_v3_response(
        v3_msg.msg_id,
        ctx.engine_id,
        &v3_msg.user_name,
        &response_context_name,
        ctx.engine_boots,
        ctx.engine_time,
        response_auth,
        response_priv,
        &response,
    )
    .inspect_err(|encode_error| debug!("failed to encode SNMPv3 response: {encode_error}"))
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
        unknown_security_models: u32,
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
                unknown_security_models: 0,
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

        fn with_decryption_errors(mut self, initial_count: u32) -> Self {
            self.decryption_errors = initial_count;
            self
        }

        fn with_unknown_security_models(mut self, initial_count: u32) -> Self {
            self.unknown_security_models = initial_count;
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
                unknown_security_models_counter: &mut self.unknown_security_models,
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
        // Verifies: REQ-0093, REQ-0104 — counter unchanged for correct engine ID
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
            tc.unknown_engine_ids, 1,
            "counter must be incremented even for non-reportable probe"
        );
    }

    // ── contextEngineID mismatch (REQ-0104) ──────────────────────────────────

    #[test]
    fn given_wrong_context_engine_id_when_process_then_returns_report_and_increments_counter() {
        // Verifies: REQ-0104
        let mib = crate::mib::Store::new();
        // A non-empty but wrong engine ID: not a discovery probe (auth_engine_id is non-empty),
        // but the ScopedPDU's contextEngineID does not match the agent's engine ID.
        let frame = snmpv3_frames::encode_get_request(
            b"\x80\x00\x1f\x88\x04wrong",
            b"",
            1,
            2,
            test_oid_arcs(),
        );
        let mut tc = TestCtx::new().with_boots_time(3, 100);
        let result = {
            let mut ctx = tc.ctx(None);
            process_snmpv3_request(&frame, &mut ctx, &mib)
        };
        assert!(
            result.is_some(),
            "contextEngineID mismatch must produce a Report response"
        );
        assert_eq!(
            tc.unknown_engine_ids, 1,
            "counter must be incremented on contextEngineID mismatch"
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
            3u32,
            "Report response must carry the agent's engine boots"
        );
        assert_eq!(
            u32::try_from(usm_params.authoritative_engine_time).unwrap(),
            100u32,
            "Report response must carry the agent's engine time"
        );

        // Verify Report PDU carries usmStatsUnknownEngineIDs.
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
        let expected_oid: crate::codec::Oid = crate::usm::counters::USM_STATS_UNKNOWN_ENGINE_IDS
            .parse()
            .unwrap();
        assert_eq!(
            varbind.name.as_ref(),
            expected_oid.as_slice(),
            "Report varbind OID must be usmStatsUnknownEngineIDs"
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
    fn given_wrong_context_engine_id_without_reportable_flag_when_process_then_discarded_but_counter_incremented()
     {
        // Verifies: REQ-0104
        let mib = crate::mib::Store::new();
        // reportableFlag cleared (0x00) — agent must not send a Report, but counter still increments.
        let frame = snmpv3_frames::encode_get_request_with_user_no_report(
            b"\x80\x00\x1f\x88\x04wrong",
            b"",
            b"",
            1,
            2,
            test_oid_arcs(),
        );
        let mut tc = TestCtx::new();
        let result = {
            let mut ctx = tc.ctx(None);
            process_snmpv3_request(&frame, &mut ctx, &mib)
        };
        assert!(
            result.is_none(),
            "contextEngineID mismatch without reportableFlag must be silently discarded"
        );
        assert_eq!(
            tc.unknown_engine_ids, 1,
            "counter must still be incremented even when no Report is sent"
        );
    }

    #[test]
    fn given_counter_at_max_when_wrong_context_engine_id_then_counter_does_not_overflow() {
        // Verifies: REQ-0104 — saturating_add prevents overflow
        let mib = crate::mib::Store::new();
        let frame = snmpv3_frames::encode_get_request(
            b"\x80\x00\x1f\x88\x04wrong",
            b"",
            1,
            2,
            test_oid_arcs(),
        );
        let mut tc = TestCtx::new().with_unknown_engine_ids(u32::MAX);
        {
            let mut ctx = tc.ctx(None);
            let _ = process_snmpv3_request(&frame, &mut ctx, &mib);
        }
        assert_eq!(tc.unknown_engine_ids, u32::MAX, "counter must not overflow");
    }

    #[test]
    fn given_matching_usm_engine_id_but_wrong_context_engine_id_when_process_then_returns_report() {
        // Verifies: REQ-0104 — checks contextEngineID specifically, not msgAuthoritativeEngineID
        let mib = crate::mib::Store::new();
        let frame = snmpv3_frames::encode_get_request_with_context_engine_id(
            test_engine_id(),             // msgAuthoritativeEngineID matches agent
            b"\x80\x00\x1f\x88\x04wrong", // contextEngineID does NOT match
            b"",
            1,
            2,
            test_oid_arcs(),
        );
        let mut tc = TestCtx::new();
        let result = {
            let mut ctx = tc.ctx(None);
            process_snmpv3_request(&frame, &mut ctx, &mib)
        };
        assert!(
            result.is_some(),
            "contextEngineID mismatch must produce a Report response even when msgAuthoritativeEngineID matches"
        );
        assert_eq!(
            tc.unknown_engine_ids, 1,
            "counter must be incremented on contextEngineID mismatch"
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
        let alice = crate::usm::user::UsmUser::no_auth_no_priv(
            crate::usm::user::UserName::new("alice").unwrap(),
        );
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
        let alice = crate::usm::user::UsmUser::no_auth_no_priv(
            crate::usm::user::UserName::new("alice").unwrap(),
        );
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
        let alice = crate::usm::user::UsmUser::no_auth_no_priv(
            crate::usm::user::UserName::new("alice").unwrap(),
        );
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
        let alice = crate::usm::user::UsmUser::no_auth_no_priv(
            crate::usm::user::UserName::new("alice").unwrap(),
        );
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
        let alice = crate::usm::user::UsmUser::no_auth_no_priv(
            crate::usm::user::UserName::new("alice").unwrap(),
        );
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
        let alice = crate::usm::user::UsmUser::no_auth_no_priv(
            crate::usm::user::UserName::new("alice").unwrap(),
        );
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
        let alice = crate::usm::user::UsmUser::no_auth_no_priv(
            crate::usm::user::UserName::new("alice").unwrap(),
        );
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
        let alice = crate::usm::user::UsmUser::no_auth_no_priv(
            crate::usm::user::UserName::new("alice").unwrap(),
        );
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
        let alice = crate::usm::user::UsmUser::no_auth_no_priv(
            crate::usm::user::UserName::new("alice").unwrap(),
        );
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
        // Verifies: REQ-0100, REQ-0102, REQ-0107
        use crate::usm::auth::AuthProtocol;
        use crate::usm::keys::SecretKey;

        let mib = crate::mib::Store::new();
        let auth_key_bytes = [0x42u8; 32];
        let alice = crate::usm::user::UsmUser::auth_no_priv(
            crate::usm::user::UserName::new("alice").unwrap(),
            AuthProtocol::HmacSha256,
            SecretKey::new_from_exposed_slice(&auth_key_bytes),
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
            crate::usm::user::UserName::new("alice").unwrap(),
            AuthProtocol::HmacSha256,
            SecretKey::new_from_exposed_slice(&[0x42u8; 32]),
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
            crate::usm::user::UserName::new("alice").unwrap(),
            AuthProtocol::HmacSha256,
            SecretKey::new_from_exposed_slice(&[0x42u8; 32]),
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
            crate::usm::user::UserName::new("alice").unwrap(),
            AuthProtocol::HmacSha256,
            SecretKey::new_from_exposed_slice(&[0x42u8; 32]),
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
            crate::usm::user::UserName::new("alice").unwrap(),
            AuthProtocol::HmacSha256,
            SecretKey::new_from_exposed_slice(&[0x42u8; 32]),
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
        // Verifies: REQ-0100, REQ-0111 — correct region is zeroed
        let message = b"hello MAC-goes-here world";
        let zeroed = zero_auth_params_in_message(message, 6, 12);
        assert_eq!(&zeroed[..6], b"hello ");
        assert_eq!(&zeroed[6..18], &[0u8; 12]);
        assert_eq!(&zeroed[18..], b"e world");
    }

    #[test]
    fn given_offset_at_start_when_zero_auth_params_then_prefix_zeroed() {
        // Verifies: REQ-0100, REQ-0111 — boundary at start
        let message = b"MACxxxxrest";
        let zeroed = zero_auth_params_in_message(message, 0, 3);
        assert_eq!(&zeroed[..3], &[0u8; 3]);
        assert_eq!(&zeroed[3..], b"xxxxrest");
    }

    #[test]
    fn given_offset_at_end_when_zero_auth_params_then_suffix_zeroed() {
        // Verifies: REQ-0100, REQ-0111 — boundary at end
        let message = b"prefixMAC";
        let zeroed = zero_auth_params_in_message(message, 6, 3);
        assert_eq!(&zeroed[..6], b"prefix");
        assert_eq!(&zeroed[6..], &[0u8; 3]);
    }

    #[test]
    fn given_input_when_zero_auth_params_then_original_message_is_not_modified() {
        // Verifies: REQ-0100, REQ-0111 — original raw_message is not mutated
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

        let key = SecretKey::new_from_exposed_slice(auth_key_bytes);
        let mac = AuthProtocol::HmacSha256
            .compute_mac(&key, &frame_with_zeros)
            .unwrap();

        let auth_params_offset = crate::codec::ber::snmp::decode_v3_envelope(&frame_with_zeros)
            .expect("frame must be a valid SNMPv3 envelope")
            .auth_params_offset
            .expect("authenticated frame must carry a non-empty auth_params field");
        let mut frame = frame_with_zeros;
        frame[auth_params_offset..auth_params_offset + mac_len].copy_from_slice(&mac);
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
            crate::usm::user::UserName::new("alice").unwrap(),
            AuthProtocol::HmacSha256,
            SecretKey::new_from_exposed_slice(&auth_key_bytes),
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
            crate::usm::user::UserName::new("alice").unwrap(),
            AuthProtocol::HmacSha256,
            SecretKey::new_from_exposed_slice(&auth_key_bytes),
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
            crate::usm::user::UserName::new("alice").unwrap(),
            AuthProtocol::HmacSha256,
            SecretKey::new_from_exposed_slice(&auth_key_bytes),
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
            crate::usm::user::UserName::new("alice").unwrap(),
            AuthProtocol::HmacSha256,
            SecretKey::new_from_exposed_slice(&auth_key_bytes),
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
        let alice = crate::usm::user::UsmUser::no_auth_no_priv(
            crate::usm::user::UserName::new("alice").unwrap(),
        );
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
            crate::usm::user::UserName::new("alice").unwrap(),
            AuthProtocol::HmacSha256,
            SecretKey::new_from_exposed_slice(&auth_key_bytes),
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

    // ── Encrypted PDU path (REQ-0101) ─────────────────────────────────────────

    #[test]
    fn given_encrypted_v3_message_when_process_then_silently_dropped() {
        // Verifies: REQ-0101
        // An authPriv message with usm_user: None reaches the Encrypted arm with no
        // configured user — without privacy credentials, decryption cannot proceed
        // and the message is silently discarded (REQ-0101).
        use rasn_snmp::v3::{
            HeaderData, Message as V3Message, ScopedPduData, USMSecurityParameters,
        };

        let mib = crate::mib::Store::new();
        let fake_ciphertext = b"fake-ciphertext-bytes".to_vec();

        // Build an authPriv V3 message addressed to test_engine_id(). With usm_user: None,
        // the HMAC-verification block is skipped entirely (gated on usm_user.is_some()),
        // so the message reaches the Encrypted arm which returns None.
        let usm_params = USMSecurityParameters {
            authoritative_engine_id: test_engine_id().to_vec().into(),
            authoritative_engine_boots: 1.into(),
            authoritative_engine_time: 0.into(),
            user_name: rasn::types::OctetString::from(vec![]),
            authentication_parameters: rasn::types::OctetString::from(vec![]),
            privacy_parameters: rasn::types::OctetString::from(vec![0xAAu8; 8]),
        };
        let security_params = rasn::ber::encode(&usm_params).unwrap();
        let v3_msg = V3Message {
            version: 3.into(),
            global_data: HeaderData {
                message_id: 5.into(),
                max_size: 65535.into(),
                // authPriv + reportable: 0x03 | 0x04 = 0x07
                flags: rasn::types::OctetString::from(vec![0x07u8]),
                security_model: 3.into(),
            },
            security_parameters: security_params.into(),
            scoped_data: ScopedPduData::EncryptedPdu(rasn::types::OctetString::from(
                fake_ciphertext,
            )),
        };
        let encoded_frame = rasn::ber::encode(&v3_msg).unwrap();

        let mut tc = TestCtx::new();
        let result = {
            let mut ctx = tc.ctx(None);
            process_snmpv3_request(&encoded_frame, &mut ctx, &mib)
        };

        // No configured user means the user-name and security-level checks are skipped.
        // The empty auth_params with no user also means HMAC verification is skipped.
        // The Encrypted arm is reached but decryption cannot proceed without credentials.
        assert!(
            result.is_none(),
            "encrypted PDU with no configured user must be silently discarded"
        );
    }

    // ── authPriv decryption (REQ-0101) ───────────────────────────────────────────

    /// Build a complete authPriv `GetRequest` frame (authenticated + encrypted).
    ///
    /// Uses `engine_id` = `test_engine_id()`, `user_name` = "alice",
    /// `msgFlags` = 0x07 (authPriv + reportable), auth protocol = `HmacSha256` (24-byte MAC).
    /// IV = `boots_be(4)` || `time_be(4)` || `salt(8)` per RFC 3826 §2.2.
    fn build_authpriv_frame(
        auth_key_bytes: &[u8],
        priv_key_bytes: &[u8],
        priv_protocol: crate::usm::privacy::PrivProtocol,
        boots: u32,
        time: u32,
        oid_arcs: &[u32],
        salt: [u8; 8],
    ) -> Vec<u8> {
        use crate::usm::auth::AuthProtocol;
        use crate::usm::keys::SecretKey;
        use rasn_snmp::v2::{GetRequest as RasnGetRequest, Pdu, VarBind, VarBindValue};
        use rasn_snmp::v3::{
            HeaderData, Message as V3Message, ScopedPdu, ScopedPduData, USMSecurityParameters,
        };
        use std::borrow::Cow;

        let engine_id = test_engine_id();
        let mac_len = AuthProtocol::HmacSha256.mac_len();

        // Build and BER-encode the ScopedPdu.
        let rasn_oid = rasn::types::ObjectIdentifier::new_unchecked(Cow::Owned(oid_arcs.to_vec()));
        let get_request = RasnGetRequest(Pdu {
            request_id: 1,
            error_status: 0,
            error_index: 0,
            variable_bindings: vec![VarBind {
                name: rasn_oid,
                value: VarBindValue::Unspecified,
            }],
        });
        let scoped_pdu = ScopedPdu {
            engine_id: engine_id.to_vec().into(),
            name: vec![].into(),
            data: rasn_snmp::v2::Pdus::GetRequest(get_request),
        };
        let scoped_pdu_ber = rasn::ber::encode(&scoped_pdu).unwrap();

        // Construct IV and encrypt the ScopedPdu.
        let mut aes_iv = [0u8; 16];
        aes_iv[0..4].copy_from_slice(&boots.to_be_bytes());
        aes_iv[4..8].copy_from_slice(&time.to_be_bytes());
        aes_iv[8..16].copy_from_slice(&salt);
        let priv_key = SecretKey::new_from_exposed_slice(priv_key_bytes);
        let ciphertext = priv_protocol
            .encrypt(&priv_key, &aes_iv, &scoped_pdu_ber)
            .unwrap();

        // Build the V3Message with zeroed auth_params.
        let zeroed_auth_params = vec![0u8; mac_len];
        let usm_params = USMSecurityParameters {
            authoritative_engine_id: engine_id.to_vec().into(),
            authoritative_engine_boots: boots.into(),
            authoritative_engine_time: time.into(),
            user_name: b"alice".to_vec().into(),
            authentication_parameters: zeroed_auth_params.clone().into(),
            privacy_parameters: salt.to_vec().into(),
        };
        let security_params = rasn::ber::encode(&usm_params).unwrap();
        let v3_msg = V3Message {
            version: 3.into(),
            global_data: HeaderData {
                message_id: 1.into(),
                max_size: 65535.into(),
                flags: rasn::types::OctetString::from(vec![0x07u8]), // authPriv + reportable
                security_model: 3.into(),
            },
            security_parameters: security_params.into(),
            scoped_data: ScopedPduData::EncryptedPdu(rasn::types::OctetString::from(ciphertext)),
        };
        let frame_with_zeros = rasn::ber::encode(&v3_msg).unwrap();

        // Compute HMAC over frame with zeroed auth_params and splice it in.
        let auth_key = SecretKey::new_from_exposed_slice(auth_key_bytes);
        let mac = AuthProtocol::HmacSha256
            .compute_mac(&auth_key, &frame_with_zeros)
            .unwrap();
        let auth_params_offset = crate::codec::ber::snmp::decode_v3_envelope(&frame_with_zeros)
            .expect("frame must be a valid SNMPv3 envelope")
            .auth_params_offset
            .expect("authenticated frame must carry a non-empty auth_params field");
        let mut frame = frame_with_zeros;
        frame[auth_params_offset..auth_params_offset + mac_len].copy_from_slice(&mac);
        frame
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn given_correct_priv_key_when_process_authpriv_then_decrypts_and_responds() {
        // Verifies: REQ-0101, REQ-0107, REQ-0109
        use crate::usm::auth::AuthProtocol;
        use crate::usm::keys::SecretKey;
        use crate::usm::privacy::PrivProtocol;

        let mib = crate::mib::Store::new();
        let auth_key_bytes = [0x42u8; 32];
        let priv_key_bytes = [0xAAu8; 16];
        let alice = crate::usm::user::UsmUser::auth_priv(
            crate::usm::user::UserName::new("alice").unwrap(),
            AuthProtocol::HmacSha256,
            SecretKey::new_from_exposed_slice(&auth_key_bytes),
            PrivProtocol::Aes128,
            SecretKey::new_from_exposed_slice(&priv_key_bytes),
        );
        let frame = build_authpriv_frame(
            &auth_key_bytes,
            &priv_key_bytes,
            PrivProtocol::Aes128,
            1,
            0,
            test_oid_arcs(),
            [0x01u8; 8],
        );
        let mut tc = TestCtx::new().with_boots_time(1, 0);
        let result = {
            let mut ctx = tc.ctx(Some(&alice));
            process_snmpv3_request(&frame, &mut ctx, &mib)
        };
        assert!(
            result.is_some(),
            "correct authPriv message must produce a response"
        );
        assert_eq!(
            tc.decryption_errors, 0,
            "counter must not be incremented on success"
        );
        let response_bytes = result.unwrap();
        let v3_response = rasn::ber::decode::<rasn_snmp::v3::Message>(&response_bytes)
            .expect("response must be a valid SNMPv3 message");

        // authPriv response must have flags 0x03 (auth + priv).
        let flags_byte = v3_response.global_data.flags.first().copied().unwrap_or(0);
        assert_eq!(flags_byte, 0x03, "authPriv response flags must be 0x03");

        // Response ScopedPdu must be encrypted.
        let rasn_snmp::v3::ScopedPduData::EncryptedPdu(ciphertext) = v3_response.scoped_data else {
            panic!("authPriv response must contain an encrypted ScopedPDU");
        };

        // Privacy parameters must be an 8-byte salt.
        let usm_params: rasn_snmp::v3::USMSecurityParameters =
            rasn::ber::decode(v3_response.security_parameters.as_ref())
                .expect("response must have valid USM security parameters");
        assert_eq!(
            usm_params.privacy_parameters.len(),
            8,
            "response privacy_parameters must be 8 bytes"
        );

        // Decrypt the response ScopedPdu using the same priv key and verify the inner PDU.
        let mut aes_iv = [0u8; 16];
        aes_iv[0..4].copy_from_slice(&1u32.to_be_bytes()); // engine_boots = 1
        aes_iv[4..8].copy_from_slice(&0u32.to_be_bytes()); // engine_time = 0
        aes_iv[8..16].copy_from_slice(usm_params.privacy_parameters.as_ref());
        let priv_key = SecretKey::new_from_exposed_slice(&priv_key_bytes);
        let plaintext = PrivProtocol::Aes128
            .decrypt(&priv_key, &aes_iv, ciphertext.as_ref())
            .expect("response decryption must succeed");
        let scoped_pdu: rasn_snmp::v3::ScopedPdu =
            rasn::ber::decode(&plaintext).expect("decrypted bytes must be a valid ScopedPdu");
        let rasn_snmp::v2::Pdus::Response(response_pdu) = scoped_pdu.data else {
            panic!("decrypted ScopedPdu must contain a GetResponse");
        };
        assert_eq!(
            response_pdu.0.request_id, 1,
            "response request_id must match the request (1)"
        );
        assert_eq!(
            response_pdu.0.error_status, 0,
            "error_status must be NoError (0)"
        );
        // The MIB is empty, so the OID from the request produces a NoSuchObject varbind.
        assert_eq!(
            response_pdu.0.variable_bindings.len(),
            1,
            "response must contain one varbind"
        );
        assert_eq!(
            response_pdu.0.variable_bindings[0].name.as_ref(),
            test_oid_arcs(),
            "response varbind OID must match the request OID"
        );
        // The MIB is empty, so the OID resolves to NoSuchObject.
        assert!(
            matches!(
                response_pdu.0.variable_bindings[0].value,
                rasn_snmp::v2::VarBindValue::NoSuchObject
            ),
            "varbind value must be NoSuchObject when OID is not in MIB"
        );

        // Verify the HMAC over the encrypted response is valid.
        let auth_key_for_verify = SecretKey::new_from_exposed_slice(&auth_key_bytes);
        let embedded_mac = usm_params.authentication_parameters.to_vec();
        let auth_params_offset = crate::codec::ber::snmp::decode_v3_envelope(&response_bytes)
            .expect("response must be a valid SNMPv3 envelope")
            .auth_params_offset
            .expect("authenticated response must carry a non-empty auth_params field");
        let mut zeroed_response = response_bytes.clone();
        zeroed_response[auth_params_offset..auth_params_offset + embedded_mac.len()].fill(0);
        AuthProtocol::HmacSha256
            .verify_mac(&auth_key_for_verify, &zeroed_response, &embedded_mac)
            .expect("response HMAC must verify");
    }

    #[test]
    fn given_wrong_priv_key_when_process_authpriv_then_returns_report_and_increments_counter() {
        // Verifies: REQ-0101
        // AES-CFB decryption with a wrong key produces garbage bytes. When we try to
        // BER-decode those bytes as a ScopedPDU, it fails — the counter is incremented
        // and a Report is returned.
        use crate::usm::auth::AuthProtocol;
        use crate::usm::keys::SecretKey;
        use crate::usm::privacy::PrivProtocol;

        let mib = crate::mib::Store::new();
        let auth_key_bytes = [0x42u8; 32];
        let priv_key_bytes = [0xAAu8; 16];
        let wrong_priv_key_bytes = [0xBBu8; 16];
        let alice = crate::usm::user::UsmUser::auth_priv(
            crate::usm::user::UserName::new("alice").unwrap(),
            AuthProtocol::HmacSha256,
            SecretKey::new_from_exposed_slice(&auth_key_bytes),
            PrivProtocol::Aes128,
            SecretKey::new_from_exposed_slice(&wrong_priv_key_bytes),
        );
        let frame = build_authpriv_frame(
            &auth_key_bytes,
            &priv_key_bytes,
            PrivProtocol::Aes128,
            1,
            0,
            test_oid_arcs(),
            [0x01u8; 8],
        );
        let mut tc = TestCtx::new().with_boots_time(1, 0);
        let result = {
            let mut ctx = tc.ctx(Some(&alice));
            process_snmpv3_request(&frame, &mut ctx, &mib)
        };
        assert!(
            result.is_some(),
            "decryption failure must produce a Report response"
        );
        assert_eq!(
            tc.decryption_errors, 1,
            "counter must be incremented on decryption failure"
        );
        let v3_response = rasn::ber::decode::<rasn_snmp::v3::Message>(&result.unwrap())
            .expect("response must be a valid SNMPv3 message");
        let rasn_snmp::v3::ScopedPduData::CleartextPdu(scoped_pdu) = v3_response.scoped_data else {
            panic!("Report response must contain a cleartext ScopedPDU");
        };
        let rasn_snmp::v2::Pdus::Report(report_pdu) = scoped_pdu.data else {
            panic!("response must be a Report PDU");
        };
        let varbind = &report_pdu.0.variable_bindings[0];
        let expected_oid: crate::codec::Oid = crate::usm::counters::USM_STATS_DECRYPTION_ERRORS
            .parse()
            .unwrap();
        assert_eq!(
            varbind.name.as_ref(),
            expected_oid.as_slice(),
            "Report varbind OID must be usmStatsDecryptionErrors"
        );
    }

    #[test]
    fn given_invalid_priv_params_length_when_process_authpriv_then_returns_report_and_increments_counter()
     {
        // Verifies: REQ-0101 — msgPrivacyParameters of length != 8 must be rejected
        use crate::usm::auth::AuthProtocol;
        use crate::usm::keys::SecretKey;
        use crate::usm::privacy::PrivProtocol;
        use rasn_snmp::v3::{
            HeaderData, Message as V3Message, ScopedPduData, USMSecurityParameters,
        };

        let mib = crate::mib::Store::new();
        let auth_key_bytes = [0x42u8; 32];
        let priv_key_bytes = [0xAAu8; 16];
        let mac_len = AuthProtocol::HmacSha256.mac_len();
        let engine_id = test_engine_id();
        let boots = 1u32;
        let time = 0u32;

        let alice = crate::usm::user::UsmUser::auth_priv(
            crate::usm::user::UserName::new("alice").unwrap(),
            AuthProtocol::HmacSha256,
            SecretKey::new_from_exposed_slice(&auth_key_bytes),
            PrivProtocol::Aes128,
            SecretKey::new_from_exposed_slice(&priv_key_bytes),
        );

        // Build a frame with privacy_parameters of length 4 (not 8) and fake ciphertext.
        let zeroed_auth_params = vec![0u8; mac_len];
        let usm_params = USMSecurityParameters {
            authoritative_engine_id: engine_id.to_vec().into(),
            authoritative_engine_boots: boots.into(),
            authoritative_engine_time: time.into(),
            user_name: b"alice".to_vec().into(),
            authentication_parameters: zeroed_auth_params.clone().into(),
            // 4-byte salt (invalid — RFC 3826 §2.2 requires exactly 8 bytes)
            privacy_parameters: vec![0x01u8; 4].into(),
        };
        let security_params = rasn::ber::encode(&usm_params).unwrap();
        let v3_msg = V3Message {
            version: 3.into(),
            global_data: HeaderData {
                message_id: 1.into(),
                max_size: 65535.into(),
                flags: rasn::types::OctetString::from(vec![0x07u8]), // authPriv + reportable
                security_model: 3.into(),
            },
            security_parameters: security_params.into(),
            scoped_data: ScopedPduData::EncryptedPdu(rasn::types::OctetString::from(
                b"fake-ciphertext".to_vec(),
            )),
        };
        let frame_with_zeros = rasn::ber::encode(&v3_msg).unwrap();

        // Compute a valid HMAC so dispatch proceeds past authentication to the decryption arm.
        let auth_key = SecretKey::new_from_exposed_slice(&auth_key_bytes);
        let mac = AuthProtocol::HmacSha256
            .compute_mac(&auth_key, &frame_with_zeros)
            .unwrap();
        let auth_params_offset = crate::codec::ber::snmp::decode_v3_envelope(&frame_with_zeros)
            .expect("frame must be a valid SNMPv3 envelope")
            .auth_params_offset
            .expect("authenticated frame must carry a non-empty auth_params field");
        let mut frame = frame_with_zeros;
        frame[auth_params_offset..auth_params_offset + mac_len].copy_from_slice(&mac);

        let mut tc = TestCtx::new().with_boots_time(1, 0);
        let result = {
            let mut ctx = tc.ctx(Some(&alice));
            process_snmpv3_request(&frame, &mut ctx, &mib)
        };
        assert!(
            result.is_some(),
            "invalid priv_params length must produce a Report response"
        );
        assert_eq!(
            tc.decryption_errors, 1,
            "decryption_errors counter must be incremented for invalid priv_params length"
        );
        let v3_response = rasn::ber::decode::<rasn_snmp::v3::Message>(&result.unwrap())
            .expect("response must be a valid SNMPv3 message");
        let rasn_snmp::v3::ScopedPduData::CleartextPdu(scoped_pdu) = v3_response.scoped_data else {
            panic!("Report response must contain a cleartext ScopedPDU");
        };
        let rasn_snmp::v2::Pdus::Report(report_pdu) = scoped_pdu.data else {
            panic!("response must be a Report PDU");
        };
        let varbind = &report_pdu.0.variable_bindings[0];
        let expected_oid: crate::codec::Oid = crate::usm::counters::USM_STATS_DECRYPTION_ERRORS
            .parse()
            .unwrap();
        assert_eq!(
            varbind.name.as_ref(),
            expected_oid.as_slice(),
            "Report varbind OID must be usmStatsDecryptionErrors"
        );
    }

    #[test]
    fn given_decryption_failure_without_reportable_flag_when_process_then_discarded_but_counter_incremented()
     {
        // Verifies: REQ-0101
        // Builds an authPriv frame manually with flags = 0x03 (authPriv, no reportableFlag)
        // and uses a wrong priv key so decryption produces garbage → ScopedPDU decode fails.
        // Counter is incremented but no Report is sent.
        use crate::usm::auth::AuthProtocol;
        use crate::usm::keys::SecretKey;
        use crate::usm::privacy::PrivProtocol;
        use rasn_snmp::v3::{
            HeaderData, Message as V3Message, ScopedPduData, USMSecurityParameters,
        };

        let mib = crate::mib::Store::new();
        let auth_key_bytes = [0x42u8; 32];
        let wrong_priv_key_bytes = [0xBBu8; 16];
        let mac_len = AuthProtocol::HmacSha256.mac_len();
        let salt = [0x01u8; 8];
        let engine_id = test_engine_id();
        let boots = 1u32;
        let time = 0u32;

        let alice = crate::usm::user::UsmUser::auth_priv(
            crate::usm::user::UserName::new("alice").unwrap(),
            AuthProtocol::HmacSha256,
            SecretKey::new_from_exposed_slice(&auth_key_bytes),
            PrivProtocol::Aes128,
            SecretKey::new_from_exposed_slice(&wrong_priv_key_bytes),
        );

        // Build frame with flags = 0x03 (authPriv, no reportableFlag) and corrupted ciphertext.
        let fake_ciphertext = b"corrupted-ciphertext-that-wont-decode-as-scoped-pdu".to_vec();
        let zeroed_auth_params = vec![0u8; mac_len];
        let usm_params = USMSecurityParameters {
            authoritative_engine_id: engine_id.to_vec().into(),
            authoritative_engine_boots: boots.into(),
            authoritative_engine_time: time.into(),
            user_name: b"alice".to_vec().into(),
            authentication_parameters: zeroed_auth_params.clone().into(),
            privacy_parameters: salt.to_vec().into(),
        };
        let security_params = rasn::ber::encode(&usm_params).unwrap();
        let v3_msg = V3Message {
            version: 3.into(),
            global_data: HeaderData {
                message_id: 1.into(),
                max_size: 65535.into(),
                flags: rasn::types::OctetString::from(vec![0x03u8]), // authPriv, no reportableFlag
                security_model: 3.into(),
            },
            security_parameters: security_params.into(),
            scoped_data: ScopedPduData::EncryptedPdu(rasn::types::OctetString::from(
                fake_ciphertext,
            )),
        };
        let frame_with_zeros = rasn::ber::encode(&v3_msg).unwrap();
        let auth_key = SecretKey::new_from_exposed_slice(&auth_key_bytes);
        let mac = AuthProtocol::HmacSha256
            .compute_mac(&auth_key, &frame_with_zeros)
            .unwrap();
        let auth_params_offset = crate::codec::ber::snmp::decode_v3_envelope(&frame_with_zeros)
            .expect("frame must be a valid SNMPv3 envelope")
            .auth_params_offset
            .expect("authenticated frame must carry a non-empty auth_params field");
        let mut frame = frame_with_zeros;
        frame[auth_params_offset..auth_params_offset + mac_len].copy_from_slice(&mac);

        let mut tc = TestCtx::new().with_boots_time(1, 0);
        let result = {
            let mut ctx = tc.ctx(Some(&alice));
            process_snmpv3_request(&frame, &mut ctx, &mib)
        };
        assert!(
            result.is_none(),
            "decryption failure without reportableFlag must be silently discarded"
        );
        assert_eq!(
            tc.decryption_errors, 1,
            "counter must still be incremented even when no Report is sent"
        );
    }

    #[test]
    fn given_counter_at_max_when_decryption_fails_then_counter_does_not_overflow() {
        // Verifies: REQ-0101
        use crate::usm::auth::AuthProtocol;
        use crate::usm::keys::SecretKey;
        use crate::usm::privacy::PrivProtocol;

        let mib = crate::mib::Store::new();
        let auth_key_bytes = [0x42u8; 32];
        let priv_key_bytes = [0xAAu8; 16];
        let wrong_priv_key_bytes = [0xBBu8; 16];
        let alice = crate::usm::user::UsmUser::auth_priv(
            crate::usm::user::UserName::new("alice").unwrap(),
            AuthProtocol::HmacSha256,
            SecretKey::new_from_exposed_slice(&auth_key_bytes),
            PrivProtocol::Aes128,
            SecretKey::new_from_exposed_slice(&wrong_priv_key_bytes),
        );
        let frame = build_authpriv_frame(
            &auth_key_bytes,
            &priv_key_bytes,
            PrivProtocol::Aes128,
            1,
            0,
            test_oid_arcs(),
            [0x01u8; 8],
        );
        let mut tc = TestCtx::new()
            .with_boots_time(1, 0)
            .with_decryption_errors(u32::MAX);
        {
            let mut ctx = tc.ctx(Some(&alice));
            let _ = process_snmpv3_request(&frame, &mut ctx, &mib);
        }
        assert_eq!(tc.decryption_errors, u32::MAX, "counter must not overflow");
    }

    #[test]
    fn given_security_model_not_usm_when_processed_then_returns_report_and_increments_counter() {
        // Verifies: REQ-0115
        let mib = crate::mib::Store::new();
        // Build a frame with security_model=3 then patch the byte to 4.
        // In a standard SNMPv3 frame, security_model=3 is encoded as 02 01 03.
        // The version field is also encoded as 02 01 03 (the first occurrence),
        // so we skip the first match and patch the second, which is the
        // security_model in HeaderData. Replacing 03 with 04 produces
        // security_model=4 (not USM), rejected per RFC 3412 §7.2 step 2.
        let mut frame =
            snmpv3_frames::encode_get_request(test_engine_id(), b"", 1, 1, test_oid_arcs());
        // The reportable flag (0x04) is set by snmpv3_frames::encode_get_request,
        // so patching security_model should produce a Report PDU response.
        let security_model_tlv: &[u8] = &[0x02, 0x01, 0x03];
        let security_model_patched: &[u8] = &[0x02, 0x01, 0x04];
        // Skip the first occurrence (version=3) and patch the second (security_model=3).
        let pos = frame
            .windows(3)
            .enumerate()
            .filter(|(_, w)| *w == security_model_tlv)
            .nth(1)
            .map(|(i, _)| i)
            .expect("security_model=3 must appear as the second 02 01 03 in the frame");
        frame[pos..pos + 3].copy_from_slice(security_model_patched);

        let mut tc = TestCtx::new();
        let response = {
            let mut ctx = tc.ctx(None);
            process_snmpv3_request(&frame, &mut ctx, &mib)
        };
        let report_bytes =
            response.expect("should return a Report PDU for unsupported security model");
        assert_eq!(tc.unknown_security_models, 1);
        // Verify the Report PDU carries the snmpUnknownSecurityModels OID.
        let v3_response = rasn::ber::decode::<rasn_snmp::v3::Message>(&report_bytes)
            .expect("report must be a valid SNMPv3 message");
        let rasn_snmp::v3::ScopedPduData::CleartextPdu(scoped_pdu) = v3_response.scoped_data else {
            panic!("report must contain a cleartext ScopedPDU");
        };
        let rasn_snmp::v2::Pdus::Report(report_pdu) = scoped_pdu.data else {
            panic!("response must be a Report PDU");
        };
        let varbind = &report_pdu.0.variable_bindings[0];
        let expected_oid: crate::codec::Oid = "1.3.6.1.6.3.11.2.1.1.0".parse().unwrap();
        assert_eq!(
            varbind.name.as_ref(),
            expected_oid.as_slice(),
            "Report varbind OID must be snmpUnknownSecurityModels"
        );
    }

    #[test]
    fn given_security_model_not_usm_and_no_reportable_flag_when_processed_then_silent_discard() {
        // Verifies: REQ-0115
        let mib = crate::mib::Store::new();
        // Build frame with security_model patched to 4 AND reportable flag cleared.
        let mut frame =
            snmpv3_frames::encode_get_request(test_engine_id(), b"", 1, 1, test_oid_arcs());
        let security_model_tlv: &[u8] = &[0x02, 0x01, 0x03];
        let security_model_patched: &[u8] = &[0x02, 0x01, 0x04];
        let pos = frame
            .windows(3)
            .enumerate()
            .filter(|(_, w)| *w == security_model_tlv)
            .nth(1)
            .map(|(i, _)| i)
            .expect("security_model=3 must appear as the second 02 01 03 in the frame");
        frame[pos..pos + 3].copy_from_slice(security_model_patched);
        // msgFlags is encoded as 04 01 <flags>; clear the reportable bit (0x04).
        let flags_tlv: &[u8] = &[0x04, 0x01];
        let flags_pos = frame
            .windows(2)
            .enumerate()
            .find(|(_, w)| *w == flags_tlv)
            .map(|(i, _)| i + 2)
            .expect("msgFlags must be present in frame");
        frame[flags_pos] &= !0x04u8;

        let mut tc = TestCtx::new();
        let response = {
            let mut ctx = tc.ctx(None);
            process_snmpv3_request(&frame, &mut ctx, &mib)
        };
        assert!(
            response.is_none(),
            "no reportable flag means silent discard"
        );
        assert_eq!(
            tc.unknown_security_models, 1,
            "counter must still be incremented"
        );
    }

    #[test]
    fn given_unknown_security_models_counter_at_max_when_incremented_then_does_not_overflow() {
        // Verifies: REQ-0115
        let mib = crate::mib::Store::new();
        let mut frame =
            snmpv3_frames::encode_get_request(test_engine_id(), b"", 1, 1, test_oid_arcs());
        let security_model_tlv: &[u8] = &[0x02, 0x01, 0x03];
        let security_model_patched: &[u8] = &[0x02, 0x01, 0x04];
        let pos = frame
            .windows(3)
            .enumerate()
            .filter(|(_, w)| *w == security_model_tlv)
            .nth(1)
            .map(|(i, _)| i)
            .expect("security_model=3 must appear as the second 02 01 03 in the frame");
        frame[pos..pos + 3].copy_from_slice(security_model_patched);

        let mut tc = TestCtx::new().with_unknown_security_models(u32::MAX);
        {
            let mut ctx = tc.ctx(None);
            let _ = process_snmpv3_request(&frame, &mut ctx, &mib);
        }
        assert_eq!(
            tc.unknown_security_models,
            u32::MAX,
            "counter must not overflow"
        );
    }
}
