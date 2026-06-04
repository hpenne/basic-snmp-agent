//! Pure request dispatch: decode, validate, and encode a single `SNMPv3` frame.
//!
//! This module is intentionally free of I/O and side effects so that the
//! dispatch path can be exercised by fuzz targets and unit tests without
//! requiring a running event loop.

mod dispatch_context;
mod report;
pub use dispatch_context::{DispatchContext, DispatchInputs, NoUserSecurityLevelError};
use report::{
    DECRYPTION_ERRORS_OID, NOT_IN_TIME_WINDOWS_OID, Reject, UNKNOWN_ENGINE_IDS_OID,
    UNKNOWN_SECURITY_MODELS_OID, UNKNOWN_USER_NAMES_OID, UNSUPPORTED_SEC_LEVELS_OID,
    WRONG_DIGESTS_OID, emit_report_response,
};

use crate::transport::event_loop::{MAX_BULK_REPETITIONS, MAX_FRAME_SIZE};
use crate::transport::request;
// Implements: [[RFC-0009:C-FACADE]]
use log::{debug, trace};
/// Decode, validate, and dispatch a single RFC 3430 BER frame, returning
/// the encoded response bytes on success.
///
/// `frame` is the complete BER bytes (SEQUENCE tag + length + content).
/// Returns `Some(encoded_response)` when the frame produces a response, or
/// `None` when it should be silently discarded (invalid encoding, or
/// unsupported context name).
///
/// Engine-ID discovery probes (empty `msgAuthoritativeEngineID`) always produce
/// a Report PDU response and increment `ctx.inputs.unknown_engine_ids_counter` (REQ-0093),
/// provided the `reportableFlag` (bit 0x04) is set in `msgFlags`. Probes without
/// the flag set are silently discarded per RFC 3412 §7.1.3a.
///
/// Kept `pub` only so the out-of-workspace `fuzz` crate can drive dispatch directly;
/// `#[doc(hidden)]` keeps it off the advertised API. Not a supported public entry point — do not widen.
///
/// # Requirements
/// Implements: REQ-0056, REQ-0058, REQ-0066, REQ-0068, REQ-0073, REQ-0077, REQ-0078, REQ-0079, REQ-0080, REQ-0093, REQ-0098, REQ-0100, REQ-0101, REQ-0102, REQ-0103, REQ-0104, REQ-0107, REQ-0109, REQ-0115, REQ-0130
#[doc(hidden)]
#[must_use]
pub fn process_snmpv3_request(
    frame: &[u8],
    ctx: &mut DispatchContext<'_>,
    mib: &crate::mib::Store,
) -> Option<Vec<u8>> {
    match run_validation_pipeline(frame, ctx, mib) {
        Ok(response) => Some(response),
        Err(reject) => Option::from(reject),
    }
}

fn run_validation_pipeline(
    frame: &[u8],
    ctx: &mut DispatchContext<'_>,
    mib: &crate::mib::Store,
) -> Result<Vec<u8>, Reject> {
    // Decode as an SNMPv3 message. Non-v3 messages are silently discarded
    // per REQ-0073.
    let v3_msg = crate::codec::decode_v3_message(frame)
        .inspect_err(|decode_error| debug!("failed to decode SNMPv3 message: {decode_error}"))
        .map_err(|_| Reject::Discard)?;

    check_security_model(&v3_msg, ctx)?;
    check_discovery_probe(&v3_msg, ctx)?;
    check_engine_id(&v3_msg, ctx)?;
    check_user_name(&v3_msg, ctx)?;
    check_security_level(&v3_msg, ctx)?;
    verify_authentication(&v3_msg, ctx)?;
    check_time_window(&v3_msg, ctx)?;
    check_context_name(&v3_msg)?;

    // REQ-0101, REQ-0102: decrypt authPriv ScopedPDU ciphertext after HMAC and
    // time-window validation pass (processing order mandated by REQ-0102).
    // Returns (inbound_pdu, effective_context_name) so the correct context name
    // flows to the response encoder regardless of whether it came from the outer
    // message envelope (cleartext) or the decrypted ScopedPdu (authPriv).
    let (inbound_pdu, response_context_name) = match v3_msg.scoped_data {
        crate::codec::V3ScopedData::Plaintext(pdu) => (pdu, v3_msg.context_name),
        crate::codec::V3ScopedData::Encrypted(ciphertext) => decrypt_scoped_pdu(
            ctx,
            v3_msg.msg_id,
            v3_msg.usm.security_flags,
            &ciphertext,
            &v3_msg.usm.priv_params,
            v3_msg.usm.auth_engine_boots,
            v3_msg.usm.auth_engine_time,
        )?,
    };

    dispatch_pdu_and_encode_response(
        ctx,
        v3_msg.msg_id,
        v3_msg.max_size,
        &v3_msg.user_name,
        mib,
        inbound_pdu,
        &response_context_name,
    )
    .ok_or(Reject::Discard)
}

// RFC 3412 §7.2 step 2: reject messages with unsupported security models.
// Implements: REQ-0115
fn check_security_model(
    v3_msg: &crate::codec::V3InboundMessage<'_>,
    ctx: &mut DispatchContext<'_>,
) -> Result<(), Reject> {
    if v3_msg.security_model.is_usm() {
        return Ok(());
    }
    Err(emit_report_response(
        ctx,
        |inputs| &mut inputs.unknown_security_models_counter,
        &UNKNOWN_SECURITY_MODELS_OID,
        "unknown security model",
        v3_msg.msg_id,
        v3_msg.usm.security_flags,
    ))
}

// REQ-0093: engine-ID discovery probe — the manager sent an empty
// msgAuthoritativeEngineID. Respond with a Report PDU carrying the
// usmStatsUnknownEngineIDs counter and our authoritative engine state
// so the manager can learn our engine ID, boots, and approximate time.
// Implements: REQ-0093
fn check_discovery_probe(
    v3_msg: &crate::codec::V3InboundMessage<'_>,
    ctx: &mut DispatchContext<'_>,
) -> Result<(), Reject> {
    if !v3_msg.usm.auth_engine_id.is_empty() {
        return Ok(());
    }
    Err(emit_report_response(
        ctx,
        |inputs| &mut inputs.unknown_engine_ids_counter,
        &UNKNOWN_ENGINE_IDS_OID,
        "engine-ID discovery probe",
        v3_msg.msg_id,
        v3_msg.usm.security_flags,
    ))
}

// REQ-0104: contextEngineID mismatch — the ScopedPDU's contextEngineID does not
// match the agent's snmpEngineID. Respond with a Report PDU carrying
// usmStatsUnknownEngineIDs.
// Implements: REQ-0104
fn check_engine_id(
    v3_msg: &crate::codec::V3InboundMessage<'_>,
    ctx: &mut DispatchContext<'_>,
) -> Result<(), Reject> {
    if v3_msg.engine_id == ctx.inputs.engine_id {
        return Ok(());
    }
    Err(emit_report_response(
        ctx,
        |inputs| &mut inputs.unknown_engine_ids_counter,
        &UNKNOWN_ENGINE_IDS_OID,
        "unknown engine ID",
        v3_msg.msg_id,
        v3_msg.usm.security_flags,
    ))
}

// REQ-0078, REQ-0080: user-name lookup — discovery (above) runs before this check.
// If a USM user is configured and the request names a different user, increment the
// counter and respond with a Report PDU only if the reportableFlag is set
// (RFC 3412 §7.1.3a).
// Non-constant-time comparison is acceptable: user names are transmitted in cleartext
// on the wire (RFC 3414 §2.4), so they are not secret.
// Implements: REQ-0078, REQ-0080
fn check_user_name(
    v3_msg: &crate::codec::V3InboundMessage<'_>,
    ctx: &mut DispatchContext<'_>,
) -> Result<(), Reject> {
    if ctx
        .inputs
        .usm_user
        .is_none_or(|user| v3_msg.user_name == user.name().as_bytes())
    {
        return Ok(());
    }
    Err(emit_report_response(
        ctx,
        |inputs| &mut inputs.unknown_user_names_counter,
        &UNKNOWN_USER_NAMES_OID,
        "unknown user name",
        v3_msg.msg_id,
        v3_msg.usm.security_flags,
    ))
}

// REQ-0079, REQ-0103, REQ-0130: security-level enforcement — runs after user-name lookup.
// The invalid combination (privFlag without authFlag) is treated as a rejection.
// For noAuthNoPriv messages that pass both checks, authentication and decryption
// are skipped naturally (REQ-0103).
// Implements: REQ-0079, REQ-0103, REQ-0130
fn check_security_level(
    v3_msg: &crate::codec::V3InboundMessage<'_>,
    ctx: &mut DispatchContext<'_>,
) -> Result<(), Reject> {
    let msg_level = crate::usm::user::SecurityLevel::try_from(v3_msg.usm.security_flags);
    if !ctx.inputs.should_reject_security_level(msg_level) {
        return Ok(());
    }
    Err(emit_report_response(
        ctx,
        |inputs| &mut inputs.unsupported_sec_levels_counter,
        &UNSUPPORTED_SEC_LEVELS_OID,
        "unsupported security level",
        v3_msg.msg_id,
        v3_msg.usm.security_flags,
    ))
}

// REQ-0100, REQ-0102: HMAC verification for authenticated messages.
// Runs after security-level check per REQ-0102 processing order.
// For noAuthNoPriv users, auth_protocol() returns None so this check is skipped (REQ-0103).
// Implements: REQ-0100, REQ-0102
fn verify_authentication(
    v3_msg: &crate::codec::V3InboundMessage<'_>,
    ctx: &mut DispatchContext<'_>,
) -> Result<(), Reject> {
    let Some(user) = ctx.inputs.usm_user else {
        return Ok(());
    };
    let (Some(auth_protocol), Some(auth_key)) = (user.auth_protocol(), user.auth_key()) else {
        return Ok(());
    };
    if verify_hmac(
        auth_protocol,
        auth_key,
        v3_msg.raw_message,
        &v3_msg.usm.auth_params,
        v3_msg.auth_params_offset,
    ) {
        return Ok(());
    }
    Err(emit_report_response(
        ctx,
        |inputs| &mut inputs.wrong_digests_counter,
        &WRONG_DIGESTS_OID,
        "wrong digest",
        v3_msg.msg_id,
        v3_msg.usm.security_flags,
    ))
}

// REQ-0098: time-window validation for authenticated messages.
// Runs after HMAC verification per REQ-0102 processing order.
// Implements: REQ-0098
fn check_time_window(
    v3_msg: &crate::codec::V3InboundMessage<'_>,
    ctx: &mut DispatchContext<'_>,
) -> Result<(), Reject> {
    let Some(user) = ctx.inputs.usm_user else {
        return Ok(());
    };
    if user.auth_protocol().is_none() {
        return Ok(());
    }
    if crate::usm::time_window::is_in_time_window(
        v3_msg.usm.auth_engine_boots,
        v3_msg.usm.auth_engine_time,
        ctx.inputs.engine_boots,
        ctx.inputs.engine_time,
    ) {
        return Ok(());
    }
    Err(emit_report_response(
        ctx,
        |inputs| &mut inputs.not_in_time_windows_counter,
        &NOT_IN_TIME_WINDOWS_OID,
        "not-in-time-window",
        v3_msg.msg_id,
        v3_msg.usm.security_flags,
    ))
}

// Only the default (empty) context name is supported per REQ-0058.
// For authPriv messages the context_name is inside the encrypted blob and is validated
// after decryption. For cleartext messages it is already decoded.
// Implements: REQ-0058
fn check_context_name(v3_msg: &crate::codec::V3InboundMessage<'_>) -> Result<(), Reject> {
    if v3_msg.context_name.is_empty() {
        return Ok(());
    }
    debug!("unsupported context name (plaintext), discarding");
    Err(Reject::Discard)
}

/// Dispatch a decoded PDU to the appropriate request handler and encode the response.
///
/// Called after all security checks pass. Determines the effective `max_size` for GETBULK
/// from the message header, dispatches to the correct handler, then encodes the `SNMPv3`
/// response with the security credentials from `ctx`.
///
/// # Requirements
/// Implements: REQ-0056, REQ-0066, REQ-0068, REQ-0107
fn dispatch_pdu_and_encode_response(
    ctx: &DispatchContext<'_>,
    msg_id: i32,
    max_size: i32,
    user_name: &[u8],
    mib: &crate::mib::Store,
    inbound_pdu: crate::codec::InboundPdu,
    response_context_name: &[u8],
) -> Option<Vec<u8>> {
    let response = match inbound_pdu {
        crate::codec::InboundPdu::GetRequest(req) => request::handle_get(&req, mib),
        crate::codec::InboundPdu::GetNextRequest(req) => request::handle_get_next(&req, mib),
        crate::codec::InboundPdu::GetBulkRequest(req) => {
            // Bound response by the lesser of the sender's declared max_size and
            // the agent's own frame limit, then convert to usize for size arithmetic.
            // max_size is validated >= 484 during decode (RFC 3412 §7.2 step 5), so
            // it is always positive; unwrap_or(0) is defence-in-depth only.
            let effective_max_size = usize::try_from(max_size).unwrap_or(0).min(MAX_FRAME_SIZE);
            request::handle_get_bulk(&req, mib, MAX_BULK_REPETITIONS, effective_max_size)
        }
        crate::codec::InboundPdu::SetRequest(req) => request::handle_set(&req),
    };

    // Implements: REQ-0107 — response security level must match the request.
    let response_auth = ctx
        .inputs
        .usm_user
        .and_then(|user| user.auth_protocol().zip(user.auth_key()));
    // Implements: REQ-0101, REQ-0107
    let response_priv = ctx
        .inputs
        .usm_user
        .and_then(|user| user.priv_protocol().zip(user.priv_key()));
    crate::codec::encode_v3_response(
        msg_id,
        ctx.inputs.engine_id,
        user_name,
        response_context_name,
        ctx.inputs.engine_boots,
        ctx.inputs.engine_time,
        response_auth,
        response_priv,
        &response,
    )
    .inspect_err(|encode_error| debug!("failed to encode SNMPv3 response: {encode_error}"))
    .ok()
}

/// Verify the HMAC of an authenticated `SNMPv3` message.
///
/// Returns `true` when the MAC is valid, `false` when verification fails or
/// `auth_params_offset` is absent (which is treated as a MAC failure).
///
/// # Requirements
/// Implements: REQ-0100, REQ-0102
fn verify_hmac(
    auth_protocol: crate::usm::auth::AuthProtocol,
    auth_key: &crate::usm::keys::SecretKey,
    raw_message: &[u8],
    auth_params: &[u8],
    auth_params_offset: Option<usize>,
) -> bool {
    let Some(offset) = auth_params_offset else {
        trace!("auth_params_offset absent, treating as HMAC failure");
        return false;
    };
    let zeroed = zero_auth_params_in_message(raw_message, offset, auth_params.len());
    auth_protocol
        .verify_mac(auth_key, &zeroed, auth_params)
        .is_ok()
}

/// Decrypt an authPriv `ScopedPDU` ciphertext and decode the plaintext.
///
/// Returns `Ok((pdu, context_name))` on success.
/// Returns `Err(Reject::Report(bytes))` when a decryption or decode error occurs and a
/// Report PDU should be sent.
/// Returns `Err(Reject::Discard)` for a silent discard (no privacy credentials configured,
/// or non-empty context name).
///
/// # Requirements
/// Implements: REQ-0101, REQ-0102, REQ-0104, REQ-0109
fn decrypt_scoped_pdu(
    ctx: &mut DispatchContext<'_>,
    msg_id: i32,
    security_flags: u8,
    ciphertext: &[u8],
    priv_params: &[u8],
    auth_engine_boots: u32,
    auth_engine_time: u32,
) -> Result<(crate::codec::InboundPdu, Vec<u8>), Reject> {
    // Security-level enforcement (REQ-0079) already verified the configured user
    // is authPriv, so priv_protocol/priv_key must be Some here.
    let Some((priv_protocol, priv_key)) = ctx
        .inputs
        .usm_user
        .and_then(|user| user.priv_protocol().zip(user.priv_key()))
    else {
        // No configured user or no privacy credentials — can't decrypt, discard.
        debug!("encrypted message but no privacy credentials configured, discarding");
        return Err(Reject::Discard);
    };

    // msgPrivacyParameters must be exactly 8 bytes (the AES salt per RFC 3826 §2.2).
    if priv_params.len() != 8 {
        debug!("msgPrivacyParameters length {} != 8", priv_params.len());
        // Implements: REQ-0101
        return Err(emit_report_response(
            ctx,
            |inputs| &mut inputs.decryption_errors_counter,
            &DECRYPTION_ERRORS_OID,
            "decryption error",
            msg_id,
            security_flags,
        ));
    }

    // Implements: REQ-0109
    // IV = engineBoots (4 BE) || engineTime (4 BE) || salt (8 bytes) per RFC 3826 §2.2.
    let mut aes_iv = [0_u8; 16];
    aes_iv[0..4].copy_from_slice(&auth_engine_boots.to_be_bytes());
    aes_iv[4..8].copy_from_slice(&auth_engine_time.to_be_bytes());
    aes_iv[8..16].copy_from_slice(priv_params);

    let Ok(scoped_pdu_bytes) = priv_protocol.decrypt(priv_key, &aes_iv, ciphertext) else {
        debug!("AES-CFB128 decryption failed");
        // Implements: REQ-0101
        return Err(emit_report_response(
            ctx,
            |inputs| &mut inputs.decryption_errors_counter,
            &DECRYPTION_ERRORS_OID,
            "decryption error",
            msg_id,
            security_flags,
        ));
    };

    let Ok(decoded) = crate::codec::decode_scoped_pdu(&scoped_pdu_bytes) else {
        debug!("failed to decode decrypted ScopedPDU");
        // Implements: REQ-0101
        return Err(emit_report_response(
            ctx,
            |inputs| &mut inputs.decryption_errors_counter,
            &DECRYPTION_ERRORS_OID,
            "decryption error",
            msg_id,
            security_flags,
        ));
    };

    // REQ-0104: contextEngineID validation — the decrypted ScopedPDU's contextEngineID
    // must match the agent's snmpEngineID per RFC 3412 §7.2 step 9d.
    // Implements: REQ-0104
    if decoded.context_engine_id != ctx.inputs.engine_id {
        return Err(emit_report_response(
            ctx,
            |inputs| &mut inputs.unknown_engine_ids_counter,
            &UNKNOWN_ENGINE_IDS_OID,
            "unknown engine ID",
            msg_id,
            security_flags,
        ));
    }

    // Context name validated after decryption; only the default (empty) context is supported.
    if !decoded.context_name.is_empty() {
        debug!("unsupported context name (decrypted), discarding");
        return Err(Reject::Discard);
    }

    Ok((decoded.pdu, decoded.context_name))
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

#[cfg(test)]
mod tests {
    use super::*;
    use report::SNMP_UNKNOWN_SECURITY_MODELS_OID;

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
        minimum_security_level: crate::usm::user::SecurityLevel,
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
                minimum_security_level: crate::usm::user::SecurityLevel::NoAuthNoPriv,
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

        fn with_minimum_security_level(mut self, level: crate::usm::user::SecurityLevel) -> Self {
            self.minimum_security_level = level;
            self
        }

        fn ctx<'a>(
            &'a mut self,
            usm_user: Option<&'a crate::usm::user::UsmUser>,
        ) -> DispatchContext<'a> {
            self.try_ctx(usm_user)
                .expect("test configuration upholds the no-user invariant")
        }

        fn try_ctx<'a>(
            &'a mut self,
            usm_user: Option<&'a crate::usm::user::UsmUser>,
        ) -> Result<DispatchContext<'a>, NoUserSecurityLevelError> {
            DispatchContext::new(DispatchInputs {
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
                minimum_security_level: self.minimum_security_level,
            })
        }
    }

    // Build a noAuthNoPriv UsmUser with the given name.
    fn test_no_auth_user(name: &str) -> crate::usm::user::UsmUser {
        crate::usm::user::UsmUser::no_auth_no_priv(crate::usm::user::UserName::new(name).unwrap())
    }

    // Build an authNoPriv UsmUser (HMAC-SHA-256) with the given name and key bytes.
    fn test_auth_user(name: &str, auth_key_bytes: &[u8]) -> crate::usm::user::UsmUser {
        crate::usm::user::AuthNoPrivUser::new(
            crate::usm::user::UserName::new(name).unwrap(),
            crate::usm::auth::AuthProtocol::HmacSha256,
            crate::usm::keys::SecretKey::new_from_exposed_slice(auth_key_bytes),
        )
        .unwrap()
        .into()
    }

    // Build an authPriv UsmUser (HMAC-SHA-256 + AES-128) with the given name and auth key bytes.
    // The priv key is derived from the first 16 bytes of the auth key, matching the convention
    // used throughout the dispatch tests.
    fn test_authpriv_user(name: &str, auth_key_bytes: &[u8]) -> crate::usm::user::UsmUser {
        crate::usm::user::AuthPrivUser::new(
            crate::usm::user::UserName::new(name).unwrap(),
            crate::usm::auth::AuthProtocol::HmacSha256,
            crate::usm::keys::SecretKey::new_from_exposed_slice(auth_key_bytes),
            crate::usm::privacy::PrivProtocol::Aes128,
        )
        .unwrap()
        .into()
    }

    // Decode `response_bytes` as an SNMPv3 message, assert the ScopedPDU is a cleartext
    // Report PDU, and verify that its single varbind has the expected OID and Counter32 value.
    // Returns the decoded message so callers can perform additional assertions (e.g. USM params).
    fn assert_report_pdu_varbind(
        response_bytes: &[u8],
        expected_counter_oid: &str,
        expected_counter_value: u32,
    ) -> rasn_snmp::v3::Message {
        let v3_response = rasn::ber::decode::<rasn_snmp::v3::Message>(response_bytes)
            .expect("response must be a valid SNMPv3 message");
        let rasn_snmp::v3::ScopedPduData::CleartextPdu(scoped_pdu) =
            v3_response.scoped_data.clone()
        else {
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
        let expected_oid: crate::codec::Oid = expected_counter_oid.parse().unwrap();
        assert_eq!(
            varbind.name.as_ref(),
            expected_oid.as_slice(),
            "Report varbind OID must be {expected_counter_oid}"
        );
        let rasn_snmp::v2::VarBindValue::Value(rasn_smi::v2::ObjectSyntax::ApplicationWide(
            rasn_smi::v2::ApplicationSyntax::Counter(ref counter),
        )) = varbind.value
        else {
            panic!("Report varbind value must be a Counter32");
        };
        assert_eq!(
            counter.0, expected_counter_value,
            "Report varbind must carry counter value {expected_counter_value}"
        );
        v3_response
    }

    // Decode USM security parameters from `v3_response` and assert the engine ID, boots, and time.
    fn assert_usm_params(
        v3_response: &rasn_snmp::v3::Message,
        expected_boots: u32,
        expected_time: u32,
    ) {
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
            expected_boots,
            "response must carry engine boots {expected_boots}"
        );
        assert_eq!(
            u32::try_from(usm_params.authoritative_engine_time).unwrap(),
            expected_time,
            "response must carry engine time {expected_time}"
        );
    }

    // Decode `response_bytes` as an SNMPv3 message, assert the ScopedPDU is a cleartext
    // GetResponse (Pdus::Response), and return the decoded message for further inspection.
    fn assert_get_response(response_bytes: &[u8]) -> rasn_snmp::v3::Message {
        let v3_response = rasn::ber::decode::<rasn_snmp::v3::Message>(response_bytes)
            .expect("response must be a valid SNMPv3 message");
        let rasn_snmp::v3::ScopedPduData::CleartextPdu(scoped_pdu) =
            v3_response.scoped_data.clone()
        else {
            panic!("response must contain a cleartext ScopedPDU");
        };
        let rasn_snmp::v2::Pdus::Response(_) = scoped_pdu.data else {
            panic!("response must be a GetResponse, not a Report");
        };
        v3_response
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
        let response_bytes = result.expect("discovery probe must produce a Report response");
        let v3_response = assert_report_pdu_varbind(
            &response_bytes,
            crate::usm::counters::USM_STATS_UNKNOWN_ENGINE_IDS,
            1,
        );
        assert_usm_params(&v3_response, 3, 100);
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
            let _response = process_snmpv3_request(&probe_frame, &mut ctx, &mib);
        }
        {
            let mut ctx = tc.ctx(None);
            let _response = process_snmpv3_request(&probe_frame, &mut ctx, &mib);
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
        {
            let mut ctx = tc.ctx(None);
            let _response = process_snmpv3_request(&frame, &mut ctx, &mib);
        }
        assert_eq!(tc.unknown_engine_ids, 0);
    }

    #[test]
    fn given_counter_at_max_when_discovery_probe_then_counter_does_not_overflow() {
        // Verifies: REQ-0093 — saturating_add prevents overflow
        let mib = crate::mib::Store::new();
        let probe_frame = snmpv3_frames::encode_discovery_probe();
        let mut tc = TestCtx::new().with_unknown_engine_ids(u32::MAX);
        let response_bytes = {
            let mut ctx = tc.ctx(None);
            process_snmpv3_request(&probe_frame, &mut ctx, &mib)
        }
        .expect("discovery probe must produce a Report response even when counter is at max");
        assert_eq!(tc.unknown_engine_ids, u32::MAX);
        assert_report_pdu_varbind(
            &response_bytes,
            crate::usm::counters::USM_STATS_UNKNOWN_ENGINE_IDS,
            u32::MAX,
        );
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
        assert_eq!(
            tc.unknown_engine_ids, 1,
            "counter must be incremented on contextEngineID mismatch"
        );
        let response_bytes =
            result.expect("contextEngineID mismatch must produce a Report response");
        // Verify Report PDU carries usmStatsUnknownEngineIDs.
        let v3_response = assert_report_pdu_varbind(
            &response_bytes,
            crate::usm::counters::USM_STATS_UNKNOWN_ENGINE_IDS,
            1,
        );
        assert_usm_params(&v3_response, 3, 100);
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
        let response_bytes = {
            let mut ctx = tc.ctx(None);
            process_snmpv3_request(&frame, &mut ctx, &mib)
        }
        .expect(
            "contextEngineID mismatch must produce a Report response even when counter is at max",
        );
        assert_eq!(tc.unknown_engine_ids, u32::MAX, "counter must not overflow");
        assert_report_pdu_varbind(
            &response_bytes,
            crate::usm::counters::USM_STATS_UNKNOWN_ENGINE_IDS,
            u32::MAX,
        );
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
        assert_eq!(
            tc.unknown_engine_ids, 1,
            "counter must be incremented on contextEngineID mismatch"
        );
        let response_bytes = result.expect(
            "contextEngineID mismatch must produce a Report response even when msgAuthoritativeEngineID matches"
        );
        assert_report_pdu_varbind(
            &response_bytes,
            crate::usm::counters::USM_STATS_UNKNOWN_ENGINE_IDS,
            1,
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
        assert_eq!(tc.unknown_user_names, 0, "counter must not be incremented");
        let response_bytes =
            result.expect("request must pass through when no USM user is configured");
        assert_get_response(&response_bytes);
    }

    #[test]
    fn given_matching_user_name_when_process_then_proceeds() {
        // Verifies: REQ-0078
        let mib = crate::mib::Store::new();
        let alice = test_no_auth_user("alice");
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
        assert_eq!(
            tc.unknown_user_names, 0,
            "counter must not be incremented on match"
        );
        // A Report PDU would decode as Pdus::Report; a GetResponse decodes as Pdus::Response.
        let response_bytes = result.expect("matching user name must produce a response");
        assert_get_response(&response_bytes);
    }

    #[test]
    fn given_mismatched_user_name_when_process_then_returns_report_and_increments_counter() {
        // Verifies: REQ-0078, REQ-0080
        let mib = crate::mib::Store::new();
        let alice = test_no_auth_user("alice");
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
        assert_eq!(
            tc.unknown_user_names, 1,
            "counter must be incremented on mismatch"
        );
        let response_bytes = result.expect("mismatched user name must produce a Report response");
        let v3_response = assert_report_pdu_varbind(
            &response_bytes,
            crate::usm::counters::USM_STATS_UNKNOWN_USER_NAMES,
            1,
        );
        assert_usm_params(&v3_response, 1, 0);
    }

    #[test]
    fn given_mismatched_user_name_without_reportable_flag_when_process_then_discarded_but_counter_incremented()
     {
        // Verifies: REQ-0078 — no Report when reportableFlag is not set, but counter still increments
        let mib = crate::mib::Store::new();
        let alice = test_no_auth_user("alice");
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
        let alice = test_no_auth_user("alice");
        let frame = snmpv3_frames::encode_get_request_with_user(
            test_engine_id(),
            b"eve",
            b"",
            1,
            2,
            test_oid_arcs(),
        );
        let mut tc = TestCtx::new().with_unknown_user_names(u32::MAX);
        let response_bytes = {
            let mut ctx = tc.ctx(Some(&alice));
            process_snmpv3_request(&frame, &mut ctx, &mib)
        }
        .expect("user-name mismatch must produce a Report response even when counter is at max");
        assert_eq!(tc.unknown_user_names, u32::MAX, "counter must not overflow");
        assert_report_pdu_varbind(
            &response_bytes,
            crate::usm::counters::USM_STATS_UNKNOWN_USER_NAMES,
            u32::MAX,
        );
    }

    // ── Security-level enforcement (REQ-0077, REQ-0079, REQ-0103, REQ-0130) ───

    #[test]
    fn given_matching_security_level_when_process_then_proceeds() {
        // Verifies: REQ-0079, REQ-0103
        let mib = crate::mib::Store::new();
        let alice = test_no_auth_user("alice");
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
        assert_eq!(
            tc.unsupported_sec_levels, 0,
            "counter must not be incremented on match"
        );
        let response_bytes = result.expect("matching security level must produce a response");
        assert_get_response(&response_bytes);
    }

    #[test]
    fn given_ceiling_violation_when_process_then_returns_report_and_increments_counter() {
        // Verifies: REQ-0130
        let mib = crate::mib::Store::new();
        let alice = test_no_auth_user("alice");
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
        assert_eq!(
            tc.unsupported_sec_levels, 1,
            "counter must be incremented on ceiling violation"
        );
        // Verify the Report PDU contains the correct varbind (usmStatsUnsupportedSecLevels).
        let v3_response = assert_report_pdu_varbind(
            &result.expect("ceiling violation must produce a Report response"),
            crate::usm::counters::USM_STATS_UNSUPPORTED_SEC_LEVELS,
            1,
        );
        assert_usm_params(&v3_response, 1, 0);
    }

    #[test]
    fn given_ceiling_violation_without_reportable_flag_when_process_then_discarded_but_counter_incremented()
     {
        // Verifies: REQ-0130
        let mib = crate::mib::Store::new();
        let alice = test_no_auth_user("alice");
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
            "ceiling violation without reportableFlag must be silently discarded"
        );
        assert_eq!(
            tc.unsupported_sec_levels, 1,
            "counter must still be incremented even when no Report is sent"
        );
    }

    #[test]
    fn given_no_usm_user_when_auth_no_priv_msg_then_rejected_with_report() {
        // Verifies: REQ-0079
        // F1 fail-closed: when no USM user is configured, the agent has no credentials
        // and cannot authenticate messages. A forged cleartext message claiming authNoPriv
        // (flags 0x05 has reportableFlag set) must be rejected with a Report PDU carrying
        // usmStatsUnsupportedSecLevels rather than being served as if authenticated.
        let mib = crate::mib::Store::new();
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
        assert_eq!(
            tc.unsupported_sec_levels, 1,
            "counter must be incremented for no-user auth/priv message (fail-closed)"
        );
        let response_bytes = result
            .expect("authNoPriv message with reportableFlag set must produce a Report response");
        assert_report_pdu_varbind(
            &response_bytes,
            crate::usm::counters::USM_STATS_UNSUPPORTED_SEC_LEVELS,
            1,
        );
    }

    #[test]
    fn given_counter_at_max_when_ceiling_violation_then_counter_does_not_overflow() {
        // Verifies: REQ-0130 — saturating_add prevents overflow
        let mib = crate::mib::Store::new();
        let alice = test_no_auth_user("alice");
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
        let response_bytes = {
            let mut ctx = tc.ctx(Some(&alice));
            process_snmpv3_request(&frame, &mut ctx, &mib)
        }
        .expect("ceiling violation must produce a Report response even when counter is at max");
        assert_eq!(
            tc.unsupported_sec_levels,
            u32::MAX,
            "counter must not overflow"
        );
        assert_report_pdu_varbind(
            &response_bytes,
            crate::usm::counters::USM_STATS_UNSUPPORTED_SEC_LEVELS,
            u32::MAX,
        );
    }

    #[test]
    fn given_invalid_priv_without_auth_flags_when_process_then_returns_report_and_increments_counter()
     {
        // Verifies: REQ-0079, REQ-0130 — privFlag=1, authFlag=0 (0x06) is invalid; rejected regardless of floor/ceiling
        let mib = crate::mib::Store::new();
        let alice = test_no_auth_user("alice");
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
        let response_bytes =
            result.expect("invalid msgFlags combination must produce a Report response");
        assert_eq!(
            tc.unsupported_sec_levels, 1,
            "counter must be incremented for invalid msgFlags"
        );
        assert_report_pdu_varbind(
            &response_bytes,
            crate::usm::counters::USM_STATS_UNSUPPORTED_SEC_LEVELS,
            1,
        );
    }

    #[test]
    fn given_auth_no_priv_floor_when_no_auth_msg_then_rejects() {
        // Verifies: REQ-0079
        let mib = crate::mib::Store::new();
        let alice = test_auth_user("alice", &[0x42_u8; 32]);
        // noAuthNoPriv message (flags 0x04 = reportable only) but floor is AuthNoPriv
        let frame = snmpv3_frames::encode_get_request_with_user(
            test_engine_id(),
            b"alice",
            b"",
            1,
            2,
            test_oid_arcs(),
        );
        let mut tc =
            TestCtx::new().with_minimum_security_level(crate::usm::user::SecurityLevel::AuthNoPriv);
        let result = {
            let mut ctx = tc.ctx(Some(&alice));
            process_snmpv3_request(&frame, &mut ctx, &mib)
        };
        assert_eq!(
            tc.unsupported_sec_levels, 1,
            "counter must be incremented for below-floor message"
        );
        // Verify Report carries usmStatsUnsupportedSecLevels
        assert_report_pdu_varbind(
            &result.expect("below-floor message must produce a Report response"),
            crate::usm::counters::USM_STATS_UNSUPPORTED_SEC_LEVELS,
            1,
        );
    }

    #[test]
    fn given_auth_priv_floor_when_auth_no_priv_msg_then_rejects() {
        // Verifies: REQ-0079
        let mib = crate::mib::Store::new();
        let alice = test_authpriv_user("alice", &[0x42_u8; 32]);
        // authNoPriv message (flags 0x05) but floor is AuthPriv — rejected at floor check
        // before HMAC verification
        let frame = snmpv3_frames::encode_get_request_with_user_and_flags(
            test_engine_id(),
            b"alice",
            b"",
            1,
            2,
            test_oid_arcs(),
            0x05,
        );
        let mut tc =
            TestCtx::new().with_minimum_security_level(crate::usm::user::SecurityLevel::AuthPriv);
        let result = {
            let mut ctx = tc.ctx(Some(&alice));
            process_snmpv3_request(&frame, &mut ctx, &mib)
        };
        let response_bytes =
            result.expect("below-floor authNoPriv message must produce a Report response");
        assert_eq!(
            tc.unsupported_sec_levels, 1,
            "counter must be incremented for below-floor message"
        );
        assert_report_pdu_varbind(
            &response_bytes,
            crate::usm::counters::USM_STATS_UNSUPPORTED_SEC_LEVELS,
            1,
        );
    }

    #[test]
    fn given_auth_priv_user_when_auth_no_priv_msg_above_floor_then_accepts() {
        // Verifies: REQ-0079, REQ-0130
        let mib = crate::mib::Store::new();
        let auth_key_bytes = [0x42_u8; 32];
        let alice = test_authpriv_user("alice", &auth_key_bytes);
        // Floor=AuthNoPriv, user=AuthPriv, msg=authNoPriv (flags 0x05)
        // level >= floor (authNoPriv >= authNoPriv) and level <= user capabilities (authNoPriv <= authPriv)
        let frame = build_authenticated_frame(&auth_key_bytes);
        let mut tc =
            TestCtx::new().with_minimum_security_level(crate::usm::user::SecurityLevel::AuthNoPriv);
        let result = {
            let mut ctx = tc.ctx(Some(&alice));
            process_snmpv3_request(&frame, &mut ctx, &mib)
        };
        let response_bytes = result.expect(
            "authNoPriv message must be accepted when user has authPriv capabilities and floor is authNoPriv"
        );
        assert_eq!(
            tc.unsupported_sec_levels, 0,
            "counter must not be incremented when message passes both floor and ceiling checks"
        );
        // Verify the response is not a cleartext Report PDU (which would indicate a
        // security-level rejection). An AuthPriv user responding to any authenticated
        // request will produce an authPriv-encrypted response per REQ-0107, so the
        // ScopedPduData will be EncryptedPdu.
        let v3_response = rasn::ber::decode::<rasn_snmp::v3::Message>(&response_bytes)
            .expect("response must be a valid SNMPv3 message");
        let rasn_snmp::v3::ScopedPduData::EncryptedPdu(_) = v3_response.scoped_data else {
            panic!("authPriv user must produce an encrypted response, not a cleartext Report");
        };
    }

    #[test]
    fn given_auth_no_priv_floor_when_auth_priv_msg_with_no_priv_user_then_rejects_ceiling() {
        // Verifies: REQ-0130
        let mib = crate::mib::Store::new();
        let alice = test_auth_user("alice", &[0x42_u8; 32]);
        // authPriv message (flags 0x07) but user only has authNoPriv capabilities
        // Passes floor (authPriv >= authNoPriv) but fails ceiling (authPriv > authNoPriv)
        let frame = snmpv3_frames::encode_get_request_with_user_and_flags(
            test_engine_id(),
            b"alice",
            b"",
            1,
            2,
            test_oid_arcs(),
            0x07,
        );
        let mut tc =
            TestCtx::new().with_minimum_security_level(crate::usm::user::SecurityLevel::AuthNoPriv);
        let result = {
            let mut ctx = tc.ctx(Some(&alice));
            process_snmpv3_request(&frame, &mut ctx, &mib)
        };
        let response_bytes = result.expect("ceiling violation must produce a Report response");
        assert_eq!(
            tc.unsupported_sec_levels, 1,
            "counter must be incremented for ceiling violation"
        );
        assert_report_pdu_varbind(
            &response_bytes,
            crate::usm::counters::USM_STATS_UNSUPPORTED_SEC_LEVELS,
            1,
        );
    }

    // ── DispatchContext::new (REQ-0079) ─────────────────────────────────────────

    #[test]
    fn given_no_user_and_auth_no_priv_floor_when_new_then_err() {
        // Verifies: REQ-0079 — construction must fail when no user and floor > noAuthNoPriv
        let mut tc =
            TestCtx::new().with_minimum_security_level(crate::usm::user::SecurityLevel::AuthNoPriv);
        let result = tc.try_ctx(None);
        assert!(
            matches!(result, Err(NoUserSecurityLevelError)),
            "expected Err(NoUserSecurityLevelError)"
        );
    }

    #[test]
    fn given_no_user_and_auth_priv_floor_when_new_then_err() {
        // Verifies: REQ-0079 — construction must fail for AuthPriv floor with no user
        let mut tc =
            TestCtx::new().with_minimum_security_level(crate::usm::user::SecurityLevel::AuthPriv);
        let result = tc.try_ctx(None);
        assert!(
            matches!(result, Err(NoUserSecurityLevelError)),
            "expected Err(NoUserSecurityLevelError)"
        );
    }

    #[test]
    fn given_no_user_and_no_auth_no_priv_floor_when_new_then_ok() {
        // Verifies: REQ-0079 — no-user with noAuthNoPriv floor is valid
        let mib = crate::mib::Store::new();
        let mut tc = TestCtx::new();
        let mut ctx = tc
            .try_ctx(None)
            .expect("no-user with noAuthNoPriv floor is a valid configuration");
        // Dispatch garbage bytes to prove the constructed context is functional.
        assert!(
            process_snmpv3_request(b"\x00\x01\x02", &mut ctx, &mib).is_none(),
            "garbage bytes must be silently discarded"
        );
    }

    #[test]
    fn given_user_and_auth_priv_floor_when_new_then_ok() {
        // Verifies: REQ-0079 — a configured user with AuthPriv floor is valid
        let mib = crate::mib::Store::new();
        let alice = test_authpriv_user("alice", &[0x42_u8; 32]);
        let mut tc =
            TestCtx::new().with_minimum_security_level(crate::usm::user::SecurityLevel::AuthPriv);
        let mut ctx = tc
            .try_ctx(Some(&alice))
            .expect("a configured user with AuthPriv floor is a valid configuration");
        // Dispatch garbage bytes to prove the constructed context is functional.
        assert!(
            process_snmpv3_request(b"\x00\x01\x02", &mut ctx, &mib).is_none(),
            "garbage bytes must be silently discarded"
        );
    }

    #[test]
    fn given_garbage_bytes_when_process_snmpv3_request_then_returns_none() {
        // Verifies: REQ-0073 — garbage bytes are silently discarded
        // This is the unit-test equivalent of the (removed) doctest.
        let mib = crate::mib::Store::new();
        let mut tc = TestCtx::new();
        let mut ctx = tc.ctx(None);
        let result = process_snmpv3_request(b"\x00\x01\x02", &mut ctx, &mib);
        assert!(result.is_none(), "garbage bytes must be silently discarded");
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
        let mib = crate::mib::Store::new();
        let auth_key_bytes = [0x42_u8; 32];
        let alice = test_auth_user("alice", &auth_key_bytes);
        let authenticated_frame = build_authenticated_frame(&auth_key_bytes);
        let mut tc = TestCtx::new();
        let result = {
            let mut ctx = tc.ctx(Some(&alice));
            process_snmpv3_request(&authenticated_frame, &mut ctx, &mib)
        };
        assert_eq!(
            tc.wrong_digests, 0,
            "counter must not be incremented on correct HMAC"
        );
        // Verify it's a GetResponse (not a Report)
        let response_bytes = result.expect("correct HMAC must produce a normal response");
        assert_get_response(&response_bytes);
    }

    #[test]
    fn given_wrong_hmac_when_process_then_returns_report_and_increments_counter() {
        // Verifies: REQ-0100, REQ-0102
        let mib = crate::mib::Store::new();
        let alice = test_auth_user("alice", &[0x42_u8; 32]);
        // Build frame with an incorrect MAC (all-0xBB bytes)
        let frame_with_wrong_mac = snmpv3_frames::encode_get_request_with_auth_params(
            test_engine_id(),
            b"alice",
            b"",
            1,
            2,
            test_oid_arcs(),
            0x05,
            &[0xBB_u8; 24],
        );
        let mut tc = TestCtx::new();
        let result = {
            let mut ctx = tc.ctx(Some(&alice));
            process_snmpv3_request(&frame_with_wrong_mac, &mut ctx, &mib)
        };
        assert_eq!(
            tc.wrong_digests, 1,
            "counter must be incremented on wrong HMAC"
        );
        // Verify the Report carries usmStatsWrongDigests
        assert_report_pdu_varbind(
            &result.expect("wrong HMAC must produce a Report response"),
            crate::usm::counters::USM_STATS_WRONG_DIGESTS,
            1,
        );
    }

    #[test]
    fn given_empty_auth_params_with_auth_user_when_process_then_returns_report() {
        // Verifies: REQ-0100 — empty auth_params for an authenticated user is rejected
        let mib = crate::mib::Store::new();
        let alice = test_auth_user("alice", &[0x42_u8; 32]);
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
        assert_eq!(
            tc.wrong_digests, 1,
            "counter must be incremented for empty auth_params"
        );
        assert_report_pdu_varbind(
            &result.expect("empty auth_params must produce a Report response"),
            crate::usm::counters::USM_STATS_WRONG_DIGESTS,
            1,
        );
    }

    #[test]
    fn given_wrong_hmac_without_reportable_flag_when_process_then_discarded_but_counter_incremented()
     {
        // Verifies: REQ-0100 — no Report when reportableFlag not set, counter still increments
        let mib = crate::mib::Store::new();
        let alice = test_auth_user("alice", &[0x42_u8; 32]);
        // flags 0x01 = authFlag only (no reportableFlag)
        let frame = snmpv3_frames::encode_get_request_with_auth_params(
            test_engine_id(),
            b"alice",
            b"",
            1,
            2,
            test_oid_arcs(),
            0x01,
            &[0xBB_u8; 24],
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
        let mib = crate::mib::Store::new();
        let alice = test_auth_user("alice", &[0x42_u8; 32]);
        let frame = snmpv3_frames::encode_get_request_with_auth_params(
            test_engine_id(),
            b"alice",
            b"",
            1,
            2,
            test_oid_arcs(),
            0x05,
            &[0xBB_u8; 24],
        );
        let mut tc = TestCtx::new().with_wrong_digests(u32::MAX);
        let response_bytes = {
            let mut ctx = tc.ctx(Some(&alice));
            process_snmpv3_request(&frame, &mut ctx, &mib)
        }
        .expect("wrong HMAC must produce a Report response even when counter is at max");
        assert_eq!(tc.wrong_digests, u32::MAX, "counter must not overflow");
        assert_report_pdu_varbind(
            &response_bytes,
            crate::usm::counters::USM_STATS_WRONG_DIGESTS,
            u32::MAX,
        );
    }

    // ── zero_auth_params_in_message ──────────────────────────────────────────────

    #[test]
    fn given_offset_and_len_when_zero_auth_params_then_bytes_at_offset_are_zeroed() {
        // Verifies: REQ-0100, REQ-0111 — correct region is zeroed
        let message = b"hello MAC-goes-here world";
        let zeroed = zero_auth_params_in_message(message, 6, 12);
        assert_eq!(&zeroed[..6], b"hello ");
        assert_eq!(&zeroed[6..18], &[0_u8; 12]);
        assert_eq!(&zeroed[18..], b"e world");
    }

    #[test]
    fn given_offset_at_start_when_zero_auth_params_then_prefix_zeroed() {
        // Verifies: REQ-0100, REQ-0111 — boundary at start
        let message = b"MACxxxxrest";
        let zeroed = zero_auth_params_in_message(message, 0, 3);
        assert_eq!(&zeroed[..3], &[0_u8; 3]);
        assert_eq!(&zeroed[3..], b"xxxxrest");
    }

    #[test]
    fn given_offset_at_end_when_zero_auth_params_then_suffix_zeroed() {
        // Verifies: REQ-0100, REQ-0111 — boundary at end
        let message = b"prefixMAC";
        let zeroed = zero_auth_params_in_message(message, 6, 3);
        assert_eq!(&zeroed[..6], b"prefix");
        assert_eq!(&zeroed[6..], &[0_u8; 3]);
    }

    #[test]
    fn given_input_when_zero_auth_params_then_original_message_is_not_modified() {
        // Verifies: REQ-0100, REQ-0111 — original raw_message is not mutated
        let message = b"prefix MAC suffix";
        let zeroed = zero_auth_params_in_message(message, 7, 3);
        assert_eq!(message, b"prefix MAC suffix", "original must be unchanged");
        assert_eq!(&zeroed[7..10], &[0_u8; 3]);
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

        let zeroed_auth_params = vec![0_u8; mac_len];
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
        let mib = crate::mib::Store::new();
        let auth_key_bytes = [0x42_u8; 32];
        let alice = test_auth_user("alice", &auth_key_bytes);
        // boots=1 matches engine_boots=1; time=0 matches engine_time=0 (within 150s window)
        let frame = build_authenticated_frame_with_time(&auth_key_bytes, 1, 0);
        let mut tc = TestCtx::new().with_boots_time(1, 0);
        let result = {
            let mut ctx = tc.ctx(Some(&alice));
            process_snmpv3_request(&frame, &mut ctx, &mib)
        };
        assert_eq!(
            tc.not_in_time_windows, 0,
            "counter must not be incremented for in-window message"
        );
        let response_bytes = result.expect("in-window message must produce a normal response");
        assert_get_response(&response_bytes);
    }

    #[test]
    fn given_out_of_time_window_when_process_then_returns_report_and_increments_counter() {
        // Verifies: REQ-0098
        let mib = crate::mib::Store::new();
        let auth_key_bytes = [0x42_u8; 32];
        let alice = test_auth_user("alice", &auth_key_bytes);
        // boots=2 does not match engine_boots=1 → out of window
        let frame = build_authenticated_frame_with_time(&auth_key_bytes, 2, 0);
        let mut tc = TestCtx::new().with_boots_time(1, 0);
        let result = {
            let mut ctx = tc.ctx(Some(&alice));
            process_snmpv3_request(&frame, &mut ctx, &mib)
        };
        assert_eq!(
            tc.not_in_time_windows, 1,
            "counter must be incremented for out-of-window message"
        );
        let response_bytes = result.expect("out-of-window message must produce a Report response");
        let v3_response = assert_report_pdu_varbind(
            &response_bytes,
            crate::usm::counters::USM_STATS_NOT_IN_TIME_WINDOWS,
            1,
        );
        assert_eq!(
            i32::try_from(v3_response.global_data.message_id.clone()).unwrap(),
            1_i32,
            "Report response must echo the request msg_id"
        );
        assert_usm_params(&v3_response, 1, 0);
    }

    #[test]
    fn given_out_of_time_window_without_reportable_flag_when_process_then_discarded_but_counter_incremented()
     {
        // Verifies: REQ-0098
        let mib = crate::mib::Store::new();
        let auth_key_bytes = [0x42_u8; 32];
        let alice = test_auth_user("alice", &auth_key_bytes);
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
        let mib = crate::mib::Store::new();
        let auth_key_bytes = [0x42_u8; 32];
        let alice = test_auth_user("alice", &auth_key_bytes);
        let frame = build_authenticated_frame_with_time(&auth_key_bytes, 2, 0);
        let mut tc = TestCtx::new()
            .with_not_in_time_windows(u32::MAX)
            .with_boots_time(1, 0);
        let response_bytes = {
            let mut ctx = tc.ctx(Some(&alice));
            process_snmpv3_request(&frame, &mut ctx, &mib)
        }
        .expect("out-of-window must produce a Report response even when counter is at max");
        assert_eq!(
            tc.not_in_time_windows,
            u32::MAX,
            "counter must not overflow"
        );
        assert_report_pdu_varbind(
            &response_bytes,
            crate::usm::counters::USM_STATS_NOT_IN_TIME_WINDOWS,
            u32::MAX,
        );
    }

    #[test]
    fn given_no_auth_user_when_process_then_time_window_check_skipped() {
        // Verifies: REQ-0098
        let mib = crate::mib::Store::new();
        let alice = test_no_auth_user("alice");
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
        assert_eq!(
            tc.not_in_time_windows, 0,
            "counter must not be incremented for noAuthNoPriv messages"
        );
        let response_bytes =
            result.expect("noAuthNoPriv message must pass through regardless of boots/time");
        assert_get_response(&response_bytes);
    }

    #[test]
    fn given_time_difference_out_of_window_when_process_then_returns_report() {
        // Verifies: REQ-0098 — time-based (not boots-based) out-of-window rejection
        let mib = crate::mib::Store::new();
        let auth_key_bytes = [0x42_u8; 32];
        let alice = test_auth_user("alice", &auth_key_bytes);
        // boots=1 matches engine_boots=1, but msg_time=200, engine_time=0 → diff=200 > 150
        let frame = build_authenticated_frame_with_time(&auth_key_bytes, 1, 200);
        let mut tc = TestCtx::new().with_boots_time(1, 0);
        let result = {
            let mut ctx = tc.ctx(Some(&alice));
            process_snmpv3_request(&frame, &mut ctx, &mib)
        };
        assert_eq!(
            tc.not_in_time_windows, 1,
            "counter must be incremented for time-difference out-of-window message"
        );
        assert_report_pdu_varbind(
            &result.expect("time-difference out-of-window message must produce a Report response"),
            crate::usm::counters::USM_STATS_NOT_IN_TIME_WINDOWS,
            1,
        );
    }

    // ── Encrypted PDU path (REQ-0101) ─────────────────────────────────────────

    #[test]
    fn given_encrypted_v3_message_with_no_user_when_process_then_rejected_with_report() {
        // Verifies: REQ-0079
        // F1 fail-closed: an authPriv message (flags 0x07) with no configured user is now
        // rejected at the security-level check before it ever reaches the Encrypted arm.
        // The agent has no credentials, so any message claiming auth or priv is rejected
        // with a Report PDU carrying usmStatsUnsupportedSecLevels. Previously this message
        // reached the Encrypted arm and was silently discarded; the fail-closed fix changes
        // the outcome to a Report response (flags 0x07 includes reportableFlag).
        use rasn_snmp::v3::{
            HeaderData, Message as V3Message, ScopedPduData, USMSecurityParameters,
        };

        let mib = crate::mib::Store::new();
        let fake_ciphertext = b"fake-ciphertext-bytes".to_vec();

        let usm_params = USMSecurityParameters {
            authoritative_engine_id: test_engine_id().to_vec().into(),
            authoritative_engine_boots: 1.into(),
            authoritative_engine_time: 0.into(),
            user_name: rasn::types::OctetString::from(vec![]),
            authentication_parameters: rasn::types::OctetString::from(vec![]),
            privacy_parameters: rasn::types::OctetString::from(vec![0xAA_u8; 8]),
        };
        let security_params = rasn::ber::encode(&usm_params).unwrap();
        let v3_msg = V3Message {
            version: 3.into(),
            global_data: HeaderData {
                message_id: 5.into(),
                max_size: 0xFFFF.into(),
                // authPriv + reportable: 0x03 | 0x04 = 0x07
                flags: rasn::types::OctetString::from(vec![0x07_u8]),
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

        // F1: with no configured user the F1 guard fires at the security-level check,
        // incrementing the counter and returning a Report PDU (reportableFlag is set).
        assert_eq!(
            tc.unsupported_sec_levels, 1,
            "counter must be incremented for no-user authPriv message (fail-closed)"
        );
        let response_bytes =
            result.expect("authPriv message with reportableFlag and no user must produce a Report");
        assert_report_pdu_varbind(
            &response_bytes,
            crate::usm::counters::USM_STATS_UNSUPPORTED_SEC_LEVELS,
            1,
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
        let mut aes_iv = [0_u8; 16];
        aes_iv[0..4].copy_from_slice(&boots.to_be_bytes());
        aes_iv[4..8].copy_from_slice(&time.to_be_bytes());
        aes_iv[8..16].copy_from_slice(&salt);
        let priv_key = SecretKey::new_from_exposed_slice(priv_key_bytes);
        let ciphertext = priv_protocol
            .encrypt(&priv_key, &aes_iv, &scoped_pdu_ber)
            .unwrap();

        // Build the V3Message with zeroed auth_params.
        let zeroed_auth_params = vec![0_u8; mac_len];
        let usm_params = USMSecurityParameters {
            authoritative_engine_id: engine_id.to_vec().into(),
            authoritative_engine_boots: boots.into(),
            authoritative_engine_time: time.into(),
            user_name: b"alice".to_vec().into(),
            authentication_parameters: zeroed_auth_params.into(),
            privacy_parameters: salt.to_vec().into(),
        };
        let security_params = rasn::ber::encode(&usm_params).unwrap();
        let v3_msg = V3Message {
            version: 3.into(),
            global_data: HeaderData {
                message_id: 1.into(),
                max_size: 0xFFFF.into(),
                flags: rasn::types::OctetString::from(vec![0x07_u8]), // authPriv + reportable
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
    fn given_correct_priv_key_when_process_authpriv_then_decrypts_and_responds() {
        // Verifies: REQ-0101, REQ-0107, REQ-0109
        use crate::usm::auth::AuthProtocol;
        use crate::usm::keys::SecretKey;
        use crate::usm::privacy::PrivProtocol;

        let mib = crate::mib::Store::new();
        let auth_key_bytes = [0x42_u8; 32];
        let alice = test_authpriv_user("alice", &auth_key_bytes);
        let frame = build_authpriv_frame(
            &auth_key_bytes,
            &auth_key_bytes[..16],
            PrivProtocol::Aes128,
            1,
            0,
            test_oid_arcs(),
            [0x01_u8; 8],
        );
        let mut tc = TestCtx::new().with_boots_time(1, 0);
        let result = {
            let mut ctx = tc.ctx(Some(&alice));
            process_snmpv3_request(&frame, &mut ctx, &mib)
        };
        assert_eq!(
            tc.decryption_errors, 0,
            "counter must not be incremented on success"
        );
        let response_bytes = result.expect("correct authPriv message must produce a response");
        let v3_response = rasn::ber::decode::<rasn_snmp::v3::Message>(&response_bytes)
            .expect("response must be a valid SNMPv3 message");

        // authPriv response must have flags 0x03 (auth + priv).
        let flags_byte = v3_response
            .global_data
            .flags
            .first()
            .copied()
            .expect("msgFlags must not be empty in any SNMPv3 message");
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
        let mut aes_iv = [0_u8; 16];
        aes_iv[0..4].copy_from_slice(&1_u32.to_be_bytes()); // engine_boots = 1
        aes_iv[4..8].copy_from_slice(&0_u32.to_be_bytes()); // engine_time = 0
        aes_iv[8..16].copy_from_slice(usm_params.privacy_parameters.as_ref());
        let derived_priv_key = SecretKey::new_from_exposed_slice(&auth_key_bytes[..16]);
        let plaintext = PrivProtocol::Aes128
            .decrypt(&derived_priv_key, &aes_iv, ciphertext.as_ref())
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
        let rasn_snmp::v2::VarBindValue::NoSuchObject =
            response_pdu.0.variable_bindings[0].value.clone()
        else {
            panic!("varbind value must be NoSuchObject when OID is not in MIB");
        };

        // Verify the HMAC over the encrypted response is valid.
        let auth_key_for_verify = SecretKey::new_from_exposed_slice(&auth_key_bytes);
        let embedded_mac = usm_params.authentication_parameters.to_vec();
        let auth_params_offset = crate::codec::ber::snmp::decode_v3_envelope(&response_bytes)
            .expect("response must be a valid SNMPv3 envelope")
            .auth_params_offset
            .expect("authenticated response must carry a non-empty auth_params field");
        let mut zeroed_response = response_bytes;
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
        use crate::usm::privacy::PrivProtocol;

        let mib = crate::mib::Store::new();
        let auth_key_bytes = [0x42_u8; 32];
        let alice = test_authpriv_user("alice", &auth_key_bytes);
        // Frame encrypted with a different key so the agent's derived key [0x42; 16] will not match.
        let frame = build_authpriv_frame(
            &auth_key_bytes,
            &[0xAA_u8; 16],
            PrivProtocol::Aes128,
            1,
            0,
            test_oid_arcs(),
            [0x01_u8; 8],
        );
        let mut tc = TestCtx::new().with_boots_time(1, 0);
        let result = {
            let mut ctx = tc.ctx(Some(&alice));
            process_snmpv3_request(&frame, &mut ctx, &mib)
        };
        assert_eq!(
            tc.decryption_errors, 1,
            "counter must be incremented on decryption failure"
        );
        assert_report_pdu_varbind(
            &result.expect("decryption failure must produce a Report response"),
            crate::usm::counters::USM_STATS_DECRYPTION_ERRORS,
            1,
        );
    }

    #[test]
    fn given_invalid_priv_params_length_when_process_authpriv_then_returns_report_and_increments_counter()
     {
        // Verifies: REQ-0101 — msgPrivacyParameters of length != 8 must be rejected
        use crate::usm::auth::AuthProtocol;
        use crate::usm::keys::SecretKey;
        use rasn_snmp::v3::{
            HeaderData, Message as V3Message, ScopedPduData, USMSecurityParameters,
        };

        let mib = crate::mib::Store::new();
        let auth_key_bytes = [0x42_u8; 32];
        let mac_len = AuthProtocol::HmacSha256.mac_len();
        let engine_id = test_engine_id();
        let boots = 1_u32;
        let time = 0_u32;

        let alice = test_authpriv_user("alice", &auth_key_bytes);

        // Build a frame with privacy_parameters of length 4 (not 8) and fake ciphertext.
        let zeroed_auth_params = vec![0_u8; mac_len];
        let usm_params = USMSecurityParameters {
            authoritative_engine_id: engine_id.to_vec().into(),
            authoritative_engine_boots: boots.into(),
            authoritative_engine_time: time.into(),
            user_name: b"alice".to_vec().into(),
            authentication_parameters: zeroed_auth_params.into(),
            // 4-byte salt (invalid — RFC 3826 §2.2 requires exactly 8 bytes)
            privacy_parameters: vec![0x01_u8; 4].into(),
        };
        let security_params = rasn::ber::encode(&usm_params).unwrap();
        let v3_msg = V3Message {
            version: 3.into(),
            global_data: HeaderData {
                message_id: 1.into(),
                max_size: 0xFFFF.into(),
                flags: rasn::types::OctetString::from(vec![0x07_u8]), // authPriv + reportable
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
        assert_eq!(
            tc.decryption_errors, 1,
            "decryption_errors counter must be incremented for invalid priv_params length"
        );
        assert_report_pdu_varbind(
            &result.expect("invalid priv_params length must produce a Report response"),
            crate::usm::counters::USM_STATS_DECRYPTION_ERRORS,
            1,
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
        use rasn_snmp::v3::{
            HeaderData, Message as V3Message, ScopedPduData, USMSecurityParameters,
        };

        let mib = crate::mib::Store::new();
        let auth_key_bytes = [0x42_u8; 32];
        let mac_len = AuthProtocol::HmacSha256.mac_len();
        let salt = [0x01_u8; 8];
        let engine_id = test_engine_id();
        let boots = 1_u32;
        let time = 0_u32;

        let alice = test_authpriv_user("alice", &auth_key_bytes);

        // Build frame with flags = 0x03 (authPriv, no reportableFlag) and corrupted ciphertext.
        let fake_ciphertext = b"corrupted-ciphertext-that-wont-decode-as-scoped-pdu".to_vec();
        let zeroed_auth_params = vec![0_u8; mac_len];
        let usm_params = USMSecurityParameters {
            authoritative_engine_id: engine_id.to_vec().into(),
            authoritative_engine_boots: boots.into(),
            authoritative_engine_time: time.into(),
            user_name: b"alice".to_vec().into(),
            authentication_parameters: zeroed_auth_params.into(),
            privacy_parameters: salt.to_vec().into(),
        };
        let security_params = rasn::ber::encode(&usm_params).unwrap();
        let v3_msg = V3Message {
            version: 3.into(),
            global_data: HeaderData {
                message_id: 1.into(),
                max_size: 0xFFFF.into(),
                flags: rasn::types::OctetString::from(vec![0x03_u8]), // authPriv, no reportableFlag
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
        use crate::usm::privacy::PrivProtocol;

        let mib = crate::mib::Store::new();
        let auth_key_bytes = [0x42_u8; 32];
        let alice = test_authpriv_user("alice", &auth_key_bytes);
        // Frame encrypted with a mismatched key to trigger decryption failure.
        let frame = build_authpriv_frame(
            &auth_key_bytes,
            &[0xAA_u8; 16],
            PrivProtocol::Aes128,
            1,
            0,
            test_oid_arcs(),
            [0x01_u8; 8],
        );
        let mut tc = TestCtx::new()
            .with_boots_time(1, 0)
            .with_decryption_errors(u32::MAX);
        let response_bytes = {
            let mut ctx = tc.ctx(Some(&alice));
            process_snmpv3_request(&frame, &mut ctx, &mib)
        }
        .expect("decryption failure must produce a Report response even when counter is at max");
        assert_eq!(tc.decryption_errors, u32::MAX, "counter must not overflow");
        assert_report_pdu_varbind(
            &response_bytes,
            crate::usm::counters::USM_STATS_DECRYPTION_ERRORS,
            u32::MAX,
        );
    }

    #[test]
    fn given_security_model_not_usm_when_processed_then_returns_report_and_increments_counter() {
        // Verifies: REQ-0115
        let mib = crate::mib::Store::new();
        // The reportable flag (0x04) is set by snmpv3_frames::encode_get_request,
        // so patching security_model should produce a Report PDU response.
        let frame = build_frame_with_non_usm_security_model();
        let mut tc = TestCtx::new();
        let response = {
            let mut ctx = tc.ctx(None);
            process_snmpv3_request(&frame, &mut ctx, &mib)
        };
        let report_bytes =
            response.expect("should return a Report PDU for unsupported security model");
        assert_eq!(tc.unknown_security_models, 1);
        // Verify the Report PDU carries the snmpUnknownSecurityModels OID.
        assert_report_pdu_varbind(&report_bytes, SNMP_UNKNOWN_SECURITY_MODELS_OID, 1);
    }

    #[test]
    fn given_security_model_not_usm_and_no_reportable_flag_when_processed_then_silent_discard() {
        // Verifies: REQ-0115
        let mib = crate::mib::Store::new();
        // Start from the patched (non-USM) frame and also clear the reportable flag.
        let mut frame = build_frame_with_non_usm_security_model();
        clear_reportable_flag(&mut frame);

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

    // Clears the reportable bit (0x04) in the msgFlags field of an SNMPv3 frame.
    // msgFlags is BER-encoded as OCTET STRING: tag 0x04, length 0x01, value byte.
    // Searching for [0x04, 0x01] locates the TLV prefix; the byte immediately following
    // is the flags value. This pattern is unique in a well-formed SNMPv3 frame because
    // the headerData SEQUENCE contains msgFlags as the only single-byte OCTET STRING.
    fn clear_reportable_flag(frame: &mut [u8]) {
        let flags_tlv: &[u8] = &[0x04, 0x01];
        let flags_pos = frame
            .windows(2)
            .enumerate()
            .find(|(_, w)| *w == flags_tlv)
            .map(|(i, _)| i + 2)
            .expect("msgFlags must be present in frame");
        frame[flags_pos] &= !0x04_u8;
    }

    // Build a GetRequest frame with the security_model field patched from 3 (USM) to 4
    // (an unsupported model). The version field also encodes as 02 01 03, so this skips
    // the first occurrence and patches the second — which is the security_model in HeaderData.
    fn build_frame_with_non_usm_security_model() -> Vec<u8> {
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
        frame
    }

    // ── GetBulk msgMaxSize plumbing (REQ-0133) ───────────────────────────────

    #[test]
    fn given_small_msg_max_size_when_get_bulk_then_response_truncated_compared_to_large_limit() {
        // Verifies: REQ-0133
        // A GETBULK request with a small msgMaxSize must produce fewer varbinds than
        // the same request with a large msgMaxSize, proving that max_size is plumbed
        // through dispatch into handle_get_bulk.
        let mut mib = crate::mib::Store::new();
        // Populate 20 OIDs with 200-byte values so there is plenty to walk.
        for i in 0_u32..20 {
            mib.set(
                format!("1.3.6.1.2.1.1.{i}.0").parse().unwrap(),
                crate::codec::Value::OctetString(vec![0xAA; 200]),
            );
        }

        let engine_id = test_engine_id();
        let oid_arcs: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 0, 0];

        // Decode a GetBulk response and return the number of varbinds it contains.
        let count_response_varbinds = |response_bytes: &[u8]| -> usize {
            let v3_response = rasn::ber::decode::<rasn_snmp::v3::Message>(response_bytes)
                .expect("response must be a valid SNMPv3 message");
            let rasn_snmp::v3::ScopedPduData::CleartextPdu(scoped_pdu) = v3_response.scoped_data
            else {
                panic!("response must contain a cleartext ScopedPDU");
            };
            let rasn_snmp::v2::Pdus::Response(resp_pdu) = scoped_pdu.data else {
                panic!("response must be a GetResponse PDU");
            };
            resp_pdu.0.variable_bindings.len()
        };

        // Request with a generous size limit — all 20 repetitions should be returned
        // (subject to the max_repetitions_cap, which is MAX_BULK_REPETITIONS).
        let large_frame = snmpv3_frames::encode_get_bulk_request_with_max_size(
            engine_id, b"", 1, 1, 0, 20, oid_arcs, 0x7FFF,
        );
        let full_varbind_count = {
            let mut tc = TestCtx::new();
            let response_bytes = {
                let mut ctx = tc.ctx(None);
                process_snmpv3_request(&large_frame, &mut ctx, &mib)
            }
            .expect("large-limit GetBulk must produce a response");
            count_response_varbinds(&response_bytes)
        };

        // Request with a small size limit — the repeating section must be truncated.
        let small_frame = snmpv3_frames::encode_get_bulk_request_with_max_size(
            engine_id, b"", 2, 2, 0, 20, oid_arcs, 1500,
        );
        let truncated_varbind_count = {
            let mut tc = TestCtx::new();
            let response_bytes = {
                let mut ctx = tc.ctx(None);
                process_snmpv3_request(&small_frame, &mut ctx, &mib)
            }
            .expect("small-limit GetBulk must produce a response");
            count_response_varbinds(&response_bytes)
        };

        assert!(
            truncated_varbind_count < full_varbind_count,
            "small msgMaxSize ({truncated_varbind_count} varbinds) must yield fewer varbinds \
             than large msgMaxSize ({full_varbind_count} varbinds)"
        );
    }

    #[test]
    fn given_unknown_security_models_counter_at_max_when_incremented_then_does_not_overflow() {
        // Verifies: REQ-0115
        let mib = crate::mib::Store::new();
        let frame = build_frame_with_non_usm_security_model();
        let mut tc = TestCtx::new().with_unknown_security_models(u32::MAX);
        let response_bytes = {
            let mut ctx = tc.ctx(None);
            process_snmpv3_request(&frame, &mut ctx, &mib)
        }
        .expect(
            "unsupported security model must produce a Report response even when counter is at max",
        );
        assert_eq!(
            tc.unknown_security_models,
            u32::MAX,
            "counter must not overflow"
        );
        assert_report_pdu_varbind(&response_bytes, SNMP_UNKNOWN_SECURITY_MODELS_OID, u32::MAX);
    }
}
