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
use crate::usm::engine_time::{EngineBoots, EngineTime};
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

    check_message_envelope(&v3_msg, ctx)?;
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
            &DecryptionParams {
                msg_id: v3_msg.msg_id,
                security_flags: v3_msg.usm.security_flags,
                priv_params: &v3_msg.usm.priv_params,
                auth_engine_boots: EngineBoots::from(v3_msg.usm.auth_engine_boots),
                auth_engine_time: EngineTime::from(v3_msg.usm.auth_engine_time),
            },
            &ciphertext,
        )?,
    };

    dispatch_pdu_and_encode_response(
        ctx,
        &ResponseEnvelope {
            msg_id: v3_msg.msg_id,
            max_size: v3_msg.max_size,
            user_name: &v3_msg.user_name,
            context_name: &response_context_name,
        },
        mib,
        inbound_pdu,
    )
    .ok_or(Reject::Discard)
}

// Pre-USM-user envelope checks: security model, discovery probe, and engine-ID.
// These run in RFC 3412 §7.2 order before any per-user validation.
// Implements: REQ-0115, REQ-0093, REQ-0104
fn check_message_envelope(
    v3_msg: &crate::codec::V3InboundMessage<'_>,
    ctx: &mut DispatchContext<'_>,
) -> Result<(), Reject> {
    // RFC 3412 §7.2 step 2: reject messages with unsupported security models (REQ-0115).
    if !v3_msg.security_model.is_usm() {
        return Err(emit_report_response(
            ctx,
            |inputs| &mut inputs.unknown_security_models_counter,
            &UNKNOWN_SECURITY_MODELS_OID,
            "unknown security model",
            v3_msg.msg_id,
            v3_msg.usm.security_flags,
        ));
    }
    // REQ-0093: engine-ID discovery probe — the manager sent an empty
    // msgAuthoritativeEngineID. The Report response carries the agent's
    // authoritative engine state so the manager can learn the engine ID,
    // boots, and approximate time.
    if v3_msg.usm.auth_engine_id.is_empty() {
        return Err(emit_report_response(
            ctx,
            |inputs| &mut inputs.unknown_engine_ids_counter,
            &UNKNOWN_ENGINE_IDS_OID,
            "engine-ID discovery probe",
            v3_msg.msg_id,
            v3_msg.usm.security_flags,
        ));
    }
    // REQ-0104: contextEngineID mismatch — the ScopedPDU's contextEngineID does not match the agent's snmpEngineID.
    if v3_msg.engine_id != ctx.inputs.engine_id {
        return Err(emit_report_response(
            ctx,
            |inputs| &mut inputs.unknown_engine_ids_counter,
            &UNKNOWN_ENGINE_IDS_OID,
            "unknown engine ID",
            v3_msg.msg_id,
            v3_msg.usm.security_flags,
        ));
    }
    Ok(())
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
    let name_matches = ctx
        .inputs
        .usm_user
        .is_none_or(|user| v3_msg.user_name == user.name().as_bytes());
    if !name_matches {
        return Err(emit_report_response(
            ctx,
            |inputs| &mut inputs.unknown_user_names_counter,
            &UNKNOWN_USER_NAMES_OID,
            "unknown user name",
            v3_msg.msg_id,
            v3_msg.usm.security_flags,
        ));
    }
    Ok(())
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
    if ctx.inputs.should_reject_security_level(msg_level) {
        return Err(emit_report_response(
            ctx,
            |inputs| &mut inputs.unsupported_sec_levels_counter,
            &UNSUPPORTED_SEC_LEVELS_OID,
            "unsupported security level",
            v3_msg.msg_id,
            v3_msg.usm.security_flags,
        ));
    }
    Ok(())
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
    let hmac_valid = verify_hmac(
        auth_protocol,
        auth_key,
        &HmacInput {
            raw_message: v3_msg.raw_message,
            auth_params: &v3_msg.usm.auth_params,
            auth_params_offset: v3_msg.auth_params_offset,
        },
    );
    if !hmac_valid {
        return Err(emit_report_response(
            ctx,
            |inputs| &mut inputs.wrong_digests_counter,
            &WRONG_DIGESTS_OID,
            "wrong digest",
            v3_msg.msg_id,
            v3_msg.usm.security_flags,
        ));
    }
    Ok(())
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
    let in_time_window = crate::usm::time_window::is_in_time_window(
        EngineBoots::from(v3_msg.usm.auth_engine_boots),
        EngineTime::from(v3_msg.usm.auth_engine_time),
        ctx.inputs.engine_boots,
        ctx.inputs.engine_time,
    );
    if !in_time_window {
        return Err(emit_report_response(
            ctx,
            |inputs| &mut inputs.not_in_time_windows_counter,
            &NOT_IN_TIME_WINDOWS_OID,
            "not-in-time-window",
            v3_msg.msg_id,
            v3_msg.usm.security_flags,
        ));
    }
    Ok(())
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

// Message-level fields needed for response encoding.
#[derive(Debug)]
struct ResponseEnvelope<'a> {
    msg_id: i32,
    max_size: i32,
    user_name: &'a [u8],
    // May come from the outer message (cleartext) or the decrypted ScopedPDU (authPriv).
    context_name: &'a [u8],
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
    envelope: &ResponseEnvelope<'_>,
    mib: &crate::mib::Store,
    inbound_pdu: crate::codec::InboundPdu,
) -> Option<Vec<u8>> {
    let response = match inbound_pdu {
        crate::codec::InboundPdu::GetRequest(req) => request::handle_get(&req, mib),
        crate::codec::InboundPdu::GetNextRequest(req) => request::handle_get_next(&req, mib),
        crate::codec::InboundPdu::GetBulkRequest(req) => {
            // Bound response by the lesser of the sender's declared max_size and
            // the agent's own frame limit, then convert to usize for size arithmetic.
            // max_size is validated >= 484 during decode (RFC 3412 §7.2 step 5), so
            // it is always positive; unwrap_or(0) is defence-in-depth only.
            let effective_max_size = usize::try_from(envelope.max_size)
                .unwrap_or(0)
                .min(MAX_FRAME_SIZE);
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
        envelope.msg_id,
        ctx.inputs.engine_id,
        envelope.user_name,
        envelope.context_name,
        u32::from(ctx.inputs.engine_boots),
        u32::from(ctx.inputs.engine_time),
        response_auth,
        response_priv,
        &response,
    )
    .inspect_err(|encode_error| debug!("failed to encode SNMPv3 response: {encode_error}"))
    .ok()
}

// Bundles message-level fields for HMAC verification.
#[derive(Debug)]
struct HmacInput<'a> {
    raw_message: &'a [u8],
    auth_params: &'a [u8],
    auth_params_offset: Option<usize>,
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
    hmac: &HmacInput<'_>,
) -> bool {
    let Some(offset) = hmac.auth_params_offset else {
        trace!("auth_params_offset absent, treating as HMAC failure");
        return false;
    };
    let zeroed = zero_auth_params_in_message(hmac.raw_message, offset, hmac.auth_params.len());
    auth_protocol
        .verify_mac(auth_key, &zeroed, hmac.auth_params)
        .is_ok()
}

// Bundles USM fields needed for decryption and error reporting.
#[derive(Debug)]
struct DecryptionParams<'a> {
    msg_id: i32,
    security_flags: u8,
    priv_params: &'a [u8],
    auth_engine_boots: EngineBoots,
    auth_engine_time: EngineTime,
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
    decryption: &DecryptionParams<'_>,
    ciphertext: &[u8],
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
    if decryption.priv_params.len() != 8 {
        debug!(
            "msgPrivacyParameters length {} != 8",
            decryption.priv_params.len()
        );
        // Implements: REQ-0101
        return Err(emit_report_response(
            ctx,
            |inputs| &mut inputs.decryption_errors_counter,
            &DECRYPTION_ERRORS_OID,
            "decryption error",
            decryption.msg_id,
            decryption.security_flags,
        ));
    }

    // Implements: REQ-0109
    // IV = engineBoots (4 BE) || engineTime (4 BE) || salt (8 bytes) per RFC 3826 §2.2.
    let mut aes_iv = [0_u8; 16];
    aes_iv[0..4].copy_from_slice(&u32::from(decryption.auth_engine_boots).to_be_bytes());
    aes_iv[4..8].copy_from_slice(&u32::from(decryption.auth_engine_time).to_be_bytes());
    aes_iv[8..16].copy_from_slice(decryption.priv_params);

    let Ok(scoped_pdu_bytes) = priv_protocol.decrypt(priv_key, &aes_iv, ciphertext) else {
        debug!("AES-CFB128 decryption failed");
        // Implements: REQ-0101
        return Err(emit_report_response(
            ctx,
            |inputs| &mut inputs.decryption_errors_counter,
            &DECRYPTION_ERRORS_OID,
            "decryption error",
            decryption.msg_id,
            decryption.security_flags,
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
            decryption.msg_id,
            decryption.security_flags,
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
            decryption.msg_id,
            decryption.security_flags,
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

    // Run dispatch with a single-shot context: build ctx from `tc` and `usm_user`,
    // call `process_snmpv3_request`, then return the result. Eliminates the
    // repeated { let mut ctx = tc.ctx(...); process_snmpv3_request(...) } block.
    fn run_dispatch(
        tc: &mut TestCtx,
        usm_user: Option<&crate::usm::user::UsmUser>,
        frame: &[u8],
        mib: &crate::mib::Store,
    ) -> Option<Vec<u8>> {
        let mut ctx = tc.ctx(usm_user);
        process_snmpv3_request(frame, &mut ctx, mib)
    }

    // Assert that a dispatch result was silently discarded (None) and that the
    // named counter was incremented by exactly one from zero.
    fn assert_discarded_and_counter_incremented(
        result: Option<&Vec<u8>>,
        counter: crate::usm::counters::UsmStatsCounter,
    ) {
        assert!(result.is_none(), "must be silently discarded");
        assert_eq!(
            counter.get(),
            1,
            "counter must be incremented even when no Report is sent"
        );
    }

    // Parameters for building an authPriv GetRequest frame.
    // Only the fields that vary across tests are kept here; invariant values
    // (protocol, OID, salt, flags) are constants inside build_authpriv_frame_inner.
    struct AuthPrivFrameParams<'a> {
        auth_key_bytes: &'a [u8],
        // Override priv_key_bytes via with_priv_key to exercise wrong-key scenarios.
        // Defaults to the first 16 bytes of auth_key_bytes (the convention throughout
        // the dispatch tests).
        priv_key_bytes: Option<&'a [u8]>,
        boots: u32,
        time: u32,
    }

    impl<'a> AuthPrivFrameParams<'a> {
        fn new(auth_key_bytes: &'a [u8]) -> Self {
            Self {
                auth_key_bytes,
                priv_key_bytes: None,
                boots: 1,
                time: 0,
            }
        }

        fn with_priv_key(mut self, priv_key_bytes: &'a [u8]) -> Self {
            self.priv_key_bytes = Some(priv_key_bytes);
            self
        }

        fn with_boots_time(mut self, boots: u32, time: u32) -> Self {
            self.boots = boots;
            self.time = time;
            self
        }

        fn build(&self) -> Vec<u8> {
            build_authpriv_frame_inner(self)
        }
    }

    // Holds the outer V3Message assembly context for an authPriv frame.
    // privacy_parameters is Vec<u8> rather than [u8; 8] so that malformed-length
    // test scenarios can supply a shorter salt without a separate helper.
    struct AuthPrivAssembly {
        boots: u32,
        time: u32,
        privacy_parameters: Vec<u8>,
        msg_flags_byte: u8,
        ciphertext: Vec<u8>,
    }

    // Build a complete authPriv GetRequest frame. Separated from AuthPrivFrameParams
    // so the frame-assembly logic can be read top-down.
    fn build_authpriv_frame_inner(params: &AuthPrivFrameParams<'_>) -> Vec<u8> {
        use crate::usm::auth::AuthProtocol;
        use crate::usm::keys::SecretKey;
        use rasn_snmp::v2::{GetRequest as RasnGetRequest, Pdu, VarBind, VarBindValue};
        use rasn_snmp::v3::ScopedPdu;
        use std::borrow::Cow;

        // Invariant values shared by all standard authPriv test frames.
        const SALT: [u8; 8] = [0x01_u8; 8];
        const MSG_FLAGS: u8 = 0x07;

        let engine_id = test_engine_id();
        let rasn_oid =
            rasn::types::ObjectIdentifier::new_unchecked(Cow::Owned(test_oid_arcs().to_vec()));
        let scoped_pdu = ScopedPdu {
            engine_id: engine_id.to_vec().into(),
            name: vec![].into(),
            data: rasn_snmp::v2::Pdus::GetRequest(RasnGetRequest(Pdu {
                request_id: 1,
                error_status: 0,
                error_index: 0,
                variable_bindings: vec![VarBind {
                    name: rasn_oid,
                    value: VarBindValue::Unspecified,
                }],
            })),
        };
        let scoped_pdu_ber = rasn::ber::encode(&scoped_pdu).unwrap();
        let mut aes_iv = [0_u8; 16];
        aes_iv[0..4].copy_from_slice(&params.boots.to_be_bytes());
        aes_iv[4..8].copy_from_slice(&params.time.to_be_bytes());
        aes_iv[8..16].copy_from_slice(&SALT);
        // When no override key is supplied, derive from the first 16 bytes of auth_key_bytes.
        let priv_key_slice = params
            .priv_key_bytes
            .unwrap_or(&params.auth_key_bytes[..16]);
        let priv_key = SecretKey::new_from_exposed_slice(priv_key_slice);
        let ciphertext = crate::usm::privacy::PrivProtocol::Aes128
            .encrypt(&priv_key, &aes_iv, &scoped_pdu_ber)
            .unwrap();
        let mac_len = AuthProtocol::HmacSha256.mac_len();
        splice_hmac_into_authpriv_frame(
            params.auth_key_bytes,
            mac_len,
            engine_id,
            &AuthPrivAssembly {
                boots: params.boots,
                time: params.time,
                privacy_parameters: SALT.to_vec(),
                msg_flags_byte: MSG_FLAGS,
                ciphertext,
            },
        )
    }

    // Assemble the V3Message with zeroed auth_params, then compute and splice in the real HMAC.
    fn splice_hmac_into_authpriv_frame(
        auth_key_bytes: &[u8],
        mac_len: usize,
        engine_id: &[u8],
        assembly: &AuthPrivAssembly,
    ) -> Vec<u8> {
        use rasn_snmp::v3::{
            HeaderData, Message as V3Message, ScopedPduData, USMSecurityParameters,
        };

        let usm_params = USMSecurityParameters {
            authoritative_engine_id: engine_id.to_vec().into(),
            authoritative_engine_boots: assembly.boots.into(),
            authoritative_engine_time: assembly.time.into(),
            user_name: b"alice".to_vec().into(),
            authentication_parameters: vec![0_u8; mac_len].into(),
            privacy_parameters: assembly.privacy_parameters.clone().into(),
        };
        let frame_with_zeros = rasn::ber::encode(&V3Message {
            version: 3.into(),
            global_data: HeaderData {
                message_id: 1.into(),
                max_size: 0xFFFF.into(),
                flags: rasn::types::OctetString::from(vec![assembly.msg_flags_byte]),
                security_model: 3.into(),
            },
            security_parameters: rasn::ber::encode(&usm_params).unwrap().into(),
            scoped_data: ScopedPduData::EncryptedPdu(rasn::types::OctetString::from(
                assembly.ciphertext.clone(),
            )),
        })
        .unwrap();
        splice_hmac_into_frame(auth_key_bytes, frame_with_zeros)
    }

    // Compute HMAC-SHA-256 over frame_with_zeros and splice it in at the
    // auth_params offset found by the BER envelope parser. Returns the
    // authenticated frame.
    fn splice_hmac_into_frame(auth_key_bytes: &[u8], frame_with_zeros: Vec<u8>) -> Vec<u8> {
        use crate::usm::auth::AuthProtocol;
        use crate::usm::keys::SecretKey;

        let mac_len = AuthProtocol::HmacSha256.mac_len();
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

    // Keys and expected engine state for verifying an authPriv response.
    struct AuthPrivResponseParams<'a> {
        auth_key_bytes: &'a [u8],
        priv_key_bytes: &'a [u8],
        expected_boots: u32,
        expected_time: u32,
    }

    // Decrypt a response ScopedPdu and return it, verifying the HMAC over the
    // encrypted response in the process.
    fn decrypt_and_verify_authpriv_response(
        response_bytes: &[u8],
        params: &AuthPrivResponseParams<'_>,
    ) -> rasn_snmp::v3::ScopedPdu {
        use crate::usm::auth::AuthProtocol;
        use crate::usm::keys::SecretKey;
        use crate::usm::privacy::PrivProtocol;

        let v3_response = rasn::ber::decode::<rasn_snmp::v3::Message>(response_bytes)
            .expect("response must be a valid SNMPv3 message");
        let rasn_snmp::v3::ScopedPduData::EncryptedPdu(ciphertext) = v3_response.scoped_data else {
            panic!("authPriv response must contain an encrypted ScopedPDU");
        };
        let usm_params: rasn_snmp::v3::USMSecurityParameters =
            rasn::ber::decode(v3_response.security_parameters.as_ref())
                .expect("response must have valid USM security parameters");
        assert_eq!(
            usm_params.privacy_parameters.len(),
            8,
            "response privacy_parameters must be 8 bytes"
        );
        let mut aes_iv = [0_u8; 16];
        aes_iv[0..4].copy_from_slice(&params.expected_boots.to_be_bytes());
        aes_iv[4..8].copy_from_slice(&params.expected_time.to_be_bytes());
        aes_iv[8..16].copy_from_slice(usm_params.privacy_parameters.as_ref());
        let derived_priv_key = SecretKey::new_from_exposed_slice(params.priv_key_bytes);
        let plaintext = PrivProtocol::Aes128
            .decrypt(&derived_priv_key, &aes_iv, ciphertext.as_ref())
            .expect("response decryption must succeed");

        // Verify HMAC over the encrypted response.
        let auth_key_for_verify = SecretKey::new_from_exposed_slice(params.auth_key_bytes);
        let embedded_mac = usm_params.authentication_parameters.to_vec();
        let auth_params_offset = crate::codec::ber::snmp::decode_v3_envelope(response_bytes)
            .expect("response must be a valid SNMPv3 envelope")
            .auth_params_offset
            .expect("authenticated response must carry a non-empty auth_params field");
        let mut zeroed_response = response_bytes.to_vec();
        zeroed_response[auth_params_offset..auth_params_offset + embedded_mac.len()].fill(0);
        AuthProtocol::HmacSha256
            .verify_mac(&auth_key_for_verify, &zeroed_response, &embedded_mac)
            .expect("response HMAC must verify");

        rasn::ber::decode(&plaintext).expect("decrypted bytes must be a valid ScopedPdu")
    }

    // Build an authPriv frame where privacy_parameters has a non-standard length,
    // authenticated with the given key so dispatch proceeds past HMAC to the decryption arm.
    fn build_authpriv_frame_with_short_priv_params(
        auth_key_bytes: &[u8],
        boots: u32,
        time: u32,
    ) -> Vec<u8> {
        use crate::usm::auth::AuthProtocol;
        // 4-byte salt (invalid — RFC 3826 §2.2 requires exactly 8 bytes)
        splice_hmac_into_authpriv_frame(
            auth_key_bytes,
            AuthProtocol::HmacSha256.mac_len(),
            test_engine_id(),
            &AuthPrivAssembly {
                boots,
                time,
                privacy_parameters: vec![0x01_u8; 4],
                msg_flags_byte: 0x07,
                ciphertext: b"fake-ciphertext".to_vec(),
            },
        )
    }

    // Build a no-reportable-flag authPriv frame with corrupted ciphertext, authenticated
    // so that dispatch reaches the decryption arm and then fails to decode the ScopedPDU.
    fn build_authpriv_frame_no_report_corrupted_ciphertext(auth_key_bytes: &[u8]) -> Vec<u8> {
        use crate::usm::auth::AuthProtocol;
        // flags 0x03 = authPriv, no reportableFlag
        splice_hmac_into_authpriv_frame(
            auth_key_bytes,
            AuthProtocol::HmacSha256.mac_len(),
            test_engine_id(),
            &AuthPrivAssembly {
                boots: 1,
                time: 0,
                privacy_parameters: [0x01_u8; 8].to_vec(),
                msg_flags_byte: 0x03,
                ciphertext: b"corrupted-ciphertext-that-wont-decode-as-scoped-pdu".to_vec(),
            },
        )
    }

    // Build a no-user authPriv frame (flags 0x07) carrying fake ciphertext.
    fn build_no_user_authpriv_frame() -> Vec<u8> {
        use rasn_snmp::v3::{
            HeaderData, Message as V3Message, ScopedPduData, USMSecurityParameters,
        };
        let usm_params = USMSecurityParameters {
            authoritative_engine_id: test_engine_id().to_vec().into(),
            authoritative_engine_boots: 1.into(),
            authoritative_engine_time: 0.into(),
            user_name: rasn::types::OctetString::from(vec![]),
            authentication_parameters: rasn::types::OctetString::from(vec![]),
            privacy_parameters: rasn::types::OctetString::from(vec![0xAA_u8; 8]),
        };
        rasn::ber::encode(&V3Message {
            version: 3.into(),
            global_data: HeaderData {
                message_id: 5.into(),
                max_size: 0xFFFF.into(),
                flags: rasn::types::OctetString::from(vec![0x07_u8]),
                security_model: 3.into(),
            },
            security_parameters: rasn::ber::encode(&usm_params).unwrap().into(),
            scoped_data: ScopedPduData::EncryptedPdu(rasn::types::OctetString::from(
                b"fake-ciphertext-bytes".to_vec(),
            )),
        })
        .unwrap()
    }

    // Test helper that owns counter storage and produces a DispatchContext,
    // eliminating the repeated boilerplate of seven local counter declarations.
    struct TestCtx {
        unknown_engine_ids: crate::usm::counters::UsmStatsCounter,
        unknown_user_names: crate::usm::counters::UsmStatsCounter,
        unsupported_sec_levels: crate::usm::counters::UsmStatsCounter,
        wrong_digests: crate::usm::counters::UsmStatsCounter,
        not_in_time_windows: crate::usm::counters::UsmStatsCounter,
        decryption_errors: crate::usm::counters::UsmStatsCounter,
        unknown_security_models: crate::usm::counters::UsmStatsCounter,
        engine_boots: u32,
        engine_time: u32,
        minimum_security_level: crate::usm::user::SecurityLevel,
    }

    impl TestCtx {
        fn new() -> Self {
            Self {
                unknown_engine_ids: crate::usm::counters::UsmStatsCounter::default(),
                unknown_user_names: crate::usm::counters::UsmStatsCounter::default(),
                unsupported_sec_levels: crate::usm::counters::UsmStatsCounter::default(),
                wrong_digests: crate::usm::counters::UsmStatsCounter::default(),
                not_in_time_windows: crate::usm::counters::UsmStatsCounter::default(),
                decryption_errors: crate::usm::counters::UsmStatsCounter::default(),
                unknown_security_models: crate::usm::counters::UsmStatsCounter::default(),
                engine_boots: 1,
                engine_time: 0,
                minimum_security_level: crate::usm::user::SecurityLevel::NoAuthNoPriv,
            }
        }

        fn with_unknown_engine_ids(mut self, initial_count: u32) -> Self {
            self.unknown_engine_ids = crate::usm::counters::UsmStatsCounter::from(initial_count);
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
                engine_boots: EngineBoots::from(self.engine_boots),
                engine_time: EngineTime::from(self.engine_time),
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
        let response_bytes = run_dispatch(&mut tc, None, &probe_frame, &mib)
            .expect("discovery probe must produce a Report response");
        assert_eq!(
            tc.unknown_engine_ids.get(),
            1,
            "counter must be incremented for discovery probe"
        );
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
        run_dispatch(&mut tc, None, &probe_frame, &mib);
        run_dispatch(&mut tc, None, &probe_frame, &mib);
        assert_eq!(tc.unknown_engine_ids.get(), 7);
    }

    #[test]
    fn given_normal_request_when_process_then_counter_unchanged() {
        // Verifies: REQ-0093, REQ-0104 — counter unchanged for correct engine ID
        let mib = crate::mib::Store::new();
        let oid: crate::codec::Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        let frame = snmpv3_frames::encode_get_request(test_engine_id(), b"", 1, 2, oid.as_slice());
        let mut tc = TestCtx::new();
        run_dispatch(&mut tc, None, &frame, &mib);
        assert_eq!(tc.unknown_engine_ids.get(), 0);
    }

    #[test]
    fn given_discovery_probe_without_reportable_flag_when_process_then_discarded() {
        // Verifies: REQ-0093 — non-reportable probes are silently discarded
        let mib = crate::mib::Store::new();
        let probe_frame = snmpv3_frames::encode_discovery_probe_no_report();
        let mut tc = TestCtx::new().with_boots_time(3, 100);
        let result = run_dispatch(&mut tc, None, &probe_frame, &mib);
        assert!(
            result.is_none(),
            "probe without reportableFlag must be silently discarded"
        );
        assert_eq!(
            tc.unknown_engine_ids.get(),
            1,
            "counter must be incremented even for non-reportable probe"
        );
    }

    // ── contextEngineID mismatch (REQ-0104) ──────────────────────────────────

    #[test]
    fn given_wrong_context_engine_id_when_process_then_returns_report_and_increments_counter() {
        // Verifies: REQ-0104
        let mib = crate::mib::Store::new();
        // A non-empty but wrong engine ID: not a discovery probe (auth_engine_id is non-empty),
        // but the engine ID does not match the agent's.
        let frame = snmpv3_frames::encode_get_request(
            b"\x80\x00\x1f\x88\x04wrong",
            b"",
            1,
            2,
            test_oid_arcs(),
        );
        let mut tc = TestCtx::new().with_boots_time(3, 100);
        let response_bytes = run_dispatch(&mut tc, None, &frame, &mib)
            .expect("contextEngineID mismatch must produce a Report response");
        assert_eq!(
            tc.unknown_engine_ids.get(),
            1,
            "counter must be incremented on contextEngineID mismatch"
        );
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
        let result = run_dispatch(&mut tc, None, &frame, &mib);
        assert_discarded_and_counter_incremented(result.as_ref(), tc.unknown_engine_ids);
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
        let response_bytes = run_dispatch(&mut tc, None, &frame, &mib).expect(
            "contextEngineID mismatch must produce a Report response even when msgAuthoritativeEngineID matches"
        );
        assert_eq!(
            tc.unknown_engine_ids.get(),
            1,
            "counter must be incremented on contextEngineID mismatch"
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
        let frame = snmpv3_frames::encode_get_request(test_engine_id(), b"", 1, 2, test_oid_arcs());
        let mut tc = TestCtx::new();
        let response_bytes = run_dispatch(&mut tc, None, &frame, &mib)
            .expect("request must pass through when no USM user is configured");
        assert_eq!(
            tc.unknown_user_names.get(),
            0,
            "counter must not be incremented"
        );
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
        let response_bytes = run_dispatch(&mut tc, Some(&alice), &frame, &mib)
            .expect("matching user name must produce a response");
        assert_eq!(
            tc.unknown_user_names.get(),
            0,
            "counter must not be incremented on match"
        );
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
        let response_bytes = run_dispatch(&mut tc, Some(&alice), &frame, &mib)
            .expect("mismatched user name must produce a Report response");
        assert_eq!(
            tc.unknown_user_names.get(),
            1,
            "counter must be incremented on mismatch"
        );
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
        let result = run_dispatch(&mut tc, Some(&alice), &frame, &mib);
        assert_discarded_and_counter_incremented(result.as_ref(), tc.unknown_user_names);
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
        let response_bytes = run_dispatch(&mut tc, Some(&alice), &frame, &mib)
            .expect("matching security level must produce a response");
        assert_eq!(
            tc.unsupported_sec_levels.get(),
            0,
            "counter must not be incremented on match"
        );
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
            0x05,
        );
        let mut tc = TestCtx::new();
        let response_bytes = run_dispatch(&mut tc, Some(&alice), &frame, &mib)
            .expect("ceiling violation must produce a Report response");
        assert_eq!(
            tc.unsupported_sec_levels.get(),
            1,
            "counter must be incremented on ceiling violation"
        );
        let v3_response = assert_report_pdu_varbind(
            &response_bytes,
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
        let result = run_dispatch(&mut tc, Some(&alice), &frame, &mib);
        assert_discarded_and_counter_incremented(result.as_ref(), tc.unsupported_sec_levels);
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
        let response_bytes = run_dispatch(&mut tc, None, &frame, &mib)
            .expect("authNoPriv message with reportableFlag set must produce a Report response");
        assert_eq!(
            tc.unsupported_sec_levels.get(),
            1,
            "counter must be incremented for no-user auth/priv message (fail-closed)"
        );
        assert_report_pdu_varbind(
            &response_bytes,
            crate::usm::counters::USM_STATS_UNSUPPORTED_SEC_LEVELS,
            1,
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
        let response_bytes = run_dispatch(&mut tc, Some(&alice), &frame, &mib)
            .expect("invalid msgFlags combination must produce a Report response");
        assert_eq!(
            tc.unsupported_sec_levels.get(),
            1,
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
        let response_bytes = run_dispatch(&mut tc, Some(&alice), &frame, &mib)
            .expect("below-floor message must produce a Report response");
        assert_eq!(
            tc.unsupported_sec_levels.get(),
            1,
            "counter must be incremented for below-floor message"
        );
        assert_report_pdu_varbind(
            &response_bytes,
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
        let response_bytes = run_dispatch(&mut tc, Some(&alice), &frame, &mib)
            .expect("below-floor authNoPriv message must produce a Report response");
        assert_eq!(
            tc.unsupported_sec_levels.get(),
            1,
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
        let response_bytes = run_dispatch(&mut tc, Some(&alice), &frame, &mib).expect(
            "authNoPriv message must be accepted when user has authPriv capabilities and floor is authNoPriv"
        );
        assert_eq!(
            tc.unsupported_sec_levels.get(),
            0,
            "counter must not be incremented when message passes both floor and ceiling checks"
        );
        // An AuthPriv user responding to any authenticated request will produce an authPriv-encrypted
        // response per REQ-0107, so the ScopedPduData will be EncryptedPdu.
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
        let response_bytes = run_dispatch(&mut tc, Some(&alice), &frame, &mib)
            .expect("ceiling violation must produce a Report response");
        assert_eq!(
            tc.unsupported_sec_levels.get(),
            1,
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
        assert!(
            process_snmpv3_request(b"\x00\x01\x02", &mut ctx, &mib).is_none(),
            "garbage bytes must be silently discarded"
        );
    }

    #[test]
    fn given_garbage_bytes_when_process_snmpv3_request_then_returns_none() {
        // Verifies: REQ-0073 — garbage bytes are silently discarded
        let mib = crate::mib::Store::new();
        let mut tc = TestCtx::new();
        let result = run_dispatch(&mut tc, None, b"\x00\x01\x02", &mib);
        assert!(result.is_none(), "garbage bytes must be silently discarded");
    }

    // ── HMAC verification (REQ-0100, REQ-0102) ───────────────────────────────

    // Build a `GetRequest` frame authenticated with HMAC-SHA-256 using the given key bytes.
    // Uses boots=1 and time=0 to match the default `TestCtx::new()` engine state, ensuring
    // the time-window check passes for HMAC verification tests.
    // The frame is addressed to `test_engine_id()` with user "alice", flags 0x05 (authNoPriv + reportable).
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
        let frame = build_authenticated_frame(&auth_key_bytes);
        let mut tc = TestCtx::new();
        let response_bytes = run_dispatch(&mut tc, Some(&alice), &frame, &mib)
            .expect("correct HMAC must produce a normal response");
        assert_eq!(
            tc.wrong_digests.get(),
            0,
            "counter must not be incremented on correct HMAC"
        );
        assert_get_response(&response_bytes);
    }

    #[test]
    fn given_wrong_hmac_when_process_then_returns_report_and_increments_counter() {
        // Verifies: REQ-0100, REQ-0102
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
        let mut tc = TestCtx::new();
        let result = run_dispatch(&mut tc, Some(&alice), &frame, &mib);
        assert_eq!(
            tc.wrong_digests.get(),
            1,
            "counter must be incremented on wrong HMAC"
        );
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
        let result = run_dispatch(&mut tc, Some(&alice), &frame, &mib);
        assert_eq!(
            tc.wrong_digests.get(),
            1,
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
        let result = run_dispatch(&mut tc, Some(&alice), &frame, &mib);
        assert_discarded_and_counter_incremented(result.as_ref(), tc.wrong_digests);
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

    // Build an authenticated `GetRequest` frame with explicit USM boots, time, and msgFlags.
    // The frame is addressed to `test_engine_id()` with user "alice".
    fn build_authenticated_frame_with_time_and_flags(
        auth_key_bytes: &[u8],
        boots: u32,
        time: u32,
        msg_flags_byte: u8,
    ) -> Vec<u8> {
        use crate::usm::auth::AuthProtocol;

        let mac_len = AuthProtocol::HmacSha256.mac_len();
        let frame_with_zeros = snmpv3_frames::encode_get_request_with_auth_params_and_time(
            test_engine_id(),
            b"alice",
            b"",
            1,
            2,
            test_oid_arcs(),
            msg_flags_byte,
            &vec![0_u8; mac_len],
            boots,
            time,
        );
        splice_hmac_into_frame(auth_key_bytes, frame_with_zeros)
    }

    // Build an authenticated `GetRequest` frame with explicit USM boots and time parameters.
    // Uses flags 0x05 (authNoPriv + reportable).
    // The frame is addressed to `test_engine_id()` with user "alice".
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
        let frame = build_authenticated_frame_with_time(&auth_key_bytes, 1, 0);
        let mut tc = TestCtx::new().with_boots_time(1, 0);
        let response_bytes = run_dispatch(&mut tc, Some(&alice), &frame, &mib)
            .expect("in-window message must produce a normal response");
        assert_eq!(
            tc.not_in_time_windows.get(),
            0,
            "counter must not be incremented for in-window message"
        );
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
        let response_bytes = run_dispatch(&mut tc, Some(&alice), &frame, &mib)
            .expect("out-of-window message must produce a Report response");
        assert_eq!(
            tc.not_in_time_windows.get(),
            1,
            "counter must be incremented for out-of-window message"
        );
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
        // boots=2 does not match engine_boots=1 → out of window; flags=0x01 = authFlag only
        // (no reportableFlag), so agent must discard silently.
        let frame = build_authenticated_frame_with_time_and_flags(&auth_key_bytes, 2, 0, 0x01);
        let mut tc = TestCtx::new().with_boots_time(1, 0);
        let result = run_dispatch(&mut tc, Some(&alice), &frame, &mib);
        assert_discarded_and_counter_incremented(result.as_ref(), tc.not_in_time_windows);
    }

    #[test]
    fn given_no_auth_user_when_process_then_time_window_check_skipped() {
        // Verifies: REQ-0098
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
        // engine_boots=5 but message has boots=0 (from encode_get_request_with_user default).
        // If the check were applied, this would fail; it must be skipped for noAuthNoPriv.
        let mut tc = TestCtx::new().with_boots_time(5, 100);
        let response_bytes = run_dispatch(&mut tc, Some(&alice), &frame, &mib)
            .expect("noAuthNoPriv message must pass through regardless of boots/time");
        assert_eq!(
            tc.not_in_time_windows.get(),
            0,
            "counter must not be incremented for noAuthNoPriv messages"
        );
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
        let result = run_dispatch(&mut tc, Some(&alice), &frame, &mib);
        assert_eq!(
            tc.not_in_time_windows.get(),
            1,
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
        // F1 fail-closed: an authPriv message (flags 0x07) with no configured user is
        // rejected at the security-level check before it ever reaches the Encrypted arm.
        // The agent has no credentials, so any message claiming auth or priv is rejected
        // with a Report PDU carrying usmStatsUnsupportedSecLevels (flags 0x07 includes
        // reportableFlag).
        let mib = crate::mib::Store::new();
        let encoded_frame = build_no_user_authpriv_frame();
        let mut tc = TestCtx::new();
        let result = run_dispatch(&mut tc, None, &encoded_frame, &mib);
        assert_eq!(
            tc.unsupported_sec_levels.get(),
            1,
            "counter must be incremented for no-user authPriv message (fail-closed)"
        );
        assert_report_pdu_varbind(
            &result
                .expect("authPriv message with reportableFlag and no user must produce a Report"),
            crate::usm::counters::USM_STATS_UNSUPPORTED_SEC_LEVELS,
            1,
        );
    }

    // ── authPriv decryption (REQ-0101) ───────────────────────────────────────────

    #[test]
    fn given_correct_priv_key_when_process_authpriv_then_decrypts_and_responds() {
        // Verifies: REQ-0101, REQ-0107, REQ-0109
        let mib = crate::mib::Store::new();
        let auth_key_bytes = [0x42_u8; 32];
        let alice = test_authpriv_user("alice", &auth_key_bytes);
        let frame = AuthPrivFrameParams::new(&auth_key_bytes)
            .with_boots_time(1, 0)
            .build();
        let mut tc = TestCtx::new().with_boots_time(1, 0);
        let response_bytes = run_dispatch(&mut tc, Some(&alice), &frame, &mib)
            .expect("correct authPriv message must produce a response");
        assert_eq!(
            tc.decryption_errors.get(),
            0,
            "counter must not be incremented on success"
        );

        // authPriv response must have flags 0x03 (auth + priv, no reportableFlag).
        let v3_response = rasn::ber::decode::<rasn_snmp::v3::Message>(&response_bytes)
            .expect("response must be a valid SNMPv3 message");
        let flags_byte = v3_response
            .global_data
            .flags
            .first()
            .copied()
            .expect("msgFlags must not be empty in any SNMPv3 message");
        assert_eq!(flags_byte, 0x03, "authPriv response flags must be 0x03");

        // Decrypt the response and verify the inner GetResponse PDU.
        let scoped_pdu = decrypt_and_verify_authpriv_response(
            &response_bytes,
            &AuthPrivResponseParams {
                auth_key_bytes: &auth_key_bytes,
                priv_key_bytes: &auth_key_bytes[..16],
                expected_boots: 1,
                expected_time: 0,
            },
        );
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
    }

    #[test]
    fn given_wrong_priv_key_when_process_authpriv_then_returns_report_and_increments_counter() {
        // Verifies: REQ-0101
        // AES-CFB decryption with a wrong key produces garbage bytes. When we try to
        // BER-decode those bytes as a ScopedPDU, it fails — the counter is incremented
        // and a Report is returned.
        let mib = crate::mib::Store::new();
        let auth_key_bytes = [0x42_u8; 32];
        let alice = test_authpriv_user("alice", &auth_key_bytes);
        // Frame encrypted with a different key so the agent's derived key [0x42; 16] will not match.
        let frame = AuthPrivFrameParams::new(&auth_key_bytes)
            .with_priv_key(&[0xAA_u8; 16])
            .with_boots_time(1, 0)
            .build();
        let mut tc = TestCtx::new().with_boots_time(1, 0);
        let result = run_dispatch(&mut tc, Some(&alice), &frame, &mib);
        assert_eq!(
            tc.decryption_errors.get(),
            1,
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
        let mib = crate::mib::Store::new();
        let auth_key_bytes = [0x42_u8; 32];
        let alice = test_authpriv_user("alice", &auth_key_bytes);
        let frame = build_authpriv_frame_with_short_priv_params(&auth_key_bytes, 1, 0);
        let mut tc = TestCtx::new().with_boots_time(1, 0);
        let result = run_dispatch(&mut tc, Some(&alice), &frame, &mib);
        assert_eq!(
            tc.decryption_errors.get(),
            1,
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
        // Builds an authPriv frame with flags = 0x03 (authPriv, no reportableFlag) and
        // corrupted ciphertext so the ScopedPDU decode fails. Counter is incremented but
        // no Report is sent.
        let mib = crate::mib::Store::new();
        let auth_key_bytes = [0x42_u8; 32];
        let alice = test_authpriv_user("alice", &auth_key_bytes);
        let frame = build_authpriv_frame_no_report_corrupted_ciphertext(&auth_key_bytes);
        let mut tc = TestCtx::new().with_boots_time(1, 0);
        let result = run_dispatch(&mut tc, Some(&alice), &frame, &mib);
        assert_discarded_and_counter_incremented(result.as_ref(), tc.decryption_errors);
    }

    #[test]
    fn given_security_model_not_usm_when_processed_then_returns_report_and_increments_counter() {
        // Verifies: REQ-0115
        let mib = crate::mib::Store::new();
        let frame = build_frame_with_non_usm_security_model();
        let mut tc = TestCtx::new();
        let report_bytes = run_dispatch(&mut tc, None, &frame, &mib)
            .expect("should return a Report PDU for unsupported security model");
        assert_eq!(tc.unknown_security_models.get(), 1);
        assert_report_pdu_varbind(&report_bytes, SNMP_UNKNOWN_SECURITY_MODELS_OID, 1);
    }

    #[test]
    fn given_security_model_not_usm_and_no_reportable_flag_when_processed_then_silent_discard() {
        // Verifies: REQ-0115
        let mib = crate::mib::Store::new();
        let mut frame = build_frame_with_non_usm_security_model();
        clear_reportable_flag(&mut frame);
        let mut tc = TestCtx::new();
        let result = run_dispatch(&mut tc, None, &frame, &mib);
        assert!(result.is_none(), "no reportable flag means silent discard");
        assert_eq!(
            tc.unknown_security_models.get(),
            1,
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
        for i in 0_u32..20 {
            mib.set(
                format!("1.3.6.1.2.1.1.{i}.0").parse().unwrap(),
                crate::codec::Value::OctetString(vec![0xAA; 200]),
            );
        }
        let engine_id = test_engine_id();
        let oid_arcs: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 0, 0];

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

        let large_frame = snmpv3_frames::encode_get_bulk_request_with_max_size(
            engine_id, b"", 1, 1, 0, 20, oid_arcs, 0x7FFF,
        );
        let full_varbind_count = {
            let mut tc = TestCtx::new();
            let response_bytes = run_dispatch(&mut tc, None, &large_frame, &mib)
                .expect("large-limit GetBulk must produce a response");
            count_response_varbinds(&response_bytes)
        };

        let small_frame = snmpv3_frames::encode_get_bulk_request_with_max_size(
            engine_id, b"", 2, 2, 0, 20, oid_arcs, 1500,
        );
        let truncated_varbind_count = {
            let mut tc = TestCtx::new();
            let response_bytes = run_dispatch(&mut tc, None, &small_frame, &mib)
                .expect("small-limit GetBulk must produce a response");
            count_response_varbinds(&response_bytes)
        };

        assert!(
            truncated_varbind_count < full_varbind_count,
            "small msgMaxSize ({truncated_varbind_count} varbinds) must yield fewer varbinds \
             than large msgMaxSize ({full_varbind_count} varbinds)"
        );
    }
}
