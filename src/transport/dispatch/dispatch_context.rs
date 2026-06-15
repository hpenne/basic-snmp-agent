//! Validated dispatch context and security-level policy for inbound frame processing.

use crate::usm::counters::UsmStatsCounter;
use crate::usm::engine_time::{EngineBoots, EngineTime};

/// Named inputs for constructing a [`DispatchContext`].
///
/// Bundles the per-frame engine state, USM statistics counters, configured user,
/// and security-level floor so the validating constructor takes a single struct
/// (named fields at the call site) instead of many positional arguments.
///
/// Kept `pub` only so the out-of-workspace `fuzz` crate can build inputs directly;
/// `#[doc(hidden)]` keeps it off the advertised API. Not a supported public type.
///
/// # Requirements
/// Implements: REQ-0077, REQ-0078, REQ-0079, REQ-0093, REQ-0094, REQ-0098, REQ-0100, REQ-0101, REQ-0104, REQ-0115, REQ-0130
#[doc(hidden)]
pub struct DispatchInputs<'a> {
    /// The agent's authoritative engine ID.
    pub engine_id: &'a [u8],
    /// Current `snmpEngineBoots` value.
    pub engine_boots: EngineBoots,
    /// Current `snmpEngineTime` in seconds.
    pub engine_time: EngineTime,
    /// Counter for `usmStatsUnknownEngineIDs` (REQ-0093).
    pub unknown_engine_ids_counter: &'a mut UsmStatsCounter,
    /// Counter for `usmStatsUnknownUserNames` (REQ-0078).
    // Implements: REQ-0078
    pub unknown_user_names_counter: &'a mut UsmStatsCounter,
    /// Counter for `usmStatsUnsupportedSecLevels` (REQ-0079).
    // Implements: REQ-0079
    pub unsupported_sec_levels_counter: &'a mut UsmStatsCounter,
    /// Counter for `usmStatsWrongDigests` (REQ-0100).
    // Implements: REQ-0100
    pub wrong_digests_counter: &'a mut UsmStatsCounter,
    /// Counter for `usmStatsNotInTimeWindows` (REQ-0098).
    // Implements: REQ-0098
    pub not_in_time_windows_counter: &'a mut UsmStatsCounter,
    /// Counter for `usmStatsDecryptionErrors` (REQ-0101).
    // Implements: REQ-0101
    pub decryption_errors_counter: &'a mut UsmStatsCounter,
    /// Counter for `snmpUnknownSecurityModels` (RFC 3412 §7.1).
    // Implements: REQ-0115
    pub unknown_security_models_counter: &'a mut UsmStatsCounter,
    /// Optional configured USM user; `None` when no USM user is configured (REQ-0078, REQ-0079).
    // Implements: REQ-0078, REQ-0079
    pub usm_user: Option<&'a crate::usm::user::UsmUser>,
    /// The agent's configured minimum acceptable security level (REQ-0077, REQ-0079).
    /// Messages with a security level below this floor are rejected.
    // Implements: REQ-0077, REQ-0079
    pub minimum_security_level: crate::usm::user::SecurityLevel,
}

impl DispatchInputs<'_> {
    /// Determine whether the message's security level should be rejected.
    ///
    /// Three checks in priority order:
    /// 1. Floor: `msg_level < minimum_security_level` (REQ-0079)
    /// 2. Ceiling: `msg_level > user.security_level()` when a user is configured (REQ-0130)
    /// 3. F1 fail-closed: no configured user and `msg_level > noAuthNoPriv` (REQ-0079)
    ///
    /// Returns `true` when the message must be rejected.
    ///
    /// # Requirements
    /// Implements: REQ-0079, REQ-0103, REQ-0130
    pub(super) fn should_reject_security_level(
        &self,
        msg_level: Result<crate::usm::user::SecurityLevel, crate::usm::user::InvalidMsgFlags>,
    ) -> bool {
        // Invalid flags (e.g. privFlag without authFlag) → always reject.
        let Ok(level) = msg_level else { return true };
        // REQ-0079: below the configured floor
        level < self.minimum_security_level
        // REQ-0130: above what the user can satisfy (if a user is configured)
        || self.usm_user.is_some_and(|user| level > user.security_level())
        // F1: with no configured user the agent has no credentials, so it can
        // only serve noAuthNoPriv. A message claiming auth/priv must be rejected
        // rather than served as if authenticated (fail closed). Implements: REQ-0079
        || (self.usm_user.is_none() && level > crate::usm::user::SecurityLevel::NoAuthNoPriv)
    }
}

/// Validated engine state and statistics for inbound frame dispatch.
///
/// Construct via [`DispatchContext::new`] (validating) — the no-user-implies-noAuthNoPriv
/// invariant is upheld so the bad state is never observable at dispatch time.
///
/// Kept `pub` only so the out-of-workspace `fuzz` crate can construct a context directly;
/// `#[doc(hidden)]` on `new` keeps it off the advertised API. Not a supported public entry
/// point — do not widen.
///
/// # Requirements
/// Implements: REQ-0077, REQ-0079
pub struct DispatchContext<'a> {
    // pub(super) so the dispatch submodules can access fields directly
    // without requiring accessor methods on the hot dispatch path.
    pub(super) inputs: DispatchInputs<'a>,
}

impl<'a> DispatchContext<'a> {
    /// Construct a [`DispatchContext`], validating the no-user security-level invariant.
    ///
    /// # Errors
    ///
    /// Returns [`NoUserSecurityLevelError`] when `inputs.usm_user` is `None` and
    /// `inputs.minimum_security_level` is above `noAuthNoPriv`. Without a USM user the
    /// agent cannot authenticate or decrypt messages, so a floor above
    /// `noAuthNoPriv` would be silently unsatisfiable and must be rejected
    /// at construction time (fail-closed, REQ-0079).
    ///
    /// # Requirements
    /// Implements: REQ-0079
    #[doc(hidden)]
    pub fn new(inputs: DispatchInputs<'a>) -> Result<Self, NoUserSecurityLevelError> {
        // F1: without a configured user the agent has no credentials and cannot
        // serve any security level above noAuthNoPriv. Reject at construction
        // time so the invalid state is never observable downstream.
        if crate::usm::user::security_level_requires_user(
            inputs.usm_user,
            inputs.minimum_security_level,
        ) {
            return Err(NoUserSecurityLevelError);
        }
        Ok(Self::new_unchecked(inputs))
    }

    /// Construct a [`DispatchContext`] without validating the no-user security-level invariant.
    ///
    /// The caller MUST have already enforced the invariant (e.g. via [`EventLoop::new`]) before
    /// calling this. It exists so the validated per-frame dispatch hot path carries no `Result`
    /// or panic site.
    ///
    /// Kept `pub` only so the out-of-workspace `fuzz` crate can construct contexts directly
    /// after performing its own validation. Not a supported public entry point — do not widen.
    ///
    /// # Requirements
    /// Implements: REQ-0077
    #[doc(hidden)]
    #[must_use]
    pub fn new_unchecked(inputs: DispatchInputs<'a>) -> Self {
        Self { inputs }
    }
}

/// Error returned when a [`DispatchContext`] is constructed with a minimum security
/// level above `noAuthNoPriv` but no configured USM user.
///
/// Without a USM user the agent has no credentials and cannot authenticate or
/// decrypt inbound messages. Configuring a security-level floor above
/// `noAuthNoPriv` in that state would be silently unsatisfiable and is rejected
/// at construction time so the bad state is never observable at dispatch time.
///
/// # Requirements
/// Implements: REQ-0079
#[derive(Debug, PartialEq, Eq)]
pub struct NoUserSecurityLevelError;

impl std::fmt::Display for NoUserSecurityLevelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(crate::usm::user::SECURITY_LEVEL_REQUIRES_USER_MESSAGE)
    }
}

impl std::error::Error for NoUserSecurityLevelError {}
