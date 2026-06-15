//! OID constants and counter type for USM statistics counters.
//!
//! # Requirements
//! Implements: REQ-0078, REQ-0079, REQ-0093, REQ-0098, REQ-0099, REQ-0100, REQ-0101, REQ-0115

/// A single RFC 3414 §5.1 USM statistics counter.
///
/// Wraps a `u32` and provides a `saturating_increment` method that advances
/// the counter without overflowing at `u32::MAX`. All seven USM/SNMP-MPD
/// counters that appear in Report PDU varbinds use this type so that the
/// saturation invariant lives in one place rather than being repeated at every
/// increment site.
///
/// # Examples
///
/// ```
/// use basic_snmp_agent::usm::counters::UsmStatsCounter;
///
/// let mut counter = UsmStatsCounter::from(0_u32);
/// counter.saturating_increment();
/// assert_eq!(u32::from(counter), 1);
///
/// let mut at_max = UsmStatsCounter::from(u32::MAX);
/// at_max.saturating_increment();
/// assert_eq!(u32::from(at_max), u32::MAX);
/// ```
///
/// # Requirements
/// Implements: REQ-0078, REQ-0079, REQ-0093, REQ-0098, REQ-0100, REQ-0101, REQ-0115
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UsmStatsCounter(u32);

impl UsmStatsCounter {
    /// Advance the counter by one, saturating at `u32::MAX`.
    ///
    /// Saturation matches RFC 3414 §5.1 semantics: counters are unsigned 32-bit
    /// values and must not wrap. Once `u32::MAX` is reached the counter stays
    /// there until the agent restarts.
    ///
    /// # Examples
    ///
    /// ```
    /// use basic_snmp_agent::usm::counters::UsmStatsCounter;
    ///
    /// let mut counter = UsmStatsCounter::from(0_u32);
    /// counter.saturating_increment();
    /// assert_eq!(u32::from(counter), 1);
    ///
    /// // Saturation at u32::MAX — the counter does not wrap.
    /// let mut at_max = UsmStatsCounter::from(u32::MAX);
    /// at_max.saturating_increment();
    /// assert_eq!(u32::from(at_max), u32::MAX);
    /// ```
    ///
    /// # Requirements
    /// Implements: REQ-0078, REQ-0079, REQ-0093, REQ-0098, REQ-0100, REQ-0101, REQ-0115
    pub fn saturating_increment(&mut self) {
        self.0 = self.0.saturating_add(1);
    }

    /// Return the current counter value.
    ///
    /// Used when encoding Report PDU varbinds, which carry the raw `u32`.
    ///
    /// # Examples
    ///
    /// ```
    /// use basic_snmp_agent::usm::counters::UsmStatsCounter;
    ///
    /// let counter = UsmStatsCounter::from(42_u32);
    /// assert_eq!(counter.get(), 42);
    /// ```
    #[must_use]
    pub fn get(&self) -> u32 {
        self.0
    }
}

impl From<u32> for UsmStatsCounter {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<UsmStatsCounter> for u32 {
    fn from(counter: UsmStatsCounter) -> Self {
        counter.0
    }
}

/// OID for `usmStatsUnknownEngineIDs` (RFC 3414 §5.1).
///
/// Returned in a Report PDU when the agent responds to an engine-ID discovery
/// probe — an `SNMPv3` message with an empty `msgAuthoritativeEngineID`.
///
/// # Requirements
/// Implements: REQ-0093
pub const USM_STATS_UNKNOWN_ENGINE_IDS: &str = "1.3.6.1.6.3.15.1.1.4.0";

/// OID for `usmStatsNotInTimeWindows` (RFC 3414 §5.1).
///
/// Returned in a Report PDU when the agent rejects an authenticated message
/// whose time parameters fall outside the 150-second window, or responds to
/// a time-synchronisation probe (boots=0, time=0).
///
/// # Requirements
/// Implements: REQ-0098, REQ-0099
pub const USM_STATS_NOT_IN_TIME_WINDOWS: &str = "1.3.6.1.6.3.15.1.1.2.0";

/// OID for `usmStatsUnknownUserNames` (RFC 3414 §5.1).
///
/// Returned in a Report PDU when the agent rejects a USM message whose
/// `msgUserName` does not match the configured user.
///
/// # Requirements
/// Implements: REQ-0078
pub const USM_STATS_UNKNOWN_USER_NAMES: &str = "1.3.6.1.6.3.15.1.1.3.0";

/// OID for `usmStatsUnsupportedSecLevels` (RFC 3414 §5.1).
///
/// Returned in a Report PDU when the agent rejects a USM message whose
/// security level does not match the configured user's level.
///
/// # Requirements
/// Implements: REQ-0079
pub const USM_STATS_UNSUPPORTED_SEC_LEVELS: &str = "1.3.6.1.6.3.15.1.1.1.0";

/// OID for `usmStatsWrongDigests` (RFC 3414 §5.1).
///
/// Returned in a Report PDU when HMAC verification of an authenticated USM
/// message fails.
///
/// # Requirements
/// Implements: REQ-0100
pub const USM_STATS_WRONG_DIGESTS: &str = "1.3.6.1.6.3.15.1.1.5.0";

/// OID for `usmStatsDecryptionErrors` (RFC 3414 §5.1).
///
/// Returned in a Report PDU when decryption of an `authPriv` USM message
/// fails.
///
/// # Requirements
/// Implements: REQ-0101
pub const USM_STATS_DECRYPTION_ERRORS: &str = "1.3.6.1.6.3.15.1.1.6.0";

#[cfg(test)]
mod tests {
    use super::*;

    // ── UsmStatsCounter ──────────────────────────────────────────────────────

    #[test]
    fn given_zero_counter_when_saturating_increment_then_value_is_one() {
        // Verifies: REQ-0078, REQ-0079, REQ-0093, REQ-0098, REQ-0100, REQ-0101, REQ-0115
        let mut counter = UsmStatsCounter::from(0_u32);
        counter.saturating_increment();
        assert_eq!(u32::from(counter), 1);
    }

    #[test]
    fn given_nonzero_counter_when_saturating_increment_then_value_advances() {
        // Verifies: REQ-0078, REQ-0079, REQ-0093, REQ-0098, REQ-0100, REQ-0101, REQ-0115
        let mut counter = UsmStatsCounter::from(41_u32);
        counter.saturating_increment();
        assert_eq!(u32::from(counter), 42);
    }

    #[test]
    fn given_counter_at_max_when_saturating_increment_then_value_stays_at_max() {
        // Verifies: REQ-0078, REQ-0079, REQ-0093, REQ-0098, REQ-0100, REQ-0101, REQ-0115
        // Saturation prevents u32 overflow; the invariant lives here so it does not
        // need to be policed per call site.
        let mut counter = UsmStatsCounter::from(u32::MAX);
        counter.saturating_increment();
        assert_eq!(u32::from(counter), u32::MAX);
    }

    #[test]
    fn given_counter_when_get_then_returns_current_value() {
        // Verifies: REQ-0078, REQ-0079, REQ-0093, REQ-0098, REQ-0100, REQ-0101, REQ-0115
        let counter = UsmStatsCounter::from(7_u32);
        assert_eq!(counter.get(), 7);
    }

    #[test]
    fn given_u32_when_from_then_counter_wraps_value() {
        // Verifies: REQ-0078, REQ-0079, REQ-0093, REQ-0098, REQ-0100, REQ-0101, REQ-0115
        let counter = UsmStatsCounter::from(99_u32);
        assert_eq!(u32::from(counter), 99);
    }

    // ── OID constants ────────────────────────────────────────────────────────

    #[test]
    fn usm_stats_unknown_user_names_oid_is_correct() {
        // Verifies: REQ-0078
        // OID arcs: 1.3.6.1.6.3.15.1.1.3.0
        let oid: crate::codec::Oid = USM_STATS_UNKNOWN_USER_NAMES.parse().unwrap();
        assert_eq!(oid.as_slice(), &[1_u32, 3, 6, 1, 6, 3, 15, 1, 1, 3, 0]);
    }

    #[test]
    fn usm_stats_unsupported_sec_levels_oid_is_correct() {
        // Verifies: REQ-0079
        // OID arcs: 1.3.6.1.6.3.15.1.1.1.0
        let oid: crate::codec::Oid = USM_STATS_UNSUPPORTED_SEC_LEVELS.parse().unwrap();
        assert_eq!(oid.as_slice(), &[1_u32, 3, 6, 1, 6, 3, 15, 1, 1, 1, 0]);
    }

    #[test]
    fn usm_stats_wrong_digests_oid_is_correct() {
        // Verifies: REQ-0100
        // OID arcs: 1.3.6.1.6.3.15.1.1.5.0
        let oid: crate::codec::Oid = USM_STATS_WRONG_DIGESTS.parse().unwrap();
        assert_eq!(oid.as_slice(), &[1_u32, 3, 6, 1, 6, 3, 15, 1, 1, 5, 0]);
    }

    #[test]
    fn usm_stats_decryption_errors_oid_is_correct() {
        // Verifies: REQ-0101
        // OID arcs: 1.3.6.1.6.3.15.1.1.6.0
        let oid: crate::codec::Oid = USM_STATS_DECRYPTION_ERRORS.parse().unwrap();
        assert_eq!(oid.as_slice(), &[1_u32, 3, 6, 1, 6, 3, 15, 1, 1, 6, 0]);
    }
}
