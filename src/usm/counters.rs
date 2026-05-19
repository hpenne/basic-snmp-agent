//! OID constants for USM statistics counters.
//!
//! # Requirements
//! Implements: REQ-0093, REQ-0098, REQ-0099, REQ-0078, REQ-0079, REQ-0100, REQ-0101

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
