//! OID constants for USM statistics counters.
//!
//! # Requirements
//! Implements: REQ-0093, REQ-0098, REQ-0099

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
