//! Newtype for the `SNMPv3` engine identifier (`snmpEngineID`).
//!
//! `EngineId` enforces the RFC 3411 §5 length invariant (5–32 octets)
//! at construction time, so downstream code never needs to re-validate the length.
//!
//! # Requirements
//! Implements: REQ-0055

use std::fmt;

/// An `SNMPv3` authoritative engine identifier.
///
/// Wraps the raw octet string and enforces the RFC 3411 §5 requirement that
/// the identifier is between 5 and 32 octets inclusive.  Wire-decoded engine
/// IDs from untrusted input (e.g. `msgAuthoritativeEngineID` in USM headers)
/// are *not* wrapped in this type because they may be empty (discovery probes).
///
/// # Requirements
/// Implements: REQ-0055
///
/// # Examples
///
/// ```
/// use basic_snmp_agent::usm::engine_id::EngineId;
///
/// let id = EngineId::try_from(b"\x80\x00\x1f\x88\x04agent".to_vec())
///     .expect("valid engine ID");
/// assert_eq!(id.as_ref(), b"\x80\x00\x1f\x88\x04agent");
/// ```
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EngineId(Vec<u8>);

impl EngineId {
    /// Minimum valid length per RFC 3411 §5.
    const MIN_LEN: usize = 5;

    /// Maximum valid length per RFC 3411 §5.
    const MAX_LEN: usize = 32;
}

impl TryFrom<Vec<u8>> for EngineId {
    type Error = InvalidEngineIdLength;

    /// Construct an `EngineId` from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidEngineIdLength`] when `bytes` has fewer than 5 or
    /// more than 32 octets.
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        if bytes.len() < Self::MIN_LEN || bytes.len() > Self::MAX_LEN {
            return Err(InvalidEngineIdLength(bytes.len()));
        }
        Ok(Self(bytes))
    }
}

impl AsRef<[u8]> for EngineId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// ── InvalidEngineIdLength ───────────────────────────────────────────────────

/// Error returned when constructing an [`EngineId`] with an invalid length.
///
/// RFC 3411 §5 requires engine IDs to be between 5 and 32 octets inclusive.
///
/// # Examples
///
/// ```
/// use basic_snmp_agent::usm::engine_id::EngineId;
///
/// let err = EngineId::try_from(vec![0u8; 3]).unwrap_err();
/// assert_eq!(err.actual_len(), 3);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidEngineIdLength(usize);

impl InvalidEngineIdLength {
    /// Returns the actual length that was rejected.
    #[must_use]
    pub fn actual_len(&self) -> usize {
        self.0
    }
}

impl fmt::Display for InvalidEngineIdLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "engine ID length {} is invalid: must be between 5 and 32 octets (RFC 3411 \u{a7}5)",
            self.0
        )
    }
}

impl std::error::Error for InvalidEngineIdLength {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn given_5_byte_id_when_try_from_then_ok() {
        // Verifies: REQ-0055
        let bytes = vec![0x80_u8, 0x00, 0x1f, 0x88, 0x01];
        let id = EngineId::try_from(bytes.clone()).expect("5 bytes is the minimum valid length");
        assert_eq!(id.as_ref(), bytes.as_slice());
    }

    #[test]
    fn given_32_byte_id_when_try_from_then_ok() {
        // Verifies: REQ-0055
        let bytes = vec![0xAA_u8; 32];
        let id = EngineId::try_from(bytes.clone()).expect("32 bytes is the maximum valid length");
        assert_eq!(id.as_ref(), bytes.as_slice());
    }

    #[test]
    fn given_4_byte_id_when_try_from_then_error() {
        // Verifies: REQ-0055
        let result = EngineId::try_from(vec![0_u8; 4]);
        assert_eq!(result.unwrap_err().actual_len(), 4);
    }

    #[test]
    fn given_33_byte_id_when_try_from_then_error() {
        // Verifies: REQ-0055
        let result = EngineId::try_from(vec![0_u8; 33]);
        assert_eq!(result.unwrap_err().actual_len(), 33);
    }

    #[test]
    fn given_empty_id_when_try_from_then_error() {
        // Verifies: REQ-0055
        let result = EngineId::try_from(vec![]);
        assert_eq!(result.unwrap_err().actual_len(), 0);
    }

    #[test]
    fn invalid_engine_id_length_display_mentions_rfc() {
        // Verifies: REQ-0055
        let err = InvalidEngineIdLength(2);
        let msg = err.to_string();
        assert!(msg.contains("RFC 3411"), "{msg}");
        assert!(msg.contains('2'), "{msg}");
    }

    #[test]
    fn invalid_engine_id_length_is_std_error() {
        // Verifies: REQ-0055
        let err = InvalidEngineIdLength(1);
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn engine_id_as_ref_returns_inner_bytes() {
        // Verifies: REQ-0055 — uses a 16-byte mid-range value to distinguish from boundary tests
        let bytes = vec![0xAB_u8; 16];
        let id = EngineId::try_from(bytes.clone()).unwrap();
        assert_eq!(id.as_ref(), bytes.as_slice());
    }

    #[test]
    fn engine_id_equality_compares_bytes() {
        let a = EngineId::try_from(b"\x80\x00\x1f\x88\x01test".to_vec()).unwrap();
        let b = EngineId::try_from(b"\x80\x00\x1f\x88\x01test".to_vec()).unwrap();
        let c = EngineId::try_from(b"\x80\x00\x1f\x88\x02test".to_vec()).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
