//! Newtypes for USM security-parameter byte fields.
//!
//! [`AuthenticationParams`] wraps the `msgAuthenticationParameters` MAC bytes
//! from an authenticated `SNMPv3` message.  [`PrivacySalt`] wraps the 8-byte
//! `msgPrivacyParameters` AES salt from an authPriv message.
//!
//! Wire-decoded values arrive as raw `Vec<u8>` from `UsmSecurityFields`; the
//! newtypes are constructed via `TryFrom` at that boundary.  For empty fields
//! (noAuthNoPriv / authNoPriv messages), the caller stores `None` in the
//! containing `Option<_>` field.
//!
//! # Requirements
//! Implements: REQ-0099, REQ-0100, REQ-0101, REQ-0109

use std::fmt;

// ── AuthenticationParams ─────────────────────────────────────────────────────

/// The `msgAuthenticationParameters` MAC from an authenticated `SNMPv3` message.
///
/// Contains the received MAC bytes exactly as they appeared on the wire. The
/// length is protocol-determined (24 bytes for HMAC-SHA-256 per RFC 7860, 48
/// bytes for HMAC-SHA-512) but is not enforced at construction time — the HMAC
/// verification step handles wrong-length MACs as authentication failures.
///
/// Empty `msgAuthenticationParameters` (noAuthNoPriv messages) are represented
/// as `None` in the containing `Option<AuthenticationParams>` field rather than
/// an empty `AuthenticationParams`.
///
/// # Requirements
/// Implements: REQ-0099, REQ-0100
///
/// # Examples
///
/// ```
/// use basic_snmp_agent::usm::security_params::AuthenticationParams;
///
/// let params = AuthenticationParams::try_from(vec![0u8; 24])
///     .expect("non-empty MAC bytes are valid");
/// assert_eq!(params.as_ref().len(), 24);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticationParams(Vec<u8>);

impl TryFrom<Vec<u8>> for AuthenticationParams {
    type Error = EmptyAuthParams;

    /// Construct `AuthenticationParams` from raw MAC bytes.
    ///
    /// # Errors
    ///
    /// Returns [`EmptyAuthParams`] when `bytes` is empty.  Empty authentication
    /// parameters indicate a noAuthNoPriv message; the caller should store
    /// `None` rather than constructing this type.
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        if bytes.is_empty() {
            return Err(EmptyAuthParams);
        }
        Ok(Self(bytes))
    }
}

impl AsRef<[u8]> for AuthenticationParams {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Error returned when constructing [`AuthenticationParams`] from empty bytes.
///
/// Empty `msgAuthenticationParameters` indicate a noAuthNoPriv message.
/// The caller should represent this as `None` in an `Option<AuthenticationParams>`.
///
/// # Examples
///
/// ```
/// use basic_snmp_agent::usm::security_params::AuthenticationParams;
///
/// let err = AuthenticationParams::try_from(vec![]).unwrap_err();
/// assert!(err.to_string().contains("None"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmptyAuthParams;

impl fmt::Display for EmptyAuthParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "authentication parameters are empty; \
             use None for noAuthNoPriv messages",
        )
    }
}

impl std::error::Error for EmptyAuthParams {}

// ── PrivacySalt ──────────────────────────────────────────────────────────────

/// The 8-byte `msgPrivacyParameters` AES salt from an authPriv `SNMPv3` message.
///
/// Per RFC 3826 §2.2, `msgPrivacyParameters` is an 8-octet salt used together
/// with `snmpEngineBoots` and `snmpEngineTime` to construct the AES-CFB128 IV.
/// This type enforces the 8-byte constraint at construction time.
///
/// Empty `msgPrivacyParameters` (noAuthNoPriv and authNoPriv messages) are
/// represented as `None` in the containing `Option<PrivacySalt>` field.
///
/// # Requirements
/// Implements: REQ-0101, REQ-0109
///
/// # Examples
///
/// ```
/// use basic_snmp_agent::usm::security_params::PrivacySalt;
///
/// let salt = PrivacySalt::try_from(vec![0u8; 8])
///     .expect("8-byte salt is valid");
/// assert_eq!(salt.as_ref().len(), 8);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivacySalt([u8; 8]);

impl PrivacySalt {
    /// Required length of the AES privacy salt per RFC 3826 §2.2.
    ///
    /// # Examples
    ///
    /// ```
    /// use basic_snmp_agent::usm::security_params::PrivacySalt;
    ///
    /// assert_eq!(PrivacySalt::LEN, 8);
    /// ```
    pub const LEN: usize = 8;
}

impl TryFrom<Vec<u8>> for PrivacySalt {
    type Error = InvalidPrivSaltLength;

    /// Construct a `PrivacySalt` from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPrivSaltLength`] when `bytes` is not exactly 8 octets.
    /// Empty bytes indicate a non-priv message; the caller should represent
    /// this as `None`.
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let actual_len = bytes.len();
        let array: [u8; 8] = bytes
            .try_into()
            .map_err(|_| InvalidPrivSaltLength(actual_len))?;
        Ok(Self(array))
    }
}

impl From<[u8; 8]> for PrivacySalt {
    /// Construct a `PrivacySalt` from a statically-sized 8-byte array.
    ///
    /// Infallible because the length is guaranteed by the type.
    fn from(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for PrivacySalt {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Error returned when constructing a [`PrivacySalt`] from bytes that are not
/// exactly 8 octets.
///
/// Per RFC 3826 §2.2 the AES IV is constructed from `snmpEngineBoots` (4 bytes),
/// `snmpEngineTime` (4 bytes), and the 8-byte salt, totalling 16 bytes.
///
/// # Examples
///
/// ```
/// use basic_snmp_agent::usm::security_params::PrivacySalt;
///
/// let err = PrivacySalt::try_from(vec![0u8; 5]).unwrap_err();
/// assert_eq!(err.actual_len(), 5);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidPrivSaltLength(usize);

impl InvalidPrivSaltLength {
    /// Returns the actual length that was rejected.
    #[must_use]
    pub fn actual_len(&self) -> usize {
        self.0
    }
}

impl fmt::Display for InvalidPrivSaltLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "privacy salt length {} is invalid: must be exactly 8 octets (RFC 3826 \u{a7}2.2)",
            self.0
        )
    }
}

impl std::error::Error for InvalidPrivSaltLength {}

#[cfg(test)]
mod tests {
    use super::*;

    // ── AuthenticationParams ─────────────────────────────────────────────────

    #[test]
    fn given_24_byte_mac_when_try_from_then_ok() {
        // Verifies: REQ-0100 — 24-byte SHA-256 MAC
        let bytes = vec![0xAB_u8; 24];
        let params =
            AuthenticationParams::try_from(bytes.clone()).expect("24-byte MAC is valid SHA-256");
        assert_eq!(params.as_ref(), bytes.as_slice());
    }

    #[test]
    fn given_48_byte_mac_when_try_from_then_ok() {
        // Verifies: REQ-0100 — 48-byte SHA-512 MAC
        let bytes = vec![0xCD_u8; 48];
        let params =
            AuthenticationParams::try_from(bytes.clone()).expect("48-byte MAC is valid SHA-512");
        assert_eq!(params.as_ref(), bytes.as_slice());
    }

    #[test]
    fn given_non_standard_length_when_try_from_then_ok() {
        // Verifies: REQ-0100 — length is not enforced at the type boundary;
        // HMAC verification handles wrong-length MACs as authentication failures.
        let params =
            AuthenticationParams::try_from(vec![0_u8; 12]).expect("non-standard length is valid");
        assert_eq!(params.as_ref(), &[0_u8; 12]);
    }

    #[test]
    fn given_empty_bytes_when_try_from_then_error() {
        // Verifies: REQ-0100 — empty means noAuthNoPriv, represented as None
        let result = AuthenticationParams::try_from(vec![]);
        assert!(matches!(result, Err(EmptyAuthParams)));
    }

    #[test]
    fn empty_auth_params_display_mentions_none() {
        // Verifies: REQ-0100
        let err = EmptyAuthParams;
        assert!(err.to_string().contains("None"), "{}", err.to_string());
    }

    #[test]
    fn empty_auth_params_is_std_error() {
        // Verifies: REQ-0099, REQ-0100
        let err = EmptyAuthParams;
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn auth_params_as_ref_returns_inner_bytes() {
        // Verifies: REQ-0100 — uses 36 bytes to distinguish from the 24- and 48-byte boundary tests
        let bytes = vec![0x42_u8; 36];
        let params = AuthenticationParams::try_from(bytes.clone()).unwrap();
        assert_eq!(params.as_ref(), bytes.as_slice());
    }

    // ── PrivacySalt ──────────────────────────────────────────────────────────

    #[test]
    fn given_8_byte_salt_when_try_from_vec_then_ok() {
        // Verifies: REQ-0101, REQ-0109
        let bytes = vec![0x01_u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let salt = PrivacySalt::try_from(bytes.clone()).expect("8-byte salt is valid");
        assert_eq!(salt.as_ref(), bytes.as_slice());
    }

    #[test]
    fn given_8_byte_array_when_from_array_then_ok() {
        // Verifies: REQ-0109 — From<[u8; 8]> for statically-known sizes
        let array = [0x01_u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let salt = PrivacySalt::from(array);
        assert_eq!(salt.as_ref(), array.as_slice());
    }

    #[test]
    fn given_7_byte_salt_when_try_from_then_error() {
        // Verifies: REQ-0101, REQ-0109
        let result = PrivacySalt::try_from(vec![0_u8; 7]);
        assert_eq!(result.unwrap_err().actual_len(), 7);
    }

    #[test]
    fn given_9_byte_salt_when_try_from_then_error() {
        // Verifies: REQ-0101, REQ-0109
        let result = PrivacySalt::try_from(vec![0_u8; 9]);
        assert_eq!(result.unwrap_err().actual_len(), 9);
    }

    #[test]
    fn given_empty_bytes_when_try_from_privacy_salt_then_error() {
        // Verifies: REQ-0101 — empty means non-priv, represented as None
        let result = PrivacySalt::try_from(vec![]);
        assert_eq!(result.unwrap_err().actual_len(), 0);
    }

    #[test]
    fn invalid_priv_salt_length_display_mentions_rfc() {
        // Verifies: REQ-0109
        let err = InvalidPrivSaltLength(12);
        let msg = err.to_string();
        assert!(msg.contains("RFC 3826"), "{msg}");
        assert!(msg.contains("12"), "{msg}");
    }

    #[test]
    fn invalid_priv_salt_length_is_std_error() {
        // Verifies: REQ-0101, REQ-0109
        let err = InvalidPrivSaltLength(1);
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn privacy_salt_len_constant_is_eight() {
        // Verifies: REQ-0109
        assert_eq!(PrivacySalt::LEN, 8);
    }

    #[test]
    fn privacy_salt_as_ref_returns_inner_bytes() {
        // Verifies: REQ-0109 — uniform fill value to distinguish from the sequential-byte test
        let bytes = vec![0xFF_u8; 8];
        let salt = PrivacySalt::try_from(bytes.clone()).unwrap();
        assert_eq!(salt.as_ref(), bytes.as_slice());
    }
}
