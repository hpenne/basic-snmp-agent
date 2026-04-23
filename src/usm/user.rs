//! USM user representation, associating a user name with its security level
//! and the key material required for that level.
//!
//! # Requirements
//! Implements: REQ-0075, REQ-0076, REQ-0077, REQ-0079, REQ-0090, REQ-0091, REQ-0092

use std::fmt;

use crate::usm::auth::AuthProtocol;
use crate::usm::keys::SecretKey;
use crate::usm::privacy::PrivProtocol;

// ── SecurityLevel ─────────────────────────────────────────────────────────────

/// The security level of a USM user, as defined in RFC 3414 §3.4.
///
/// The variants are ordered from least to most secure:
/// `NoAuthNoPriv < AuthNoPriv < AuthPriv`.
///
/// # Requirements
/// Implements: REQ-0075, REQ-0076, REQ-0077, REQ-0079
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecurityLevel {
    /// No authentication and no privacy.  Messages are neither authenticated
    /// nor encrypted.
    NoAuthNoPriv,

    /// Authentication without privacy.  Messages carry a MAC but the payload
    /// is transmitted in the clear.
    AuthNoPriv,

    /// Authentication with privacy.  Messages carry a MAC and the payload is
    /// encrypted.
    AuthPriv,
}

/// Error returned by [`SecurityLevel::from_msg_flags`] when the `msgFlags`
/// byte contains `privFlag` set without `authFlag`, which RFC 3412 §7.1.2a
/// forbids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidMsgFlags(pub u8);

impl fmt::Display for InvalidMsgFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid msgFlags 0x{:02x}: privFlag set without authFlag (RFC 3412 §7.1.2a)",
            self.0,
        )
    }
}

impl std::error::Error for InvalidMsgFlags {}

impl SecurityLevel {
    /// Derive the security level from the `msgFlags` byte (RFC 3412 §7.2.4).
    ///
    /// Returns an error for the invalid combination where `privFlag` is set without
    /// `authFlag` (RFC 3412 §7.1.2a forbids this combination). The raw `msgFlags`
    /// byte is preserved in the error for diagnostic purposes.
    ///
    /// # Requirements
    /// Implements: REQ-0079
    ///
    /// # Errors
    ///
    /// Returns [`InvalidMsgFlags`] when `flags & 0x03 == 0x02` (privFlag set, authFlag clear).
    ///
    /// # Examples
    ///
    /// ```
    /// use basic_snmp_agent::usm::user::{SecurityLevel, InvalidMsgFlags};
    ///
    /// assert_eq!(SecurityLevel::from_msg_flags(0x00), Ok(SecurityLevel::NoAuthNoPriv));
    /// assert_eq!(SecurityLevel::from_msg_flags(0x01), Ok(SecurityLevel::AuthNoPriv));
    /// assert_eq!(SecurityLevel::from_msg_flags(0x03), Ok(SecurityLevel::AuthPriv));
    /// assert!(SecurityLevel::from_msg_flags(0x02).is_err()); // privFlag without authFlag
    /// // The reportableFlag (bit 2) is ignored:
    /// assert_eq!(SecurityLevel::from_msg_flags(0x04), Ok(SecurityLevel::NoAuthNoPriv));
    /// ```
    pub fn from_msg_flags(flags: u8) -> Result<Self, InvalidMsgFlags> {
        match flags & 0x03 {
            0x00 => Ok(SecurityLevel::NoAuthNoPriv),
            0x01 => Ok(SecurityLevel::AuthNoPriv),
            0x03 => Ok(SecurityLevel::AuthPriv),
            _ => Err(InvalidMsgFlags(flags)), // 0x02: privFlag without authFlag — invalid per RFC 3412 §7.1.2a
        }
    }
}

// ── UsmUser ───────────────────────────────────────────────────────────────────

/// A USM user entry, holding the user name and all key material required for
/// its security level.
///
/// The [`UserCredentials`] enum ensures that invalid states (e.g. a privacy
/// key without an authentication key) are unrepresentable at the type level.
///
/// `Clone` is intentionally not derived: [`SecretKey`] does not implement
/// `Clone` to prevent accidental duplication of key material.
///
/// # Requirements
/// Implements: REQ-0090, REQ-0091, REQ-0092
pub struct UsmUser {
    name: String,
    credentials: UserCredentials,
}

impl UsmUser {
    /// Create a user that sends unauthenticated, unencrypted messages.
    ///
    /// # Panics (debug builds)
    /// Panics if `name` is empty. RFC 3414 requires non-empty security names
    /// for user lookup.
    ///
    /// # Requirements
    /// Implements: REQ-0090, REQ-0091, REQ-0092
    ///
    /// # Examples
    ///
    /// ```
    /// use basic_snmp_agent::usm::user::{UsmUser, SecurityLevel};
    ///
    /// let user = UsmUser::no_auth_no_priv("public");
    /// assert_eq!(user.security_level(), SecurityLevel::NoAuthNoPriv);
    /// ```
    #[must_use]
    pub fn no_auth_no_priv(name: impl Into<String>) -> Self {
        let name = name.into();
        debug_assert!(!name.is_empty(), "USM user name must not be empty");
        Self {
            name,
            credentials: UserCredentials::NoAuthNoPriv,
        }
    }

    /// Create a user that authenticates messages but does not encrypt them.
    ///
    /// # Panics (debug builds)
    /// Panics if `name` is empty. RFC 3414 requires non-empty security names
    /// for user lookup.
    ///
    /// # Requirements
    /// Implements: REQ-0090, REQ-0091, REQ-0092
    ///
    /// # Examples
    ///
    /// ```
    /// use basic_snmp_agent::usm::user::{UsmUser, SecurityLevel};
    /// use basic_snmp_agent::usm::auth::AuthProtocol;
    /// use basic_snmp_agent::usm::keys::SecretKey;
    ///
    /// let auth_key = SecretKey::new(vec![0u8; 32]);
    /// let user = UsmUser::auth_no_priv("alice", AuthProtocol::HmacSha256, auth_key);
    /// assert_eq!(user.security_level(), SecurityLevel::AuthNoPriv);
    /// ```
    #[must_use]
    pub fn auth_no_priv(
        name: impl Into<String>,
        auth_protocol: AuthProtocol,
        auth_key: SecretKey,
    ) -> Self {
        let name = name.into();
        debug_assert!(!name.is_empty(), "USM user name must not be empty");
        Self {
            name,
            credentials: UserCredentials::AuthNoPriv {
                auth_protocol,
                auth_key,
            },
        }
    }

    /// Create a user that both authenticates and encrypts messages.
    ///
    /// # Panics (debug builds)
    /// Panics if `name` is empty. RFC 3414 requires non-empty security names
    /// for user lookup.
    ///
    /// # Requirements
    /// Implements: REQ-0090, REQ-0091, REQ-0092
    ///
    /// # Examples
    ///
    /// ```
    /// use basic_snmp_agent::usm::user::{UsmUser, SecurityLevel};
    /// use basic_snmp_agent::usm::auth::AuthProtocol;
    /// use basic_snmp_agent::usm::keys::SecretKey;
    /// use basic_snmp_agent::usm::privacy::PrivProtocol;
    ///
    /// let auth_key = SecretKey::new(vec![0u8; 32]);
    /// let priv_key = SecretKey::new(vec![0u8; 16]);
    /// let user = UsmUser::auth_priv(
    ///     "bob",
    ///     AuthProtocol::HmacSha256,
    ///     auth_key,
    ///     PrivProtocol::Aes128,
    ///     priv_key,
    /// );
    /// assert_eq!(user.security_level(), SecurityLevel::AuthPriv);
    /// ```
    #[must_use]
    pub fn auth_priv(
        name: impl Into<String>,
        auth_protocol: AuthProtocol,
        auth_key: SecretKey,
        priv_protocol: PrivProtocol,
        priv_key: SecretKey,
    ) -> Self {
        let name = name.into();
        debug_assert!(!name.is_empty(), "USM user name must not be empty");
        Self {
            name,
            credentials: UserCredentials::AuthPriv {
                auth_protocol,
                auth_key,
                priv_protocol,
                priv_key,
            },
        }
    }

    /// Return the user name.
    ///
    /// # Requirements
    /// Implements: REQ-0091
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return the security level of this user.
    ///
    /// # Requirements
    /// Implements: REQ-0075, REQ-0076, REQ-0077
    #[must_use]
    pub fn security_level(&self) -> SecurityLevel {
        match &self.credentials {
            UserCredentials::NoAuthNoPriv => SecurityLevel::NoAuthNoPriv,
            UserCredentials::AuthNoPriv { .. } => SecurityLevel::AuthNoPriv,
            UserCredentials::AuthPriv { .. } => SecurityLevel::AuthPriv,
        }
    }

    /// Return the authentication protocol, if configured.
    ///
    /// Returns `None` for `NoAuthNoPriv` users.
    ///
    /// # Requirements
    /// Implements: REQ-0092
    #[must_use]
    pub fn auth_protocol(&self) -> Option<AuthProtocol> {
        match &self.credentials {
            UserCredentials::AuthNoPriv { auth_protocol, .. }
            | UserCredentials::AuthPriv { auth_protocol, .. } => Some(*auth_protocol),
            UserCredentials::NoAuthNoPriv => None,
        }
    }

    /// Return a reference to the authentication key, if configured.
    ///
    /// Returns `None` for `NoAuthNoPriv` users.
    ///
    /// # Requirements
    /// Implements: REQ-0092
    #[must_use]
    pub fn auth_key(&self) -> Option<&SecretKey> {
        match &self.credentials {
            UserCredentials::AuthNoPriv { auth_key, .. }
            | UserCredentials::AuthPriv { auth_key, .. } => Some(auth_key),
            UserCredentials::NoAuthNoPriv => None,
        }
    }

    /// Return the privacy protocol, if configured.
    ///
    /// Returns `None` for `NoAuthNoPriv` and `AuthNoPriv` users.
    ///
    /// # Requirements
    /// Implements: REQ-0092
    #[must_use]
    pub fn priv_protocol(&self) -> Option<PrivProtocol> {
        match &self.credentials {
            UserCredentials::AuthPriv { priv_protocol, .. } => Some(*priv_protocol),
            UserCredentials::NoAuthNoPriv | UserCredentials::AuthNoPriv { .. } => None,
        }
    }

    /// Return a reference to the privacy key, if configured.
    ///
    /// Returns `None` for `NoAuthNoPriv` and `AuthNoPriv` users.
    ///
    /// # Requirements
    /// Implements: REQ-0092
    #[must_use]
    pub fn priv_key(&self) -> Option<&SecretKey> {
        match &self.credentials {
            UserCredentials::AuthPriv { priv_key, .. } => Some(priv_key),
            UserCredentials::NoAuthNoPriv | UserCredentials::AuthNoPriv { .. } => None,
        }
    }
}

// ── UserCredentials ───────────────────────────────────────────────────────────

// The `Priv` postfix shared by all variants is RFC 3414 terminology; renaming
// would harm clarity. The lint is suppressed intentionally.
#[allow(clippy::enum_variant_names)]
enum UserCredentials {
    NoAuthNoPriv,
    AuthNoPriv {
        auth_protocol: AuthProtocol,
        auth_key: SecretKey,
    },
    AuthPriv {
        auth_protocol: AuthProtocol,
        auth_key: SecretKey,
        priv_protocol: PrivProtocol,
        priv_key: SecretKey,
    },
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_auth_no_priv_has_correct_security_level() {
        // Verifies: REQ-0075
        let user = UsmUser::no_auth_no_priv("public");
        assert_eq!(user.security_level(), SecurityLevel::NoAuthNoPriv);
    }

    #[test]
    fn auth_no_priv_has_correct_security_level() {
        // Verifies: REQ-0076
        let auth_key = SecretKey::new(vec![0u8; 32]);
        let user = UsmUser::auth_no_priv("alice", AuthProtocol::HmacSha256, auth_key);
        assert_eq!(user.security_level(), SecurityLevel::AuthNoPriv);
    }

    #[test]
    fn auth_priv_has_correct_security_level() {
        // Verifies: REQ-0077
        let auth_key = SecretKey::new(vec![0u8; 32]);
        let priv_key = SecretKey::new(vec![0u8; 16]);
        let user = UsmUser::auth_priv(
            "bob",
            AuthProtocol::HmacSha256,
            auth_key,
            PrivProtocol::Aes128,
            priv_key,
        );
        assert_eq!(user.security_level(), SecurityLevel::AuthPriv);
    }

    #[test]
    fn given_no_auth_no_priv_when_auth_key_then_none() {
        // Verifies: REQ-0092
        let user = UsmUser::no_auth_no_priv("public");
        assert!(user.auth_key().is_none());
    }

    #[test]
    fn given_auth_no_priv_when_auth_key_then_some() {
        // Verifies: REQ-0092
        let auth_key = SecretKey::new(vec![0xAAu8; 32]);
        let user = UsmUser::auth_no_priv("alice", AuthProtocol::HmacSha256, auth_key);
        assert_eq!(user.auth_key().unwrap().as_bytes(), &[0xAAu8; 32]);
    }

    #[test]
    fn given_auth_priv_when_priv_key_then_some() {
        // Verifies: REQ-0092
        let auth_key = SecretKey::new(vec![0xBBu8; 32]);
        let priv_key = SecretKey::new(vec![0xCCu8; 16]);
        let user = UsmUser::auth_priv(
            "bob",
            AuthProtocol::HmacSha256,
            auth_key,
            PrivProtocol::Aes128,
            priv_key,
        );
        assert_eq!(user.priv_key().unwrap().as_bytes(), &[0xCCu8; 16]);
    }

    #[test]
    fn given_no_auth_no_priv_when_priv_key_then_none() {
        // Verifies: REQ-0092
        let user = UsmUser::no_auth_no_priv("public");
        assert!(user.priv_key().is_none());
    }

    #[test]
    fn security_level_ordering() {
        // Verifies: REQ-0075, REQ-0076, REQ-0077
        assert!(SecurityLevel::NoAuthNoPriv < SecurityLevel::AuthNoPriv);
        assert!(SecurityLevel::AuthNoPriv < SecurityLevel::AuthPriv);
        assert!(SecurityLevel::NoAuthNoPriv < SecurityLevel::AuthPriv);
    }

    #[test]
    fn given_user_when_name_then_returns_name() {
        // Verifies: REQ-0091
        let user = UsmUser::no_auth_no_priv("test-user");
        assert_eq!(user.name(), "test-user");
    }

    #[test]
    fn given_auth_no_priv_user_when_name_then_returns_name() {
        // Verifies: REQ-0091
        let auth_key = SecretKey::new(vec![0u8; 32]);
        let user = UsmUser::auth_no_priv("alice", AuthProtocol::HmacSha256, auth_key);
        assert_eq!(user.name(), "alice");
    }

    #[test]
    fn given_auth_priv_user_when_name_then_returns_name() {
        // Verifies: REQ-0091
        let auth_key = SecretKey::new(vec![0u8; 32]);
        let priv_key = SecretKey::new(vec![0u8; 16]);
        let user = UsmUser::auth_priv(
            "bob",
            AuthProtocol::HmacSha256,
            auth_key,
            PrivProtocol::Aes128,
            priv_key,
        );
        assert_eq!(user.name(), "bob");
    }

    #[test]
    fn given_no_auth_no_priv_when_all_accessors_then_none() {
        // Verifies: REQ-0092
        let user = UsmUser::no_auth_no_priv("public");
        assert!(user.auth_protocol().is_none());
        assert!(user.auth_key().is_none());
        assert!(user.priv_protocol().is_none());
        assert!(user.priv_key().is_none());
    }

    #[test]
    fn given_auth_no_priv_when_all_accessors_then_correct_values() {
        // Verifies: REQ-0092
        let auth_key = SecretKey::new(vec![0xAAu8; 32]);
        let user = UsmUser::auth_no_priv("alice", AuthProtocol::HmacSha256, auth_key);
        assert_eq!(user.auth_protocol(), Some(AuthProtocol::HmacSha256));
        assert_eq!(user.auth_key().unwrap().as_bytes(), &[0xAAu8; 32]);
        assert!(user.priv_protocol().is_none());
        assert!(user.priv_key().is_none());
    }

    #[test]
    fn given_auth_priv_when_all_accessors_then_correct_values() {
        // Verifies: REQ-0092
        let auth_key = SecretKey::new(vec![0xAAu8; 32]);
        let priv_key = SecretKey::new(vec![0xCCu8; 16]);
        let user = UsmUser::auth_priv(
            "bob",
            AuthProtocol::HmacSha256,
            auth_key,
            PrivProtocol::Aes128,
            priv_key,
        );
        assert_eq!(user.security_level(), SecurityLevel::AuthPriv);
        assert_eq!(user.auth_protocol(), Some(AuthProtocol::HmacSha256));
        assert_eq!(user.auth_key().unwrap().as_bytes(), &[0xAAu8; 32]);
        assert_eq!(user.priv_protocol(), Some(PrivProtocol::Aes128));
        assert_eq!(user.priv_key().unwrap().as_bytes(), &[0xCCu8; 16]);
    }

    #[test]
    fn from_msg_flags_maps_flag_bits_correctly() {
        // Verifies: REQ-0079
        assert_eq!(
            SecurityLevel::from_msg_flags(0x00),
            Ok(SecurityLevel::NoAuthNoPriv)
        );
        assert_eq!(
            SecurityLevel::from_msg_flags(0x01),
            Ok(SecurityLevel::AuthNoPriv)
        );
        assert_eq!(
            SecurityLevel::from_msg_flags(0x03),
            Ok(SecurityLevel::AuthPriv)
        );
        assert_eq!(
            SecurityLevel::from_msg_flags(0x02),
            Err(InvalidMsgFlags(0x02))
        );
    }

    #[test]
    fn from_msg_flags_ignores_reportable_bit() {
        // Verifies: REQ-0079
        // Bit 2 (0x04) is the reportableFlag, which must not affect the security level.
        assert_eq!(
            SecurityLevel::from_msg_flags(0x04),
            Ok(SecurityLevel::NoAuthNoPriv)
        );
        assert_eq!(
            SecurityLevel::from_msg_flags(0x05),
            Ok(SecurityLevel::AuthNoPriv)
        );
        assert_eq!(
            SecurityLevel::from_msg_flags(0x07),
            Ok(SecurityLevel::AuthPriv)
        );
    }

    #[test]
    fn from_msg_flags_ignores_reserved_high_bits() {
        // Verifies: REQ-0079 — bits 3-7 of msgFlags are reserved and must be masked out
        assert_eq!(
            SecurityLevel::from_msg_flags(0xF8), // 0xF8 & 0x03 == 0x00 → NoAuthNoPriv
            Ok(SecurityLevel::NoAuthNoPriv)
        );
        assert_eq!(
            SecurityLevel::from_msg_flags(0xF9), // 0xF9 & 0x03 == 0x01 → AuthNoPriv
            Ok(SecurityLevel::AuthNoPriv)
        );
        assert_eq!(
            SecurityLevel::from_msg_flags(0xFF), // 0xFF & 0x03 == 0x03 → AuthPriv
            Ok(SecurityLevel::AuthPriv)
        );
    }

    #[test]
    fn from_msg_flags_invalid_combination_carries_raw_byte() {
        // Verifies: REQ-0079 — the error carries the raw flags byte for diagnostics
        let err = SecurityLevel::from_msg_flags(0x02).unwrap_err();
        assert_eq!(err, InvalidMsgFlags(0x02));
        // A flags byte with high bits set still produces an error with the full raw value
        let err = SecurityLevel::from_msg_flags(0xFE).unwrap_err(); // 0xFE & 0x03 == 0x02
        assert_eq!(err, InvalidMsgFlags(0xFE));
        // Display includes the raw byte in hex
        assert!(
            err.to_string().contains("0xfe"),
            "error message must include the raw flags byte"
        );
    }
}
