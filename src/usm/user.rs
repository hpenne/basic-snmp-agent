//! USM user representation, associating a user name with optional
//! authentication and privacy credentials.
//!
//! # Requirements
//! Implements: REQ-0075, REQ-0076, REQ-0077, REQ-0079, REQ-0083, REQ-0084, REQ-0090, REQ-0091, REQ-0092

use std::fmt;

use crate::usm::auth::AuthProtocol;
use crate::usm::keys::SecretKey;
use crate::usm::privacy::PrivProtocol;

// ── UserName ──────────────────────────────────────────────────────────────────

/// Error returned when attempting to create a [`UserName`] from an empty string.
///
/// # Requirements
/// Implements: REQ-0091
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmptyUserNameError;

impl fmt::Display for EmptyUserNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "USM user name must not be empty per RFC 3414")
    }
}

impl std::error::Error for EmptyUserNameError {}

/// A validated, non-empty USM user name.
///
/// RFC 3414 requires non-empty security names for user lookup. This type
/// enforces that invariant at construction time.
///
/// # Requirements
/// Implements: REQ-0091
///
/// # Examples
///
/// ```
/// use basic_snmp_agent::usm::user::UserName;
///
/// let name = UserName::new("admin").unwrap();
/// assert_eq!(name.as_str(), "admin");
///
/// assert!(UserName::new("").is_err());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UserName(String);

impl UserName {
    /// Create a new `UserName`, returning an error if the name is empty.
    ///
    /// # Errors
    ///
    /// Returns [`EmptyUserNameError`] if `name` is empty.
    ///
    /// # Requirements
    /// Implements: REQ-0091, REQ-0116
    pub fn new(name: impl Into<String>) -> Result<Self, EmptyUserNameError> {
        let name = name.into();
        if name.is_empty() {
            return Err(EmptyUserNameError);
        }
        Ok(Self(name))
    }

    /// Return the name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Return the name as a byte slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Display for UserName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for UserName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl AsRef<[u8]> for UserName {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

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

/// Error returned when converting a `msgFlags` byte to [`SecurityLevel`] via
/// [`TryFrom<u8>`] and the byte contains `privFlag` set without `authFlag`,
/// which RFC 3412 §7.1.2a forbids.
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

/// Shared error message for the no-user / security-level invariant, used by all three
/// error-type Display impls so the message text stays consistent across layers.
// Implements: REQ-0077, REQ-0079
pub(crate) const SECURITY_LEVEL_REQUIRES_USER_MESSAGE: &str =
    "minimum security level above noAuthNoPriv requires a configured USM user";

/// Return `true` when the combination of no configured USM user with a minimum security
/// level above `noAuthNoPriv` is requested — a state the agent cannot satisfy.
///
/// This predicate is the single authoritative source for the no-user / security-level
/// invariant checked in both [`crate::transport::dispatch::DispatchContext::new`] and
/// [`crate::transport::event_loop::EventLoop::new`].
// Implements: REQ-0077, REQ-0079
pub(crate) fn security_level_requires_user(
    usm_user: Option<&UsmUser>,
    minimum_security_level: SecurityLevel,
) -> bool {
    usm_user.is_none() && minimum_security_level > SecurityLevel::NoAuthNoPriv
}

/// Derive the security level from the `msgFlags` byte (RFC 3412 §7.2.4).
///
/// # Requirements
/// Implements: REQ-0079
impl TryFrom<u8> for SecurityLevel {
    type Error = InvalidMsgFlags;

    /// Returns an error for the invalid combination where `privFlag` is set without
    /// `authFlag` (RFC 3412 §7.1.2a forbids this combination). The raw `msgFlags`
    /// byte is preserved in the error for diagnostic purposes.
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
    /// assert_eq!(SecurityLevel::try_from(0x00_u8), Ok(SecurityLevel::NoAuthNoPriv));
    /// assert_eq!(SecurityLevel::try_from(0x01_u8), Ok(SecurityLevel::AuthNoPriv));
    /// assert_eq!(SecurityLevel::try_from(0x03_u8), Ok(SecurityLevel::AuthPriv));
    /// assert_eq!(SecurityLevel::try_from(0x02_u8), Err(InvalidMsgFlags(0x02)));
    /// // The reportableFlag (bit 2) is ignored:
    /// assert_eq!(SecurityLevel::try_from(0x04_u8), Ok(SecurityLevel::NoAuthNoPriv));
    /// ```
    fn try_from(flags: u8) -> Result<Self, Self::Error> {
        match flags & 0x03 {
            0x00 => Ok(Self::NoAuthNoPriv),
            0x01 => Ok(Self::AuthNoPriv),
            0x03 => Ok(Self::AuthPriv),
            _ => Err(InvalidMsgFlags(flags)), // 0x02: privFlag without authFlag — invalid per RFC 3412 §7.1.2a
        }
    }
}

// ── UsmUser ───────────────────────────────────────────────────────────────────

/// A USM user entry, holding the user name and the credential material
/// (authentication and/or privacy keys) that determines which security
/// levels this user can satisfy.
///
/// Per RFC 3414 §5, the user table stores credentials — not a security level.
/// The security level is a per-message property determined by `msgFlags`.
/// Use [`security_level()`](Self::security_level) to query the highest level
/// this user's credentials can satisfy.
///
/// External callers construct a `UsmUser` via [`From<AuthNoPrivUser>`] or
/// [`From<AuthPrivUser>`], which enforce correct credential combinations
/// through the type system.
///
/// `Clone` is intentionally not derived: [`SecretKey`] does not implement
/// `Clone` to prevent accidental duplication of key material.
///
/// # Requirements
/// Implements: REQ-0084, REQ-0090, REQ-0091, REQ-0092
pub struct UsmUser {
    name: UserName,
    auth_credentials: Option<AuthCredentials>,
    priv_credentials: Option<PrivCredentials>,
}

// Implements: REQ-0091, REQ-0092
struct AuthCredentials {
    protocol: AuthProtocol,
    key: SecretKey,
}

// Implements: REQ-0091, REQ-0092
struct PrivCredentials {
    protocol: PrivProtocol,
    key: SecretKey,
}

impl UsmUser {
    /// Return the user name.
    ///
    /// # Requirements
    /// Implements: REQ-0091
    #[must_use]
    pub fn name(&self) -> &UserName {
        &self.name
    }

    /// Return the security level of this user.
    ///
    /// # Requirements
    /// Implements: REQ-0075, REQ-0076, REQ-0077
    #[must_use]
    pub fn security_level(&self) -> SecurityLevel {
        match (&self.auth_credentials, &self.priv_credentials) {
            (Some(_), Some(_)) => SecurityLevel::AuthPriv,
            (Some(_), None) => SecurityLevel::AuthNoPriv,
            (None, None) => SecurityLevel::NoAuthNoPriv,
            (None, Some(_)) => {
                debug_assert!(
                    false,
                    "privacy credentials without authentication credentials"
                );
                SecurityLevel::NoAuthNoPriv
            }
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
        self.auth_credentials.as_ref().map(|a| a.protocol)
    }

    /// Return a reference to the authentication key, if configured.
    ///
    /// Returns `None` for `NoAuthNoPriv` users.
    ///
    /// # Requirements
    /// Implements: REQ-0092
    #[must_use]
    pub fn auth_key(&self) -> Option<&SecretKey> {
        self.auth_credentials.as_ref().map(|a| &a.key)
    }

    /// Return the privacy protocol, if configured.
    ///
    /// Returns `None` for `NoAuthNoPriv` and `AuthNoPriv` users.
    ///
    /// # Requirements
    /// Implements: REQ-0092
    #[must_use]
    pub fn priv_protocol(&self) -> Option<PrivProtocol> {
        self.priv_credentials.as_ref().map(|p| p.protocol)
    }

    /// Return a reference to the privacy key, if configured.
    ///
    /// Returns `None` for `NoAuthNoPriv` and `AuthNoPriv` users.
    ///
    /// # Requirements
    /// Implements: REQ-0092
    #[must_use]
    pub fn priv_key(&self) -> Option<&SecretKey> {
        self.priv_credentials.as_ref().map(|p| &p.key)
    }

    // Implements: REQ-0090, REQ-0091, REQ-0092
    #[cfg(test)]
    #[must_use]
    pub(crate) fn no_auth_no_priv(name: UserName) -> Self {
        Self {
            name,
            auth_credentials: None,
            priv_credentials: None,
        }
    }
}

impl fmt::Display for UsmUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

// ── InvalidKeyLength ──────────────────────────────────────────────────────────

/// Error returned when a key supplied to [`AuthNoPrivUser`] or [`AuthPrivUser`]
/// has the wrong length for the chosen authentication protocol.
///
/// # Requirements
/// Implements: REQ-0083
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidKeyLength {
    // Fields are `pub` so callers can pattern-match the expected and actual lengths
    // in tests and error-handling code without requiring accessor methods.
    /// The length the protocol requires.
    pub expected: usize,
    /// The length of the supplied key.
    pub actual: usize,
}

impl fmt::Display for InvalidKeyLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid key length: expected {} bytes, got {}",
            self.expected, self.actual,
        )
    }
}

impl std::error::Error for InvalidKeyLength {}

// ── Key validation helper ─────────────────────────────────────────────────────

// Implements: REQ-0083
fn validate_auth_key_length(
    auth_protocol: AuthProtocol,
    auth_key: &SecretKey,
) -> Result<(), InvalidKeyLength> {
    let expected = auth_protocol.key_len();
    if auth_key.len() != expected {
        return Err(InvalidKeyLength {
            expected,
            actual: auth_key.len(),
        });
    }
    Ok(())
}

// ── AuthNoPrivUser ────────────────────────────────────────────────────────────

/// A USM user configured for authentication without privacy (`authNoPriv`).
///
/// The constructor validates that the supplied key matches the required length
/// for the chosen authentication protocol (REQ-0083: 32 bytes for
/// HMAC-SHA-256, 64 bytes for HMAC-SHA-512).
///
/// Use [`From<AuthNoPrivUser> for UsmUser`] to convert into the type accepted
/// by [`AgentBuilder`][crate::AgentBuilder].
///
/// # Requirements
/// Implements: REQ-0083, REQ-0090, REQ-0091, REQ-0092
///
/// # Examples
///
/// ```
/// use basic_snmp_agent::usm::user::{AuthNoPrivUser, UserName};
/// use basic_snmp_agent::usm::auth::AuthProtocol;
/// use basic_snmp_agent::usm::keys::SecretKey;
///
/// let name = UserName::new("alice").unwrap();
/// let auth_key = SecretKey::new_from_exposed_slice(&[0_u8; 32]);
/// let user = AuthNoPrivUser::new(name, AuthProtocol::HmacSha256, auth_key).unwrap();
/// assert_eq!(user.name().as_str(), "alice");
/// ```
pub struct AuthNoPrivUser {
    name: UserName,
    auth_protocol: AuthProtocol,
    auth_key: SecretKey,
}

impl AuthNoPrivUser {
    /// Create an `AuthNoPrivUser`, validating the key length against the protocol.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidKeyLength`] when `auth_key.len() != auth_protocol.key_len()`.
    ///
    /// # Requirements
    /// Implements: REQ-0083, REQ-0090, REQ-0091, REQ-0092
    ///
    /// # Examples
    ///
    /// ```
    /// use basic_snmp_agent::usm::user::{AuthNoPrivUser, UserName, InvalidKeyLength};
    /// use basic_snmp_agent::usm::auth::AuthProtocol;
    /// use basic_snmp_agent::usm::keys::SecretKey;
    ///
    /// // Valid: SHA-256 requires 32 bytes.
    /// let key = SecretKey::new_from_exposed_slice(&[0_u8; 32]);
    /// let user = AuthNoPrivUser::new(UserName::new("alice").unwrap(), AuthProtocol::HmacSha256, key).unwrap();
    /// assert_eq!(user.name().as_str(), "alice");
    ///
    /// // Invalid: 16 bytes is too short for SHA-256.
    /// let short_key = SecretKey::new_from_exposed_slice(&[0_u8; 16]);
    /// let err = AuthNoPrivUser::new(UserName::new("alice").unwrap(), AuthProtocol::HmacSha256, short_key).unwrap_err();
    /// assert_eq!(err, InvalidKeyLength { expected: 32, actual: 16 });
    /// ```
    pub fn new(
        name: UserName,
        auth_protocol: AuthProtocol,
        auth_key: SecretKey,
    ) -> Result<Self, InvalidKeyLength> {
        validate_auth_key_length(auth_protocol, &auth_key)?;
        Ok(Self {
            name,
            auth_protocol,
            auth_key,
        })
    }

    /// Return the user name.
    ///
    /// # Requirements
    /// Implements: REQ-0091
    #[must_use]
    pub fn name(&self) -> &UserName {
        &self.name
    }

    /// Return the authentication protocol.
    ///
    /// # Requirements
    /// Implements: REQ-0092
    #[must_use]
    pub fn auth_protocol(&self) -> AuthProtocol {
        self.auth_protocol
    }

    /// Return a reference to the authentication key.
    ///
    /// # Requirements
    /// Implements: REQ-0092
    #[must_use]
    pub fn auth_key(&self) -> &SecretKey {
        &self.auth_key
    }
}

// Implements: REQ-0090
impl From<AuthNoPrivUser> for UsmUser {
    fn from(user: AuthNoPrivUser) -> Self {
        Self {
            name: user.name,
            auth_credentials: Some(AuthCredentials {
                protocol: user.auth_protocol,
                key: user.auth_key,
            }),
            priv_credentials: None,
        }
    }
}

impl fmt::Display for AuthNoPrivUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl fmt::Debug for AuthNoPrivUser {
    // The auth key is intentionally omitted to prevent accidental leakage.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthNoPrivUser")
            .field("name", &self.name)
            .field("auth_protocol", &self.auth_protocol)
            .field("auth_key", &"[REDACTED]")
            .finish()
    }
}

// ── AuthPrivUser ──────────────────────────────────────────────────────────────

/// A USM user configured for authentication with privacy (`authPriv`).
///
/// The constructor validates that the supplied key matches the required length
/// for the chosen authentication protocol (REQ-0083: 32 bytes for
/// HMAC-SHA-256, 64 bytes for HMAC-SHA-512). The privacy key is derived
/// internally from the leading bytes of the authentication key when the user
/// is converted into a [`UsmUser`] (REQ-0084).
///
/// Use [`From<AuthPrivUser> for UsmUser`] to convert into the type accepted
/// by [`AgentBuilder`][crate::AgentBuilder].
///
/// # Requirements
/// Implements: REQ-0083, REQ-0084, REQ-0090, REQ-0091, REQ-0092
///
/// # Examples
///
/// ```
/// use basic_snmp_agent::usm::user::{AuthPrivUser, UserName};
/// use basic_snmp_agent::usm::auth::AuthProtocol;
/// use basic_snmp_agent::usm::keys::SecretKey;
/// use basic_snmp_agent::usm::privacy::PrivProtocol;
///
/// let name = UserName::new("bob").unwrap();
/// let auth_key = SecretKey::new_from_exposed_slice(&[0_u8; 32]);
/// let user = AuthPrivUser::new(name, AuthProtocol::HmacSha256, auth_key, PrivProtocol::Aes128).unwrap();
/// assert_eq!(user.name().as_str(), "bob");
/// ```
pub struct AuthPrivUser {
    name: UserName,
    auth_protocol: AuthProtocol,
    auth_key: SecretKey,
    priv_protocol: PrivProtocol,
}

impl AuthPrivUser {
    /// Create an `AuthPrivUser`, validating the key length against the protocol.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidKeyLength`] when `auth_key.len() != auth_protocol.key_len()`.
    ///
    /// # Requirements
    /// Implements: REQ-0083, REQ-0084, REQ-0090, REQ-0091, REQ-0092
    ///
    /// # Examples
    ///
    /// ```
    /// use basic_snmp_agent::usm::user::{AuthPrivUser, UserName, InvalidKeyLength};
    /// use basic_snmp_agent::usm::auth::AuthProtocol;
    /// use basic_snmp_agent::usm::keys::SecretKey;
    /// use basic_snmp_agent::usm::privacy::PrivProtocol;
    ///
    /// // Valid: SHA-256 requires 32 bytes.
    /// let key = SecretKey::new_from_exposed_slice(&[0_u8; 32]);
    /// let user = AuthPrivUser::new(UserName::new("bob").unwrap(), AuthProtocol::HmacSha256, key, PrivProtocol::Aes128).unwrap();
    /// assert_eq!(user.name().as_str(), "bob");
    ///
    /// // Invalid: 16 bytes is too short for SHA-256.
    /// let short_key = SecretKey::new_from_exposed_slice(&[0_u8; 16]);
    /// let err = AuthPrivUser::new(UserName::new("bob").unwrap(), AuthProtocol::HmacSha256, short_key, PrivProtocol::Aes128).unwrap_err();
    /// assert_eq!(err, InvalidKeyLength { expected: 32, actual: 16 });
    /// ```
    pub fn new(
        name: UserName,
        auth_protocol: AuthProtocol,
        auth_key: SecretKey,
        priv_protocol: PrivProtocol,
    ) -> Result<Self, InvalidKeyLength> {
        validate_auth_key_length(auth_protocol, &auth_key)?;
        Ok(Self {
            name,
            auth_protocol,
            auth_key,
            priv_protocol,
        })
    }

    /// Return the user name.
    ///
    /// # Requirements
    /// Implements: REQ-0091
    #[must_use]
    pub fn name(&self) -> &UserName {
        &self.name
    }

    /// Return the authentication protocol.
    ///
    /// # Requirements
    /// Implements: REQ-0092
    #[must_use]
    pub fn auth_protocol(&self) -> AuthProtocol {
        self.auth_protocol
    }

    /// Return a reference to the authentication key.
    ///
    /// # Requirements
    /// Implements: REQ-0092
    #[must_use]
    pub fn auth_key(&self) -> &SecretKey {
        &self.auth_key
    }

    /// Return the privacy protocol.
    ///
    /// # Requirements
    /// Implements: REQ-0092
    #[must_use]
    pub fn priv_protocol(&self) -> PrivProtocol {
        self.priv_protocol
    }
}

// Implements: REQ-0084, REQ-0090
impl From<AuthPrivUser> for UsmUser {
    fn from(user: AuthPrivUser) -> Self {
        // REQ-0084: the privacy key is the leading N bytes of the localised
        // authentication key, where N = priv_protocol.key_len().
        let priv_key_bytes = user
            .auth_key
            .as_bytes()
            .get(..user.priv_protocol.key_len())
            // The localised auth key is always >= priv key length: SHA-256 produces
            // 32 bytes and SHA-512 produces 64 bytes; AES-128 needs 16 and AES-256
            // needs 32. No valid protocol combination can trigger this.
            .expect("auth key is always at least as long as the privacy key");
        let priv_key = SecretKey::new_from_exposed_slice(priv_key_bytes);
        Self {
            name: user.name,
            auth_credentials: Some(AuthCredentials {
                protocol: user.auth_protocol,
                key: user.auth_key,
            }),
            priv_credentials: Some(PrivCredentials {
                protocol: user.priv_protocol,
                key: priv_key,
            }),
        }
    }
}

impl fmt::Display for AuthPrivUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl fmt::Debug for AuthPrivUser {
    // The auth key is intentionally omitted to prevent accidental leakage.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthPrivUser")
            .field("name", &self.name)
            .field("auth_protocol", &self.auth_protocol)
            .field("auth_key", &"[REDACTED]")
            .field("priv_protocol", &self.priv_protocol)
            .finish()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_level_requires_user_predicate() {
        // Verifies: REQ-0077, REQ-0079
        let auth_priv_user: UsmUser = AuthPrivUser::new(
            UserName::new("alice").unwrap(),
            crate::usm::auth::AuthProtocol::HmacSha256,
            crate::usm::keys::SecretKey::new_from_exposed_slice(&[0x42_u8; 32]),
            crate::usm::privacy::PrivProtocol::Aes128,
        )
        .unwrap()
        .into();

        // (None, NoAuthNoPriv) → false: no user is valid at the lowest floor
        assert!(!security_level_requires_user(
            None,
            SecurityLevel::NoAuthNoPriv
        ));
        // (None, AuthNoPriv) → true: no user cannot satisfy an auth floor
        assert!(security_level_requires_user(
            None,
            SecurityLevel::AuthNoPriv
        ));
        // (None, AuthPriv) → true: no user cannot satisfy an authPriv floor
        assert!(security_level_requires_user(None, SecurityLevel::AuthPriv));
        // (Some(user), AuthPriv) → false: a configured user can satisfy any floor
        assert!(!security_level_requires_user(
            Some(&auth_priv_user),
            SecurityLevel::AuthPriv
        ));
    }

    fn user_name(s: &str) -> UserName {
        UserName::new(s).unwrap()
    }

    fn auth_no_priv_user(name: &str, key_bytes: &[u8]) -> UsmUser {
        let key = SecretKey::new_from_exposed_slice(key_bytes);
        AuthNoPrivUser::new(user_name(name), AuthProtocol::HmacSha256, key)
            .unwrap()
            .into()
    }

    fn auth_priv_user(name: &str, key_bytes: &[u8]) -> UsmUser {
        let key = SecretKey::new_from_exposed_slice(key_bytes);
        AuthPrivUser::new(
            user_name(name),
            AuthProtocol::HmacSha256,
            key,
            PrivProtocol::Aes128,
        )
        .unwrap()
        .into()
    }

    #[test]
    fn given_non_empty_string_when_username_new_then_ok() {
        // Verifies: REQ-0091, REQ-0116
        let name = UserName::new("admin").unwrap();
        assert_eq!(name.as_str(), "admin");
        assert_eq!(name.as_bytes(), b"admin");
    }

    #[test]
    fn given_empty_string_when_username_new_then_error() {
        // Verifies: REQ-0091, REQ-0116
        let result = UserName::new("");
        assert_eq!(
            result.unwrap_err().to_string(),
            "USM user name must not be empty per RFC 3414"
        );
    }

    #[test]
    fn no_auth_no_priv_has_correct_security_level() {
        // Verifies: REQ-0075
        let user = UsmUser::no_auth_no_priv(user_name("public"));
        assert_eq!(user.security_level(), SecurityLevel::NoAuthNoPriv);
    }

    #[test]
    fn auth_no_priv_has_correct_security_level() {
        // Verifies: REQ-0076
        let user = auth_no_priv_user("alice", &[0_u8; 32]);
        assert_eq!(user.security_level(), SecurityLevel::AuthNoPriv);
    }

    #[test]
    fn auth_priv_has_correct_security_level() {
        // Verifies: REQ-0077
        let user = auth_priv_user("bob", &[0_u8; 32]);
        assert_eq!(user.security_level(), SecurityLevel::AuthPriv);
    }

    #[test]
    fn given_no_auth_no_priv_when_auth_key_then_none() {
        // Verifies: REQ-0092
        let user = UsmUser::no_auth_no_priv(user_name("public"));
        assert!(user.auth_key().is_none());
    }

    #[test]
    fn given_auth_no_priv_when_auth_key_then_some() {
        // Verifies: REQ-0092
        let user = auth_no_priv_user("alice", &[0xAA_u8; 32]);
        assert_eq!(user.auth_key().unwrap().as_bytes(), &[0xAA_u8; 32]);
    }

    #[test]
    fn given_auth_priv_when_priv_key_then_some() {
        // Verifies: REQ-0084, REQ-0092
        let user = auth_priv_user("bob", &[0xBB_u8; 32]);
        // REQ-0084: priv_key is the first 16 bytes of auth_key
        assert_eq!(user.priv_key().unwrap().as_bytes(), &[0xBB_u8; 16]);
    }

    #[test]
    fn given_no_auth_no_priv_when_priv_key_then_none() {
        // Verifies: REQ-0092
        let user = UsmUser::no_auth_no_priv(user_name("public"));
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
        let user = UsmUser::no_auth_no_priv(user_name("test-user"));
        assert_eq!(user.name().as_str(), "test-user");
    }

    #[test]
    fn given_auth_no_priv_user_when_name_then_returns_name() {
        // Verifies: REQ-0091
        let user = auth_no_priv_user("alice", &[0_u8; 32]);
        assert_eq!(user.name().as_str(), "alice");
    }

    #[test]
    fn given_auth_priv_user_when_name_then_returns_name() {
        // Verifies: REQ-0091
        let user = auth_priv_user("bob", &[0_u8; 32]);
        assert_eq!(user.name().as_str(), "bob");
    }

    #[test]
    fn given_no_auth_no_priv_when_all_accessors_then_none() {
        // Verifies: REQ-0092
        let user = UsmUser::no_auth_no_priv(user_name("public"));
        assert!(user.auth_protocol().is_none());
        assert!(user.auth_key().is_none());
        assert!(user.priv_protocol().is_none());
        assert!(user.priv_key().is_none());
    }

    #[test]
    fn given_auth_no_priv_when_all_accessors_then_correct_values() {
        // Verifies: REQ-0092
        let user = auth_no_priv_user("alice", &[0xAA_u8; 32]);
        assert_eq!(user.auth_protocol(), Some(AuthProtocol::HmacSha256));
        assert_eq!(user.auth_key().unwrap().as_bytes(), &[0xAA_u8; 32]);
        assert!(user.priv_protocol().is_none());
        assert!(user.priv_key().is_none());
    }

    #[test]
    fn given_auth_priv_when_all_accessors_then_correct_values() {
        // Verifies: REQ-0084, REQ-0092
        let user = auth_priv_user("bob", &[0xAA_u8; 32]);
        assert_eq!(user.security_level(), SecurityLevel::AuthPriv);
        assert_eq!(user.auth_protocol(), Some(AuthProtocol::HmacSha256));
        assert_eq!(user.auth_key().unwrap().as_bytes(), &[0xAA_u8; 32]);
        assert_eq!(user.priv_protocol(), Some(PrivProtocol::Aes128));
        // REQ-0084: priv_key is the first 16 bytes of auth_key
        assert_eq!(user.priv_key().unwrap().as_bytes(), &[0xAA_u8; 16]);
    }

    #[test]
    fn given_auth_priv_aes256_when_priv_key_then_first_32_bytes_of_auth_key() {
        // Verifies: REQ-0084
        // AES-256 requires a 32-byte privacy key, so the full auth_key is used.
        let key = SecretKey::new_from_exposed_slice(&[0xBB_u8; 64]);
        let user: UsmUser = AuthPrivUser::new(
            user_name("carol"),
            AuthProtocol::HmacSha512,
            key,
            PrivProtocol::Aes256,
        )
        .unwrap()
        .into();
        assert_eq!(user.priv_key().unwrap().as_bytes(), &[0xBB_u8; 32]);
    }

    #[test]
    fn given_auth_priv_aes256_with_sha256_when_priv_key_then_entire_auth_key() {
        // Verifies: REQ-0084
        // SHA-256 produces exactly 32 bytes; AES-256 needs exactly 32 bytes.
        // This is the tightest valid combination: the full auth key becomes the priv key.
        let key = SecretKey::new_from_exposed_slice(&[0xCC_u8; 32]);
        let user: UsmUser = AuthPrivUser::new(
            user_name("dave"),
            AuthProtocol::HmacSha256,
            key,
            PrivProtocol::Aes256,
        )
        .unwrap()
        .into();
        assert_eq!(user.priv_key().unwrap().as_bytes(), &[0xCC_u8; 32]);
    }

    #[test]
    fn given_auth_priv_aes128_with_distinct_bytes_when_priv_key_then_correct_prefix() {
        // Verifies: REQ-0084
        // Distinct byte values prove the priv key is the leading prefix of auth_key,
        // not some other subset or a copy of the full key.
        let auth_key_bytes: Vec<u8> = (0..32).collect();
        let key = SecretKey::new_from_exposed_slice(&auth_key_bytes);
        let user: UsmUser = AuthPrivUser::new(
            user_name("eve"),
            AuthProtocol::HmacSha256,
            key,
            PrivProtocol::Aes128,
        )
        .unwrap()
        .into();
        let expected_priv_key: Vec<u8> = (0..16).collect();
        assert_eq!(user.priv_key().unwrap().as_bytes(), &expected_priv_key);
    }

    #[test]
    fn try_from_maps_flag_bits_correctly() {
        // Verifies: REQ-0079
        assert_eq!(
            SecurityLevel::try_from(0x00_u8),
            Ok(SecurityLevel::NoAuthNoPriv)
        );
        assert_eq!(
            SecurityLevel::try_from(0x01_u8),
            Ok(SecurityLevel::AuthNoPriv)
        );
        assert_eq!(
            SecurityLevel::try_from(0x03_u8),
            Ok(SecurityLevel::AuthPriv)
        );
        assert_eq!(SecurityLevel::try_from(0x02_u8), Err(InvalidMsgFlags(0x02)));
    }

    #[test]
    fn try_from_ignores_reportable_bit() {
        // Verifies: REQ-0079
        // Bit 2 (0x04) is the reportableFlag, which must not affect the security level.
        assert_eq!(
            SecurityLevel::try_from(0x04_u8),
            Ok(SecurityLevel::NoAuthNoPriv)
        );
        assert_eq!(
            SecurityLevel::try_from(0x05_u8),
            Ok(SecurityLevel::AuthNoPriv)
        );
        assert_eq!(
            SecurityLevel::try_from(0x07_u8),
            Ok(SecurityLevel::AuthPriv)
        );
        assert_eq!(SecurityLevel::try_from(0x06_u8), Err(InvalidMsgFlags(0x06)));
    }

    #[test]
    fn try_from_ignores_reserved_high_bits() {
        // Verifies: REQ-0079 — bits 3-7 of msgFlags are reserved and must be masked out
        assert_eq!(
            SecurityLevel::try_from(0xF8_u8), // 0xF8 & 0x03 == 0x00 → NoAuthNoPriv
            Ok(SecurityLevel::NoAuthNoPriv)
        );
        assert_eq!(
            SecurityLevel::try_from(0xF9_u8), // 0xF9 & 0x03 == 0x01 → AuthNoPriv
            Ok(SecurityLevel::AuthNoPriv)
        );
        assert_eq!(
            SecurityLevel::try_from(0xFF_u8), // 0xFF & 0x03 == 0x03 → AuthPriv
            Ok(SecurityLevel::AuthPriv)
        );
        assert_eq!(
            SecurityLevel::try_from(0xFA_u8), // 0xFA & 0x03 == 0x02 → error
            Err(InvalidMsgFlags(0xFA))
        );
    }

    #[test]
    fn try_from_invalid_combination_carries_raw_byte() {
        // Verifies: REQ-0079 — the error carries the raw flags byte for diagnostics
        let err = SecurityLevel::try_from(0x02_u8).unwrap_err();
        assert_eq!(err, InvalidMsgFlags(0x02));
        // A flags byte with high bits set still produces an error with the full raw value
        let err = SecurityLevel::try_from(0xFE_u8).unwrap_err(); // 0xFE & 0x03 == 0x02
        assert_eq!(err, InvalidMsgFlags(0xFE));
        // Display includes the raw byte in hex
        assert!(
            err.to_string().contains("0xfe"),
            "error message must include the raw flags byte"
        );
    }

    #[test]
    fn given_username_when_displayed_then_shows_the_name_string() {
        // Verifies: REQ-0091
        // Exercises UserName::fmt — a mutant replacing fmt with () would produce
        // an empty string, causing this assertion to fail.
        let name = user_name("admin");
        assert_eq!(name.to_string(), "admin");
    }

    #[test]
    fn given_username_when_asref_str_then_returns_name_as_str_slice() {
        // Verifies: REQ-0091
        // Calls the AsRef<str> impl explicitly so a mutant on that impl is caught.
        let name = user_name("admin");
        assert_eq!(<UserName as AsRef<str>>::as_ref(&name), "admin");
    }

    #[test]
    fn given_username_when_asref_bytes_then_returns_name_as_byte_slice() {
        // Verifies: REQ-0091
        // Calls the AsRef<[u8]> impl explicitly so a mutant on that impl is caught.
        let name = user_name("admin");
        assert_eq!(<UserName as AsRef<[u8]>>::as_ref(&name), b"admin");
    }

    #[test]
    fn given_usm_user_when_displayed_then_shows_user_name() {
        // Verifies: REQ-0091
        // Exercises UsmUser::fmt, which delegates to the user name's Display impl.
        let user = UsmUser::no_auth_no_priv(user_name("test"));
        assert_eq!(user.to_string(), "test");
    }

    // ── InvalidKeyLength ──────────────────────────────────────────────────────

    #[test]
    fn given_invalid_key_length_when_display_then_includes_expected_and_actual() {
        // Verifies: REQ-0083
        let err = InvalidKeyLength {
            expected: 32,
            actual: 16,
        };
        assert_eq!(
            err.to_string(),
            "invalid key length: expected 32 bytes, got 16"
        );
    }

    #[test]
    fn given_invalid_key_length_when_std_error_then_implements_trait() {
        // Verifies: REQ-0083
        let err = InvalidKeyLength {
            expected: 64,
            actual: 32,
        };
        let err_ref: &dyn std::error::Error = &err;
        assert!(err_ref.source().is_none());
    }

    // ── AuthNoPrivUser ────────────────────────────────────────────────────────

    #[test]
    fn given_valid_key_length_when_new_auth_no_priv_user_then_ok() {
        // Verifies: REQ-0083, REQ-0090, REQ-0091, REQ-0092
        let key = SecretKey::new_from_exposed_slice(&[0xAA_u8; 32]);
        let user = AuthNoPrivUser::new(user_name("alice"), AuthProtocol::HmacSha256, key).unwrap();
        assert_eq!(user.name().as_str(), "alice");
        assert_eq!(user.auth_protocol(), AuthProtocol::HmacSha256);
        assert_eq!(user.auth_key().as_bytes(), &[0xAA_u8; 32]);
    }

    #[test]
    fn given_wrong_key_length_when_new_auth_no_priv_user_then_error() {
        // Verifies: REQ-0083
        let short_key = SecretKey::new_from_exposed_slice(&[0_u8; 16]);
        let err = AuthNoPrivUser::new(user_name("alice"), AuthProtocol::HmacSha256, short_key)
            .unwrap_err();
        assert_eq!(
            err,
            InvalidKeyLength {
                expected: 32,
                actual: 16
            }
        );
    }

    #[test]
    fn given_sha512_valid_key_when_new_auth_no_priv_user_then_ok() {
        // Verifies: REQ-0083, REQ-0090
        let key = SecretKey::new_from_exposed_slice(&[0xBB_u8; 64]);
        let user = AuthNoPrivUser::new(user_name("alice"), AuthProtocol::HmacSha512, key).unwrap();
        assert_eq!(user.name().as_str(), "alice");
        assert_eq!(user.auth_protocol(), AuthProtocol::HmacSha512);
        assert_eq!(user.auth_key().as_bytes(), &[0xBB_u8; 64]);
    }

    #[test]
    fn given_sha512_wrong_key_when_new_auth_no_priv_user_then_error() {
        // Verifies: REQ-0083
        let short_key = SecretKey::new_from_exposed_slice(&[0_u8; 32]); // 32 bytes, not 64
        let err = AuthNoPrivUser::new(user_name("alice"), AuthProtocol::HmacSha512, short_key)
            .unwrap_err();
        assert_eq!(
            err,
            InvalidKeyLength {
                expected: 64,
                actual: 32
            }
        );
    }

    #[test]
    fn given_auth_no_priv_user_when_into_usm_user_then_correct_security_level() {
        // Verifies: REQ-0090, REQ-0091, REQ-0092
        let key = SecretKey::new_from_exposed_slice(&[0xCC_u8; 32]);
        let auth_no_priv_user =
            AuthNoPrivUser::new(user_name("alice"), AuthProtocol::HmacSha256, key).unwrap();
        let usm_user: UsmUser = auth_no_priv_user.into();
        assert_eq!(usm_user.security_level(), SecurityLevel::AuthNoPriv);
        assert_eq!(usm_user.name().as_str(), "alice");
        assert_eq!(usm_user.auth_protocol(), Some(AuthProtocol::HmacSha256));
        assert_eq!(usm_user.auth_key().unwrap().as_bytes(), &[0xCC_u8; 32]);
    }

    #[test]
    fn given_auth_no_priv_user_when_accessors_then_correct_values() {
        // Verifies: REQ-0091, REQ-0092
        let key = SecretKey::new_from_exposed_slice(&[0xDD_u8; 32]);
        let user = AuthNoPrivUser::new(user_name("alice"), AuthProtocol::HmacSha256, key).unwrap();
        assert_eq!(user.name().as_str(), "alice");
        assert_eq!(user.auth_protocol(), AuthProtocol::HmacSha256);
        assert_eq!(user.auth_key().as_bytes(), &[0xDD_u8; 32]);
    }

    #[test]
    fn given_auth_no_priv_user_when_displayed_then_shows_user_name() {
        // Verifies: REQ-0091
        let key = SecretKey::new_from_exposed_slice(&[0_u8; 32]);
        let user = AuthNoPrivUser::new(user_name("alice"), AuthProtocol::HmacSha256, key).unwrap();
        assert_eq!(user.to_string(), "alice");
    }

    // ── AuthPrivUser ──────────────────────────────────────────────────────────

    #[test]
    fn given_valid_key_length_when_new_auth_priv_user_then_ok() {
        // Verifies: REQ-0083, REQ-0090, REQ-0091, REQ-0092
        let key = SecretKey::new_from_exposed_slice(&[0xAA_u8; 32]);
        let user = AuthPrivUser::new(
            user_name("bob"),
            AuthProtocol::HmacSha256,
            key,
            PrivProtocol::Aes128,
        )
        .unwrap();
        assert_eq!(user.name().as_str(), "bob");
        assert_eq!(user.auth_protocol(), AuthProtocol::HmacSha256);
        assert_eq!(user.auth_key().as_bytes(), &[0xAA_u8; 32]);
        assert_eq!(user.priv_protocol(), PrivProtocol::Aes128);
    }

    #[test]
    fn given_wrong_key_length_when_new_auth_priv_user_then_error() {
        // Verifies: REQ-0083
        let short_key = SecretKey::new_from_exposed_slice(&[0_u8; 16]);
        let err = AuthPrivUser::new(
            user_name("bob"),
            AuthProtocol::HmacSha256,
            short_key,
            PrivProtocol::Aes128,
        )
        .unwrap_err();
        assert_eq!(
            err,
            InvalidKeyLength {
                expected: 32,
                actual: 16
            }
        );
    }

    #[test]
    fn given_sha512_valid_key_when_new_auth_priv_user_then_ok() {
        // Verifies: REQ-0083, REQ-0090
        let key = SecretKey::new_from_exposed_slice(&[0xCC_u8; 64]);
        let user = AuthPrivUser::new(
            user_name("bob"),
            AuthProtocol::HmacSha512,
            key,
            PrivProtocol::Aes256,
        )
        .unwrap();
        assert_eq!(user.name().as_str(), "bob");
        assert_eq!(user.auth_protocol(), AuthProtocol::HmacSha512);
        assert_eq!(user.auth_key().as_bytes(), &[0xCC_u8; 64]);
        assert_eq!(user.priv_protocol(), PrivProtocol::Aes256);
    }

    #[test]
    fn given_sha512_wrong_key_when_new_auth_priv_user_then_error() {
        // Verifies: REQ-0083
        let short_key = SecretKey::new_from_exposed_slice(&[0_u8; 32]); // 32 bytes, not 64
        let err = AuthPrivUser::new(
            user_name("bob"),
            AuthProtocol::HmacSha512,
            short_key,
            PrivProtocol::Aes256,
        )
        .unwrap_err();
        assert_eq!(
            err,
            InvalidKeyLength {
                expected: 64,
                actual: 32
            }
        );
    }

    #[test]
    fn given_auth_priv_user_when_into_usm_user_then_correct_security_level() {
        // Verifies: REQ-0090, REQ-0091
        let key = SecretKey::new_from_exposed_slice(&[0xBB_u8; 32]);
        let auth_priv_user = AuthPrivUser::new(
            user_name("bob"),
            AuthProtocol::HmacSha256,
            key,
            PrivProtocol::Aes128,
        )
        .unwrap();
        let usm_user: UsmUser = auth_priv_user.into();
        assert_eq!(usm_user.security_level(), SecurityLevel::AuthPriv);
        assert_eq!(usm_user.name().as_str(), "bob");
    }

    #[test]
    fn given_auth_priv_user_aes256_when_into_usm_user_then_correct_values() {
        // Verifies: REQ-0084, REQ-0090, REQ-0091, REQ-0092
        let key = SecretKey::new_from_exposed_slice(&[0xDD_u8; 64]);
        let auth_priv_user = AuthPrivUser::new(
            user_name("carol"),
            AuthProtocol::HmacSha512,
            key,
            PrivProtocol::Aes256,
        )
        .unwrap();
        let usm_user: UsmUser = auth_priv_user.into();
        assert_eq!(usm_user.security_level(), SecurityLevel::AuthPriv);
        assert_eq!(usm_user.name().as_str(), "carol");
        assert_eq!(usm_user.auth_protocol(), Some(AuthProtocol::HmacSha512));
        // REQ-0084: priv_key is the first 32 bytes of auth_key for AES-256
        assert_eq!(usm_user.priv_key().unwrap().as_bytes(), &[0xDD_u8; 32]);
        assert_eq!(usm_user.priv_protocol(), Some(PrivProtocol::Aes256));
    }

    #[test]
    fn given_auth_priv_user_when_into_usm_user_then_priv_key_derived() {
        // Verifies: REQ-0084
        // The privacy key must be the leading priv_protocol.key_len() bytes of auth_key.
        let key_bytes: Vec<u8> = (0..32_u8).collect();
        let key = SecretKey::new_from_exposed_slice(&key_bytes);
        let auth_priv_user = AuthPrivUser::new(
            user_name("bob"),
            AuthProtocol::HmacSha256,
            key,
            PrivProtocol::Aes128,
        )
        .unwrap();
        let usm_user: UsmUser = auth_priv_user.into();
        let expected_priv_key: Vec<u8> = (0..16_u8).collect();
        assert_eq!(
            usm_user.priv_key().unwrap().as_bytes(),
            expected_priv_key.as_slice()
        );
    }

    #[test]
    fn given_auth_priv_user_when_accessors_then_correct_values() {
        // Verifies: REQ-0091, REQ-0092
        let key = SecretKey::new_from_exposed_slice(&[0xEE_u8; 32]);
        let user = AuthPrivUser::new(
            user_name("bob"),
            AuthProtocol::HmacSha256,
            key,
            PrivProtocol::Aes128,
        )
        .unwrap();
        assert_eq!(user.name().as_str(), "bob");
        assert_eq!(user.auth_protocol(), AuthProtocol::HmacSha256);
        assert_eq!(user.auth_key().as_bytes(), &[0xEE_u8; 32]);
        assert_eq!(user.priv_protocol(), PrivProtocol::Aes128);
    }

    #[test]
    fn given_auth_priv_user_when_displayed_then_shows_user_name() {
        // Verifies: REQ-0091
        let key = SecretKey::new_from_exposed_slice(&[0_u8; 32]);
        let user = AuthPrivUser::new(
            user_name("bob"),
            AuthProtocol::HmacSha256,
            key,
            PrivProtocol::Aes128,
        )
        .unwrap();
        assert_eq!(user.to_string(), "bob");
    }
}
