//! USM user representation, associating a user name with optional
//! authentication and privacy credentials.
//!
//! # Requirements
//! Implements: REQ-0075, REQ-0076, REQ-0077, REQ-0079, REQ-0083, REQ-0084, REQ-0090, REQ-0091, REQ-0092, REQ-0131

use std::fmt;

use crate::usm::auth::AuthProtocol;
use crate::usm::keys::SecretKey;
use crate::usm::privacy::PrivProtocol;

// ── UserName ──────────────────────────────────────────────────────────────────

/// Error returned when a [`UserName`] cannot be constructed from the
/// provided string.
///
/// # Requirements
/// Implements: REQ-0091, REQ-0131
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidUserNameError {
    /// The name is empty (zero-length).
    Empty,
    /// The name exceeds the RFC 3414 maximum of 32 octets.
    TooLong {
        /// The actual byte length of the supplied name.
        length: usize,
    },
}

impl fmt::Display for InvalidUserNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "USM user name must not be empty per RFC 3414"),
            Self::TooLong { length } => write!(
                f,
                "USM user name length {length} exceeds the RFC 3414 maximum of {} octets",
                UserName::MAX_LENGTH,
            ),
        }
    }
}

impl std::error::Error for InvalidUserNameError {}

/// A validated USM user name: non-empty and at most 32 octets.
///
/// RFC 3414 `usmUserName` is typed `SnmpAdminString (SIZE(1..32))`, so
/// both the lower bound (non-empty) and the upper bound (32 octets) are
/// enforced at construction time.
///
/// # Requirements
/// Implements: REQ-0091, REQ-0131
///
/// # Examples
///
/// ```
/// use basic_snmp_agent::usm::user::{UserName, InvalidUserNameError};
///
/// let name = UserName::new("admin").unwrap();
/// assert_eq!(name.as_str(), "admin");
///
/// assert_eq!(UserName::new("").unwrap_err(), InvalidUserNameError::Empty);
///
/// let long_name = "a".repeat(33);
/// assert_eq!(
///     UserName::new(long_name).unwrap_err(),
///     InvalidUserNameError::TooLong { length: 33 }
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UserName(String);

impl UserName {
    /// RFC 3414 `usmUserName` upper bound: `SnmpAdminString (SIZE(1..32))`.
    ///
    /// The same 32-octet limit is enforced on the wire in `codec::ber::snmp`
    /// as `MSG_USER_NAME_MAX_LENGTH`, per the `msgUserName OCTET STRING
    /// (SIZE(0..32))` constraint in RFC 3414 §2.4.
    pub const MAX_LENGTH: usize = 32;

    /// Create a new `UserName`, validating both the lower and upper length bounds.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidUserNameError::Empty`] if `name` is empty, or
    /// [`InvalidUserNameError::TooLong`] if `name` exceeds 32 octets.
    ///
    /// # Requirements
    /// Implements: REQ-0091, REQ-0116, REQ-0131
    pub fn new(name: impl Into<String>) -> Result<Self, InvalidUserNameError> {
        let name = name.into();
        if name.is_empty() {
            return Err(InvalidUserNameError::Empty);
        }
        if name.len() > Self::MAX_LENGTH {
            return Err(InvalidUserNameError::TooLong { length: name.len() });
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

    // Named-field struct so that each call site is self-documenting without
    // relying on positional argument order.
    struct ExpectedCredentials<'a> {
        name: &'a str,
        security_level: SecurityLevel,
        auth_protocol: Option<AuthProtocol>,
        auth_key: Option<&'a [u8]>,
        priv_protocol: Option<PrivProtocol>,
        priv_key: Option<&'a [u8]>,
    }

    // Asserts all credential fields of a `UsmUser` in one place.  Pass `None`
    // for protocols and key slices when the corresponding credentials are absent.
    fn assert_usm_user_credentials(user: &UsmUser, expected: &ExpectedCredentials<'_>) {
        assert_eq!(user.name().as_str(), expected.name);
        assert_eq!(user.security_level(), expected.security_level);
        assert_eq!(user.auth_protocol(), expected.auth_protocol);
        assert_eq!(user.auth_key().map(SecretKey::as_bytes), expected.auth_key);
        assert_eq!(user.priv_protocol(), expected.priv_protocol);
        assert_eq!(user.priv_key().map(SecretKey::as_bytes), expected.priv_key);
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
        assert_eq!(result.unwrap_err(), InvalidUserNameError::Empty);
        assert_eq!(
            InvalidUserNameError::Empty.to_string(),
            "USM user name must not be empty per RFC 3414"
        );
    }

    #[test]
    fn given_name_exceeding_32_bytes_when_username_new_then_error() {
        // Verifies: REQ-0131
        let long_name = "a".repeat(33);
        let result = UserName::new(long_name);
        assert_eq!(
            result.unwrap_err(),
            InvalidUserNameError::TooLong { length: 33 }
        );
        assert_eq!(
            InvalidUserNameError::TooLong { length: 33 }.to_string(),
            "USM user name length 33 exceeds the RFC 3414 maximum of 32 octets"
        );
    }

    #[test]
    fn given_name_within_char_limit_but_exceeding_byte_limit_when_username_new_then_error() {
        // Verifies: REQ-0131
        // 11 snowman characters (☃ = U+2603, 3 bytes each) = 33 bytes, 11 chars.
        // The RFC 3414 constraint is on octets, not characters.
        let snowmen: String = std::iter::repeat_n('\u{2603}', 11).collect();
        assert_eq!(snowmen.len(), 33);
        assert_eq!(snowmen.chars().count(), 11);
        let result = UserName::new(snowmen);
        assert_eq!(
            result.unwrap_err(),
            InvalidUserNameError::TooLong { length: 33 }
        );
    }

    #[test]
    fn given_name_of_exactly_32_bytes_when_username_new_then_ok() {
        // Verifies: REQ-0131
        let boundary_name = "a".repeat(32);
        let name = UserName::new(boundary_name).unwrap();
        assert_eq!(name.as_str(), &"a".repeat(32));
    }

    #[test]
    fn security_level_ordering() {
        // Verifies: REQ-0075, REQ-0076, REQ-0077
        assert!(SecurityLevel::NoAuthNoPriv < SecurityLevel::AuthNoPriv);
        assert!(SecurityLevel::AuthNoPriv < SecurityLevel::AuthPriv);
        assert!(SecurityLevel::NoAuthNoPriv < SecurityLevel::AuthPriv);
    }

    #[test]
    fn given_no_auth_no_priv_when_all_accessors_then_none() {
        // Verifies: REQ-0075, REQ-0091, REQ-0092
        let user = UsmUser::no_auth_no_priv(user_name("public"));
        assert_usm_user_credentials(
            &user,
            &ExpectedCredentials {
                name: "public",
                security_level: SecurityLevel::NoAuthNoPriv,
                auth_protocol: None,
                auth_key: None,
                priv_protocol: None,
                priv_key: None,
            },
        );
    }

    #[test]
    fn given_auth_priv_aes256_with_sha256_when_priv_key_then_entire_auth_key() {
        // Verifies: REQ-0084
        // SHA-256 produces exactly 32 bytes; AES-256 needs exactly 32 bytes.
        // This is the tightest valid combination: the full auth key becomes the priv key.
        let user: UsmUser = AuthPrivUser::new(
            user_name("dave"),
            AuthProtocol::HmacSha256,
            SecretKey::new_from_exposed_slice(&[0xCC_u8; 32]),
            PrivProtocol::Aes256,
        )
        .unwrap()
        .into();
        assert_usm_user_credentials(
            &user,
            &ExpectedCredentials {
                name: "dave",
                security_level: SecurityLevel::AuthPriv,
                auth_protocol: Some(AuthProtocol::HmacSha256),
                auth_key: Some(&[0xCC_u8; 32]),
                priv_protocol: Some(PrivProtocol::Aes256),
                priv_key: Some(&[0xCC_u8; 32]),
            },
        );
    }

    #[test]
    fn try_from_maps_flag_bits_correctly() {
        // Verifies: REQ-0079 — bit masking, reportableFlag (bit 2), and reserved bits 3-7 are
        // all ignored; only bits 0-1 determine the security level.
        //
        // Each row is (raw_flags_byte, expected_result).
        let cases: &[(u8, Result<SecurityLevel, InvalidMsgFlags>)] = &[
            // Core flag bit mapping (bits 0-1 only)
            (0x00, Ok(SecurityLevel::NoAuthNoPriv)),
            (0x01, Ok(SecurityLevel::AuthNoPriv)),
            (0x03, Ok(SecurityLevel::AuthPriv)),
            (0x02, Err(InvalidMsgFlags(0x02))),
            // reportableFlag (bit 2) must be ignored
            (0x04, Ok(SecurityLevel::NoAuthNoPriv)),
            (0x05, Ok(SecurityLevel::AuthNoPriv)),
            (0x07, Ok(SecurityLevel::AuthPriv)),
            (0x06, Err(InvalidMsgFlags(0x06))),
            // Reserved high bits (3-7) must be masked out
            (0xF8, Ok(SecurityLevel::NoAuthNoPriv)), // 0xF8 & 0x03 == 0x00
            (0xF9, Ok(SecurityLevel::AuthNoPriv)),   // 0xF9 & 0x03 == 0x01
            (0xFF, Ok(SecurityLevel::AuthPriv)),     // 0xFF & 0x03 == 0x03
            (0xFA, Err(InvalidMsgFlags(0xFA))),      // 0xFA & 0x03 == 0x02
        ];
        for &(flags, ref expected) in cases {
            assert_eq!(
                SecurityLevel::try_from(flags),
                *expected,
                "flags=0x{flags:02x}"
            );
        }
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

    // Exercises all four key-length validation cases for AuthNoPrivUser:
    // valid SHA-256, wrong-length SHA-256, valid SHA-512, wrong-length SHA-512.
    // REQ-0090 is verified here because both acceptance cases confirm the user
    // is constructable from each supported protocol variant.
    //
    // Both the success and failure paths are tested in a single helper so that
    // adding a new protocol variant requires updating one place, keeping the
    // acceptance and rejection logic in sync with each other.
    fn assert_auth_no_priv_key_validation(
        protocol: AuthProtocol,
        valid_key_bytes: &[u8],
        short_key_bytes: &[u8],
    ) {
        let valid_key = SecretKey::new_from_exposed_slice(valid_key_bytes);
        let user = AuthNoPrivUser::new(user_name("alice"), protocol, valid_key).unwrap();
        assert_eq!(user.name().as_str(), "alice", "protocol={protocol:?}");
        assert_eq!(user.auth_protocol(), protocol, "protocol={protocol:?}");
        assert_eq!(
            user.auth_key().as_bytes(),
            valid_key_bytes,
            "protocol={protocol:?}"
        );

        let short_key = SecretKey::new_from_exposed_slice(short_key_bytes);
        let err = AuthNoPrivUser::new(user_name("alice"), protocol, short_key).unwrap_err();
        assert_eq!(
            err,
            InvalidKeyLength {
                expected: protocol.key_len(),
                actual: short_key_bytes.len(),
            },
            "protocol={protocol:?}"
        );
    }

    #[test]
    fn given_key_length_variants_when_new_auth_no_priv_user_then_accepts_valid_and_rejects_wrong() {
        // Verifies: REQ-0083, REQ-0090, REQ-0091, REQ-0092
        assert_auth_no_priv_key_validation(AuthProtocol::HmacSha256, &[0xAA_u8; 32], &[0_u8; 16]);
        assert_auth_no_priv_key_validation(AuthProtocol::HmacSha512, &[0xBB_u8; 64], &[0_u8; 32]);
    }

    #[test]
    fn given_auth_no_priv_user_when_into_usm_user_then_all_credentials_correct() {
        // Verifies: REQ-0076, REQ-0090, REQ-0091, REQ-0092
        let usm_user: UsmUser = AuthNoPrivUser::new(
            user_name("alice"),
            AuthProtocol::HmacSha256,
            SecretKey::new_from_exposed_slice(&[0xCC_u8; 32]),
        )
        .unwrap()
        .into();
        assert_usm_user_credentials(
            &usm_user,
            &ExpectedCredentials {
                name: "alice",
                security_level: SecurityLevel::AuthNoPriv,
                auth_protocol: Some(AuthProtocol::HmacSha256),
                auth_key: Some(&[0xCC_u8; 32]),
                priv_protocol: None,
                priv_key: None,
            },
        );
    }

    #[test]
    fn given_auth_no_priv_user_when_displayed_then_shows_user_name() {
        // Verifies: REQ-0091
        let key = SecretKey::new_from_exposed_slice(&[0_u8; 32]);
        let user = AuthNoPrivUser::new(user_name("alice"), AuthProtocol::HmacSha256, key).unwrap();
        assert_eq!(user.to_string(), "alice");
    }

    // ── AuthPrivUser ──────────────────────────────────────────────────────────

    // Exercises all four key-length validation cases for AuthPrivUser:
    // valid SHA-256 + AES-128, wrong-length SHA-256, valid SHA-512 + AES-256,
    // wrong-length SHA-512.
    // REQ-0090 is verified here because both acceptance cases confirm the user
    // is constructable from each supported protocol combination.
    //
    // Both the success and failure paths are tested in a single helper so that
    // adding a new protocol combination requires updating one place, keeping the
    // acceptance and rejection logic in sync with each other.
    fn assert_auth_priv_key_validation(
        auth_protocol: AuthProtocol,
        priv_protocol: PrivProtocol,
        valid_key_bytes: &[u8],
        short_key_bytes: &[u8],
    ) {
        let valid_key = SecretKey::new_from_exposed_slice(valid_key_bytes);
        let user =
            AuthPrivUser::new(user_name("bob"), auth_protocol, valid_key, priv_protocol).unwrap();
        assert_eq!(user.name().as_str(), "bob", "protocol={auth_protocol:?}");
        assert_eq!(
            user.auth_protocol(),
            auth_protocol,
            "protocol={auth_protocol:?}"
        );
        assert_eq!(
            user.auth_key().as_bytes(),
            valid_key_bytes,
            "protocol={auth_protocol:?}"
        );
        assert_eq!(
            user.priv_protocol(),
            priv_protocol,
            "protocol={auth_protocol:?}"
        );

        let short_key = SecretKey::new_from_exposed_slice(short_key_bytes);
        let err = AuthPrivUser::new(user_name("bob"), auth_protocol, short_key, priv_protocol)
            .unwrap_err();
        assert_eq!(
            err,
            InvalidKeyLength {
                expected: auth_protocol.key_len(),
                actual: short_key_bytes.len(),
            },
            "protocol={auth_protocol:?}"
        );
    }

    #[test]
    fn given_key_length_variants_when_new_auth_priv_user_then_accepts_valid_and_rejects_wrong() {
        // Verifies: REQ-0083, REQ-0090, REQ-0091, REQ-0092
        assert_auth_priv_key_validation(
            AuthProtocol::HmacSha256,
            PrivProtocol::Aes128,
            &[0xAA_u8; 32],
            &[0_u8; 16],
        );
        assert_auth_priv_key_validation(
            AuthProtocol::HmacSha512,
            PrivProtocol::Aes256,
            &[0xCC_u8; 64],
            &[0_u8; 32],
        );
    }

    #[test]
    fn given_auth_priv_user_when_into_usm_user_then_all_credentials_correct() {
        // Verifies: REQ-0077, REQ-0084, REQ-0090, REQ-0091, REQ-0092
        // REQ-0084: priv_key is the first 16 bytes of the 32-byte auth_key for AES-128
        let usm_user: UsmUser = AuthPrivUser::new(
            user_name("bob"),
            AuthProtocol::HmacSha256,
            SecretKey::new_from_exposed_slice(&[0xBB_u8; 32]),
            PrivProtocol::Aes128,
        )
        .unwrap()
        .into();
        assert_usm_user_credentials(
            &usm_user,
            &ExpectedCredentials {
                name: "bob",
                security_level: SecurityLevel::AuthPriv,
                auth_protocol: Some(AuthProtocol::HmacSha256),
                auth_key: Some(&[0xBB_u8; 32]),
                priv_protocol: Some(PrivProtocol::Aes128),
                priv_key: Some(&[0xBB_u8; 16]),
            },
        );
    }

    #[test]
    fn given_auth_priv_user_aes256_when_into_usm_user_then_correct_values() {
        // Verifies: REQ-0084, REQ-0090, REQ-0091, REQ-0092
        // REQ-0084: priv_key is the first 32 bytes of the 64-byte auth_key for AES-256
        let usm_user: UsmUser = AuthPrivUser::new(
            user_name("carol"),
            AuthProtocol::HmacSha512,
            SecretKey::new_from_exposed_slice(&[0xDD_u8; 64]),
            PrivProtocol::Aes256,
        )
        .unwrap()
        .into();
        assert_usm_user_credentials(
            &usm_user,
            &ExpectedCredentials {
                name: "carol",
                security_level: SecurityLevel::AuthPriv,
                auth_protocol: Some(AuthProtocol::HmacSha512),
                auth_key: Some(&[0xDD_u8; 64]),
                priv_protocol: Some(PrivProtocol::Aes256),
                priv_key: Some(&[0xDD_u8; 32]),
            },
        );
    }

    #[test]
    fn given_auth_priv_user_when_into_usm_user_then_priv_key_derived() {
        // Verifies: REQ-0084
        // The privacy key must be the leading priv_protocol.key_len() bytes of auth_key.
        // Distinct ascending byte values prove it is the leading prefix, not some other subset.
        let auth_key_bytes: Vec<u8> = (0..32_u8).collect();
        let expected_priv_key: Vec<u8> = (0..16_u8).collect();
        let usm_user: UsmUser = AuthPrivUser::new(
            user_name("bob"),
            AuthProtocol::HmacSha256,
            SecretKey::new_from_exposed_slice(&auth_key_bytes),
            PrivProtocol::Aes128,
        )
        .unwrap()
        .into();
        assert_usm_user_credentials(
            &usm_user,
            &ExpectedCredentials {
                name: "bob",
                security_level: SecurityLevel::AuthPriv,
                auth_protocol: Some(AuthProtocol::HmacSha256),
                auth_key: Some(&auth_key_bytes),
                priv_protocol: Some(PrivProtocol::Aes128),
                priv_key: Some(&expected_priv_key),
            },
        );
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
