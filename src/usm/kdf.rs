//! USM key derivation functions: password-to-key and privacy key derivation.
//!
//! # Requirements
//! Implements: REQ-0081, REQ-0082

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

use crate::usm::auth::AuthProtocol;
use crate::usm::keys::SecretKey;
use crate::usm::privacy::PrivProtocol;

// The RFC 3414 §2.6 mandated stream length for the password-to-key algorithm.
const KDF_STREAM_LEN: usize = 1_048_576;

// ── Public functions ──────────────────────────────────────────────────────────

/// Derive a localised USM key from a passphrase and an engine identifier.
///
/// Implements the RFC 3414 §2.6 password-to-key algorithm extended to
/// HMAC-SHA-2 per RFC 7860 §2:
/// 1. Hash a 1 MiB stream formed by repeating `password` cyclically with
///    the protocol's underlying hash (SHA-256 or SHA-512) to produce a
///    master key.
/// 2. Localise: `HMAC(master_key, engineID || master_key)`, truncated to
///    `protocol.key_len()` bytes.
///
/// If `password` is longer than 1,048,576 bytes, only the first 1,048,576
/// bytes are effectively used: the cyclic repetition produces at most one
/// full or partial copy of the password within the stream length.
///
/// # Requirements
/// Implements: REQ-0081, REQ-0082
///
/// # Panics
/// Panics if `password` is empty.
#[must_use]
pub fn password_to_localised_key(
    password: &[u8],
    engine_id: &[u8],
    protocol: AuthProtocol,
) -> SecretKey {
    assert!(!password.is_empty(), "USM password must not be empty per RFC 3414");

    // Step 1: hash a 1 MiB stream of cyclically repeated password bytes.
    // The stream length of 2^20 bytes is mandated by RFC 3414 §2.6 and
    // RFC 7860 §2 to provide adequate work against dictionary attacks.
    // Streaming into the hasher avoids materialising the 1 MiB buffer.
    let full_copies = KDF_STREAM_LEN / password.len();
    let remainder = KDF_STREAM_LEN % password.len();
    let master_key_bytes: Vec<u8> = match protocol {
        AuthProtocol::HmacSha256 => {
            let mut hasher = Sha256::new();
            for _ in 0..full_copies {
                hasher.update(password);
            }
            hasher.update(&password[..remainder]);
            hasher.finalize().to_vec()
        }
        AuthProtocol::HmacSha512 => {
            let mut hasher = Sha512::new();
            for _ in 0..full_copies {
                hasher.update(password);
            }
            hasher.update(&password[..remainder]);
            hasher.finalize().to_vec()
        }
    };

    // Step 2: localise by HMACing engineID || master_key with the master key.
    // Using the full HMAC output (before any truncation) ensures we can
    // provide the correct number of bytes for the target protocol's key length.
    let mut localisation_message = Vec::with_capacity(engine_id.len() + master_key_bytes.len());
    localisation_message.extend_from_slice(engine_id);
    localisation_message.extend_from_slice(&master_key_bytes);

    let localised_bytes = hmac_full(protocol, &master_key_bytes, &localisation_message);
    SecretKey::new(localised_bytes[..protocol.key_len()].to_vec())
}

/// Derive a USM privacy key from a localised authentication key.
///
/// Implements RFC 3826 §2.1: the privacy key is derived by computing
/// `HMAC(auth_key, engineID || auth_key)` and taking the first
/// `priv_protocol.key_len()` bytes of the full HMAC output.
///
/// Using the full (non-truncated) HMAC output before slicing ensures
/// AES-256 can obtain its required 32 bytes even when the auth protocol's
/// normal MAC truncation length is shorter.
///
/// # Requirements
/// Implements: REQ-0081, REQ-0082
#[must_use]
pub fn derive_priv_key_from_auth_key(
    auth_key: &SecretKey,
    engine_id: &[u8],
    auth_protocol: AuthProtocol,
    priv_protocol: PrivProtocol,
) -> SecretKey {
    let mut localisation_message = Vec::with_capacity(engine_id.len() + auth_key.as_bytes().len());
    localisation_message.extend_from_slice(engine_id);
    localisation_message.extend_from_slice(auth_key.as_bytes());

    let full_hmac = hmac_full(auth_protocol, auth_key.as_bytes(), &localisation_message);
    SecretKey::new(full_hmac[..priv_protocol.key_len()].to_vec())
}

// ── Private helpers ───────────────────────────────────────────────────────────

// TODO: extract hmac_full into a shared helper so adding a new AuthProtocol
// variant cannot be missed in kdf.rs
// Implements: REQ-0081, REQ-0082
fn hmac_full(protocol: AuthProtocol, key: &[u8], message: &[u8]) -> Vec<u8> {
    // Returns the complete (non-truncated) HMAC output so callers can slice to
    // whatever length the target protocol requires.
    match protocol {
        AuthProtocol::HmacSha256 => {
            let mut h = Hmac::<Sha256>::new_from_slice(key)
                .expect("HMAC accepts any key length");
            h.update(message);
            h.finalize().into_bytes().to_vec()
        }
        AuthProtocol::HmacSha512 => {
            let mut h = Hmac::<Sha512>::new_from_slice(key)
                .expect("HMAC accepts any key length");
            h.update(message);
            h.finalize().into_bytes().to_vec()
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const MAPLE_ENGINE_ID: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

    #[test]
    fn given_password_when_derive_sha256_key_then_returns_32_bytes() {
        // Verifies: REQ-0081
        let key =
            password_to_localised_key(b"maplesyrup", MAPLE_ENGINE_ID, AuthProtocol::HmacSha256);
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn given_password_when_derive_sha512_key_then_returns_64_bytes() {
        // Verifies: REQ-0081
        let key =
            password_to_localised_key(b"maplesyrup", MAPLE_ENGINE_ID, AuthProtocol::HmacSha512);
        assert_eq!(key.len(), 64);
    }

    #[test]
    fn given_same_password_and_engine_id_when_derive_twice_then_same_key() {
        // Verifies: REQ-0081 — deterministic
        let key_a =
            password_to_localised_key(b"passphrase", MAPLE_ENGINE_ID, AuthProtocol::HmacSha256);
        let key_b =
            password_to_localised_key(b"passphrase", MAPLE_ENGINE_ID, AuthProtocol::HmacSha256);
        assert_eq!(key_a.as_bytes(), key_b.as_bytes());
    }

    #[test]
    fn given_different_engine_ids_when_derive_then_different_keys() {
        // Verifies: REQ-0082 — engine ID localises the key
        let engine_id_a = &[0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let engine_id_b = &[0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let key_a = password_to_localised_key(b"passphrase", engine_id_a, AuthProtocol::HmacSha256);
        let key_b = password_to_localised_key(b"passphrase", engine_id_b, AuthProtocol::HmacSha256);
        assert_ne!(key_a.as_bytes(), key_b.as_bytes());
    }

    #[test]
    fn given_different_passwords_when_derive_then_different_keys() {
        // Verifies: REQ-0081 — distinct passwords produce distinct keys
        let key_a =
            password_to_localised_key(b"password_one", MAPLE_ENGINE_ID, AuthProtocol::HmacSha256);
        let key_b =
            password_to_localised_key(b"password_two", MAPLE_ENGINE_ID, AuthProtocol::HmacSha256);
        assert_ne!(key_a.as_bytes(), key_b.as_bytes());
    }

    #[test]
    fn given_known_password_and_engine_id_when_derive_sha256_then_matches_reference() {
        // Verifies: REQ-0081
        // Reference computed using Python:
        //   import hashlib, hmac
        //   pw = b"maplesyrup"
        //   stream = (pw * (1048576 // len(pw) + 1))[:1048576]
        //   master = hashlib.sha256(stream).digest()
        //   engine_id = bytes([0,0,0,0,0,0,0,0,0,0,0,2])
        //   msg = engine_id + master
        //   localised = hmac.new(master, msg, hashlib.sha256).digest()[:32]
        //   # => fed2bc2c194909b1e76d274ec4072b8c92ee4a411c7e3711c729e5511d67027c
        let key =
            password_to_localised_key(b"maplesyrup", MAPLE_ENGINE_ID, AuthProtocol::HmacSha256);
        let expected: [u8; 32] = [
            0xfe, 0xd2, 0xbc, 0x2c, 0x19, 0x49, 0x09, 0xb1, 0xe7, 0x6d, 0x27, 0x4e, 0xc4, 0x07,
            0x2b, 0x8c, 0x92, 0xee, 0x4a, 0x41, 0x1c, 0x7e, 0x37, 0x11, 0xc7, 0x29, 0xe5, 0x51,
            0x1d, 0x67, 0x02, 0x7c,
        ];
        assert_eq!(key.as_bytes(), expected.as_slice());
    }

    #[test]
    fn given_known_password_and_engine_id_when_derive_sha512_then_matches_reference() {
        // Verifies: REQ-0081
        // Reference computed using Python:
        //   import hashlib, hmac
        //   pw = b"maplesyrup"
        //   stream = (pw * (1048576 // len(pw) + 1))[:1048576]
        //   master = hashlib.sha512(stream).digest()
        //   engine_id = bytes([0,0,0,0,0,0,0,0,0,0,0,2])
        //   msg = engine_id + master
        //   localised = hmac.new(master, msg, hashlib.sha512).digest()[:64]
        //   # => bc731c73e72186f8fb758bdaaea95c8e81943ec99...
        let key =
            password_to_localised_key(b"maplesyrup", MAPLE_ENGINE_ID, AuthProtocol::HmacSha512);
        let expected: [u8; 64] = [
            188, 115, 28, 115, 231, 33, 134, 248, 251, 117, 139, 218, 174, 169, 92, 142, 129, 148,
            62, 201, 146, 8, 77, 143, 126, 109, 64, 138, 69, 17, 206, 121, 72, 139, 33, 15, 226,
            169, 95, 178, 18, 5, 93, 199, 71, 131, 230, 201, 22, 51, 93, 41, 181, 171, 230, 137, 1,
            204, 71, 230, 198, 140, 223, 43,
        ];
        assert_eq!(key.as_bytes(), expected.as_slice());
    }

    #[test]
    fn given_auth_key_when_derive_priv_key_aes128_then_returns_16_bytes() {
        // Verifies: REQ-0082
        let auth_key = SecretKey::new(vec![0xABu8; 32]);
        let priv_key = derive_priv_key_from_auth_key(
            &auth_key,
            MAPLE_ENGINE_ID,
            AuthProtocol::HmacSha256,
            PrivProtocol::Aes128,
        );
        assert_eq!(priv_key.len(), 16);
    }

    #[test]
    fn given_auth_key_when_derive_priv_key_aes256_then_returns_32_bytes() {
        // Verifies: REQ-0082
        let auth_key = SecretKey::new(vec![0xABu8; 32]);
        let priv_key = derive_priv_key_from_auth_key(
            &auth_key,
            MAPLE_ENGINE_ID,
            AuthProtocol::HmacSha256,
            PrivProtocol::Aes256,
        );
        assert_eq!(priv_key.len(), 32);
    }

    #[test]
    fn given_sha512_auth_key_when_derive_priv_key_aes128_then_returns_16_bytes() {
        // Verifies: REQ-0082 — SHA-512 auth with AES-128 priv
        let auth_key = SecretKey::new(vec![0xCDu8; 64]);
        let priv_key = derive_priv_key_from_auth_key(
            &auth_key,
            MAPLE_ENGINE_ID,
            AuthProtocol::HmacSha512,
            PrivProtocol::Aes128,
        );
        assert_eq!(priv_key.len(), 16);
    }

    #[test]
    fn given_sha512_auth_key_when_derive_priv_key_aes256_then_returns_32_bytes() {
        // Verifies: REQ-0082 — SHA-512 auth with AES-256 priv
        let auth_key = SecretKey::new(vec![0xCDu8; 64]);
        let priv_key = derive_priv_key_from_auth_key(
            &auth_key,
            MAPLE_ENGINE_ID,
            AuthProtocol::HmacSha512,
            PrivProtocol::Aes256,
        );
        assert_eq!(priv_key.len(), 32);
    }

    #[test]
    fn given_same_auth_key_and_engine_id_when_derive_priv_twice_then_same() {
        // Verifies: REQ-0082 — deterministic
        let auth_key_a = SecretKey::new(vec![0x77u8; 32]);
        let auth_key_b = SecretKey::new(vec![0x77u8; 32]);
        let priv_key_a = derive_priv_key_from_auth_key(
            &auth_key_a,
            MAPLE_ENGINE_ID,
            AuthProtocol::HmacSha256,
            PrivProtocol::Aes128,
        );
        let priv_key_b = derive_priv_key_from_auth_key(
            &auth_key_b,
            MAPLE_ENGINE_ID,
            AuthProtocol::HmacSha256,
            PrivProtocol::Aes128,
        );
        assert_eq!(priv_key_a.as_bytes(), priv_key_b.as_bytes());
    }

    #[test]
    fn given_different_engine_ids_when_derive_priv_then_different_keys() {
        // Verifies: REQ-0082 — engine ID localises the privacy key
        let auth_key_a = SecretKey::new(vec![0x55u8; 32]);
        let auth_key_b = SecretKey::new(vec![0x55u8; 32]);
        let engine_id_a = &[0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let engine_id_b = &[0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let priv_key_a = derive_priv_key_from_auth_key(
            &auth_key_a,
            engine_id_a,
            AuthProtocol::HmacSha256,
            PrivProtocol::Aes128,
        );
        let priv_key_b = derive_priv_key_from_auth_key(
            &auth_key_b,
            engine_id_b,
            AuthProtocol::HmacSha256,
            PrivProtocol::Aes128,
        );
        assert_ne!(priv_key_a.as_bytes(), priv_key_b.as_bytes());
    }

    #[test]
    fn given_known_auth_key_and_engine_id_when_derive_priv_key_sha256_aes128_then_matches_reference() {
        // Verifies: REQ-0082
        // Reference computed using Python:
        //   import hashlib, hmac as hmac_mod
        //   auth_key = bytes([0xAB] * 32)
        //   engine_id = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2])
        //   msg = engine_id + auth_key
        //   full_hmac = hmac_mod.new(auth_key, msg, hashlib.sha256).digest()
        //   priv_key_aes128 = full_hmac[:16]
        //   # => 72a067e3c813a9e499ef311304f0d2dd
        let auth_key = SecretKey::new(vec![0xABu8; 32]);
        let priv_key = derive_priv_key_from_auth_key(
            &auth_key,
            MAPLE_ENGINE_ID,
            AuthProtocol::HmacSha256,
            PrivProtocol::Aes128,
        );
        let expected: [u8; 16] = [
            0x72, 0xa0, 0x67, 0xe3, 0xc8, 0x13, 0xa9, 0xe4, 0x99, 0xef, 0x31, 0x13, 0x04, 0xf0,
            0xd2, 0xdd,
        ];
        assert_eq!(priv_key.as_bytes(), expected.as_slice());
    }

    #[test]
    fn given_known_auth_key_and_engine_id_when_derive_priv_key_sha512_aes256_then_matches_reference() {
        // Verifies: REQ-0082
        // Reference computed using Python:
        //   import hashlib, hmac as hmac_mod
        //   auth_key = bytes([0xCD] * 64)
        //   engine_id = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2])
        //   msg = engine_id + auth_key
        //   full_hmac = hmac_mod.new(auth_key, msg, hashlib.sha512).digest()
        //   priv_key_aes256 = full_hmac[:32]
        //   # => 0b177da2cc286c5b8be5f98dd27fe09f65d7263f4a3d015b1a4ca5ede0d62a12
        let auth_key = SecretKey::new(vec![0xCDu8; 64]);
        let priv_key = derive_priv_key_from_auth_key(
            &auth_key,
            MAPLE_ENGINE_ID,
            AuthProtocol::HmacSha512,
            PrivProtocol::Aes256,
        );
        let expected: [u8; 32] = [
            0x0b, 0x17, 0x7d, 0xa2, 0xcc, 0x28, 0x6c, 0x5b, 0x8b, 0xe5, 0xf9, 0x8d, 0xd2, 0x7f,
            0xe0, 0x9f, 0x65, 0xd7, 0x26, 0x3f, 0x4a, 0x3d, 0x01, 0x5b, 0x1a, 0x4c, 0xa5, 0xed,
            0xe0, 0xd6, 0x2a, 0x12,
        ];
        assert_eq!(priv_key.as_bytes(), expected.as_slice());
    }

    #[test]
    fn given_single_byte_password_when_derive_sha256_key_then_matches_reference() {
        // Verifies: REQ-0081
        // Reference computed using Python:
        //   import hashlib, hmac as hmac_mod
        //   pw = b"x"
        //   stream_len = 1048576
        //   full_copies = stream_len // len(pw)  # = 1048576
        //   remainder = stream_len % len(pw)     # = 0
        //   h = hashlib.sha256()
        //   for _ in range(full_copies):
        //       h.update(pw)
        //   # remainder is 0, skip
        //   master = h.digest()
        //   engine_id = bytes([0,0,0,0,0,0,0,0,0,0,0,2])
        //   msg = engine_id + master
        //   localised = hmac_mod.new(master, msg, hashlib.sha256).digest()[:32]
        //   # => 02a49e62d47e70a75004c07134ea76cd3f9a48956d4730f146c0e1a0b4de1265
        let key =
            password_to_localised_key(b"x", MAPLE_ENGINE_ID, AuthProtocol::HmacSha256);
        let expected: [u8; 32] = [
            0x02, 0xa4, 0x9e, 0x62, 0xd4, 0x7e, 0x70, 0xa7, 0x50, 0x04, 0xc0, 0x71, 0x34, 0xea,
            0x76, 0xcd, 0x3f, 0x9a, 0x48, 0x95, 0x6d, 0x47, 0x30, 0xf1, 0x46, 0xc0, 0xe1, 0xa0,
            0xb4, 0xde, 0x12, 0x65,
        ];
        assert_eq!(key.as_bytes(), expected.as_slice());
    }

    #[test]
    fn given_password_longer_than_stream_when_derive_then_same_length_key() {
        // Verifies: REQ-0081
        let long_password = vec![0x42u8; 2_000_000]; // longer than 1 MiB
        let key = password_to_localised_key(&long_password, MAPLE_ENGINE_ID, AuthProtocol::HmacSha256);
        assert_eq!(key.len(), 32);
    }
}
