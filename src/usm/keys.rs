//! Key material types for USM authentication and privacy.
//!
//! # Requirements
//! Implements: REQ-0085

use std::sync::atomic::{compiler_fence, Ordering};

// ── SecretKey ────────────────────────────────────────────────────────────────

/// A heap-allocated byte buffer holding a localised USM key.
///
/// The contents are zeroised on drop using `write_volatile` followed by a
/// `compiler_fence`, ensuring the compiler cannot eliminate the zeroisation
/// as a dead store. This matches the technique used internally by the `zeroize`
/// crate and is specified by ADR-0025.
///
/// `Clone` is intentionally not derived: callers must not duplicate key material.
///
/// # Requirements
/// Implements: REQ-0085
pub struct SecretKey(Box<[u8]>);

impl SecretKey {
    /// Create a `SecretKey` from a byte vector.
    ///
    /// `SecretKey` is a raw container; callers are responsible for supplying
    /// a byte slice of the correct length for the intended protocol.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes.into_boxed_slice())
    }

    /// Return the key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Return the length of the key in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Return `true` if the key is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        // Zeroise all key material. `write_volatile` prevents the compiler from
        // treating these writes as dead stores and eliminating them. The
        // `compiler_fence` prevents reordering with any surrounding code that
        // might still reference the memory.
        //
        // Implements: REQ-0085
        let ptr = self.0.as_mut_ptr();
        for i in 0..self.0.len() {
            // SAFETY: `ptr` is valid for `self.0.len()` bytes and we are within bounds.
            unsafe { ptr.add(i).write_volatile(0u8) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn given_bytes_when_new_then_as_bytes_returns_them() {
        // Verifies: REQ-0085
        let key = SecretKey::new(vec![1, 2, 3, 4]);
        assert_eq!(key.as_bytes(), &[1, 2, 3, 4]);
    }

    #[test]
    fn given_key_when_len_then_returns_byte_count() {
        // Verifies: REQ-0085
        let key = SecretKey::new(vec![0u8; 32]);
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn given_empty_key_when_is_empty_then_true() {
        // Verifies: REQ-0085
        let key = SecretKey::new(vec![]);
        assert!(key.is_empty());
    }

    #[test]
    fn given_non_empty_key_when_is_empty_then_false() {
        // Verifies: REQ-0085
        let key = SecretKey::new(vec![0u8; 32]);
        assert!(!key.is_empty());
    }

    #[test]
    fn given_key_when_dropped_then_no_panic() {
        // Verifies: REQ-0085 — exercises the Drop impl (including the unsafe
        // write_volatile path) without triggering UB. A sanitiser run would
        // catch use-after-free; at minimum this confirms no panic on drop.
        let key = SecretKey::new(vec![0xABu8; 64]);
        drop(key);
    }
}
