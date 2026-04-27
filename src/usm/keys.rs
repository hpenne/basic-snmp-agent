//! Key material types for USM authentication and privacy.
//!
//! # Requirements
//! Implements: REQ-0085, REQ-0108

use std::fmt;
use std::sync::atomic::{Ordering, compiler_fence};

// ── zeroize_slice ─────────────────────────────────────────────────────────────

/// Zeroise all bytes of `slice` in a way the compiler cannot eliminate.
///
/// Uses `write_volatile` byte-by-byte followed by a `compiler_fence(SeqCst)`
/// to prevent the compiler from treating the writes as dead stores or
/// reordering them with surrounding code that might still reference the memory.
/// This matches the technique used internally by the `zeroize` crate and is
/// specified by ADR-0025.
///
/// # Safety / correctness
/// The writes are observable through the volatile mechanism, so no `unsafe`
/// caller annotation is required here — the `unsafe` is encapsulated inside
/// this function.
///
/// # Requirements
/// Implements: REQ-0085, REQ-0108
pub fn zeroize_slice(slice: &mut [u8]) {
    // Implements: REQ-0085, REQ-0108
    let ptr = slice.as_mut_ptr();
    for i in 0..slice.len() {
        // SAFETY: `ptr` is valid for `slice.len()` bytes and we are within bounds.
        unsafe { ptr.add(i).write_volatile(0u8) };
    }
    compiler_fence(Ordering::SeqCst);
}

// ── SecretKey ────────────────────────────────────────────────────────────────

/// A heap-allocated byte buffer holding a localised USM key.
///
/// The contents are zeroised on drop using [`zeroize_slice`], ensuring the
/// compiler cannot eliminate the zeroisation as a dead store. This matches
/// the technique used internally by the `zeroize` crate and is specified by
/// ADR-0025.
///
/// `Clone` is intentionally not derived: callers must not duplicate key
/// material.
///
/// `Debug` is intentionally redacted: the key bytes are never printed.
///
/// # Requirements
/// Implements: REQ-0085, REQ-0108
pub struct SecretKey(Box<[u8]>);

impl SecretKey {
    /// Create a `SecretKey` by copying bytes from a caller-owned slice.
    ///
    /// The name `new_from_exposed_slice` is deliberately conspicuous in audits:
    /// it signals that the caller created sensitive data elsewhere and is now
    /// transferring it into the zeroising container. Callers should minimise the
    /// lifetime of the original slice before calling this.
    ///
    /// `SecretKey` is a raw container; callers are responsible for supplying
    /// a slice of the correct length for the intended protocol.
    ///
    /// # Requirements
    /// Implements: REQ-0085
    ///
    /// # Examples
    ///
    /// ```
    /// use basic_snmp_agent::usm::keys::SecretKey;
    ///
    /// let key = SecretKey::new_from_exposed_slice(&[0xABu8; 32]);
    /// assert_eq!(key.len(), 32);
    /// ```
    #[must_use]
    pub fn new_from_exposed_slice(bytes: &[u8]) -> Self {
        Self(bytes.to_vec().into_boxed_slice())
    }

    /// Allocate a `SecretKey` of `len` zero bytes.
    ///
    /// Intended for in-place key construction: allocate with `zeroed`, then
    /// write the final key bytes via [`as_bytes_mut`][Self::as_bytes_mut].
    /// This keeps intermediate key material inside the zeroising container
    /// from the moment of allocation.
    ///
    /// # Requirements
    /// Implements: REQ-0085, REQ-0108
    ///
    /// # Examples
    ///
    /// ```
    /// use basic_snmp_agent::usm::keys::SecretKey;
    ///
    /// let key = SecretKey::zeroed(16);
    /// assert_eq!(key.len(), 16);
    /// assert!(key.as_bytes().iter().all(|&b| b == 0));
    /// ```
    #[must_use]
    pub fn zeroed(len: usize) -> Self {
        Self(vec![0u8; len].into_boxed_slice())
    }

    /// Return the key bytes as an immutable slice.
    ///
    /// # Requirements
    /// Implements: REQ-0085
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Return the key bytes as a mutable slice for in-place writes.
    ///
    /// Intended for use after [`zeroed`][Self::zeroed]: write the derived key
    /// bytes directly into the allocated buffer without creating an intermediate
    /// `Vec` outside the zeroising container.
    ///
    /// # Requirements
    /// Implements: REQ-0085, REQ-0108
    ///
    /// # Examples
    ///
    /// ```
    /// use basic_snmp_agent::usm::keys::SecretKey;
    ///
    /// let mut key = SecretKey::zeroed(4);
    /// key.as_bytes_mut().copy_from_slice(&[1, 2, 3, 4]);
    /// assert_eq!(key.as_bytes(), &[1, 2, 3, 4]);
    /// ```
    #[must_use]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Shrink the key to `new_len` bytes, zeroising the discarded tail bytes.
    ///
    /// This avoids allocating a new buffer when only a prefix of a hash output
    /// is required. The tail bytes are zeroised before the allocation is shrunk,
    /// so they are never visible outside this function.
    ///
    /// # Panics
    ///
    /// Panics if `new_len > self.len()`.
    ///
    /// # Requirements
    /// Implements: REQ-0085, REQ-0108
    ///
    /// # Examples
    ///
    /// ```
    /// use basic_snmp_agent::usm::keys::SecretKey;
    ///
    /// let mut key = SecretKey::new_from_exposed_slice(&[1, 2, 3, 4, 5, 6]);
    /// key.truncate(4);
    /// assert_eq!(key.as_bytes(), &[1, 2, 3, 4]);
    /// ```
    pub fn truncate(&mut self, new_len: usize) {
        assert!(
            new_len <= self.0.len(),
            "SecretKey::truncate: new_len ({new_len}) > current len ({})",
            self.0.len()
        );
        // Convert to Vec so we can truncate in place without a second heap
        // allocation. Zeroize the tail first — Vec::truncate only adjusts
        // the length and does not clear the freed bytes.
        let mut vec = std::mem::take(&mut self.0).into_vec();
        zeroize_slice(&mut vec[new_len..]);
        vec.truncate(new_len);
        self.0 = vec.into_boxed_slice();
    }

    /// Return the length of the key in bytes.
    ///
    /// # Requirements
    /// Implements: REQ-0085
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Return `true` if the key is empty.
    ///
    /// # Requirements
    /// Implements: REQ-0085
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        // Zeroise all key material using the shared primitive so the logic is
        // not duplicated.
        //
        // Implements: REQ-0085
        zeroize_slice(&mut self.0);
    }
}

impl fmt::Debug for SecretKey {
    // Implements: REQ-0085
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey([REDACTED; {}])", self.0.len())
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn given_slice_when_zeroize_slice_then_all_bytes_are_zero() {
        // Verifies: REQ-0085, REQ-0108
        let mut buf = [0xFFu8; 8];
        zeroize_slice(&mut buf);
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn given_empty_slice_when_zeroize_slice_then_no_panic() {
        // Verifies: REQ-0085, REQ-0108
        let mut buf: [u8; 0] = [];
        zeroize_slice(&mut buf); // must not panic
    }

    #[test]
    fn given_bytes_when_new_from_exposed_slice_then_as_bytes_returns_them() {
        // Verifies: REQ-0085
        let key = SecretKey::new_from_exposed_slice(&[1, 2, 3, 4]);
        assert_eq!(key.as_bytes(), &[1, 2, 3, 4]);
    }

    #[test]
    fn given_length_when_zeroed_then_all_bytes_are_zero() {
        // Verifies: REQ-0085, REQ-0108
        let key = SecretKey::zeroed(16);
        assert_eq!(key.len(), 16);
        assert!(key.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn given_zeroed_key_when_as_bytes_mut_then_write_is_visible() {
        // Verifies: REQ-0085, REQ-0108
        let mut key = SecretKey::zeroed(4);
        key.as_bytes_mut().copy_from_slice(&[10, 20, 30, 40]);
        assert_eq!(key.as_bytes(), &[10, 20, 30, 40]);
    }

    #[test]
    fn given_key_when_truncate_then_length_shrinks_and_prefix_preserved() {
        // Verifies: REQ-0085, REQ-0108
        let mut key = SecretKey::new_from_exposed_slice(&[1, 2, 3, 4, 5, 6]);
        key.truncate(4);
        assert_eq!(key.len(), 4);
        assert_eq!(key.as_bytes(), &[1, 2, 3, 4]);
    }

    #[test]
    fn given_key_when_truncate_to_same_length_then_no_change() {
        // Verifies: REQ-0085, REQ-0108
        let mut key = SecretKey::new_from_exposed_slice(&[7, 8, 9]);
        key.truncate(3);
        assert_eq!(key.as_bytes(), &[7, 8, 9]);
    }

    #[test]
    fn given_key_when_truncate_to_zero_then_empty() {
        // Verifies: REQ-0085, REQ-0108
        let mut key = SecretKey::new_from_exposed_slice(&[1, 2, 3, 4]);
        key.truncate(0);
        assert!(key.is_empty());
    }

    #[test]
    #[should_panic(expected = "new_len (5) > current len (3)")]
    fn given_key_when_truncate_to_larger_length_then_panics() {
        // Verifies: REQ-0085, REQ-0108
        let mut key = SecretKey::new_from_exposed_slice(&[1, 2, 3]);
        key.truncate(5);
    }

    #[test]
    fn given_key_when_len_then_returns_byte_count() {
        // Verifies: REQ-0085
        let key = SecretKey::new_from_exposed_slice(&[0u8; 32]);
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn given_empty_key_when_is_empty_then_true() {
        // Verifies: REQ-0085
        let key = SecretKey::new_from_exposed_slice(&[]);
        assert!(key.is_empty());
    }

    #[test]
    fn given_non_empty_key_when_is_empty_then_false() {
        // Verifies: REQ-0085
        let key = SecretKey::new_from_exposed_slice(&[0u8; 32]);
        assert!(!key.is_empty());
    }

    #[test]
    fn given_key_when_dropped_then_no_panic() {
        // Verifies: REQ-0085 — exercises the Drop impl (including the unsafe
        // write_volatile path) without triggering UB. A sanitiser run would
        // catch use-after-free; at minimum this confirms no panic on drop.
        let key = SecretKey::new_from_exposed_slice(&[0xABu8; 64]);
        drop(key);
    }

    #[test]
    fn given_key_when_debug_then_redacted() {
        // Verifies: REQ-0085
        let key = SecretKey::new_from_exposed_slice(&[0xFFu8; 8]);
        assert_eq!(format!("{key:?}"), "SecretKey([REDACTED; 8])");
    }
}
