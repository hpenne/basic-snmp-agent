//! Internal MIB store.
//!
//! Responsibilities:
//!
//! - **OID-to-value map**: maintains a `BTreeMap<Oid, Value>` that preserves
//!   lexicographic OID ordering, as required by GETNEXT and GETBULK traversal.
//! - **Upsert API**: exposes a method to set a single OID's value; creates the
//!   entry if it does not exist, updates it if it does. No delete operation is
//!   provided.
//! - **OID resolution**: provides point-lookup (GET) and next-OID (GETNEXT/GETBULK)
//!   query methods used by the event loop when handling inbound SNMP requests.
//!
//! The store lives entirely on the event loop thread and requires no internal
//! synchronisation. Thread-safe write access from application threads is provided
//! by the channel-based command mechanism in the `transport` crate.

use std::collections::BTreeMap;
use std::ops::Bound;

pub use codec::{Oid, Value};

/// An OID-keyed value store that preserves lexicographic ordering.
///
/// `Store` wraps a [`BTreeMap`] whose keys are [`Oid`]s, giving O(log n) point
/// lookups and efficient in-order traversal for GETNEXT and GETBULK operations.
///
/// No API for removing entries is exposed: once an OID is inserted it is
/// permanent. This is an intentional design constraint.
///
/// # Requirements
/// Implements: REQ-0060, REQ-0061, REQ-0067
///
/// # Examples
///
/// ```
/// use mib::{Oid, Store, Value};
///
/// let mut store = Store::new();
/// let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
/// store.set(oid.clone(), Value::OctetString(b"My SNMP agent".to_vec()));
///
/// assert_eq!(store.get(&oid), Some(&Value::OctetString(b"My SNMP agent".to_vec())));
/// ```
pub struct Store {
    map: BTreeMap<Oid, Value>,
}

impl Store {
    /// Creates an empty `Store`.
    ///
    /// # Requirements
    /// Implements: REQ-0060
    ///
    /// # Examples
    ///
    /// ```
    /// use mib::Store;
    ///
    /// let store = Store::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }

    /// Inserts or updates the value bound to `oid`.
    ///
    /// If `oid` is already present, its value is replaced. If it is absent, a
    /// new entry is created. There is no delete operation; entries are permanent
    /// once inserted.
    ///
    /// # Requirements
    /// Implements: REQ-0060, REQ-0063
    ///
    /// # Examples
    ///
    /// ```
    /// use mib::{Oid, Store, Value};
    ///
    /// let mut store = Store::new();
    /// let oid: Oid = "1.3.6.1.2.1.1.3.0".parse().unwrap();
    /// store.set(oid.clone(), Value::TimeTicks(0));
    /// store.set(oid.clone(), Value::TimeTicks(100));
    ///
    /// assert_eq!(store.get(&oid), Some(&Value::TimeTicks(100)));
    /// ```
    pub fn set(&mut self, oid: Oid, value: Value) {
        self.map.insert(oid, value);
    }

    /// Returns the value bound to `oid`, or `None` if no entry exists.
    ///
    /// Corresponds to the SNMP GET operation.
    ///
    /// # Requirements
    /// Implements: REQ-0060
    ///
    /// # Examples
    ///
    /// ```
    /// use mib::{Oid, Store, Value};
    ///
    /// let mut store = Store::new();
    /// let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
    /// assert_eq!(store.get(&oid), None);
    /// store.set(oid.clone(), Value::Integer32(42));
    /// assert_eq!(store.get(&oid), Some(&Value::Integer32(42)));
    /// ```
    #[must_use]
    pub fn get(&self, oid: &Oid) -> Option<&Value> {
        self.map.get(oid)
    }

    /// Returns the entry with the smallest OID strictly greater than `oid`.
    ///
    /// Returns `None` if `oid` is greater than or equal to every key in the
    /// store. Corresponds to the SNMP GETNEXT operation.
    ///
    /// # Requirements
    /// Implements: REQ-0060, REQ-0061
    ///
    /// # Examples
    ///
    /// ```
    /// use mib::{Oid, Store, Value};
    ///
    /// let mut store = Store::new();
    /// let a: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
    /// let b: Oid = "1.3.6.1.2.1.1.2.0".parse().unwrap();
    /// store.set(a.clone(), Value::Integer32(1));
    /// store.set(b.clone(), Value::Integer32(2));
    ///
    /// let (next_oid, next_val) = store.next(&a).unwrap();
    /// assert_eq!(next_oid, &b);
    /// assert_eq!(next_val, &Value::Integer32(2));
    /// ```
    #[must_use]
    pub fn next(&self, oid: &Oid) -> Option<(&Oid, &Value)> {
        self.map
            .range((Bound::Excluded(oid), Bound::Unbounded))
            .next()
    }
}

impl Default for Store {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oid(s: &str) -> Oid {
        s.parse().unwrap()
    }

    // --- Store::new ---

    #[test]
    fn new_store_is_empty() {
        // Verifies: REQ-0060
        let store = Store::new();
        let probe = oid("1.3.0");
        assert_eq!(store.get(&probe), None);
        assert_eq!(store.next(&probe), None);
    }

    // --- Store::set ---

    #[test]
    fn given_empty_store_when_set_then_entry_is_retrievable() {
        // Verifies: REQ-0060, REQ-0063
        let mut store = Store::new();
        let o = oid("1.3.6.1.2.1.1.1.0");

        store.set(o.clone(), Value::Integer32(7));

        assert_eq!(store.get(&o), Some(&Value::Integer32(7)));
    }

    #[test]
    fn given_existing_entry_when_set_then_value_is_updated() {
        // Verifies: REQ-0063
        let mut store = Store::new();
        let o = oid("1.3.6.1.2.1.1.3.0");
        store.set(o.clone(), Value::TimeTicks(0));

        store.set(o.clone(), Value::TimeTicks(9999));

        assert_eq!(store.get(&o), Some(&Value::TimeTicks(9999)));
    }

    // --- Store::get ---

    #[test]
    fn given_absent_oid_when_get_then_returns_none() {
        // Verifies: REQ-0060
        let store = Store::new();
        assert_eq!(store.get(&oid("1.3.6.1")), None);
    }

    #[test]
    fn given_store_with_entry_when_get_exact_oid_then_returns_value() {
        // Verifies: REQ-0060
        let mut store = Store::new();
        let o = oid("1.3.6.1.2.1.1.1.0");
        store.set(o.clone(), Value::Counter32(42));

        assert_eq!(store.get(&o), Some(&Value::Counter32(42)));
    }

    #[test]
    fn given_store_with_entry_when_get_different_oid_then_returns_none() {
        // Verifies: REQ-0060
        let mut store = Store::new();
        store.set(oid("1.3.6.1.2.1.1.1.0"), Value::Integer32(1));

        assert_eq!(store.get(&oid("1.3.6.1.2.1.1.2.0")), None);
    }

    // --- Store::next ---

    #[test]
    fn given_empty_store_when_next_then_returns_none() {
        // Verifies: REQ-0060, REQ-0061
        let store = Store::new();
        assert_eq!(store.next(&oid("1.3.6.1")), None);
    }

    #[test]
    fn given_store_when_next_called_with_last_oid_then_returns_none() {
        // Verifies: REQ-0061
        let mut store = Store::new();
        let last = oid("1.3.6.1.2.1.1.5.0");
        store.set(oid("1.3.6.1.2.1.1.1.0"), Value::Integer32(1));
        store.set(last.clone(), Value::Integer32(5));

        assert_eq!(store.next(&last), None);
    }

    #[test]
    fn given_store_when_next_called_with_oid_beyond_all_entries_then_returns_none() {
        // Verifies: REQ-0061
        let mut store = Store::new();
        store.set(oid("1.3.6.1.2.1.1.1.0"), Value::Integer32(1));

        assert_eq!(store.next(&oid("2.999")), None);
    }

    #[test]
    fn given_store_with_entries_when_next_called_then_returns_immediate_successor() {
        // Verifies: REQ-0061
        let mut store = Store::new();
        let a = oid("1.3.6.1.2.1.1.1.0");
        let b = oid("1.3.6.1.2.1.1.2.0");
        let c = oid("1.3.6.1.2.1.1.3.0");
        store.set(a.clone(), Value::Integer32(1));
        store.set(b.clone(), Value::Integer32(2));
        store.set(c.clone(), Value::Integer32(3));

        let (next_oid, next_val) = store.next(&a).unwrap();

        assert_eq!(next_oid, &b);
        assert_eq!(next_val, &Value::Integer32(2));
    }

    #[test]
    fn given_store_when_next_called_with_oid_not_in_store_then_returns_next_larger() {
        // Verifies: REQ-0061
        let mut store = Store::new();
        let b = oid("1.3.6.1.2.1.1.2.0");
        let b_val = Value::Integer32(2);
        store.set(oid("1.3.6.1.2.1.1.1.0"), Value::Integer32(1));
        store.set(b.clone(), b_val.clone());

        // The query OID sits between the two stored OIDs.
        let between = oid("1.3.6.1.2.1.1.1.1");
        let (next_oid, next_val) = store.next(&between).unwrap();

        assert_eq!(next_oid, &b);
        assert_eq!(next_val, &b_val);
    }

    #[test]
    fn given_store_with_single_entry_when_next_before_it_then_returns_that_entry() {
        // Verifies: REQ-0061
        let mut store = Store::new();
        let o = oid("1.3.6.1.2.1.1.5.0");
        store.set(o.clone(), Value::OctetString(b"agent".to_vec()));

        let (next_oid, next_val) = store.next(&oid("1.3.6.1")).unwrap();

        assert_eq!(next_oid, &o);
        assert_eq!(next_val, &Value::OctetString(b"agent".to_vec()));
    }

    // --- Ordering guarantee ---

    #[test]
    fn given_entries_inserted_out_of_order_when_next_traverses_then_follows_oid_order() {
        // Verifies: REQ-0061
        let mut store = Store::new();
        // Insert in reverse order to verify BTreeMap preserves OID ordering
        // regardless of insertion order.
        store.set(oid("1.3.6.1.2.1.1.3.0"), Value::Integer32(3));
        store.set(oid("1.3.6.1.2.1.1.1.0"), Value::Integer32(1));
        store.set(oid("1.3.6.1.2.1.1.2.0"), Value::Integer32(2));

        let start = oid("1.3.0");
        let (first_oid, first_val) = store.next(&start).unwrap();
        assert_eq!(first_oid, &oid("1.3.6.1.2.1.1.1.0"));
        assert_eq!(first_val, &Value::Integer32(1));

        let (second_oid, second_val) = store.next(first_oid).unwrap();
        assert_eq!(second_oid, &oid("1.3.6.1.2.1.1.2.0"));
        assert_eq!(second_val, &Value::Integer32(2));

        let (third_oid, third_val) = store.next(second_oid).unwrap();
        assert_eq!(third_oid, &oid("1.3.6.1.2.1.1.3.0"));
        assert_eq!(third_val, &Value::Integer32(3));

        assert_eq!(store.next(third_oid), None);
    }

    // --- Re-exported types ---

    #[test]
    fn oid_and_value_are_re_exported() {
        // Verify that the convenience re-exports compile and are usable without
        // importing from codec directly.
        let o: Oid = "1.3.6.1".parse().unwrap();
        let integer_value: Value = Value::Integer32(0);
        let mut store = Store::new();
        store.set(o.clone(), integer_value);
        assert_eq!(store.get(&o), Some(&Value::Integer32(0)));
    }

    // --- No delete API (REQ-0067) ---

    #[test]
    fn given_store_when_entry_set_then_no_api_to_remove_it() {
        // Verifies: REQ-0067
        // REQ-0067 is a negative requirement: the Store MUST NOT expose any
        // public API for removing OID entries. This test documents the
        // constraint by confirming that an inserted entry persists — there is
        // no `remove`, `delete`, or similar method to call. The absence of
        // such a method is enforced by the type system at compile time.
        let mut store = Store::new();
        let o = oid("1.3.6.1.2.1.1.1.0");
        store.set(o.clone(), Value::Integer32(99));

        assert_eq!(store.get(&o), Some(&Value::Integer32(99)));
    }
}
