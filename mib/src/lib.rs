//! Internal MIB store.
//!
//! Responsibilities:
//!
//! - **OID-to-value map**: maintains a `BTreeMap<ObjectIdentifier, Value>` that
//!   preserves lexicographic OID ordering, as required by GETNEXT and GETBULK
//!   traversal.
//! - **Upsert API**: exposes a method to set a single OID's value; creates the
//!   entry if it does not exist, updates it if it does. No delete operation is
//!   provided.
//! - **OID resolution**: provides point-lookup (GET) and next-OID (GETNEXT/GETBULK)
//!   query methods used by the event loop when handling inbound SNMP requests.
//!
//! The store lives entirely on the event loop thread and requires no internal
//! synchronisation. Thread-safe write access from application threads is provided
//! by the channel-based command mechanism in [`transport`].
//!
//! This crate has no dependencies on [`transport`] or [`codec`].
