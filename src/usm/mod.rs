//! SNMPv3 User-based Security Model (USM) implementation.
//!
//! This module provides authentication and privacy for SNMPv3 messages
//! per RFC 3414, with HMAC-SHA-2 extensions per RFC 7860.
//!
//! # Requirements
//! Implements: REQ-0074, REQ-0075, REQ-0076, REQ-0077, REQ-0078, REQ-0079,
//! REQ-0080, REQ-0081, REQ-0082, REQ-0083, REQ-0084, REQ-0085, REQ-0086,
//! REQ-0087, REQ-0088, REQ-0089, REQ-0090, REQ-0091, REQ-0092, REQ-0093,
//! REQ-0094, REQ-0095, REQ-0096, REQ-0097, REQ-0098, REQ-0099, REQ-0100,
//! REQ-0101, REQ-0102, REQ-0103, REQ-0104, REQ-0105, REQ-0106

pub mod keys;
