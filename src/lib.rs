//! SNMPv3 agent library.
//!
//! This crate is the public API surface. It exposes [`Agent`], the primary entry
//! point for embedding applications, and ties together the [`codec`], [`mib`], and
//! [`transport`] crates.
//!
//! The agent runs its event loop on a dedicated OS thread spawned at construction
//! time. Application threads communicate with the event loop through channel-based
//! commands: MIB value updates, trap sends, and certificate replacements. [`Agent`]
//! is `Clone + Send + Sync` and holds only channel senders, so it can be shared
//! freely across threads.

pub struct Agent;
