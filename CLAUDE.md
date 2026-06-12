# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`basic-snmp-agent` is a Rust (edition 2024) SNMPv3 agent library. It accepts inbound SNMP requests over plain TCP (RFC 3430) and sends outbound traps over UDP. Security uses the User-based Security Model (USM, RFC 3414) with noAuthNoPriv, authNoPriv (HMAC-SHA-2), and authPriv (AES-128-CFB) security levels.

## Common Commands

```bash
make test          # clippy + Rust unit/doc tests + Python + Behave
make pre-commit    # test + python-lint + fuzz + traceability + format check
make clippy        # clippy --workspace --all-targets -D warnings
cargo test <name>  # run a single test
cargo fmt          # format code
```

## Integrity

Take **NO** shortcuts. Do not use judgement calls or liberal rule interpretations to avoid work — when something is slow or seems unlikely to matter, do it anyway.
If something genuinely cannot be done, say so explicitly and upfront rather than quietly omitting it.
Never substitute a cheaper version of work and report it as the full thing.

## Workflow Rules

- When using govctl, always verify actual state of work items and cross-references before reporting status — govctl output can lag behind reality. Check for implemented-but-unclosed items.
- **Always discuss requirements with the user before adding RFC clauses.** Do not create or populate clauses until the user has agreed to the content.
- **Never create or modify ADRs without explicit user approval.** Always discuss the decision, alternatives, and rationale with the user before running `govctl adr new` or editing ADR content.
- ADRs must not reference RFCs and cross-reference direction must be respected. Validate layering before writing any governance document.
- **Never advance govctl phase or status without explicit user consent.** Do not run `govctl rfc advance`, `govctl rfc finalize`, or any equivalent mode/phase transition command unless the user explicitly asks.
- **Never mention Claude or Anthropic in commit messages.** No `Co-Authored-By` trailers, no references to Claude, Anthropic, or claude.ai. Just write the commit message.
- **Always fix MUST FIX and SHOULD FIX review comments.** Fix SUGGESTIONS that improve code quality or test coverage. Never rationalise skipping with "pre-existing code", "outside the diff", or "out of scope" — where the code lives is irrelevant. When in doubt, fix it — the cost of an unnecessary small fix is lower than the cost of accumulating ignored feedback. If a suggestion truly cannot or should not be addressed, state the concrete reason explicitly. Never leave a MUST FIX or SHOULD FIX unresolved after a review cycle.

## Architecture

Single crate, no `main.rs` — this is a library (`src/lib.rs`) that embedding applications link against (ADR-0001). Test binaries under `tests/` exercise the library.

### Threading model (ADR-0002, ADR-0003)

A dedicated OS thread runs a single-threaded **mio**-based event loop (ADR-0014) that owns the TCP listener, all accepted connections, and the MIB store. No async runtime. Application threads communicate with the event loop via `std::sync::mpsc` channels; an `mio::Waker` wakes the poller immediately. `Agent` is `Clone + Send + Sync` (holds only channel senders). Shutdown is implicit on drop (ADR-0018).

### Module layout

- **`src/lib.rs`** — public API: `Agent`, `AgentBuilder` (builder pattern), re-exports. `AgentBuilder` accepts a single USM user, an optional `EngineBootsStore`, listen address, connection limits, and timeout configuration.
- **`src/codec/`** — hand-written BER codec with zero external ASN.1 dependencies (ADR-0026, ADR-0027). `ber/` has the TLV reader/writer and SNMP-specific encode/decode (`pdu.rs`, `varbind.rs`, `snmp.rs`). `pdu/` defines public PDU types, decode/encode entry points, and the `Value` enum covering all nine SMIv2 types (ADR-0006). `oid.rs` is the project's `Oid` type. rasn is retained only as a dev-dependency for cross-implementation verification.
- **`src/mib.rs`** — `BTreeMap<Oid, Value>` store (ADR-0010). Supports GET (point lookup), GETNEXT/GETBULK (range iteration), and upsert. Lives on the event loop thread; no locking needed.
- **`src/transport/`** — `event_loop.rs`: mio poll loop, TCP accept, RFC 6353 framing, connection management (idle timeouts, max-connections cap). `dispatch.rs`: the SNMPv3 message-processing pipeline — a single sequential function with RFC 3414 §3.1-ordered security checks and early returns (ADR-0020). `request.rs`: PDU handling (GET, GETNEXT, GETBULK, SET → notWritable). `trap.rs`: synchronous UDP trap sending (bypasses the event loop; ADR-0003).
- **`src/usm/`** — USM implementation (RFC 3414 + RFC 7860). `auth.rs`: HMAC-SHA-2 authentication. `privacy.rs`: AES-128-CFB encryption. `kdf.rs`: password-to-key derivation. `keys.rs`: `SecretKey` newtype with zeroisation on drop via `write_volatile` + `compiler_fence` (ADR-0025). `user.rs`: `UsmUser` (single user, fixed at construction; ADR-0023). `boots.rs`: `EngineBootsStore` trait for persistent engine-boots counter (ADR-0024). `time_window.rs`: replay-window validation. `counters.rs`: USM stats counters.
- **`src/error.rs`** — hand-rolled error enums implementing `std::error::Error` (ADR-0012).

### Key design decisions

| Area | Decision | ADR |
|---|---|---|
| Security model | USM only; TLS/TSM abandoned | ADR-0022 |
| Inbound transport | Plain TCP (RFC 3430), permanent | ADR-0022 |
| Outbound transport | Plain UDP for traps | ADR-0003 |
| BER codec | Hand-written, zero external deps | ADR-0026 |
| Wire types | Own internal structures, public API decoupled | ADR-0027 |
| Polling | mio (epoll/kqueue) | ADR-0014 |
| Error handling | Hand-rolled, no thiserror/anyhow | ADR-0012 |
| USM users | Single user, fixed at construction | ADR-0023 |
| Engine boots | Application-provided storage trait | ADR-0024 |
| Key zeroisation | `write_volatile` + `compiler_fence` | ADR-0025 |

### Production dependencies

mio, hmac, sha2, aes, cfb-mode, getrandom, log. No other external crates without explicit approval.

### Test infrastructure

- **Unit tests**: inline `#[cfg(test)]` modules in every source file.
- **System tests**: Gherkin feature files in `tests/system/features/`, driven by Python/behave against test-agent binaries.
- **Test agent binaries**: workspace members under `tests/` (`test-agent`, `test-agent-mib`, `test-agent-mib-auth`, `test-agent-mib-auth-priv`, `test-agent-mib-common`).
- **`tests/snmpv3-frames`**: helper crate for constructing SNMPv3 wire-format test vectors.
- **Fuzz targets**: in `fuzz/` (excluded from workspace), covering BER decode paths.

## Coding rules

### govctl in general

- *ALWAYS* use govctl to edit RFCs and ADRs. Never edit files directly.

### govctl ADRs

- Use multi-line strings in the "[content]" section of ADRs. One sentence per line.

### General

- Use the "/implement-and-review" command for **ALL** coding. **STRICTLY NO EXCEPTIONS OR JUDGEMENT CALLS**.
- Language: Oxford English
- Always prefer simple and elegant solutions.
- Names should be descriptive and allow for local reasoning (code should be self-documenting through naming). Avoid generic names such as `bytes`, `buf`, `data`, `result`, `n`, or single letters — name variables after what they represent in the domain (e.g., `encoded_pdu`, `recv_buf`, `bytes_received`).
- Code comments should focus on rationale (why things are implemented the way they are, not the "how"). Add references to ADRs when helpful.
- Follow strict RFC compliance when implementing SNMP. Do not assume behavior — verify against the relevant RFC text. Wait for user confirmation before deviating from RFC specifications.
- Use red/green TDD

### Gherkin / BDD

- OID strings and other technical identifiers are acceptable in feature files when they are the actual subject under test.
- Name entities that cross step boundaries. When a `Then` step captures a result (e.g., a received trap), give it an explicit name in the step text. Subsequent `And` steps must reference that same name. The name must appear verbatim in both the step that creates the entity and every step that inspects it — never rely on implicit context state.
- Step definitions are the right place for all implementation detail (how to send a trap, how to retrieve and parse the result). Feature files express what is being tested, not how.

### Requirement traceability

Every Rust module, struct, and function must be annotated with the requirements it implements. Every unit test must be annotated with the requirements it verifies.
*DO NOT* put such annotations on test utilities (like under tests/test-agent), only on tests and production code.

**Public items** — add a `# Requirements` section to the doc comment:

```rust
/// Sends a trap PDU to one or more destinations.
///
/// # Requirements
/// Implements: REQ-0034, REQ-0035, REQ-0042, REQ-0043
pub fn send_trap(...) {}
```

**Private items** — add a comment directly above the item:

```rust
// Implements: REQ-0048, REQ-0049
fn run_event_loop() {}
```

**Unit tests** — add a comment at the top of the test body:

```rust
#[test]
fn given_empty_destinations_when_send_trap_then_returns_error() {
    // Verifies: REQ-0043
    ...
}
```

Use `grep -r 'Implements: REQ-'` to find all implementation sites, `grep -r 'Verifies: REQ-'` to find all unit test sites, and `grep -r 'REQ-0043'` to find every mention of a specific requirement.

### Rust

- No compiler warnings: Code must compile without warnings. Do not suppress warnings with `#[expect(...)]`; prefer fixing the underlying issue instead.
- Create newtypes for domain types instead of using basic types like integers.
- Document crate and module public APIs with clear and concise (but not too verbose)documentation. Add examples to public APIs.
- Use "given-when-then" naming and structure for tests (except for simple tests that do not set up any state)
- Implement `std::error::Error` for all error types (including internal "kind" enums).
- Place "impl" blocks immediately after the struct definition.
- Keep trait implementations close to the data structure but after the "impl" block.
- Order code top-down: callers above callees, so a reader encounters high-level intent before implementation details.
- Avoid using "cfg" to write code that is only used for test support. Test using the existing public APIs instead.
- Do not use "as" for conversion between integer types unless truncation is intended. Use "from" or "try_from" instead.
- Do NOT use unwrap in production code, and avoid `expect` unless it is provable that it cannot be triggered (state why in a code comment).
- Do NOT use `unsafe` without explicit user approval.
- Minimize visibility: prefer private over `pub(crate)` over `pub`. Only make items as visible as they need to be.
- Prefer guard clauses and early returns over deeply nested if/else chains.
- Tests should not use "is_ok" or "is_some" for verification (check the value properly)

## Tool preferences
- Prefer native file editing tools (Edit, MultiEdit) over shell scripts for text manipulation
- Do not use Python or sed/awk one-liners for file edits; use the Edit tool directly
- For complex find-replace across multiple files, prefer `sd` over Python regex or sed
- Do not use Python for text manipulation tasks that `sd` or the Edit tool can handle

## Testing

Gherkin feature files are in `tests/system/features/`. See `tests/system/features/CLAUDE.md` for authoring guidelines.
