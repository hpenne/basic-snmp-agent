# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`basic-snmp-agent` is a Rust project (edition 2024) intended to implement an SNMP agent. It is currently in its initial scaffold stage with no dependencies yet.

## Common Commands

```bash
# Build
cargo build

# Build release
cargo build --release

# Run
cargo run

# Run tests
cargo test

# Run a single test
cargo test <test_name>

# Lint
cargo clippy

# Format
cargo fmt

# Check without building
cargo check
```

## Workflow Rules

- **Always discuss requirements with the user before adding RFC clauses.** Do not create or populate clauses until the user has agreed to the content.
- **Never create or modify ADRs without explicit user approval.** Always discuss the decision, alternatives, and rationale with the user before running `govctl adr new` or editing ADR content.
- **Never advance govctl phase or status without explicit user consent.** Do not run `govctl rfc advance`, `govctl rfc finalize`, or any equivalent mode/phase transition command unless the user explicitly asks.
- **Always fix MUST FIX and SHOULD FIX review comments.** SUGGESTIONS are optional and require user input. Never leave a MUST FIX or SHOULD FIX unresolved after a review cycle.

## Architecture

The project currently has a single binary entry point at `src/main.rs`. As SNMP agent functionality is added, the expected areas of concern will include:

- UDP socket handling (SNMP uses UDP port 161)
- ASN.1 / BER encoding and decoding for SNMP PDUs
- OID tree / MIB management
- Request dispatch (GET, GETNEXT, GETBULK, SET)
- Agent configuration and trap emission

## Coding rules

### govctl in general

- *ALWAYS* use govctl to edit RFCs and ADRs. Never edit files directly.

### govctl ADRs

- Use multi-line strings in the "[content]" section of ADRs. One sentence per line.

### General

- Language: Oxford English
- Write clean and neat code to be proud of. Always prefer simple and elegant solutions.
- Names should be descriptive and allow for local reasoning (code should be self-documenting through naming). Avoid generic names such as `bytes`, `buf`, `data`, `result`, `n`, or single letters — name variables after what they represent in the domain (e.g., `encoded_pdu`, `recv_buf`, `bytes_received`).
- Code comments should focus on rationale (the "why", not the "how").
- Do *NOT* add external dependencies without permission.
- Follow strict RFC compliance when implementing SNMP. Do not assume behavior — verify against the relevant RFC text. Wait for user confirmation before deviating from RFC specifications.

### Gherkin / BDD

- OID strings and other technical identifiers are acceptable in feature files when they are the actual subject under test.
- Name entities that cross step boundaries. When a `Then` step captures a result (e.g., a received trap), give it an explicit name in the step text. Subsequent `And` steps must reference that same name. The name must appear verbatim in both the step that creates the entity and every step that inspects it — never rely on implicit context state.
- Step definitions are the right place for all implementation detail (how to send a trap, how to retrieve and parse the result). Feature files express what is being tested, not how.

### Requirement traceability

Every Rust module, struct, and function must be annotated with the requirements it implements. Every unit test must be annotated with the requirements it verifies.

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

- No compiler warnings: Code must compile without warnings. Do not suppress warnings with `#[expect(...)]` unless there is a compelling reason; prefer fixing the underlying issue instead.
- Write idiomatic Rust code.
- Use Rust's type system to enforce correctness and avoid common errors.
- Document crate and module public APIs with clear and concise (but not too verbose)documentation. Add examples to external APIs.
- Use "given-when-then" naming and structure for tests (except for simple tests that do not set up any state)
- Tests may use the "mockall" crate for mocking when this makes tests easier to read.
- Implement `std::error::Error` for all error types (including internal "kind" enums).
- Place "impl" blocks immediately after the struct definition.
- Keep trait implementations close to the data structure but after the "impl" block.
- Order code so that a reader starting from the top understands the high-level intent, with details filled in below.
- Keep Related Things Together: Group related structs, enums, and trait implementations, rather than splitting them arbitrarily across the file.

## Testing

Gherkin feature files are in `tests/system/features/`. See `tests/system/features/CLAUDE.md` for authoring guidelines.