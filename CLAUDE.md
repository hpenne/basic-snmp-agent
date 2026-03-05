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

- Write clean and neat code to be proud of. Always prefer simple and elegant solutions.
- Write idiomatic Rust code.
- Use Rust's type system to enforce correctness and avoid common errors.
- Names should be descriptive and allow for local reasoning (code should be self-documenting through naming).
- Document crate and module public APIs with clear and concise (but not too verbose)documentation. Add examples to external APIs.
- Code comments should focus on rationale (the "why", not the "how").