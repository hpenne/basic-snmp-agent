# syntax=docker/dockerfile:1
FROM rust:bookworm AS builder

WORKDIR /build

# Copy workspace manifests and all crate sources needed by test-agent.
# Ordering layers from least-to-most frequently changed for cache efficiency.
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY tests/test-agent/ tests/test-agent/
COPY tests/test-agent-mib/ tests/test-agent-mib/
COPY tests/snmpv3-frames/ tests/snmpv3-frames/

# Cache the cargo registry and compiled artifacts across builds so that only
# changed crates are recompiled. The binary is copied out of the cache-mounted
# target directory so it is accessible in the final stage.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build -p test-agent --release && \
    cp target/release/test-agent /test-agent

FROM debian:bookworm-slim

COPY --from=builder /test-agent /usr/local/bin/test-agent

ENTRYPOINT ["test-agent"]
