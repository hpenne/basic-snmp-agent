FROM rust:bookworm AS builder

WORKDIR /build

# Copy workspace manifests and all crate sources needed by test-agent.
# Ordering layers from least-to-most frequently changed for cache efficiency.
COPY Cargo.toml Cargo.lock ./
COPY codec/ codec/
COPY mib/ mib/
COPY transport/ transport/
COPY src/ src/
COPY tests/test-agent/ tests/test-agent/
COPY tests/test-agent-mib/ tests/test-agent-mib/

RUN cargo build -p test-agent --release

FROM debian:bookworm-slim

COPY --from=builder /build/target/release/test-agent /usr/local/bin/test-agent

ENTRYPOINT ["test-agent"]
