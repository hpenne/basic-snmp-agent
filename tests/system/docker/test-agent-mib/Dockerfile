# syntax=docker/dockerfile:1
FROM rust:bookworm AS builder

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY tests/test-agent/ tests/test-agent/
COPY tests/test-agent-mib/ tests/test-agent-mib/
COPY tests/snmpv3-frames/ tests/snmpv3-frames/

# Cache the cargo registry and compiled artifacts across builds so that only
# changed crates are recompiled. The binary is copied out of the cache-mounted
# target directory so it is accessible in the final stage.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=test-agent-mib-target,target=/build/target \
    cargo build -p test-agent-mib --release && \
    cp target/release/test-agent-mib /test-agent-mib

FROM debian:bookworm-slim

COPY --from=builder /test-agent-mib /usr/local/bin/test-agent-mib

EXPOSE 10161/tcp
ENTRYPOINT ["test-agent-mib"]
