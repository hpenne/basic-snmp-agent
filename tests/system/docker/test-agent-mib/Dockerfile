FROM rust:bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY codec/ codec/
COPY mib/ mib/
COPY transport/ transport/
COPY src/ src/
COPY tests/test-agent-mib/ tests/test-agent-mib/
RUN cargo build -p test-agent-mib --release

FROM debian:bookworm-slim
COPY --from=builder /build/target/release/test-agent-mib /usr/local/bin/test-agent-mib
EXPOSE 10161/tcp
ENTRYPOINT ["test-agent-mib"]
