.PHONY: test trace clippy rust-test python-test behave-test fuzz-gen-seeds fuzz-1s fuzz-1m fuzz-10m fuzz-30m

# Run the full test suite: lint, Rust unit/doc tests, Python unit tests, and Behave system tests.
test: clippy rust-test python-test behave-test

pre-commit: clippy rust-test python-test fuzz-gen-seeds fuzz-1s trace check-format

# Lint with pedantic Clippy warnings.
clippy:
	cargo clippy --workspace --all-targets -- -W clippy::pedantic -D warnings

# Rust unit tests and doc tests.
rust-test:
	cargo test --workspace
	cargo test --doc

# Python unit tests for the tooling scripts.
python-test:
	python3 -m pytest tools/tests/ -v

# Behave system tests (requires Docker).
behave-test:
	cd tests/system && python3 -m behave

# Check requirement tracing coverage for all implemented RFCs.
trace:
	python3 tools/req_coverage_check.py

# Generate seed corpus files for all fuzz targets.
fuzz-gen-seeds:
	cargo run --manifest-path fuzz/Cargo.toml --bin generate_seeds

# Run all fuzzers locally for 1 second each.
fuzz-1s:
	cargo +nightly fuzz run snmpv3_request -- -max_total_time=1
	cargo +nightly fuzz run tcp_framing -- -max_total_time=1
	cargo +nightly fuzz run snmpv3_request_auth -- -max_total_time=1

# Run all fuzzers locally for 1 minute each.
fuzz-1m:
	cargo +nightly fuzz run snmpv3_request -- -max_total_time=60
	cargo +nightly fuzz run tcp_framing -- -max_total_time=60
	cargo +nightly fuzz run snmpv3_request_auth -- -max_total_time=60

# Run all fuzzers locally for 10 minutes each.
fuzz-10m:
	cargo +nightly fuzz run snmpv3_request -- -max_total_time=600
	cargo +nightly fuzz run tcp_framing -- -max_total_time=600
	cargo +nightly fuzz run snmpv3_request_auth -- -max_total_time=600

# Run all fuzzers locally for 30 minutes each.
fuzz-30m:
	cargo +nightly fuzz run snmpv3_request -- -max_total_time=1800
	cargo +nightly fuzz run tcp_framing -- -max_total_time=1800
	cargo +nightly fuzz run snmpv3_request_auth -- -max_total_time=1800

check-format:
	cargo fmt --check
