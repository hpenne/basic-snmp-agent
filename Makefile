.PHONY: test trace clippy rust-test python-test behave-test

# Run the full test suite: lint, Rust unit/doc tests, Python unit tests, and Behave system tests.
test: clippy rust-test python-test behave-test

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
