_sync:
    uv sync --extra dev

check:
    @just test
    @just typecheck
    @just lint

test: _sync
    uv run pytest

typecheck: _sync
    uv run mypy src tests

lint: _sync
    uv run ruff check src tests

run: _sync
    uv run python -m opsgate serve

run-runner: _sync
    uv run python -m opsgate runner

# ========= Rust port (rust/, rust/PLAN.md 7.6; needs rustup, see rust/README.md) =========

# Rust checks as in CI: rustfmt, clippy with warnings as errors, tests
rs-check:
    cd rust && cargo fmt --all --check
    cd rust && cargo clippy --workspace --all-targets --locked -- -D warnings
    just rs-test

# Rust tests
rs-test:
    cd rust && cargo test --workspace --locked

# Supply-chain check (licenses, advisories, sources; needs cargo-deny on PATH)
rs-deny:
    cd rust && cargo deny --locked check

# Format the Rust code
rs-fmt:
    cd rust && cargo fmt --all

# Regenerate the Rust fixtures from the Python implementation (rust/PLAN.md 7.2)
rs-fixtures: _sync
    uv run python rust/fixtures/generate.py

# Release build for this host (rust/target/release/opsgate)
rs-build:
    cd rust && cargo build --release --locked

# API parity harness (rust/PLAN.md 7.3): scenarios against Python and Rust `serve`, then the record diff.
# Scenarios whose Rust slices have not landed are skipped on the Rust side (harness.RUST_SLICES_LANDED).
rs-parity-api *args: _sync
    cd rust && cargo build --release --locked
    rm -rf rust/target/parity-api && mkdir -p rust/target/parity-api/python rust/target/parity-api/rust
    uv run pytest rust/parity/api -rs --impl python --records rust/target/parity-api/python {{args}}
    uv run pytest rust/parity/api -rs --impl rust --records rust/target/parity-api/rust {{args}}
    uv run python rust/parity/api/compare.py rust/target/parity-api/python rust/target/parity-api/rust --report rust/target/parity-api/report.json

# Runner parity harness (rust/PLAN.md 7.4; needs tmux): the Python runner, then the Rust runner
# (stacks with a Rust API are skipped until slices S4a and S4b land), then the diff of both record sets
rs-parity-runner: _sync rs-build
    rm -rf rust/target/parity-runner
    uv run pytest rust/parity/runner --impl python --records rust/target/parity-runner/python
    uv run pytest rust/parity/runner --impl rust --records rust/target/parity-runner/rust
    uv run python rust/parity/runner/compare.py rust/target/parity-runner/python rust/target/parity-runner/rust
