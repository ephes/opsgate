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
