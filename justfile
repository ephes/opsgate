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
