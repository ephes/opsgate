_sync:
    uv sync --extra dev

test: _sync
    uv run pytest

typecheck: _sync
    uv run mypy src tests

lint: _sync
    uv run ruff check src tests

run: _sync
    uv run python -m opsgate serve
