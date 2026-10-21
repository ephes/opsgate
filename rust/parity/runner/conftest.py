"""pytest wiring of the runner parity harness (rust/PLAN.md 7.4); see runner_harness.py and rust/README.md."""

from __future__ import annotations

import json
import os
import re
import shutil
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fake_api import FakeApi
from runner_harness import (
    IMPLS,
    RUNNER_TOKEN,
    RUST_API_SLICES,
    RUST_RUNNER_SLICES,
    ApiServer,
    Normaliser,
    Process,
    Workspace,
    missing_rust_slices,
    opsgate_command,
    write_env_file,
)

OUTCOME = pytest.StashKey[str]()


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("opsgate runner parity")
    group.addoption(
        "--impl",
        choices=IMPLS,
        default=os.environ.get("OPSGATE_IMPL", "python"),
        help="runner implementation under test (default: $OPSGATE_IMPL or python); the cross-implementation "
        "and mixed-stack scenarios run the all-Python stacks for python and every stack with Rust for rust",
    )
    group.addoption("--records", default=None, help="write one normalised record per scenario into this directory")


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers", "stacks: the scenario is parametrised over implementation stacks (parameter `impls`)"
    )
    if shutil.which("tmux") is None:
        raise pytest.UsageError("the runner parity harness needs tmux on PATH (PLAN.md 7.4)")


def stack_of(item: pytest.Item, impl: str) -> tuple[list[str], str]:
    """(runner implementations in start order, API implementation or "fake") of a collected scenario."""
    callspec = getattr(item, "callspec", None)
    params = callspec.params if callspec is not None else {}
    if "runners" in params:
        runners = list(params["runners"])
    else:
        runners = [impl]
    return runners, str(params.get("api", "fake"))


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    impl = config.getoption("--impl")
    keep: list[pytest.Item] = []
    deselected: list[pytest.Item] = []
    for item in items:
        runners, api = stack_of(item, impl)
        stack = [*runners, api]
        parametrised = item.get_closest_marker("stacks") is not None
        if parametrised and (impl == "python") != all(part in {"python", "fake"} for part in stack):
            deselected.append(item)
            continue
        keep.append(item)
        needed: list[str] = []
        if "rust" in runners:
            needed += RUST_RUNNER_SLICES
        if api == "rust":
            needed += RUST_API_SLICES
        missing = missing_rust_slices(needed)
        if missing:
            item.add_marker(pytest.mark.skip(reason=f"Rust slices {', '.join(missing)} not landed"))
    if deselected:
        config.hook.pytest_deselected(items=deselected)
        items[:] = keep


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[None]) -> Any:
    report = yield
    if report.when == "call":
        item.stash[OUTCOME] = report.outcome
    elif report.when == "setup" and report.skipped:
        # A scenario skipped before its rig exists (a missing Rust slice, any skip marker) still leaves a
        # record, so that `compare.py --complete` sees the skipped stack.
        runners, api = stack_of(item, str(item.config.getoption("--impl")))
        write_record(item, scenario_name(item), api, runners, "skipped", {})
    return report


def write_record(
    node: pytest.Item, scenario: str, api: str, runners: list[str], outcome: str, observed: dict[str, Any]
) -> None:
    """Write the scenario's record into ``--records`` (if given); one file per scenario and stack."""
    records = node.config.getoption("--records")
    if not records:
        return
    out = Path(records)
    out.mkdir(parents=True, exist_ok=True)
    record = {
        "scenario": scenario,
        "test": node.nodeid,
        "stack": {"api": api, "runners": runners},
        "outcome": outcome,
        "observed": observed,
    }
    stack = "-".join([api, *runners])
    name = re.sub(r"[^A-Za-z0-9_.=-]+", "_", f"{scenario}__{stack}")[:200]
    (out / f"{name}.json").write_text(
        json.dumps(record, indent=1, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def scenario_name(item: pytest.Item) -> str:
    callspec = getattr(item, "callspec", None)
    name = getattr(item, "originalname", item.name)
    if callspec is None:
        return name
    rest = [
        f"{k}={str(v).encode('ascii', 'backslashreplace').decode('ascii')}"
        for k, v in callspec.params.items()
        if k not in {"runners", "api"}
    ]
    return f"{name}[{','.join(rest)}]" if rest else name


class Rig:
    """Fake API, workspace, processes and record of one scenario."""

    def __init__(self, request: pytest.FixtureRequest, tmp_path: Path) -> None:
        self.request = request
        node = request.node
        self.impl = str(request.config.getoption("--impl"))
        self.runners_planned, self.api_impl = stack_of(node, self.impl)
        self.scenario = scenario_name(node)
        self.ws = Workspace(tmp_path, re.sub(r"[^a-z0-9]+", "-", self.scenario.lower()).strip("-"))
        self.api = FakeApi(RUNNER_TOKEN).start()
        self.norm = Normaliser(self.ws.exec_dir, self.ws.root, self.ws.tmux_tmpdir)
        self.processes: list[Process] = []
        self.servers: list[ApiServer] = []
        self.runner_impls: list[str] = []
        self.observed: dict[str, Any] = {}

    def runner(
        self,
        impl: str | None = None,
        *,
        once: bool = False,
        base_url: str | None = None,
        without_tmux: bool = False,
        settings: dict[str, str] | None = None,
        **more_settings: str,
    ) -> Process:
        """Start a runner; ``settings`` override env-file keys, ``without_tmux`` hides tmux from ``PATH``."""
        settings = {**(settings or {}), **more_settings}
        impl = impl or self.impl
        number = len(self.runner_impls) + 1
        env_file = write_env_file(
            self.ws.root / f"runner-{number}.env", self.ws.runner_settings(base_url or self.api.base_url, **settings)
        )
        command = opsgate_command(impl, "runner", *(["--once"] if once else []))
        process = Process(
            f"runner-{number}-{impl}",
            command,
            env=self.ws.runner_env(env_file, without_tmux=without_tmux),
            cwd=self.ws.cwd,
            log_dir=self.ws.logs,
        )
        self.processes.append(process)
        self.runner_impls.append(impl)
        return process

    def server(self, impl: str) -> ApiServer:
        server = ApiServer(impl, self.ws, name=f"api-{len(self.servers) + 1}-{impl}")
        self.servers.append(server)
        return server

    def observe(self, key: str, value: Any) -> Any:
        self.observed[key] = value
        return value

    def observe_statuses(self, ticket: str, key: str | None = None) -> list[dict[str, Any]]:
        return self.observe(
            key or f"status:{self.norm.ticket_token(ticket)}", self.norm.status_calls(self.api.calls("status", ticket))
        )

    def observe_tree(self) -> dict[str, Any]:
        return self.observe("tree", self.norm.tree(self.ws.exec_dir))

    def observe_agents(self) -> list[dict[str, Any]]:
        return self.observe("agents", self.norm.agent_calls(self.ws.agent_calls()))

    def observe_sessions(self) -> list[str]:
        return self.observe("tmux_sessions", [self.norm.text(s) for s in self.ws.sessions()])

    def finish(self) -> None:
        for process in self.processes:
            if process.alive():
                process.kill()
        for server in self.servers:
            try:
                server.stop()
            except Exception:  # noqa: BLE001 - teardown must continue
                server.process.kill()
        self.ws.cleanup()
        self.api.stop()
        node = self.request.node
        write_record(
            node,
            self.scenario,
            self.api_impl,
            self.runner_impls or self.runners_planned,
            node.stash.get(OUTCOME, "not-run"),
            self.observed,
        )


@pytest.fixture
def rig(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Rig]:
    rig = Rig(request, tmp_path)
    try:
        yield rig
    finally:
        rig.finish()
