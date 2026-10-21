"""pytest wiring of the API parity harness (rust/PLAN.md 7.3); see harness.py and rust/README.md."""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from harness import (
    DEFAULT_PROFILE,
    IMPLS,
    RUST_SLICES_LANDED,
    SUBMIT_TOKENS,
    Browser,
    Database,
    Profile,
    Recorder,
    Target,
    hash_password,
    start_server,
)


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("opsgate parity")
    group.addoption(
        "--impl",
        choices=IMPLS,
        default=os.environ.get("OPSGATE_IMPL", "python"),
        help="implementation under test (default: $OPSGATE_IMPL or python)",
    )
    group.addoption("--records", default=None, help="write one normalised record per scenario into this directory")
    group.addoption(
        "--target",
        default=None,
        help="run against an already running API at this base URL instead of starting one (shadow, PLAN.md 11.2)",
    )
    group.addoption(
        "--target-env",
        default=None,
        help="env file of the --target API (tokens and approver name); the approver password comes from "
        "$OPSGATE_PARITY_UI_PASSWORD",
    )
    group.addoption(
        "--target-impl",
        choices=IMPLS,
        default=None,
        help="implementation behind --target (defaults to --impl)",
    )


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "rust(*slices): Rust slices (PLAN.md 12) whose routes the scenario needs; it runs against Rust "
        "only when all of them are in harness.RUST_SLICES_LANDED",
    )
    config.addinivalue_line(
        "markers",
        "local: the scenario needs its own fresh API process (fresh database, settings profile, restarts, "
        "database or artifact access, throttle state); skipped against --target",
    )


def required_slices(item: pytest.Item) -> tuple[str, ...]:
    marker = item.get_closest_marker("rust")
    if marker is None:
        raise pytest.UsageError(f"{item.nodeid}: every parity scenario needs a @pytest.mark.rust(...) marker")
    return tuple(marker.args)


def missing_rust_slices(item: pytest.Item) -> list[str]:
    return sorted(set(required_slices(item)) - RUST_SLICES_LANDED)


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    impl = config.getoption("--impl")
    external = config.getoption("--target") is not None
    for item in items:
        missing = missing_rust_slices(item)
        if impl == "rust" and missing:
            item.add_marker(pytest.mark.skip(reason=f"Rust routes of {', '.join(missing)} not landed"))
        if external and item.get_closest_marker("local") is not None:
            item.add_marker(pytest.mark.skip(reason="needs its own API process (not possible against --target)"))


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[None]) -> Any:
    report = yield
    if report.when == "call":
        item.stash[OUTCOME] = report.outcome
    return report


OUTCOME = pytest.StashKey[str]()


def read_env_file(path: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = (part.strip() for part in stripped.split("=", 1))
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key] = value
    return values


def external_target(config: pytest.Config) -> Target | None:
    base_url = config.getoption("--target")
    if base_url is None:
        return None
    env_path = config.getoption("--target-env")
    password = os.environ.get("OPSGATE_PARITY_UI_PASSWORD", "")
    if env_path is None or not password:
        raise pytest.UsageError("--target needs --target-env and $OPSGATE_PARITY_UI_PASSWORD")
    env = read_env_file(env_path)
    return Target(
        impl=config.getoption("--target-impl") or config.getoption("--impl"),
        base_url=base_url.rstrip("/"),
        password=password,
        username=env.get("OPSGATE_UI_USERNAME", ""),
        service_name=env.get("OPSGATE_SERVICE_NAME", "opsgate").strip(),
        runner_token=env.get("OPSGATE_RUNNER_TOKEN", ""),
        submit_tokens={source: env.get(f"OPSGATE_SUBMIT_TOKEN_{source.upper()}", "") for source in SUBMIT_TOKENS},
    )


class Stack:
    """The API processes, browsers and database of one scenario."""

    def __init__(self, request: pytest.FixtureRequest, tmp_path: Path, impl: str) -> None:
        self.request = request
        self.tmp_path = tmp_path
        self.impl = impl
        self.rec = Recorder(impl, tmp_path)
        self.external = external_target(request.config)
        self.targets: list[Target] = []
        self.browsers: list[Browser] = []
        self.db_paths: list[Path] = []
        self.hashes: dict[str, str] = {}

    def _hash(self, password: str) -> str:
        if password not in self.hashes:
            self.hashes[password] = hash_password(password)
        return self.hashes[password]

    def _check_impl(self, impl: str) -> None:
        if impl == "rust":
            missing = missing_rust_slices(self.request.node)
            if missing:
                pytest.skip(f"Rust routes of {', '.join(missing)} not landed")

    def server(self, profile: Profile = DEFAULT_PROFILE, *, impl: str | None = None, name: str = "db") -> Target:
        """Start an API process on the scenario database ``name`` (shared by restarts)."""
        impl = impl or self.impl
        if self.external is not None:
            if profile != DEFAULT_PROFILE or impl != self.external.impl or self.targets:
                pytest.skip("needs its own API process (not possible against --target)")
            self.targets.append(self.external)
            return self.external
        self._check_impl(impl)
        db_path = self.tmp_path / name / "opsgate.sqlite3"
        if db_path not in self.db_paths:
            self.db_paths.append(db_path)
        target = start_server(
            impl,
            workdir=self.tmp_path / "run",
            profile=profile,
            db_path=db_path,
            exec_dir=self.tmp_path / "exec",
            password_hash=self._hash(profile.password),
        )
        self.targets.append(target)
        return target

    def restart(self, target: Target, *, impl: str | None = None, profile: Profile | None = None) -> Target:
        """Stop ``target`` and start ``impl`` on the same database and artifact tree."""
        if self.external is not None:
            pytest.skip("needs its own API process (not possible against --target)")
        assert target.db_path is not None
        target.stop()
        name = target.db_path.parent.name
        new = self.server(profile or target.profile, impl=impl or target.impl, name=name)
        for browser in self.browsers:
            if browser.target is target:
                browser.retarget(new)
        return new

    def browser(
        self, target: Target, who: str, headers: dict[str, str] | None = None, local_address: str | None = None
    ) -> Browser:
        browser = Browser(target, self.rec, who, headers, local_address)
        self.browsers.append(browser)
        return browser

    def approver(self, target: Target, who: str = "approver") -> Browser:
        browser = self.browser(target, who)
        resp = browser.login()
        assert resp.status == 302 and resp.location == "/tickets", (resp.status, resp.location)
        return browser

    def db(self, target: Target) -> Database:
        if target.db_path is None:
            pytest.skip("needs database access (not possible against --target)")
        return Database(target.db_path)

    def exec_dir(self, target: Target) -> Path:
        if target.exec_dir is None:
            pytest.skip("needs the artifact tree (not possible against --target)")
        return target.exec_dir

    def finish(self) -> None:
        for browser in self.browsers:
            browser.close()
        for target in self.targets:
            if target is not self.external:
                target.stop()
        if self.rec.snapshot_enabled:
            for path in self.db_paths:
                if path.exists():
                    self.rec.snapshots.append(Database(path).snapshot(self.rec.norm, set(self.hashes.values())))
        records = self.request.config.getoption("--records")
        node = self.request.node
        outcome = node.stash.get(OUTCOME, "not-run")
        if records and outcome in {"passed", "failed"}:
            out = Path(records)
            out.mkdir(parents=True, exist_ok=True)
            name = re.sub(r"[^A-Za-z0-9_.-]+", "_", node.nodeid.split("::", 1)[-1])[:150]
            digest = hashlib.sha256(node.nodeid.encode()).hexdigest()[:10]
            module = Path(node.nodeid.split("::", 1)[0]).stem
            name = f"{name}-{digest}"
            record = {"test": node.nodeid, "impl": self.impl, "outcome": outcome, **self.rec.as_dict()}
            (out / f"{module}__{name}.json").write_text(
                json.dumps(record, indent=1, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8"
            )


@pytest.fixture(scope="session")
def impl(request: pytest.FixtureRequest) -> str:
    return str(request.config.getoption("--impl"))


@pytest.fixture
def stack(request: pytest.FixtureRequest, tmp_path: Path, impl: str) -> Iterator[Stack]:
    stack = Stack(request, tmp_path, impl)
    try:
        yield stack
    finally:
        stack.finish()


@pytest.fixture
def rec(stack: Stack) -> Recorder:
    return stack.rec


@pytest.fixture
def api(stack: Stack) -> Target:
    """The default-profile API process of the scenario."""
    return stack.server()


@pytest.fixture
def anon(stack: Stack, api: Target) -> Browser:
    """A caller without session; bearer callers pass their token per request."""
    return stack.browser(api, "anon")


@pytest.fixture
def approver(stack: Stack, api: Target) -> Browser:
    """A browser signed in as the approver."""
    return stack.approver(api)


@pytest.fixture
def db(stack: Stack, api: Target) -> Database:
    return stack.db(api)
