"""Black-box runner parity harness: processes, tmux, fake agents, records (rust/PLAN.md 7.4).

An implementation under test is a real runner process (``python -m opsgate
runner`` or the Rust ``opsgate runner``) with a generated env file, a
temporary execution data directory, a private tmux socket label and
``TMUX_TMPDIR``, and fake ``codex``/``claude`` first on ``PATH``. Its API is
either the scripted fake of ``fake_api.py`` or, in the mixed-stack scenarios,
a real ``serve`` process of either implementation.

Scenarios assert the Python behaviour (the oracle) and record a normalised
view of what they observed: the runner's API calls (event, state, result,
result detail, tmux session entries), the artifact tree (names, modes, JSON
values, file text; generated timestamps masked, paths relative to the
execution data directory, shell quoting reduced to words), tmux session names,
state files and agent invocations. ``compare.py`` diffs the records of
different stacks of the same scenario. Formatting of JSON and shell quoting
are P2 (PLAN.md 3.3) and never compared.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from http.cookiejar import CookieJar
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
IMPLS = ("python", "rust")

# Rust slices (PLAN.md section 12) that have landed on main. A scenario runs a
# Rust runner only once S6b (supervisor and ``runner`` wiring) is listed, and a
# Rust API in the mixed stacks only once S4a and S4b (bearer routes, login and
# cookie-authenticated approval) are listed. Each of those slices adds its id
# here when it merges.
RUST_SLICES_LANDED: frozenset[str] = frozenset({"S6b"})
RUST_RUNNER_SLICES = ("S6b",)
RUST_API_SLICES = ("S4a", "S4b")

RUNNER_TOKEN = "runner-token-000000000000"
RUNNER_HOST = "runner-parity"
SUBMIT_TOKEN_NYXMON = "nyxmon-token-000000000000"
SUBMIT_TOKEN_OTHER = {"openclaw": "openclaw-token-0000000000", "operator": "operator-token-00000000000"}
UI_USERNAME = "opsgate-admin"
UI_PASSWORD = "secret-password"
SESSION_SECRET = "parity-session-secret-0000000000"

TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})")
WRITTEN_TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{6})?Z")
UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
UNHANDLED_PREFIX = "runner_unhandled_exception:"
SYSTEM_PATH = ("/usr/bin", "/bin", "/usr/sbin", "/sbin")
# The tmux configuration production uses for the runner's server: ops-library
# roles/opsgate_deploy/templates/ops.tmux.conf.j2 with the role defaults. With
# remain-on-exit, a finished step's session stays (dead pane) until the
# runner's recovery pass kills the sessions of terminal tickets.
TMUX_CONF = """\
set -g history-limit 200000
set -g base-index 1
set -g pane-base-index 1
set -g detach-on-destroy off
set -g destroy-unattached off
set -g remain-on-exit on
set -g set-titles off
set -g mouse on
"""
P1_LOG_RE = re.compile(r"(Runner claim failed|Runner API unavailable): status=(\S+) category=(\S+)")


class HarnessError(RuntimeError):
    pass


def missing_rust_slices(needed: Iterable[str]) -> list[str]:
    return sorted(set(needed) - RUST_SLICES_LANDED)


def rust_binary() -> Path:
    configured = os.environ.get("OPSGATE_RUST_BIN", "").strip()
    if configured:
        return Path(configured)
    return REPO / "rust" / "target" / "release" / "opsgate"


def opsgate_command(impl: str, *args: str) -> list[str]:
    if impl == "python":
        return [sys.executable, "-m", "opsgate", *args]
    if impl == "rust":
        binary = rust_binary()
        if not binary.is_file():
            raise HarnessError(f"Rust binary {binary} is missing: run `cargo build --release --locked` in rust/")
        return [str(binary), *args]
    raise HarnessError(f"unknown implementation {impl!r}")


# The only variables of the caller's environment that reach a runner, its tmux server and the
# agents, or an API process: locale, user and temporary directory.
INHERITED_ENV = ("LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "LOGNAME", "TMPDIR", "TZ", "USER")


def base_env() -> dict[str, str]:
    return {key: os.environ[key] for key in INHERITED_ENV if key in os.environ}


def wait_until(predicate: Callable[[], Any], *, timeout: float = 30.0, what: str, interval: float = 0.05) -> Any:
    deadline = time.monotonic() + timeout
    while True:
        value = predicate()
        if value:
            return value
        if time.monotonic() >= deadline:
            raise HarnessError(f"timed out after {timeout:.0f}s waiting for {what}")
        time.sleep(interval)


def write_env_file(path: Path, values: dict[str, str]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{key}={value}\n" for key, value in values.items()), encoding="utf-8")
    return path


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


# ----- processes -----------------------------------------------------------


class Process:
    """A runner or API subprocess with captured output."""

    def __init__(self, name: str, command: list[str], *, env: dict[str, str], cwd: Path, log_dir: Path) -> None:
        self.name = name
        self.command = command
        log_dir.mkdir(parents=True, exist_ok=True)
        self.stdout_path = log_dir / f"{name}.out"
        self.stderr_path = log_dir / f"{name}.err"
        with self.stdout_path.open("wb") as out, self.stderr_path.open("wb") as err:
            self.popen = subprocess.Popen(
                command,
                env=env,
                cwd=cwd,
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=err,
                umask=0o022,
                start_new_session=True,
            )

    @property
    def returncode(self) -> int | None:
        return self.popen.poll()

    def alive(self) -> bool:
        return self.popen.poll() is None

    def signal(self, signum: int) -> None:
        if self.alive():
            self.popen.send_signal(signum)

    def wait(self, timeout: float = 60.0) -> int:
        try:
            return self.popen.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            raise HarnessError(f"{self.name} did not exit within {timeout:.0f}s\n{self.stderr()[-3000:]}") from None

    def stop(self, timeout: float = 60.0) -> int:
        self.signal(signal.SIGTERM)
        return self.wait(timeout)

    def kill(self) -> int:
        self.signal(signal.SIGKILL)
        return self.popen.wait(timeout=30)

    def stderr(self) -> str:
        return self.stderr_path.read_text(encoding="utf-8", errors="replace")

    def p1_log_lines(self) -> list[str]:
        """The P1 log lines of PLAN.md 4.15, reduced to their contract text."""
        return [" ".join(m.groups()) for m in P1_LOG_RE.finditer(self.stderr())]


# ----- tmux, agents, runner environment ------------------------------------


class Workspace:
    """Directories, tmux socket and fake agents of one scenario."""

    def __init__(self, tmp_path: Path, name: str) -> None:
        self.root = tmp_path
        self.exec_dir = tmp_path / "exec"
        self.control = tmp_path / "control"
        self.cwd = tmp_path / "cwd"
        self.bin = tmp_path / "bin"
        self.logs = tmp_path / "logs"
        self.tools = tmp_path / "tools"
        self.home = tmp_path / "home"
        self.agent_log = tmp_path / "agents.jsonl"
        for directory in (self.exec_dir, self.control, self.cwd, self.bin, self.tools, self.home, self.logs):
            directory.mkdir(parents=True, exist_ok=True)
        tmux = shutil.which("tmux")
        if tmux is None:
            raise HarnessError("tmux is not on PATH")
        (self.tools / "tmux").symlink_to(tmux)
        (self.home / ".tmux.conf").write_text(TMUX_CONF, encoding="utf-8")
        # The runner and its tmux server see only the fake agents, tmux and the system directories:
        # a real codex or claude must never run (they would execute the prompt with full permissions).
        for system_dir in SYSTEM_PATH:
            for agent in ("codex", "claude"):
                if (Path(system_dir) / agent).exists():
                    raise HarnessError(f"{system_dir}/{agent} exists; the harness cannot shadow it safely")
        # Unix socket paths are limited to ~104 bytes; pytest's tmp_path is too long on macOS.
        self.tmux_tmpdir = Path(tempfile.mkdtemp(prefix="ogr-", dir="/tmp"))
        self.label = f"parity-{name}"[:40]
        for agent in ("codex", "claude"):
            shim = self.bin / agent
            shim.write_text(
                "#!/bin/sh\n"
                f"exec {shlex.quote(sys.executable)} -I {shlex.quote(str(HERE / 'fake_agent.py'))} {agent} \"$@\"\n",
                encoding="utf-8",
            )
            shim.chmod(0o755)

    # tmux ------------------------------------------------------------------

    def tmux_env(self) -> dict[str, str]:
        """Environment of the harness's tmux calls and the base of the runner's.

        Built from an allowlist (``BASH_ENV``, ``ENV``, exported shell functions and the like from the
        caller would reach the ``/bin/bash`` step scripts): ``HOME`` is private (its ``.tmux.conf`` is
        production's ``TMUX_CONF``; no shell start-up files), ``SHELL`` is ``/bin/sh`` (tmux runs the
        step command through it), and ``PATH`` holds only the fake agents, tmux and the system
        directories.
        """
        env = base_env()
        env.update(
            {
                "TMUX_TMPDIR": str(self.tmux_tmpdir),
                "HOME": str(self.home),
                "SHELL": "/bin/sh",
                "PATH": os.pathsep.join([str(self.bin), str(self.tools), *SYSTEM_PATH]),
            }
        )
        return env

    def tmux(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["tmux", "-L", self.label, *args], env=self.tmux_env(), capture_output=True, text=True, check=False
        )

    def sessions(self) -> list[str]:
        result = self.tmux("ls", "-F", "#{session_name}")
        if result.returncode != 0:
            return []
        return sorted(line.strip() for line in result.stdout.splitlines() if line.strip())

    def start_dummy_session(self, name: str) -> None:
        result = self.tmux("new-session", "-d", "-s", name, "sleep 600")
        if result.returncode != 0:
            raise HarnessError(f"cannot start tmux session {name}: {result.stderr}")

    def kill_session(self, name: str) -> None:
        self.tmux("kill-session", "-t", name)

    def cleanup(self) -> None:
        self.tmux("kill-server")
        for path in sorted(self.tmux_tmpdir.rglob("*"), reverse=True):
            try:
                path.rmdir() if path.is_dir() and not path.is_symlink() else path.unlink()
            except OSError:
                pass
        try:
            self.tmux_tmpdir.rmdir()
        except OSError:
            pass

    # agents ----------------------------------------------------------------

    def release(self, name: str) -> None:
        (self.control / name).touch()

    def marker(self, name: str) -> bool:
        return (self.control / name).exists()

    def wait_marker(self, name: str, timeout: float = 30.0) -> None:
        wait_until(lambda: self.marker(name), timeout=timeout, what=f"agent marker {name}")

    def agent_calls(self) -> list[dict[str, Any]]:
        if not self.agent_log.exists():
            return []
        return [json.loads(line) for line in self.agent_log.read_text(encoding="utf-8").splitlines() if line]

    # runner ----------------------------------------------------------------

    def runner_settings(self, base_url: str, **overrides: str) -> dict[str, str]:
        values = {
            "OPSGATE_SERVICE_NAME": "opsgate-parity",
            "OPSGATE_RUNNER_TOKEN": RUNNER_TOKEN,
            "OPSGATE_RUNNER_API_BASE_URL": base_url,
            "OPSGATE_RUNNER_POLL_INTERVAL_SECONDS": "1",
            "OPSGATE_RUNNER_HEARTBEAT_INTERVAL_SECONDS": "30",
            "OPSGATE_MAX_PARALLEL_JOBS": "3",
            "OPSGATE_MAX_DURATION_SECONDS_DEFAULT": "3600",
            "OPSGATE_EXECUTION_DATA_DIR": str(self.exec_dir),
            "OPSGATE_TMUX_SOCKET_LABEL": self.label,
            "OPSGATE_RUNNER_HOST": RUNNER_HOST,
            # Keys of the env file reach the agents (PLAN.md 4.2, 4.13.8).
            "OPSGATE_PARITY_ENV_MARKER": "from-env-file",
            "OPSGATE_PARITY_OVERRIDE": "env-file-wins",
            # Ignored by both implementations (PLAN.md 4.2).
            "OPSGATE_RUNNER_STALE_AFTER_SECONDS": "120",
        }
        values.update(overrides)
        return values

    def runner_env(self, env_file: Path, *, without_tmux: bool = False) -> dict[str, str]:
        env = self.tmux_env()
        if without_tmux:
            # Only the fake agents: tmux (and everything else) cannot be found (4.13.6 missing binary).
            env["PATH"] = str(self.bin)
        env.update(
            {
                "OPSGATE_ENV_FILE": str(env_file),
                "OPSGATE_PARITY_AGENT_LOG": str(self.agent_log),
                "OPSGATE_PARITY_CONTROL_DIR": str(self.control),
                "OPSGATE_PARITY_PROCESS_MARKER": "from-process",
                "OPSGATE_PARITY_OVERRIDE": "process-env",
                "PYTHONUNBUFFERED": "1",
            }
        )
        return env


# ----- normalisation -------------------------------------------------------


class Normaliser:
    """Maps one scenario's paths, ids and timestamps to stable tokens."""

    def __init__(self, exec_dir: Path, root: Path, tmux_tmpdir: Path) -> None:
        self.prefixes = [(str(exec_dir), "<exec>"), (str(root), "<root>"), (str(tmux_tmpdir), "<tmux>")]
        self.ids: dict[str, str] = {}

    def ticket_token(self, value: str) -> str:
        if value not in self.ids:
            self.ids[value] = f"<ticket-{len(self.ids) + 1}>"
        return self.ids[value]

    def text(self, value: str) -> str:
        for prefix, token in self.prefixes:
            value = value.replace(prefix, token)
        return UUID_RE.sub(lambda m: self.ticket_token(m.group(0)), value)

    def value(self, value: Any, key: str = "") -> Any:
        if isinstance(value, dict):
            return {k: self.value(v, k) for k, v in sorted(value.items())}
        if isinstance(value, list):
            return [self.value(v) for v in value]
        if isinstance(value, str):
            if TS_RE.fullmatch(value):
                return "<ts>" if WRITTEN_TS_RE.fullmatch(value) else f"<bad-ts:{value}>"
            if key == "attach_command":
                return [self.text(word) for word in shlex.split(value)]
            if key == "result_detail" and value.startswith(UNHANDLED_PREFIX):
                # The exception type name is P2 (PLAN.md 4.13.6, D-13).
                return UNHANDLED_PREFIX + "<type>"
            return self.text(value)
        return value

    def status_call(self, body: Any, response: int | str) -> dict[str, Any]:
        entry = {"payload": self.value(body), "response": response}
        return entry

    def status_calls(self, requests: Iterable[Any]) -> list[dict[str, Any]]:
        """Status calls in order; consecutive identical heartbeats collapse (their count is timing)."""
        out: list[dict[str, Any]] = []
        for request in requests:
            entry = self.status_call(request.body, request.response)
            payload = entry["payload"]
            if isinstance(payload, dict) and payload.get("event") == "heartbeat":
                entry = {**entry, "repeated": True}
                if out and out[-1] == entry:
                    continue
            out.append(entry)
        return out

    def tree(self, base: Path) -> dict[str, Any]:
        """Names, modes and content of every file and directory below ``base``."""
        out: dict[str, Any] = {}
        if not base.exists():
            return out
        for path in sorted(base.rglob("*")):
            rel = self.text(str(path.relative_to(base)))
            mode = stat.S_IMODE(path.lstat().st_mode)
            if path.is_dir():
                out[rel + "/"] = {"mode": oct(mode)}
                continue
            entry: dict[str, Any] = {"mode": oct(mode)}
            raw = path.read_bytes()
            if path.suffix == ".json" or path.name == "previous_step_summary.md":
                try:
                    entry["json"] = self.value(json.loads(raw.decode("utf-8")))
                except ValueError:
                    entry["text"] = self.text(raw.decode("utf-8", "replace"))
            elif path.name == "run_step.sh":
                entry["words"] = [[self.text(w) for w in shlex.split(line)] for line in raw.decode().splitlines()]
            else:
                entry["text"] = self.text(raw.decode("utf-8", "replace"))
            out[rel] = entry
        return out

    def agent_calls(self, calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [self.value(call) for call in calls]


# ----- artifact accessors --------------------------------------------------


@dataclass
class StepFiles:
    step_dir: Path

    def json(self, name: str) -> dict[str, Any]:
        loaded = json.loads((self.step_dir / name).read_text(encoding="utf-8"))
        assert isinstance(loaded, dict)
        return loaded

    @property
    def metadata(self) -> dict[str, Any]:
        return self.json("session_metadata.json")

    @property
    def summary(self) -> dict[str, Any]:
        return self.json("summary.json")

    def exists(self, name: str) -> bool:
        return (self.step_dir / name).exists()

    def text(self, name: str) -> str:
        return (self.step_dir / name).read_text(encoding="utf-8")

    def mode(self, name: str) -> int:
        return stat.S_IMODE((self.step_dir / name).stat().st_mode)


def step_files(exec_dir: Path, ticket: str, number: int, role_slug: str) -> StepFiles:
    return StepFiles(exec_dir / "sessions" / ticket / "steps" / f"{number:02d}-{role_slug}")


def session_name(ticket: str, number: int, role_slug: str) -> str:
    return f"job-{ticket}-{number:02d}-{role_slug}"


def step(role: str, agent: str = "codex", **fake: object) -> dict[str, str]:
    """A plan step whose prompt carries fake-agent directives (fake_agent.py)."""
    spec = " ".join(f"{key}={value}" for key, value in fake.items())
    return {"role": role, "agent": agent, "prompt_markdown": f"# {role}\n\nfake: {spec}\n"}


# ----- real API (mixed stacks) ---------------------------------------------


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


@dataclass
class Response:
    status: int
    body: bytes
    headers: dict[str, str]

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8"))


class Client:
    """A minimal HTTP client with a cookie jar and no redirect following."""

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()), NoRedirect())

    def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = None,
        form: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Response:
        data: bytes | None = None
        all_headers = {"User-Agent": "opsgate-runner-parity/1", **(headers or {})}
        if json_body is not None:
            data = json.dumps(json_body).encode("utf-8")
            all_headers["Content-Type"] = "application/json"
        elif form is not None:
            data = urllib.parse.urlencode(form).encode("ascii")
            all_headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(self.base_url + path, data=data, method=method, headers=all_headers)
        try:
            with self.opener.open(req, timeout=15) as resp:
                return Response(resp.status, resp.read(), dict(resp.headers.items()))
        except urllib.error.HTTPError as error:
            return Response(error.code, error.read(), dict(error.headers.items()))


class ApiServer:
    """A real ``serve`` process (either implementation) on a free loopback port."""

    def __init__(self, impl: str, ws: Workspace, name: str = "api") -> None:
        import bcrypt

        self.impl = impl
        self.port = free_port()
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.db_path = ws.root / "db" / "opsgate.sqlite3"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        password_hash = bcrypt.hashpw(UI_PASSWORD.encode(), bcrypt.gensalt(rounds=4)).decode("ascii")
        env_file = write_env_file(
            ws.root / f"{name}.env",
            {
                "OPSGATE_SERVICE_NAME": "opsgate-parity",
                "OPSGATE_BIND_HOST": "127.0.0.1",
                "OPSGATE_BIND_PORT": str(self.port),
                "OPSGATE_DB_PATH": str(self.db_path),
                "OPSGATE_UI_USERNAME": UI_USERNAME,
                "OPSGATE_UI_PASSWORD_BCRYPT": password_hash,
                "OPSGATE_SESSION_SECRET": SESSION_SECRET,
                "OPSGATE_RUNNER_TOKEN": RUNNER_TOKEN,
                "OPSGATE_SUBMIT_TOKEN_NYXMON": SUBMIT_TOKEN_NYXMON,
                "OPSGATE_SUBMIT_TOKEN_OPENCLAW": SUBMIT_TOKEN_OTHER["openclaw"],
                "OPSGATE_SUBMIT_TOKEN_OPERATOR": SUBMIT_TOKEN_OTHER["operator"],
                "OPSGATE_ALLOWED_CIDRS": "127.0.0.1/32,::1/128",
                "OPSGATE_EXECUTION_DATA_DIR": str(ws.exec_dir),
            },
        )
        env = {**base_env(), "HOME": str(ws.home), "PATH": os.pathsep.join(SYSTEM_PATH)}
        env["OPSGATE_ENV_FILE"] = str(env_file)
        self.process = Process(name, opsgate_command(impl, "serve"), env=env, cwd=ws.cwd, log_dir=ws.logs)
        client = Client(self.base_url)

        def healthy() -> bool:
            if not self.process.alive():
                raise HarnessError(f"{impl} API exited early:\n{self.process.stderr()[-3000:]}")
            try:
                return client.request("GET", "/api/v1/health").status == 200
            except OSError:
                return False

        wait_until(healthy, timeout=30, what=f"{impl} API health")

    def create_ticket(self, plan: list[dict[str, str]], **extra: Any) -> str:
        payload = {"title": "Mixed stack", "summary": "runner parity mixed stack", "execution_plan": plan, **extra}
        resp = Client(self.base_url).request(
            "POST", "/api/v1/tickets", json_body=payload, headers={"Authorization": f"Bearer {SUBMIT_TOKEN_NYXMON}"}
        )
        if resp.status != 201:
            raise HarnessError(f"create failed: {resp.status} {resp.body[:300]!r}")
        return str(resp.json()["id"])

    def approver(self) -> Client:
        client = Client(self.base_url)
        page = client.request("GET", "/login")
        match = re.search(rb'name="csrf_token" value="([^"]+)"', page.body)
        if page.status != 200 or match is None:
            raise HarnessError(f"login page without form token: {page.status}")
        resp = client.request(
            "POST",
            "/login",
            form={"csrf_token": match.group(1).decode(), "username": UI_USERNAME, "password": UI_PASSWORD},
        )
        if resp.status != 302:
            raise HarnessError(f"login failed: {resp.status}")
        return client

    def approve(self, client: Client, ticket: str) -> None:
        resp = client.request("POST", f"/api/v1/tickets/{ticket}/approve", headers={"Sec-Fetch-Site": "same-origin"})
        if resp.status != 200:
            raise HarnessError(f"approve failed: {resp.status} {resp.body[:300]!r}")

    def get_ticket(self, ticket: str) -> dict[str, Any]:
        resp = Client(self.base_url).request(
            "GET", f"/api/v1/tickets/{ticket}", headers={"Authorization": f"Bearer {RUNNER_TOKEN}"}
        )
        if resp.status != 200:
            raise HarnessError(f"get failed: {resp.status}")
        loaded = resp.json()
        assert isinstance(loaded, dict)
        return loaded

    def audit_events(self, ticket: str) -> list[dict[str, Any]]:
        conn = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True)
        try:
            rows = conn.execute(
                "SELECT event_type, actor, previous_state, new_state, metadata_json FROM audit_events "
                "WHERE ticket_id = ? ORDER BY id",
                (ticket,),
            ).fetchall()
        finally:
            conn.close()
        return [
            {"event_type": r[0], "actor": r[1], "previous_state": r[2], "new_state": r[3], "metadata": json.loads(r[4])}
            for r in rows
        ]

    def stop(self) -> None:
        if self.process.alive():
            self.process.stop(timeout=30)
