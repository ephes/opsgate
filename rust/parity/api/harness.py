"""Black-box API parity harness: processes, HTTP clients, records (rust/PLAN.md 7.3).

An implementation under test is a real ``serve`` process (``python -m opsgate
serve`` or the Rust ``opsgate serve``) on a free loopback port with a
generated env file, a temporary database and a temporary execution data
directory. Scenarios talk to it over HTTP only; they may prepare state the
way the Python tests do (direct SQLite updates between requests, artifact
files), which both implementations then read through their own code.

Every exchange is recorded in a normalised form (status, ``error`` code,
JSON body with ids and generated timestamps mapped to tokens and error
``message`` texts masked, redirect target, flash messages, the forms and
links of HTML pages, session cookie attributes) together with a normalised
database snapshot at the end of the scenario. ``compare.py`` diffs the
records of a Python and a Rust run. HTML bytes, JSON formatting and error
message texts are P2 (PLAN.md 3.3) and never compared.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import socket
import sqlite3
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import httpx

REPO = Path(__file__).resolve().parents[3]
IMPLS = ("python", "rust")

# Rust slices (PLAN.md section 12) whose routes have landed on main. A scenario
# runs against Rust only when every slice it names in its ``rust`` marker is
# listed here; each web slice adds its id when it merges (S4a, S4b, S5).
RUST_SLICES_LANDED: frozenset[str] = frozenset({"S4a", "S4b", "S5"})

USERNAME = "opsgate-admin"
PASSWORD = "secret-password"
SESSION_SECRET = "parity-session-secret-0000000000"
RUNNER_TOKEN = "runner-token-000000000000"
SUBMIT_TOKENS = {
    "openclaw": "openclaw-token-0000000000",
    "nyxmon": "nyxmon-token-000000000000",
    "operator": "operator-token-00000000000",
}
USER_AGENT = "opsgate-parity/1"
DEFAULT_CIDRS = "127.0.0.1/32,::1/128,100.64.0.0/10"
PLAN = [{"role": "investigator", "agent": "codex", "prompt_markdown": "Do work"}]
REVIEW_PLAN = [{"role": "reviewer", "agent": "codex", "prompt_markdown": "Review"}]
PAST = "2020-01-01T00:00:00Z"
JSON_NULL = object()  # json_body value that sends the literal ``null``
FUTURE = "2099-01-01T00:00:00Z"

SECURITY_HEADERS = {
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "same-origin",
    "cache-control": "no-store",
}
CSP_DIRECTIVES = {"frame-ancestors 'none'", "base-uri 'self'", "form-action 'self'", "object-src 'none'"}

UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})")
FRAMEWORK_STATUSES = frozenset({404, 405, 413, 500})
WRITTEN_TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{6})?Z")


class HarnessError(RuntimeError):
    pass


def hash_password(password: str) -> str:
    import bcrypt

    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=4)).decode("ascii")


@dataclass(frozen=True)
class Profile:
    """Settings of one API process (PLAN.md 4.2); the default is the profile of tests/test_api.py."""

    trust_proxy_headers: bool = False
    session_cookie_secure: bool = False
    operator_reviewer_floor: bool = False
    allowed_cidrs: str = DEFAULT_CIDRS
    session_timeout_seconds: int = 3600
    password: str = PASSWORD

    def env(self, *, port: int, db_path: Path, exec_dir: Path, password_hash: str) -> dict[str, str]:
        def flag(value: bool) -> str:
            return "true" if value else "false"

        return {
            "OPSGATE_SERVICE_NAME": "opsgate-parity",
            "OPSGATE_BIND_HOST": "127.0.0.1",
            "OPSGATE_BIND_PORT": str(port),
            "OPSGATE_DB_PATH": str(db_path),
            "OPSGATE_UI_USERNAME": USERNAME,
            "OPSGATE_UI_PASSWORD_BCRYPT": password_hash,
            "OPSGATE_SESSION_SECRET": SESSION_SECRET,
            "OPSGATE_TRUST_PROXY_HEADERS": flag(self.trust_proxy_headers),
            "OPSGATE_SESSION_COOKIE_SECURE": flag(self.session_cookie_secure),
            "OPSGATE_UI_SESSION_TIMEOUT_SECONDS": str(self.session_timeout_seconds),
            "OPSGATE_MAX_DURATION_SECONDS_DEFAULT": "3600",
            "OPSGATE_POLICY_FLOOR_REQUIRE_REVIEWER_STEP": "false",
            "OPSGATE_RUNNER_TOKEN": RUNNER_TOKEN,
            "OPSGATE_SUBMIT_TOKEN_OPENCLAW": SUBMIT_TOKENS["openclaw"],
            "OPSGATE_SUBMIT_TOKEN_NYXMON": SUBMIT_TOKENS["nyxmon"],
            "OPSGATE_SUBMIT_TOKEN_OPERATOR": SUBMIT_TOKENS["operator"],
            "OPSGATE_SUBMIT_POLICY_OPERATOR_REQUIRE_REVIEWER_STEP": flag(self.operator_reviewer_floor),
            "OPSGATE_REQUIRE_TAILSCALE_CONTEXT": "true",
            "OPSGATE_ALLOWED_CIDRS": self.allowed_cidrs,
            "OPSGATE_EXECUTION_DATA_DIR": str(exec_dir),
            "OPSGATE_DISABLE_FILE_PATH": str(exec_dir / ".disabled"),
        }


DEFAULT_PROFILE = Profile()


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def rust_binary() -> Path:
    configured = os.environ.get("OPSGATE_RUST_BIN", "").strip()
    if configured:
        return Path(configured)
    return REPO / "rust" / "target" / "release" / "opsgate"


def serve_command(impl: str) -> list[str]:
    if impl == "python":
        return [sys.executable, "-m", "opsgate", "serve"]
    if impl == "rust":
        binary = rust_binary()
        if not binary.is_file():
            raise HarnessError(f"Rust binary {binary} is missing: run `cargo build --release --locked` in rust/")
        return [str(binary), "serve"]
    raise HarnessError(f"unknown implementation {impl!r}")


@dataclass
class Target:
    """One API endpoint under test and what the harness knows about it."""

    impl: str
    base_url: str
    password: str = PASSWORD
    username: str = USERNAME
    runner_token: str = RUNNER_TOKEN
    submit_tokens: dict[str, str] = field(default_factory=lambda: dict(SUBMIT_TOKENS))
    profile: Profile = DEFAULT_PROFILE
    service_name: str = "opsgate-parity"
    db_path: Path | None = None
    exec_dir: Path | None = None
    process: subprocess.Popen[bytes] | None = None
    log_path: Path | None = None

    @property
    def host(self) -> str:
        return self.base_url.split("://", 1)[1]

    @property
    def origin(self) -> str:
        return self.base_url

    def stop(self) -> None:
        if self.process is None:
            return
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)
        self.process = None

    def log_tail(self) -> str:
        if self.log_path is None or not self.log_path.exists():
            return ""
        return self.log_path.read_text(encoding="utf-8", errors="replace")[-4000:]


def start_server(
    impl: str, *, workdir: Path, profile: Profile, db_path: Path, exec_dir: Path, password_hash: str
) -> Target:
    """Start ``impl`` with a fresh env file and wait until /api/v1/health answers."""
    workdir.mkdir(parents=True, exist_ok=True)
    exec_dir.mkdir(parents=True, exist_ok=True)
    last_error = ""
    for attempt in range(3):
        port = free_port()
        env_file = workdir / f"api-{impl}-{port}.env"
        values = profile.env(port=port, db_path=db_path, exec_dir=exec_dir, password_hash=password_hash)
        env_file.write_text("".join(f"{key}={value}\n" for key, value in values.items()), encoding="utf-8")
        env = {key: value for key, value in os.environ.items() if not key.startswith("OPSGATE_")}
        env["OPSGATE_ENV_FILE"] = str(env_file)
        log_path = workdir / f"api-{impl}-{port}.log"
        with log_path.open("wb") as log:
            process = subprocess.Popen(serve_command(impl), cwd=workdir, env=env, stdout=log, stderr=subprocess.STDOUT)
        target = Target(
            impl=impl,
            base_url=f"http://127.0.0.1:{port}",
            profile=profile,
            password=profile.password,
            db_path=db_path,
            exec_dir=exec_dir,
            process=process,
            log_path=log_path,
        )
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if process.poll() is not None:
                break
            try:
                if httpx.get(f"{target.base_url}/api/v1/health", timeout=1).status_code == 200:
                    return target
            except httpx.TransportError:
                pass
            time.sleep(0.05)
        last_error = f"attempt {attempt + 1}: exit={process.poll()}\n{target.log_tail()}"
        target.stop()
    raise HarnessError(f"{impl} serve did not become ready:\n{last_error}")


# ------------------------------------------------------------------ normalisation


class Normalizer:
    """Maps generated values of one scenario to stable tokens.

    Ticket ids (uuid4) become ``<id1>``, ``<id2>`` … in order of first
    appearance. Timestamps written by the implementation (within two days of
    now) become ``<ts>``: which generated timestamps happen to be equal is
    not part of the contract. A generated timestamp that is not in the
    ``isoformat_z`` shape (PLAN.md 4.9, P1) is kept raw so the comparison
    shows it.
    """

    def __init__(self, scratch: Path | None = None) -> None:
        self.ids: dict[str, str] = {}
        self.now = datetime.now(tz=UTC)
        roots = {str(scratch), str(scratch.resolve())} if scratch is not None else set()
        self.roots = sorted(roots, key=len, reverse=True)

    def _id(self, match: re.Match[str]) -> str:
        value = match.group(0).lower()
        return self.ids.setdefault(value, f"<id{len(self.ids) + 1}>")

    def _stamp(self, match: re.Match[str]) -> str:
        raw = match.group(0)
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return raw
        if abs(parsed - self.now) > timedelta(days=2):
            return raw
        if WRITTEN_TS_RE.fullmatch(raw) is None:
            return f"<bad-timestamp {raw}>"
        return "<ts>"

    def text(self, value: str) -> str:
        for root in self.roots:  # the scenario's temporary directory (database, artifact tree)
            value = value.replace(root, "<tmp>")
        return TS_RE.sub(self._stamp, UUID_RE.sub(self._id, value))

    def value(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.value(item) for item in value]
        if isinstance(value, dict):
            if set(value) == {"error", "message"}:
                return {"error": value["error"], "message": "<message>"}
            return {self.text(key): self.value(item) for key, item in value.items()}
        return value


class PageFacts(HTMLParser):
    """The P1 content of a page (PLAN.md 4.11): flashes, forms with their fields, internal links."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.flashes: list[list[str]] = []
        self.forms: list[dict[str, Any]] = []
        self.links: set[str] = set()
        self.csrf_tokens: list[str] = []
        self._flash: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {name: value or "" for name, value in attrs}
        css = attributes.get("class", "")
        if tag == "p" and css.startswith("flash-"):
            self._flash = [css.removeprefix("flash-"), ""]
        elif tag == "form":
            self.forms.append(
                {
                    "action": attributes.get("action", ""),
                    "method": attributes.get("method", "get").lower(),
                    "fields": [],
                }
            )
        elif tag in {"input", "select", "textarea", "button"} and attributes.get("name") and self.forms:
            self.forms[-1]["fields"].append(attributes["name"])
            if attributes["name"] == "csrf_token":
                self.csrf_tokens.append(attributes.get("value", ""))
        elif tag == "a" and attributes.get("href", "").startswith("/"):
            self.links.add(attributes["href"])

    def handle_data(self, data: str) -> None:
        if self._flash is not None:
            self._flash[1] += data

    def handle_endtag(self, tag: str) -> None:
        if tag == "p" and self._flash is not None:
            self.flashes.append([self._flash[0], " ".join(self._flash[1].split())])
            self._flash = None


@dataclass
class Resp:
    status: int
    headers: httpx.Headers
    body: bytes
    facts: PageFacts | None

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return json.loads(self.body)

    @property
    def error(self) -> str | None:
        try:
            body = self.json()
        except ValueError:
            return None
        return body.get("error") if isinstance(body, dict) else None

    @property
    def location(self) -> str | None:
        return self.headers.get("location")

    @property
    def flashes(self) -> list[list[str]]:
        return self.facts.flashes if self.facts else []

    @property
    def csrf_token(self) -> str:
        if not self.facts or not self.facts.csrf_tokens:
            raise HarnessError("page has no csrf_token field")
        return self.facts.csrf_tokens[0]


def security_headers_ok(headers: httpx.Headers) -> bool:
    if any(headers.get(name) != value for name, value in SECURITY_HEADERS.items()):
        return False
    directives = {part.strip() for part in headers.get("content-security-policy", "").split(";")}
    return CSP_DIRECTIVES <= directives


def cookie_record(headers: httpx.Headers) -> list[dict[str, Any]]:
    """Session cookie attributes (P1, PLAN.md 4.5.2); the value format is D-1."""
    records = []
    for raw in headers.get_list("set-cookie"):
        name_value, *attributes = (part.strip() for part in raw.split(";"))
        name, _, value = name_value.partition("=")
        attrs = {attr.split("=", 1)[0].lower(): attr.split("=", 1)[1] if "=" in attr else True for attr in attributes}
        deleted = value in {"", '""'} or attrs.get("max-age") == "0"
        records.append(
            {
                "name": name,
                "deleted": deleted,
                "httponly": "httponly" in attrs,
                "secure": "secure" in attrs,
                "samesite": str(attrs.get("samesite", "")).lower(),
                "path": attrs.get("path"),
                "persistent": not deleted and ("expires" in attrs or "max-age" in attrs),
            }
        )
    return records


class Recorder:
    """The normalised record of one scenario."""

    def __init__(self, impl: str, scratch: Path | None = None) -> None:
        self.impl = impl
        self.norm = Normalizer(scratch)
        self.steps: list[dict[str, Any]] = []
        self.divergences: set[str] = set()
        self.snapshots: list[Any] = []
        self.snapshot_enabled = True

    def divergence(self, code: str) -> None:
        """Mark the scenario as covering a P3 divergence (PLAN.md section 5)."""
        self.divergences.add(code)

    def note(self, key: str, value: Any) -> None:
        self.steps.append({"note": key, "value": self.norm.value(value)})

    def exchange(self, who: str, method: str, path: str, resp: Resp) -> None:
        entry: dict[str, Any] = {"who": who, "req": f"{method} {self.norm.text(path)}", "status": resp.status}
        content_type = resp.headers.get("content-type", "")
        if resp.status in FRAMEWORK_STATUSES and resp.error is None:
            # Unknown route, wrong method, unhandled error: the framework's body is D-9 (P2), only the status counts.
            entry["body"] = "<framework response>"
        elif content_type.startswith("application/json"):
            try:
                entry["json"] = self.norm.value(resp.json())
            except ValueError:
                entry["json"] = "<undecodable>"
        if resp.location is not None:
            entry["location"] = self.norm.text(resp.location)
        if resp.facts is not None and "body" not in entry:
            entry["flashes"] = [[cat, self.norm.text(text)] for cat, text in resp.facts.flashes]
            entry["forms"] = [
                {**form, "action": self.norm.text(form["action"]), "fields": sorted(set(form["fields"]))}
                for form in resp.facts.forms
            ]
            entry["links"] = sorted(self.norm.text(link) for link in resp.facts.links)
        cookies = cookie_record(resp.headers)
        if cookies:
            entry["cookies"] = cookies
        self.steps.append(entry)

    def as_dict(self) -> dict[str, Any]:
        return {
            "divergences": sorted(self.divergences),
            "steps": self.steps,
            "db": self.snapshots,
        }


# ------------------------------------------------------------------ HTTP clients


class Browser:
    """One HTTP client with its own cookie jar (one browser or one bearer caller)."""

    def __init__(
        self,
        target: Target,
        recorder: Recorder | None,
        who: str,
        headers: dict[str, str] | None = None,
        local_address: str | None = None,
    ):
        self.target = target
        self.recorder = recorder
        self.who = who
        self.headers = {"User-Agent": USER_AGENT, **(headers or {})}
        self.local_address = local_address
        self.client = self._client()

    def _client(self) -> httpx.Client:
        transport = httpx.HTTPTransport(local_address=self.local_address) if self.local_address else None
        return httpx.Client(
            base_url=self.target.base_url,
            headers=self.headers,
            follow_redirects=False,
            timeout=30,
            transport=transport,
        )

    def close(self) -> None:
        self.client.close()

    def retarget(self, target: Target) -> None:
        """Point this browser (and its cookie jar) at another process, e.g. after a restart."""
        jar = self.client.cookies.jar
        self.client.close()
        self.target = target
        self.client = self._client()
        for cookie in jar:  # cookies are not port specific; keep domain and path
            self.client.cookies.jar.set_cookie(cookie)

    @property
    def session_cookie(self) -> str | None:
        return self.client.cookies.get("session")

    def set_session_cookie(self, value: str | None) -> None:
        self.client.cookies.clear()
        if value is not None:
            self.client.cookies.set("session", value, domain=self.target.host.rsplit(":", 1)[0], path="/")

    def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = None,
        data: dict[str, str] | list[tuple[str, str]] | None = None,
        content: bytes | str | None = None,
        content_type: str | None = None,
        headers: dict[str, str | bytes] | None = None,
        bearer: str | None = None,
        record: bool = True,
    ) -> Resp:
        send_headers: dict[str, Any] = dict(headers or {})
        if bearer is not None:
            send_headers["Authorization"] = f"Bearer {bearer}".encode()
        if content_type is not None:
            send_headers["Content-Type"] = content_type
        kwargs: dict[str, Any] = {"headers": send_headers}
        if json_body is not None:
            kwargs["content"] = b"null" if json_body is JSON_NULL else json.dumps(json_body).encode()
            send_headers.setdefault("Content-Type", "application/json")
        elif data is not None:
            kwargs["data"] = data
        elif content is not None:
            kwargs["content"] = content.encode() if isinstance(content, str) else content
        response = self.client.request(method, path, **kwargs)
        facts = None
        is_page = response.headers.get("content-type", "").startswith("text/html")
        if is_page and method != "HEAD" and not 300 <= response.status_code < 400:
            facts = PageFacts()
            facts.feed(response.text)
        resp = Resp(response.status_code, response.headers, response.content, facts)
        if not security_headers_ok(response.headers):
            raise AssertionError(f"{method} {path} -> {resp.status}: security headers missing (PLAN.md 4.4)")
        if record and self.recorder is not None:
            self.recorder.exchange(self.who, method, path, resp)
        return resp

    def get(self, path: str, **kwargs: Any) -> Resp:
        return self.request("GET", path, **kwargs)

    def head(self, path: str, **kwargs: Any) -> Resp:
        return self.request("HEAD", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> Resp:
        return self.request("POST", path, **kwargs)

    def follow(self, resp: Resp) -> Resp:
        """GET the redirect target (shows the flash messages the redirect left)."""
        assert resp.location is not None, "no redirect"
        return self.get(resp.location)

    # ---- approver helpers

    def login(self, path: str = "/login", *, password: str | None = None, username: str | None = None) -> Resp:
        page = self.get(path)
        assert page.status == 200
        resp = self.post(
            path,
            data={
                "csrf_token": page.csrf_token,
                "username": self.target.username if username is None else username,
                "password": self.target.password if password is None else password,
            },
        )
        return resp

    def csrf(self) -> str:
        """The session's CSRF token, as a page renders it (GET /login renders it without side effects)."""
        return self.get("/login", record=False).csrf_token

    def api_action(self, ticket_id: str, action: str, body: Any = None, **kwargs: Any) -> Resp:
        headers = kwargs.pop("headers", None)
        if headers is None:
            headers = {"X-CSRF-Token": self.csrf()}
        return self.post(f"/api/v1/tickets/{ticket_id}/{action}", json_body=body, headers=headers, **kwargs)

    def ui_action(self, ticket_id: str, action: str, **fields: str) -> Resp:
        token = fields.pop("csrf_token", None)
        data = {"csrf_token": self.csrf() if token is None else token, **fields}
        return self.post(f"/tickets/{ticket_id}/{action}", data=data)


def ticket_payload(**fields: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {"title": "Parity", "summary": "Parity scenario", "execution_plan": PLAN}
    payload.update(fields)
    return payload


def create_ticket(browser: Browser, source: str = "nyxmon", **fields: Any) -> str:
    """Submit a ticket with the source's bearer token; the scenario expects 201."""
    resp = browser.post(
        "/api/v1/tickets", json_body=ticket_payload(**fields), bearer=browser.target.submit_tokens[source]
    )
    assert resp.status == 201, (resp.status, resp.text)
    return str(resp.json()["id"])


def claim(browser: Browser, runner_host: str | None = "runner-a", **kwargs: Any) -> Resp:
    body = {} if runner_host is None else {"runner_host": runner_host}
    return browser.post("/api/v1/runner/claim", json_body=body, bearer=browser.target.runner_token, **kwargs)


def runner_status(browser: Browser, ticket_id: str, body: Any, **kwargs: Any) -> Resp:
    return browser.post(
        f"/api/v1/runner/{ticket_id}/status", json_body=body, bearer=browser.target.runner_token, **kwargs
    )


def get_ticket(browser: Browser, ticket_id: str, source: str = "nyxmon") -> dict[str, Any]:
    resp = browser.get(f"/api/v1/tickets/{ticket_id}", bearer=browser.target.submit_tokens[source])
    assert resp.status == 200, resp.text
    return dict(resp.json())


# ------------------------------------------------------------------ database


@dataclass
class Database:
    """Direct access to the scenario's SQLite file, as the Python tests use it."""

    path: Path

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        with self.connect() as conn:
            conn.execute(sql, params)

    def rows(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        with self.connect() as conn:
            return [dict(row) for row in conn.execute(sql, params).fetchall()]

    def scalar(self, sql: str, params: tuple[Any, ...] = ()) -> Any:
        with self.connect() as conn:
            row = conn.execute(sql, params).fetchone()
        return None if row is None else row[0]

    def set_ticket(self, ticket_id: str, **columns: Any) -> None:
        assignments = ", ".join(f"{name} = ?" for name in columns)  # names come from scenario code only
        self.execute(f"UPDATE tickets SET {assignments} WHERE id = ?", (*columns.values(), ticket_id))

    def audit_types(self, ticket_id: str) -> list[str]:
        return [
            row["event_type"]
            for row in self.rows("SELECT event_type FROM audit_events WHERE ticket_id = ? ORDER BY id", (ticket_id,))
        ]

    def schema(self) -> list[tuple[str, str, str]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT type, name, sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY type DESC, name"
            ).fetchall()
        return [(row[0], row[1], " ".join(str(row[2]).split())) for row in rows]

    def snapshot(self, norm: Normalizer, password_hashes: set[str]) -> dict[str, Any]:
        """All rows, JSON columns parsed, generated values tokenised (PLAN.md 7.3)."""

        def parsed(value: Any) -> Any:
            if isinstance(value, str):
                try:
                    return norm.value(json.loads(value))
                except (ValueError, RecursionError):
                    digest = hashlib.sha256(value.encode()).hexdigest()
                    return {"<unparsable>": norm.text(value) if len(value) < 200 else f"sha256:{digest}"}
            return value

        fingerprints = {hashlib.sha256(item.encode()).hexdigest() for item in password_hashes}
        tables: dict[str, Any] = {}
        with self.connect() as conn:
            for table, order in (
                ("tickets", "rowid"),
                ("audit_events", "id"),
                ("runner_heartbeats", "runner_host"),
                ("ui_session_state", "username"),
            ):
                rows = [dict(row) for row in conn.execute(f"SELECT * FROM {table} ORDER BY {order}").fetchall()]
                out = []
                for row in rows:
                    item: dict[str, Any] = {}
                    for key, value in row.items():
                        if key.endswith("_json"):
                            item[key] = parsed(value)
                        elif key == "password_fingerprint":
                            item[key] = "<fingerprint of a configured hash>" if value in fingerprints else value
                        else:
                            item[key] = norm.value(value)
                    out.append(item)
                tables[table] = out
        return tables
