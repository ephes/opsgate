"""Scripted stand-in for the OpsGate runner API (rust/PLAN.md 7.4), standard library only.

It serves the three endpoints a runner uses (``POST /api/v1/runner/claim``,
``POST /api/v1/runner/<id>/status``, ``GET /api/v1/tickets/<id>``) from an
in-memory ticket table, records every request, and applies scripted faults
(an HTTP error with a JSON body, or a dropped connection that the runner sees
as a transport failure). The status semantics follow
``OpsGateService.update_runner_status`` closely enough for a runner (409
``invalid_state`` on terminal tickets, 409 ``runner_host_mismatch``, the state
and result mapping); everything else of the real API is out of scope here and
covered by the mixed-stack scenarios, which run the real API.
"""

from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

TERMINAL_STATES = {"succeeded", "failed", "rejected", "canceled", "expired"}
RESULTS = {"succeeded": "success", "failed": "failure", "canceled": "canceled"}
STATUS_PATH = re.compile(r"^/api/v1/runner/([^/]+)/status$")
TICKET_PATH = re.compile(r"^/api/v1/tickets/([^/]+)$")


def isoformat_z(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def ticket_id(number: int) -> str:
    """Deterministic ticket ids, so records of different runs line up without mapping."""
    return f"aaaaaaaa-0000-4000-8000-{number:012d}"


@dataclass
class Fault:
    """A scripted answer for matching requests: ``status`` + ``body`` (JSON, or ``raw`` bytes), or ``drop``."""

    kind: str  # "claim", "status" or "get"
    times: int
    event: str | None = None
    ticket: str | None = None
    status: int = 503
    body: Any = field(default_factory=lambda: {"error": "unavailable", "message": "scripted fault"})
    drop: bool = False
    raw: bytes | None = None

    def matches(self, kind: str, ticket: str | None, payload: Any) -> bool:
        if self.times <= 0 or self.kind != kind:
            return False
        if self.ticket is not None and self.ticket != ticket:
            return False
        if self.event is not None:
            return isinstance(payload, dict) and payload.get("event") == self.event
        return True


@dataclass
class Request:
    at: float
    method: str
    path: str
    kind: str
    ticket: str | None
    authorized: bool
    content_type: str | None
    body: Any
    response: int | str


class FakeApi:
    def __init__(self, runner_token: str) -> None:
        self.runner_token = runner_token
        self.lock = threading.Lock()
        self.tickets: dict[str, dict[str, Any]] = {}
        self.queue: list[str] = []
        self.claim_script: list[Any] = []
        self.faults: list[Fault] = []
        self.requests: list[Request] = []
        self.started = time.monotonic()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, name="fake-api", daemon=True)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"

    def start(self) -> FakeApi:
        self.thread.start()
        return self

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    # ----- scripting -------------------------------------------------------

    def add_ticket(
        self,
        plan: list[dict[str, Any]] | Any,
        *,
        state: str = "approved",
        max_duration_seconds: int | None = 3600,
        started_at: str | None = None,
        runner_host: str | None = None,
        claimable: bool = True,
    ) -> str:
        if started_at is None and state == "running":
            started_at = isoformat_z(datetime.now(tz=UTC))
        with self.lock:
            tid = ticket_id(len(self.tickets) + 1)
            self.tickets[tid] = {
                "id": tid,
                "source": "operator",
                "task_ref": None,
                "title": f"parity ticket {len(self.tickets) + 1}",
                "summary": "runner parity",
                "state": state,
                "execution_plan": plan,
                "max_duration_seconds": max_duration_seconds,
                "tmux_sessions": [],
                "runner_host": runner_host,
                "started_at": started_at,
                "finished_at": None,
                "last_heartbeat_at": None,
                "result": None,
                "result_detail": None,
            }
            if claimable and state == "approved":
                self.queue.append(tid)
            return tid

    def set_state(self, tid: str, state: str) -> None:
        with self.lock:
            self.tickets[tid]["state"] = state

    def ticket(self, tid: str) -> dict[str, Any]:
        with self.lock:
            return json.loads(json.dumps(self.tickets[tid]))

    def fail(self, kind: str, *, times: int = 1, **kwargs: Any) -> None:
        with self.lock:
            self.faults.append(Fault(kind=kind, times=times, **kwargs))

    def script_claims(self, *bodies: Any) -> None:
        """Answer the next claims with these bodies (200) before serving the queue."""
        with self.lock:
            self.claim_script.extend(bodies)

    def calls(self, kind: str | None = None, ticket: str | None = None) -> list[Request]:
        with self.lock:
            return [
                r for r in self.requests if (kind is None or r.kind == kind) and (ticket is None or r.ticket == ticket)
            ]

    def status_payloads(self, tid: str) -> list[dict[str, Any]]:
        return [r.body for r in self.calls("status", tid) if isinstance(r.body, dict)]

    def events(self, tid: str) -> list[str]:
        return [str(p.get("event")) for p in self.status_payloads(tid)]

    # ----- request handling ------------------------------------------------

    def _handler(self) -> type[BaseHTTPRequestHandler]:
        api = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

            def do_GET(self) -> None:  # noqa: N802
                api._dispatch(self, "GET")

            def do_POST(self) -> None:  # noqa: N802
                api._dispatch(self, "POST")

        return Handler

    def _dispatch(self, handler: BaseHTTPRequestHandler, method: str) -> None:
        length = int(handler.headers.get("Content-Length") or 0)
        raw = handler.rfile.read(length) if length else b""
        try:
            body: Any = json.loads(raw.decode("utf-8")) if raw else None
        except ValueError:
            body = {"<undecodable>": raw.decode("utf-8", "replace")}
        path = handler.path.split("?", 1)[0]
        authorized = handler.headers.get("Authorization") == f"Bearer {self.runner_token}"
        kind, tid = "other", None
        if method == "POST" and path == "/api/v1/runner/claim":
            kind = "claim"
        elif method == "POST" and (m := STATUS_PATH.match(path)):
            kind, tid = "status", m.group(1)
        elif method == "GET" and (m := TICKET_PATH.match(path)):
            kind, tid = "get", m.group(1)

        with self.lock:
            response: int | str
            fault = next((f for f in self.faults if f.matches(kind, tid, body)), None)
            if fault is not None:
                fault.times -= 1
                response = "dropped" if fault.drop else fault.status
                answer: tuple[int, Any] | None = None if fault.drop else (fault.status, fault.raw or fault.body)
            elif not authorized:
                answer = (401, {"error": "auth_required", "message": "Authentication required"})
            elif kind == "claim":
                answer = self._claim(body)
            elif kind == "status":
                answer = self._status(str(tid), body)
            elif kind == "get":
                ticket = self.tickets.get(str(tid))
                answer = (200, ticket) if ticket else (404, {"error": "ticket_not_found", "message": "not found"})
            else:
                answer = (404, {"error": "not_found", "message": "unknown route"})
            if answer is not None:
                response = answer[0]
            self.requests.append(
                Request(
                    at=time.monotonic() - self.started,
                    method=method,
                    path=path,
                    kind=kind,
                    ticket=tid,
                    authorized=authorized,
                    content_type=handler.headers.get("Content-Type"),
                    body=body,
                    response=response,
                )
            )
            if answer is None:
                data = None
            elif isinstance(answer[1], bytes):
                data = answer[1]
            else:
                data = json.dumps(answer[1]).encode("utf-8")

        if answer is None or data is None:
            # A closed connection without a response: the runner's transport-failure path.
            handler.close_connection = True
            return
        handler.send_response(answer[0])
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(data)))
        handler.end_headers()
        handler.wfile.write(data)

    def _claim(self, body: Any) -> tuple[int, Any]:
        if self.claim_script:
            return 200, self.claim_script.pop(0)
        runner_host = str(body.get("runner_host", "")).strip() if isinstance(body, dict) else ""
        while self.queue:
            tid = self.queue.pop(0)
            ticket = self.tickets[tid]
            if ticket["state"] != "approved":
                continue
            ticket["state"] = "running"
            ticket["runner_host"] = runner_host or "runner"
            ticket["started_at"] = isoformat_z(datetime.now(tz=UTC))
            return 200, {"ticket": ticket}
        return 200, {"ticket": None}

    def _status(self, tid: str, payload: Any) -> tuple[int, Any]:
        ticket = self.tickets.get(tid)
        if ticket is None:
            return 404, {"error": "ticket_not_found", "message": "not found"}
        if not isinstance(payload, dict):
            return 400, {"error": "invalid_json", "message": "JSON object required"}
        if ticket["state"] in TERMINAL_STATES or ticket["state"] not in {"approved", "running"}:
            return 409, {"error": "invalid_state", "message": "terminal"}
        runner_host = str(payload.get("runner_host", "")).strip()
        assigned = str(ticket.get("runner_host") or "").strip()
        if ticket["state"] == "running" and assigned and assigned != runner_host:
            return 409, {"error": "runner_host_mismatch", "message": "other runner"}
        now = isoformat_z(datetime.now(tz=UTC))
        ticket["runner_host"] = runner_host
        ticket["last_heartbeat_at"] = now
        state = payload.get("state")
        if state is not None:
            if ticket["state"] == "running" and state in TERMINAL_STATES:
                ticket["finished_at"] = now
            ticket["state"] = state
            if state in RESULTS:
                ticket["result"] = RESULTS[state]
        if payload.get("result"):
            ticket["result"] = payload["result"]
        if payload.get("result_detail"):
            ticket["result_detail"] = payload["result_detail"]
        if isinstance(payload.get("tmux_sessions"), list):
            ticket["tmux_sessions"] = payload["tmux_sessions"]
        return 200, ticket
