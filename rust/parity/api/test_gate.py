"""Network gate, forwarded headers, security headers, routing (PLAN.md 4.3, 4.4)."""

from __future__ import annotations

import pytest
from conftest import Stack
from harness import (
    Browser,
    Database,
    Profile,
    create_ticket,
    ticket_payload,
)

S4A = pytest.mark.rust("S4a")
S4B = pytest.mark.rust("S4a", "S4b")
pytestmark = pytest.mark.local
NOT_LOOPBACK = "100.64.0.0/10,fd7a:115c:a1e0::/48"


@S4A
@pytest.mark.parametrize("path", ["/api/v1/tickets", "/tickets", "/login", "/no-such-page", "/api/v1/no-such-route"])
def test_api_rejects_non_tailscale_source_ip(stack: Stack, path: str) -> None:
    target = stack.server(Profile(allowed_cidrs=NOT_LOOPBACK))
    anon = stack.browser(target, "outsider")
    resp = anon.post(path, json_body=ticket_payload(), bearer=target.submit_tokens["nyxmon"])
    assert resp.status == 403
    if path.startswith("/api/"):
        assert resp.json() == {"error": "forbidden", "message": "Access denied"}
    else:
        assert resp.headers.get("content-type", "").startswith("text/html")
    # The health endpoint is exempt from the gate.
    assert anon.get("/api/v1/health").status == 200


@S4A
@pytest.mark.parametrize("forwarded_for", ["8.8.8.8", "100.100.100.42", "8.8.8.8, 100.64.0.9", "100.64.0.9, 8.8.8.8"])
@pytest.mark.parametrize("trust", [False, True])
def test_forwarded_headers_never_reach_the_gate(stack: Stack, trust: bool, forwarded_for: str) -> None:
    """Waitress drops X-Forwarded-* before Flask (PLAN.md 4.4), so even a trusting process sees the peer."""
    for cidrs, status in ((NOT_LOOPBACK, 403), ("127.0.0.1/32", 201)):
        target = stack.server(Profile(trust_proxy_headers=trust, allowed_cidrs=cidrs), name=f"db-{status}")
        anon = stack.browser(target, f"proxied-{status}", headers={"X-Forwarded-For": forwarded_for})
        resp = anon.post("/api/v1/tickets", json_body=ticket_payload(), bearer=target.submit_tokens["nyxmon"])
        assert resp.status == status
        target.stop()


@S4A
def test_trusted_proxy_headers_restore_client_ip_for_access_and_audit(stack: Stack) -> None:
    # tests/test_api.py applies ProxyFix in-process; the deployed process never sees the headers (4.4).
    target = stack.server(Profile(trust_proxy_headers=True))
    anon = stack.browser(
        target,
        "proxied",
        headers={"X-Forwarded-For": "100.100.100.42", "X-Forwarded-Proto": "https", "X-Forwarded-Host": "ops.example"},
    )
    ticket_id = create_ticket(anon, task_ref="parity-proxy-audit-1")
    db = stack.db(target)
    assert (
        db.scalar(
            "SELECT source_ip FROM audit_events WHERE ticket_id = ? AND event_type = 'ticket_created'", (ticket_id,)
        )
        == "127.0.0.1"
    )


@S4B
@pytest.mark.parametrize(
    ("headers", "status"),
    [
        ({"X-Forwarded-Proto": "https", "X-Forwarded-Host": "ops.example", "Origin": "https://ops.example"}, 403),
        ({"X-Forwarded-Proto": "https", "Origin": "https://HOST"}, 403),
        ({"X-Forwarded-Proto": "https", "Origin": "http://HOST"}, 200),
        ({"Host": "ops.example", "Origin": "http://ops.example"}, 200),
        ({"Host": "ops.example", "Origin": "http://HOST"}, 403),
    ],
)
@pytest.mark.parametrize("trust", [False, True])
def test_origin_check_uses_request_scheme_and_host(
    stack: Stack, trust: bool, headers: dict[str, str], status: int
) -> None:
    target = stack.server(Profile(trust_proxy_headers=trust))
    anon = stack.browser(target, "anon")
    ticket_id = create_ticket(anon)
    approver = stack.approver(target)
    sent = {name: value.replace("HOST", target.host) for name, value in headers.items()}
    resp = approver.api_action(ticket_id, "approve", headers=sent)
    assert resp.status == status


@S4A
def test_api_error_and_redirect_responses_carry_security_headers(anon: Browser) -> None:
    # Every response the harness sees is checked for the headers (harness.Browser.request);
    # this scenario walks the response kinds S4a serves.
    assert anon.get("/api/v1/health").status == 200
    assert anon.get("/api/v1/tickets/does-not-exist").status == 401
    assert anon.get("/no-such-page").status == 404
    assert anon.get("/login").status == 200
    resp = anon.post("/login", data={"username": "x"})
    assert (resp.status, resp.location) == (302, "/tickets")


@S4A
@pytest.mark.parametrize(
    ("method", "path", "status"),
    [
        ("GET", "/api/v1/tickets", 405),
        ("PUT", "/api/v1/tickets", 405),
        ("GET", "/api/v1/runner/claim", 405),
        ("DELETE", "/api/v1/tickets/x", 405),
        ("GET", "/api/v1/health/", 404),
        ("GET", "/api/v1/tickets/a/b", 404),
        ("GET", "/api/v2/health", 404),
        ("HEAD", "/api/v1/health", 200),
        ("POST", "/api/v1/health", 405),
        ("OPTIONS", "/api/v1/health", 200),
        ("OPTIONS", "/api/v1/tickets", 200),
        ("OPTIONS", "/api/v1/tickets/x", 200),
        ("OPTIONS", "/login", 200),
        ("OPTIONS", "/no-such-page", 404),
        ("PUT", "/api//v1/health", 405),
        ("GET", "/api/v1//nope", 404),
        ("GET", "/api/v1/tickets/a//b", 404),
        ("GET", "/login//", 404),
    ],
)
def test_routing_methods_and_unknown_paths(anon: Browser, method: str, path: str, status: int) -> None:
    assert anon.request(method, path).status == status


@S4A
@pytest.mark.parametrize(
    ("method", "path", "merged"),
    [
        ("GET", "/api//v1/health", "/api/v1/health"),
        ("GET", "/api//v1/health?x=1", "/api/v1/health?x=1"),
        ("HEAD", "/api///v1//health", "/api/v1/health"),
        ("POST", "/api//v1/tickets", "/api/v1/tickets"),
        ("GET", "/api/v1/tickets//x", "/api/v1/tickets/x"),
    ],
)
def test_repeated_slashes_redirect_to_the_merged_route(anon: Browser, method: str, path: str, merged: str) -> None:
    # Werkzeug's merge_slashes: 308 to the absolute merged URL (its port differs per process, so the
    # exchange is checked here instead of recorded).
    resp = anon.request(method, path, json_body=ticket_payload(), record=False)
    assert resp.status == 308
    assert resp.location == f"{anon.target.base_url}{merged}"
    assert anon.get("/api/v1/health").json()["ticket_counters"] == {}


@S4B
@pytest.mark.parametrize("action", ["approve", "reject", "cancel", "archive", "unarchive"])
def test_routing_wrong_method_on_approver_action(anon: Browser, action: str) -> None:
    # The approver's API actions are slice S4b's routes.
    assert anon.get(f"/api/v1/tickets/x/{action}").status == 405


@S4A
def test_health_counts_tickets_by_state(anon: Browser, db: Database) -> None:
    for task_ref in ("a", "b", "c"):
        create_ticket(anon, task_ref=f"parity-count-{task_ref}")
    db.execute("UPDATE tickets SET state = 'failed' WHERE task_ref = 'parity-count-a'")
    assert anon.get("/api/v1/health").json()["ticket_counters"] == {"failed": 1, "pending_approval": 2}
