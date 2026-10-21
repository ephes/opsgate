"""Login, sessions, revocation, throttle and both CSRF mechanisms (PLAN.md 4.5).

Ported from tests/test_api.py (names kept). Where the Python test inspects or
edits the Flask session directly, the black-box version reads the CSRF token
from a rendered form and checks authentication through the API instead.
"""

from __future__ import annotations

import time

import pytest
from conftest import Stack
from harness import (
    Browser,
    Database,
    Profile,
    Recorder,
    create_ticket,
    get_ticket,
)

S4A = pytest.mark.rust("S4a")
S4B = pytest.mark.rust("S4a", "S4b")
NON_ASCII_TOKEN = "té-über"


def authenticated(browser: Browser, ticket_id: str) -> bool:
    """Whether the browser's session authenticates (4.5.2), observed through the API."""
    status = browser.get(f"/api/v1/tickets/{ticket_id}").status
    assert status in {200, 401}
    return status == 200


def failed_login(browser: Browser, password: str = "wrong-password", username: str | None = None) -> int:
    resp = browser.login(password=password, username=username)
    return resp.status


# ------------------------------------------------------------------ login page and next (4.5.3)


@S4A
def test_login_form_uses_autofill_friendly_fields(anon: Browser) -> None:
    body = anon.get("/login").text
    for snippet in (
        'id="login-form"',
        'name="login"',
        'action="/login"',
        'autocomplete="on"',
        'name="username"',
        'autocomplete="username"',
        "autofocus",
        'autocapitalize="none"',
        'autocorrect="off"',
        'spellcheck="false"',
        'name="password"',
        'id="current-password"',
        'autocomplete="current-password"',
    ):
        assert snippet in body, snippet


@S4A
def test_login_head_is_side_effect_free(anon: Browser) -> None:
    for path in ("/login", "/login?next=/tickets/test-ticket"):
        resp = anon.head(path)
        assert resp.status == 200 and resp.location is None
    page = anon.get("/login?next=/tickets/test-ticket")
    assert page.flashes == []
    assert ["next"] in [[name for name in form["fields"] if name == "next"] for form in page.facts.forms]  # type: ignore[union-attr]


@S4B
@pytest.mark.parametrize(
    ("next_path", "location"),
    [
        ("/tickets/abc", "/tickets/abc"),
        ("https://example.com/steal", "/tickets"),
        ("//evil.example/steal", "/tickets"),
        ("javascript:alert(1)", "/tickets"),
        ("/tickets/test%0D%0Ainvalid", "/tickets"),
        ("/tickets/test%09tab", "/tickets"),
        ("tickets", "/tickets"),
        ("%20/tickets?view=all%20", "/tickets?view=all"),
    ],
)
def test_login_next_path_sanitising(anon: Browser, next_path: str, location: str) -> None:
    resp = anon.login(f"/login?next={next_path}")
    assert (resp.status, resp.location) == (302, location)


@S4B
def test_login_form_next_wins_over_query_next(anon: Browser) -> None:
    page = anon.get("/login?next=/tickets/query")
    resp = anon.post(
        "/login?next=/tickets/query",
        data={
            "csrf_token": page.csrf_token,
            "username": anon.target.username,
            "password": anon.target.password,
            "next": "/tickets/form",
        },
    )
    assert resp.location == "/tickets/form"


@S4B
def test_failed_login_keeps_next(anon: Browser) -> None:
    resp = anon.login("/login?next=/tickets/abc", password="wrong")
    assert (resp.status, resp.location) == (302, "/login?next=/tickets/abc")
    assert anon.follow(resp).flashes == [["error", "Invalid username or password"]]


@S4B
def test_login_rotates_csrf_token(anon: Browser) -> None:
    before = anon.get("/login").csrf_token
    assert anon.login().status == 302
    assert anon.csrf() != before


@S4B
@pytest.mark.local
def test_wrong_username_still_runs_the_password_check(anon: Browser) -> None:
    # Black box: the right password with the wrong username signs nobody in (the bcrypt call count is unit level).
    ticket_id = create_ticket(anon)
    resp = anon.login(username="someone-else")
    assert (resp.status, resp.location) == (302, "/login")
    assert not authenticated(anon, ticket_id)


@S4B
@pytest.mark.local
@pytest.mark.parametrize("username", ["opsgäte-admin", " opsgate-admin ", "OPSGATE-ADMIN"])
def test_username_variants(anon: Browser, username: str) -> None:
    ticket_id = create_ticket(anon)
    resp = anon.login(username=username)
    ok = username.strip() == anon.target.username
    assert (resp.status, resp.location) == (302, "/tickets" if ok else "/login")
    assert authenticated(anon, ticket_id) is ok


@S4B
@pytest.mark.local
def test_login_requires_csrf_token(anon: Browser) -> None:
    ticket_id = create_ticket(anon)
    anon.get("/login")
    for token in (None, "tampered-token", NON_ASCII_TOKEN):
        data = {"username": anon.target.username, "password": anon.target.password}
        if token is not None:
            data["csrf_token"] = token
        resp = anon.post("/login", data=data)
        assert (resp.status, resp.location) == (302, "/tickets")
        assert not authenticated(anon, ticket_id)
    assert anon.get("/login").flashes == [["error", "Invalid form token"]] * 3


@S4B
@pytest.mark.parametrize("secure", [False, True])
def test_session_cookie_attributes(stack: Stack, secure: bool) -> None:
    target = stack.server(Profile(session_cookie_secure=secure))
    browser = stack.browser(target, "approver")
    page = browser.get("/login")
    resp = browser.post(
        "/login", data={"csrf_token": page.csrf_token, "username": target.username, "password": target.password}
    )
    cookies = [c for c in (stack.rec.steps[-1].get("cookies") or []) if c["name"] == "session"]
    assert resp.status == 302 and len(cookies) == 1
    assert cookies[0] | {"deleted": False} == {
        "name": "session",
        "deleted": False,
        "httponly": True,
        "secure": secure,
        "samesite": "lax",
        "path": "/",
        "persistent": False,
    }


@S4B
@pytest.mark.local
def test_session_times_out(stack: Stack) -> None:
    target = stack.server(Profile(session_timeout_seconds=1))
    anon = stack.browser(target, "anon")
    ticket_id = create_ticket(anon)
    approver = stack.approver(target)
    assert authenticated(approver, ticket_id)
    time.sleep(2.2)
    assert not authenticated(approver, ticket_id)


# ------------------------------------------------------------------ API CSRF (4.5.4)


@S4B
@pytest.mark.parametrize("action", ["approve", "reject", "cancel", "archive", "unarchive"])
def test_cookie_api_action_without_csrf_header_is_rejected(anon: Browser, approver: Browser, action: str) -> None:
    ticket_id = create_ticket(anon)
    resp = approver.post(f"/api/v1/tickets/{ticket_id}/{action}")
    assert (resp.status, resp.error) == (403, "csrf_required")
    assert get_ticket(anon, ticket_id)["state"] == "pending_approval"


@S4B
def test_cookie_approve_with_wrong_csrf_header_is_rejected(anon: Browser, approver: Browser) -> None:
    ticket_id = create_ticket(anon)
    resp = approver.api_action(
        ticket_id, "approve", headers={"X-CSRF-Token": "not-the-token", "Sec-Fetch-Site": "same-origin"}
    )
    assert (resp.status, resp.error) == (403, "invalid_csrf")
    assert get_ticket(anon, ticket_id)["state"] == "pending_approval"


@S4B
def test_cookie_approve_with_csrf_header_succeeds(anon: Browser, approver: Browser) -> None:
    ticket_id = create_ticket(anon)
    assert approver.api_action(ticket_id, "approve").json()["state"] == "approved"


@S4B
@pytest.mark.parametrize(
    ("headers", "expected_status"),
    [
        ({"Sec-Fetch-Site": "same-origin"}, 200),
        ({"Sec-Fetch-Site": "Same-Origin"}, 200),
        ({"Sec-Fetch-Site": "same-site"}, 403),
        ({"Sec-Fetch-Site": "cross-site"}, 403),
        ({"Sec-Fetch-Site": "none"}, 403),
        ({"Sec-Fetch-Site": "same-site", "Origin": "ORIGIN"}, 403),
        ({"Origin": "ORIGIN"}, 200),
        ({"Origin": "ORIGIN_UPPER"}, 200),
        ({"Origin": "ORIGIN_HTTPS"}, 403),
        ({"Origin": "http://other.localhost"}, 403),
        ({"Origin": "null"}, 403),
        ({"X-CSRF-Token": "", "Origin": "ORIGIN"}, 200),
    ],
)
def test_cookie_approve_same_origin_fallback(
    anon: Browser, approver: Browser, headers: dict[str, str], expected_status: int
) -> None:
    ticket_id = create_ticket(anon)
    origins = {
        "ORIGIN": approver.target.origin,
        "ORIGIN_UPPER": approver.target.origin.upper(),
        "ORIGIN_HTTPS": approver.target.origin.replace("http://", "https://"),
    }
    sent = {name: origins.get(value, value) for name, value in headers.items()}
    resp = approver.api_action(ticket_id, "approve", headers=sent)
    assert resp.status == expected_status
    if expected_status == 403:
        assert resp.error == "csrf_required"
    assert get_ticket(anon, ticket_id)["state"] == ("approved" if expected_status == 200 else "pending_approval")


@S4B
@pytest.mark.local
def test_bearer_callers_are_unaffected_by_api_csrf(anon: Browser, stack: Stack) -> None:
    ticket_id = create_ticket(anon)
    assert anon.get(f"/api/v1/tickets/{ticket_id}", bearer=anon.target.runner_token).status == 200
    resp = anon.post(f"/api/v1/tickets/{ticket_id}/approve", bearer=anon.target.submit_tokens["nyxmon"])
    assert (resp.status, resp.error) == (401, "auth_required")
    approver = stack.approver(anon.target)
    assert approver.api_action(ticket_id, "approve").status == 200
    claimed = anon.post("/api/v1/runner/claim", json_body={"runner_host": "runner-a"}, bearer=anon.target.runner_token)
    assert claimed.json()["ticket"]["id"] == ticket_id


@S4B
def test_unauthenticated_api_action_reports_auth_before_csrf(anon: Browser) -> None:
    ticket_id = create_ticket(anon)
    resp = anon.post(f"/api/v1/tickets/{ticket_id}/approve")
    assert (resp.status, resp.error) == (401, "auth_required")
    resp = anon.post("/api/v1/tickets/missing-ticket/approve", headers={"Sec-Fetch-Site": "cross-site"})
    assert (resp.status, resp.error) == (401, "auth_required")


@S4B
@pytest.mark.parametrize("action", ["approve", "reject", "cancel", "archive", "unarchive"])
def test_api_session_actions_reject_non_ascii_csrf_header(anon: Browser, approver: Browser, action: str) -> None:
    ticket_id = create_ticket(anon)
    resp = approver.api_action(
        ticket_id, action, {"reason": "nope"}, headers={"X-CSRF-Token": NON_ASCII_TOKEN.encode()}
    )
    assert (resp.status, resp.error) == (403, "invalid_csrf")


# ------------------------------------------------------------------ revocation (4.5.2)


@S4B
def test_cookie_replayed_after_logout_is_rejected(anon: Browser, approver: Browser, stack: Stack) -> None:
    ticket_id = create_ticket(anon)
    stolen_cookie = approver.session_cookie
    stolen_csrf = approver.csrf()
    logout = approver.post("/logout", data={"csrf_token": stolen_csrf})
    assert (logout.status, logout.location) == (302, "/login")
    assert approver.session_cookie is None
    replay = stack.browser(approver.target, "replay")
    replay.set_session_cookie(stolen_cookie)
    assert not authenticated(replay, ticket_id)
    replay.set_session_cookie(stolen_cookie)
    resp = replay.post(f"/api/v1/tickets/{ticket_id}/approve", headers={"X-CSRF-Token": stolen_csrf})
    assert (resp.status, resp.error) == (401, "auth_required")
    assert get_ticket(anon, ticket_id)["state"] == "pending_approval"


@S4B
@pytest.mark.local
def test_logout_revokes_other_sessions_and_fresh_login_works(anon: Browser, stack: Stack, db: Database) -> None:
    ticket_id = create_ticket(anon)
    first = stack.approver(anon.target, "first")
    second = stack.approver(anon.target, "second")
    assert first.post("/logout", data={"csrf_token": first.csrf()}).status == 302
    assert db.scalar("SELECT session_generation FROM ui_session_state") == 2
    assert not authenticated(second, ticket_id)
    assert second.login().status == 302
    assert authenticated(second, ticket_id)


@S4B
@pytest.mark.local
def test_anonymous_logout_does_not_revoke_sessions(anon: Browser, approver: Browser, db: Database) -> None:
    ticket_id = create_ticket(anon)
    resp = anon.post("/logout", data={"csrf_token": anon.get("/login").csrf_token})
    assert (resp.status, resp.location) == (302, "/login")
    assert authenticated(approver, ticket_id)
    assert db.scalar("SELECT session_generation FROM ui_session_state") == 1


@S4B
@pytest.mark.local
def test_password_change_revokes_existing_sessions(
    stack: Stack, anon: Browser, approver: Browser, db: Database
) -> None:
    ticket_id = create_ticket(anon)
    restarted = stack.restart(approver.target, profile=Profile(password="new-password"))
    assert db.scalar("SELECT session_generation FROM ui_session_state") == 2
    assert not authenticated(approver, ticket_id)
    assert approver.login().status == 302
    assert authenticated(approver, ticket_id)
    assert restarted.password == "new-password"


@S4B
@pytest.mark.local
def test_restart_with_same_password_keeps_sessions(
    stack: Stack, anon: Browser, approver: Browser, db: Database
) -> None:
    ticket_id = create_ticket(anon)
    stack.restart(approver.target)
    assert db.scalar("SELECT session_generation FROM ui_session_state") == 1
    assert authenticated(approver, ticket_id)


# ------------------------------------------------------------------ throttle (4.5.3)


@S4B
@pytest.mark.local
def test_login_locks_after_repeated_failures(anon: Browser) -> None:
    ticket_id = create_ticket(anon)
    for _ in range(5):
        assert failed_login(anon) == 302
    locked = anon.login()
    assert locked.status == 429
    assert locked.flashes == [["error", "Too many failed login attempts. Try again later."]]
    assert not authenticated(anon, ticket_id)


@S4B
@pytest.mark.local
def test_unknown_username_counts_toward_throttle(anon: Browser) -> None:
    for _ in range(5):
        assert failed_login(anon, password="x", username="nobody") == 302
    assert anon.login().status == 429


@S4B
@pytest.mark.local
def test_successful_login_resets_failure_count(anon: Browser) -> None:
    for _ in range(4):
        failed_login(anon)
    assert anon.login().status == 302
    assert anon.post("/logout", data={"csrf_token": anon.csrf()}).status == 302
    for _ in range(4):
        failed_login(anon)
    assert anon.login().status == 302


def loopback_alias_available(address: str) -> bool:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((address, 0))
        except OSError:
            return False
    return True


@S4B
@pytest.mark.local
def test_login_throttle_is_per_client_ip(stack: Stack) -> None:
    # The throttle key is the socket peer (forwarded headers never reach the app, PLAN.md 4.4), so the
    # second client connects from another loopback address. Linux routes all of 127/8; macOS only 127.0.0.1.
    if not loopback_alias_available("127.0.0.2"):
        pytest.skip("127.0.0.2 is not configured on this host (the Linux CI job runs this scenario)")
    target = stack.server(Profile(allowed_cidrs="127.0.0.0/8"))
    first = stack.browser(target, "client-a")
    second = stack.browser(target, "client-b", local_address="127.0.0.2")
    for _ in range(5):
        failed_login(first)
    assert first.login().status == 429
    resp = second.login()
    assert (resp.status, resp.location) == (302, "/tickets")


@S4B
@pytest.mark.local
def test_login_throttle_ignores_forwarded_for(stack: Stack) -> None:
    target = stack.server(Profile(trust_proxy_headers=True))
    first = stack.browser(target, "client-a", headers={"X-Forwarded-For": "100.64.0.6"})
    second = stack.browser(target, "client-b", headers={"X-Forwarded-For": "100.64.0.7"})
    for _ in range(5):
        failed_login(first)
    assert first.login().status == 429
    assert second.login().status == 429


@S4B
@pytest.mark.local
def test_logout_and_login_require_ui_csrf(anon: Browser, approver: Browser, rec: Recorder) -> None:
    ticket_id = create_ticket(anon)
    for token in (None, NON_ASCII_TOKEN):
        resp = approver.post("/logout", data={} if token is None else {"csrf_token": token})
        assert (resp.status, resp.location) == (302, "/tickets")
        assert authenticated(approver, ticket_id)
    rec.note("logout without token keeps the session", True)
