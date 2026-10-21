"""Bearer API: health, ticket creation and reads, validation and JSON body rules (PLAN.md 4.3, 4.6, 4.7.1).

Ported from tests/test_api.py (names kept) plus contract cases of the plan.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from harness import (
    FUTURE,
    PAST,
    PLAN,
    REVIEW_PLAN,
    Browser,
    Database,
    Recorder,
    create_ticket,
    get_ticket,
    ticket_payload,
)

S4A = pytest.mark.rust("S4a")


def post_ticket(anon: Browser, payload: Any, source: str = "nyxmon", **kwargs: Any) -> Any:
    return anon.post("/api/v1/tickets", json_body=payload, bearer=anon.target.submit_tokens[source], **kwargs)


def post_raw(anon: Browser, body: str | bytes, content_type: str = "application/json", source: str = "nyxmon") -> Any:
    return anon.post(
        "/api/v1/tickets", content=body, content_type=content_type, bearer=anon.target.submit_tokens[source]
    )


def ticket_count(db: Database) -> int:
    return int(db.scalar("SELECT count(*) FROM tickets"))


@S4A
def test_health_endpoint_reports_ok(anon: Browser) -> None:
    body = anon.get("/api/v1/health").json()
    assert body["status"] == "ok" and body["db"] == "ok"
    assert body["service"] == anon.target.service_name


@S4A
@pytest.mark.local
def test_health_reports_no_runner_heartbeat_before_first_poll(anon: Browser) -> None:
    body = anon.get("/api/v1/health").json()
    assert body == {
        "status": "ok",
        "service": "opsgate-parity",
        "db": "ok",
        "runner_last_heartbeat": None,
        "runner_host": None,
        "ticket_counters": {},
    }


@S4A
def test_create_and_get_ticket_submit_token(anon: Browser) -> None:
    resp = post_ticket(anon, ticket_payload(title="Investigate disk alert", task_ref="parity-alert-123"))
    assert resp.status == 201
    created = resp.json()
    assert created["state"] == "pending_approval" and created["source"] == "nyxmon"
    assert created["is_terminal"] is False and created["is_archivable"] is True and created["is_archived"] is False
    assert get_ticket(anon, created["id"])["id"] == created["id"]
    assert anon.get(f"/api/v1/tickets/{created['id']}", bearer=anon.target.runner_token).status == 200


@S4A
def test_get_ticket_forbidden_for_other_submitter_source(anon: Browser) -> None:
    ticket_id = create_ticket(anon, task_ref="parity-cross-source-1")
    resp = anon.get(f"/api/v1/tickets/{ticket_id}", bearer=anon.target.submit_tokens["openclaw"])
    assert (resp.status, resp.error) == (403, "forbidden")


@S4A
def test_get_ticket_reports_not_found_before_forbidden(anon: Browser) -> None:
    resp = anon.get("/api/v1/tickets/missing-ticket", bearer=anon.target.submit_tokens["openclaw"])
    assert (resp.status, resp.error) == (404, "ticket_not_found")
    resp = anon.get("/api/v1/tickets/missing-ticket")
    assert (resp.status, resp.error) == (401, "auth_required")


@S4A
def test_dedupe_enforced_for_open_task_ref(anon: Browser) -> None:
    payload = ticket_payload(task_ref="parity-same-ref")
    assert post_ticket(anon, payload, "openclaw").status == 201
    second = post_ticket(anon, payload, "openclaw")
    assert (second.status, second.error) == (409, "duplicate_open_ticket")
    # Another source has its own (source, task_ref) space.
    assert post_ticket(anon, payload, "nyxmon").status == 201


@S4A
def test_dedupe_not_applied_when_task_ref_missing(anon: Browser) -> None:
    for task_ref in (None, "", "   "):
        payload = ticket_payload() if task_ref is None else ticket_payload(task_ref=task_ref)
        assert post_ticket(anon, payload, "openclaw").status == 201
        assert post_ticket(anon, payload, "openclaw").status == 201


@S4A
def test_dedupe_expires_stale_pending_ticket_before_replacement_submit(anon: Browser, db: Database) -> None:
    original = post_ticket(anon, ticket_payload(task_ref="parity-expired-pending", expires_at=PAST)).json()
    replacement = post_ticket(
        anon, ticket_payload(task_ref="parity-expired-pending", expires_at=FUTURE, title="Recurrence")
    )
    assert replacement.status == 201
    assert replacement.json()["id"] != original["id"]
    expired = get_ticket(anon, original["id"])
    assert (expired["state"], expired["result"], expired["result_detail"]) == (
        "expired",
        "failure",
        "expired_before_execution",
    )
    assert db.audit_types(original["id"])[-1] == "ticket_expired"


@S4A
def test_operator_submitter_may_explicitly_require_reviewer_step(anon: Browser) -> None:
    resp = post_ticket(
        anon,
        ticket_payload(execution_plan=REVIEW_PLAN, policy_requirements={"require_reviewer_step": True}),
        "operator",
    )
    assert resp.status == 201
    assert resp.json()["policy_requirements"] == {"require_reviewer_step": True}


@S4A
def test_operator_submitter_omitted_ticket_policy_defaults_to_no_reviewer_floor(anon: Browser) -> None:
    resp = post_ticket(anon, ticket_payload(execution_plan=REVIEW_PLAN), "operator")
    assert resp.status == 201
    assert resp.json()["policy_requirements"] == {"require_reviewer_step": False}


@S4A
@pytest.mark.parametrize(
    ("changes", "error"),
    [
        ({"source": "openclaw"}, "source_mismatch"),
        ({"source": " nyxmon "}, None),
        ({"title": "   "}, "invalid_ticket"),
        ({"summary": ""}, "invalid_ticket"),
        ({"execution_plan": []}, "invalid_execution_plan"),
        ({"execution_plan": {"role": "investigator"}}, "invalid_execution_plan"),
        ({"execution_plan": ["step"]}, "invalid_execution_plan"),
        ({"policy_requirements": []}, "invalid_policy_requirements"),
        ({"policy_requirements": ""}, None),
        ({"policy_requirements": {"require_reviewer_step": "yes"}}, "invalid_policy_requirements"),
        ({"policy_requirements": {"require_reviewer_step": True}}, "missing_reviewer_step"),
        ({"policy_requirements": {"unknown": 1}}, None),
        ({"context": []}, "invalid_ticket"),
        ({"context": None}, None),
        ({"context": {"score": 0.95, "count": 3.0, "big": 10**30, "text": "Grüße 🛠️"}}, None),
        ({"expires_at": "not-a-date"}, "invalid_expires_at"),
        ({"expires_at": "2026-10-21T10:00:00"}, "invalid_expires_at"),
        ({"expires_at": None}, None),
        ({"task_ref": None}, None),
        ({"title": 42, "summary": 1.5, "task_ref": True}, None),
        ({"title": 1e16, "summary": False, "task_ref": 1e-05}, None),
    ],
    ids=lambda value: json.dumps(value, ensure_ascii=True) if isinstance(value, dict) else str(value),
)
def test_ticket_validation_order_and_normalisation(anon: Browser, changes: dict[str, Any], error: str | None) -> None:
    resp = post_ticket(anon, ticket_payload(**changes))
    if error is None:
        assert resp.status == 201
    else:
        assert (resp.status, resp.error) == (400 if error != "source_mismatch" else 403, error)


@S4A
@pytest.mark.parametrize("field", ["title", "summary", "task_ref", "source"])
@pytest.mark.parametrize("value", [[1, "a"], {"k": "v"}])
def test_text_fields_with_arrays_or_objects(anon: Browser, rec: Recorder, impl: str, field: str, value: Any) -> None:
    # D-3: Python stores the repr of the container (source then mismatches); Rust answers 400.
    rec.divergence("D-3")
    resp = post_ticket(anon, ticket_payload(**{field: value}))
    if field == "source":
        assert (resp.status, resp.error) == ((403, "source_mismatch") if impl == "python" else (400, "invalid_ticket"))
    elif impl == "python":
        assert resp.status == 201
        assert resp.json()[field] == str(value)
    else:
        assert (resp.status, resp.error) == (400, "invalid_ticket")


@S4A
def test_api_ticket_creation_rejects_unsupported_agent(anon: Browser) -> None:
    plan = [{"role": "investigator", "agent": "shell", "prompt_markdown": "Inspect the service"}]
    resp = post_ticket(anon, ticket_payload(execution_plan=plan))
    assert (resp.status, resp.error) == (400, "invalid_execution_plan")


@S4A
def test_api_ticket_creation_normalizes_agent_case(anon: Browser) -> None:
    plan = [{"role": "reviewer", "agent": "CLAUDE", "prompt_markdown": "Review the change"}]
    ticket_id = post_ticket(anon, ticket_payload(execution_plan=plan)).json()["id"]
    assert get_ticket(anon, ticket_id)["execution_plan"] == [
        {"role": "reviewer", "agent": "claude", "prompt_markdown": "Review the change"}
    ]


@S4A
@pytest.mark.local
@pytest.mark.parametrize("field", ["role", "agent", "prompt_markdown"])
@pytest.mark.parametrize("value", [None, True, 42, [], {}, "", "   "])
def test_api_rejects_non_text_plan_fields(anon: Browser, db: Database, field: str, value: Any) -> None:
    step: dict[str, Any] = {"role": "investigator", "agent": "codex", "prompt_markdown": "Inspect"}
    step[field] = value
    resp = post_ticket(anon, ticket_payload(execution_plan=[step]))
    assert (resp.status, resp.error) == (400, "invalid_execution_plan")
    assert ticket_count(db) == 0
    claim = anon.post("/api/v1/runner/claim", json_body={"runner_host": "test"}, bearer=anon.target.runner_token)
    assert claim.json() == {"ticket": None}


@S4A
@pytest.mark.parametrize("expiry", ["0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00"])
def test_api_rejects_utc_expiry_overflow(anon: Browser, expiry: str) -> None:
    resp = post_ticket(anon, ticket_payload(expires_at=expiry))
    assert (resp.status, resp.error) == (400, "invalid_expires_at")


@S4A
@pytest.mark.parametrize(
    ("expiry", "stored"),
    [
        (None, None),
        ("2099-01-01T01:00:00+01:00", "2099-01-01T00:00:00Z"),
        (" 2099-06-01T12:30:00.5Z ", "2099-06-01T12:30:00.500000Z"),
        ("2099-06-01 12:30+02:00", "2099-06-01T10:30:00Z"),
    ],
)
def test_api_accepts_trimmed_plan_and_optional_expiry(anon: Browser, expiry: str | None, stored: str | None) -> None:
    plan = [{"role": " investigator ", "agent": " CODEX ", "prompt_markdown": " Inspect "}]
    payload = ticket_payload(execution_plan=plan)
    if expiry is not None:
        payload["expires_at"] = expiry
    ticket = get_ticket(anon, post_ticket(anon, payload).json()["id"])
    assert ticket["execution_plan"] == [{"role": "investigator", "agent": "codex", "prompt_markdown": "Inspect"}]
    assert ticket["expires_at"] == stored


@S4A
@pytest.mark.local
@pytest.mark.parametrize(
    "duration", ["true", "false", "1.5", "900.0", "Infinity", "1e100", "1" + "0" * 100, "0", "-1", '"900"', "31536001"]
)
def test_ticket_duration_rejects_invalid_values(
    anon: Browser, db: Database, rec: Recorder, impl: str, duration: str
) -> None:
    body = json.dumps(ticket_payload())[:-1] + f', "max_duration_seconds": {duration}}}'
    resp = post_raw(anon, body)
    if duration == "Infinity":
        rec.divergence("D-2")  # Rust rejects the non-standard literal itself.
    expected = "invalid_json" if duration == "Infinity" and impl == "rust" else "invalid_ticket"
    assert (resp.status, resp.error) == (400, expected)
    assert ticket_count(db) == 0


@S4A
@pytest.mark.parametrize("duration", [1, 31536000, None])
def test_ticket_duration_accepts_boundaries(anon: Browser, duration: int | None) -> None:
    resp = post_ticket(anon, ticket_payload(max_duration_seconds=duration))
    assert resp.status == 201
    assert resp.json()["max_duration_seconds"] == (duration or 3600)


@S4A
@pytest.mark.local
def test_ticket_duration_rejects_json_exponent_overflow(anon: Browser, db: Database) -> None:
    body = json.dumps(ticket_payload())[:-1] + ', "max_duration_seconds": 1e309}'
    resp = post_raw(anon, body)
    assert (resp.status, resp.error) == (400, "invalid_ticket")
    assert ticket_count(db) == 0


@S4A
@pytest.mark.local
@pytest.mark.parametrize("field", ["title", "summary", "task_ref"])
@pytest.mark.parametrize("surrogate", ["\ud800", "\udfff"])
def test_ticket_text_rejects_unpaired_surrogates(
    anon: Browser, db: Database, rec: Recorder, impl: str, field: str, surrogate: str
) -> None:
    rec.divergence("D-2")  # Rust cannot decode a lone surrogate escape: invalid_json.
    payload = ticket_payload(task_ref="task")
    payload[field] = "private text " + surrogate * 10
    resp = post_raw(anon, json.dumps(payload, ensure_ascii=True))
    assert (resp.status, resp.error) == (400, "invalid_ticket" if impl == "python" else "invalid_json")
    assert ticket_count(db) == 0


@S4A
def test_ticket_unicode_text_round_trips(anon: Browser) -> None:
    text = "Grüße aus Köln 🛠️   \x7f"
    plan = [{"role": "investigator", "agent": "codex", "prompt_markdown": text}]
    ticket = get_ticket(
        anon, create_ticket(anon, title=text, summary=text, task_ref=text, execution_plan=plan, context={"t": text})
    )
    assert (ticket["title"], ticket["summary"], ticket["task_ref"]) == (text, text, text)
    assert ticket["execution_plan"] == plan and ticket["context"] == {"t": text}


# ------------------------------------------------------------------ JSON body rules (4.6)


@S4A
@pytest.mark.local
@pytest.mark.parametrize("depth", [64, 65, 2000])
def test_real_json_nesting_limit(anon: Browser, db: Database, depth: int) -> None:
    body = (
        json.dumps(ticket_payload())[:-1]
        + ', "context": {"nested": '
        + "[" * (depth - 2)
        + "0"
        + "]" * (depth - 2)
        + "}}"
    )
    resp = post_raw(anon, body)
    if depth == 64:
        assert resp.status == 201
    else:
        assert (resp.status, resp.error) == (400, "invalid_json")
        assert ticket_count(db) == 0


@S4A
@pytest.mark.parametrize(
    ("body", "content_type", "status"),
    [
        ("{", "application/json", 400),
        ("[]", "application/json", 400),
        ('"text"', "application/json", 400),
        ("null", "application/json", 400),
        ("", "application/json", 400),
        ("TICKET", "text/plain", 400),
        ("TICKET", "application/x-www-form-urlencoded", 400),
        ("TICKET", "application/json; charset=utf-8", 201),
        ("TICKET", "application/vnd.opsgate+json", 201),
        ("TICKET", "APPLICATION/JSON", 201),
        ("﻿TICKET", "application/json", 201),
    ],
)
def test_json_object_body_rules(anon: Browser, body: str, content_type: str, status: int) -> None:
    raw = body.replace("TICKET", json.dumps(ticket_payload()))
    resp = post_raw(anon, raw.encode("utf-8"), content_type)
    assert resp.status == status
    if status == 400:
        assert resp.error == "invalid_json"


@S4A
@pytest.mark.parametrize("endpoint", ["/api/v1/tickets", "/api/v1/runner/missing/status", "/api/v1/runner/claim"])
def test_json_decode_errors_are_domain_responses(anon: Browser, endpoint: str) -> None:
    bearer = anon.target.runner_token if "runner" in endpoint else anon.target.submit_tokens["nyxmon"]
    for body in ('{"context":' + "[" * 2000 + "0" + "]" * 2000 + "}", "{"):
        resp = anon.post(endpoint, content=body, content_type="application/json", bearer=bearer)
        if endpoint.endswith("claim") and body == "{":
            # Undecodable means "no JSON", which claim treats as {} (4.6).
            assert resp.status == 200
        else:
            assert (resp.status, resp.error) == (400, "invalid_json")


# ------------------------------------------------------------------ bearer tokens (4.5.1)


BEARER_ENDPOINTS = [
    ("POST", "/api/v1/tickets", "invalid_submit_token"),
    ("GET", "/api/v1/tickets/missing-ticket", "auth_required"),
    ("POST", "/api/v1/runner/claim", "invalid_runner_token"),
    ("POST", "/api/v1/runner/missing-ticket/status", "invalid_runner_token"),
]
BAD_TOKENS = [
    (endpoint, token) for endpoint in BEARER_ENDPOINTS for token in ["té-über", None, "wrong-token-0000000000000"]
] + [
    (BEARER_ENDPOINTS[0], "RUNNER"),  # the runner token never submits
    (BEARER_ENDPOINTS[2], "SUBMIT"),  # a submit token never claims
    (BEARER_ENDPOINTS[3], "SUBMIT"),
]


@S4A
@pytest.mark.parametrize(("endpoint", "token"), BAD_TOKENS, ids=lambda value: str(value))
def test_api_bearer_endpoints_reject_bad_tokens(
    anon: Browser, endpoint: tuple[str, str, str], token: str | None
) -> None:
    method, path, error = endpoint
    token = {"RUNNER": anon.target.runner_token, "SUBMIT": anon.target.submit_tokens["nyxmon"]}.get(token or "", token)
    headers: dict[str, str | bytes] = {"Authorization": f"Bearer {token}".encode()} if token else {}
    resp = anon.request(method, path, json_body=None if method == "GET" else {}, headers=headers)
    assert (resp.status, resp.error) == (401, error)


@S4A
@pytest.mark.parametrize(
    ("header", "status"),
    [
        ("Bearer TOKEN", 201),
        ("Bearer \t TOKEN", 201),
        ("bearer TOKEN", 401),
        ("BearerTOKEN", 401),
        ("Basic TOKEN", 401),
        ("Bearer Bearer TOKEN", 401),
        ("TOKEN", 401),
    ],
)
def test_bearer_header_parsing(anon: Browser, header: str, status: int) -> None:
    resp = anon.post(
        "/api/v1/tickets",
        json_body=ticket_payload(),
        headers={"Authorization": header.replace("TOKEN", anon.target.submit_tokens["nyxmon"])},
    )
    assert resp.status == status


@S4A
def test_plan_steps_keep_only_known_fields(anon: Browser) -> None:
    plan = [{**PLAN[0], "extra": "dropped", "role": "Implementer"}]
    ticket = get_ticket(anon, create_ticket(anon, execution_plan=plan))
    assert ticket["execution_plan"] == [{"role": "Implementer", "agent": "codex", "prompt_markdown": "Do work"}]
