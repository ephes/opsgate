"""The Python half of ``python_roundtrip.rs`` (rust/PLAN.md 12, S3a/S3b acceptance).

Reads ``{"src": <repo>/src, "db": <path>, "ops": [...]}`` as JSON on stdin, runs every operation with a fresh
``OpsGateService`` on that database (its ``init_db`` runs on the Rust-initialised database each time) and prints one
outcome per operation as JSON: ``{"ok": <value>}``, ``{"error": {"code", "status"}}`` or ``{"unhandled": <type>}``.
The settings are those of the Rust store tests (``tests/common/mod.rs``). Run with ``python3 -I``: the store and its
settings use the standard library only.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

HASH_ONE = "$2b$12$fixture.hash.one.not.verified.by.these.scenarios.xx"


def main() -> int:
    request = json.load(sys.stdin)
    sys.path.insert(0, request["src"])
    from opsgate.config import OpsGateSettings, SubmitterPolicy
    from opsgate.service import OpsGateService, ServiceError, submitter_context_from_policy

    db_path = Path(request["db"])
    policies = (
        SubmitterPolicy(source="openclaw", token="openclaw-token-0000000000", require_reviewer_step_floor=False),
        SubmitterPolicy(source="nyxmon", token="nyxmon-token-000000000000", require_reviewer_step_floor=False),
        SubmitterPolicy(source="operator", token="operator-token-00000000000", require_reviewer_step_floor=False),
    )
    settings = OpsGateSettings(
        service_name="opsgate",
        bind_host="0.0.0.0",
        bind_port=8711,
        db_path=str(db_path),
        session_secret="x" * 32,
        trust_proxy_headers=False,
        session_cookie_secure=False,
        session_timeout_seconds=28800,
        ui_username="opsgate-admin",
        ui_password_bcrypt=HASH_ONE,
        max_duration_seconds_default=3600,
        policy_floor_require_reviewer_step=False,
        runner_token="runner-token-000000000000",
        submitter_policies=policies,
        require_tailscale_context=True,
        allowed_cidrs=("127.0.0.1/32",),
        execution_data_dir=str(db_path.parent / "remediation"),
        disable_file_path=str(db_path.parent / "remediation" / ".disabled"),
    )

    def run(op: dict[str, Any]) -> Any:
        service = OpsGateService(settings)
        name = op["op"]
        if name == "create":
            policy = next(policy for policy in policies if policy.source == op["source"])
            return service.create_ticket(op["payload"], submitter_context_from_policy(policy), "127.0.0.1", "python")
        if name in ("approve", "archive", "unarchive"):
            method = getattr(service, f"{name}_ticket")
            return method(op["id"], approver="opsgate-admin", source_ip="127.0.0.1", user_agent="python")
        if name in ("reject", "cancel"):
            method = getattr(service, f"{name}_ticket")
            return method(op["id"], approver="opsgate-admin", reason=op["reason"], source_ip=None, user_agent=None)
        if name == "claim":
            return service.claim_ticket(runner_host=op["runner_host"], source_ip=None, user_agent=None)
        if name == "status":
            return service.update_runner_status(
                op["id"], runner_host=op["runner_host"], payload=op["payload"], source_ip=None, user_agent=None
            )
        if name == "get":
            return service.get_ticket(op["id"])
        if name == "generation":
            return service.get_ui_session_generation("opsgate-admin")
        raise AssertionError(f"unknown op {name!r}")

    outcomes = []
    for op in request["ops"]:
        try:
            outcomes.append({"ok": run(op)})
        except ServiceError as exc:
            outcomes.append({"error": {"code": exc.error_code, "status": exc.status_code}})
        except Exception as exc:  # noqa: BLE001 - an unhandled exception is a 500
            outcomes.append({"unhandled": type(exc).__name__})
    json.dump(outcomes, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
