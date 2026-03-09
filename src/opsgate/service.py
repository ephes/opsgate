from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from .config import OpsGateSettings, SubmitterPolicy

OPEN_TICKET_STATES = {"pending_approval", "approved", "running"}
TERMINAL_STATES = {"succeeded", "failed", "rejected", "canceled", "expired"}
RUNNER_EVENT_TYPES = {
    "heartbeat",
    "step_started",
    "step_finished",
    "step_failed",
    "timeout",
    "failed",
    "ticket_succeeded",
    "invalid_plan",
}
SUPPORTED_AGENTS = ("codex", "claude")
LIST_ARCHIVED_EXCLUDE = "exclude"
LIST_ARCHIVED_ONLY = "only"
LIST_ARCHIVED_INCLUDE = "include"


class ServiceError(RuntimeError):
    def __init__(self, message: str, status_code: int, error_code: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code


@dataclass(frozen=True)
class SubmitterContext:
    source: str
    token: str
    require_reviewer_step_floor: bool


def utc_now() -> datetime:
    return datetime.now(tz=UTC)


def isoformat_z(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def parse_iso_datetime(raw: str) -> datetime:
    normalized = raw.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("Datetime must include timezone information")
    return parsed.astimezone(UTC)


def optional_iso_datetime(raw: str | None) -> datetime | None:
    if raw is None:
        return None
    stripped = raw.strip()
    if not stripped:
        return None
    return parse_iso_datetime(stripped)


def compute_payload_checksum(payload: dict[str, Any]) -> str:
    canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def normalize_agent(raw_agent: Any) -> str:
    normalized = str(raw_agent).strip().lower()
    if normalized not in SUPPORTED_AGENTS:
        allowed_agents = ", ".join(SUPPORTED_AGENTS)
        raise ServiceError(
            f"agent must be one of: {allowed_agents}",
            400,
            "invalid_execution_plan",
        )
    return normalized


def parse_execution_plan(raw_plan: Any) -> list[dict[str, str]]:
    if not isinstance(raw_plan, list) or len(raw_plan) == 0:
        raise ServiceError("execution_plan must be a non-empty array", 400, "invalid_execution_plan")

    normalized_steps: list[dict[str, str]] = []
    for idx, step in enumerate(raw_plan):
        if not isinstance(step, dict):
            raise ServiceError(f"execution_plan[{idx}] must be an object", 400, "invalid_execution_plan")

        role = str(step.get("role", "")).strip()
        agent_raw = str(step.get("agent", "")).strip()
        prompt_markdown = str(step.get("prompt_markdown", "")).strip()
        if not role or not agent_raw or not prompt_markdown:
            raise ServiceError(
                f"execution_plan[{idx}] requires role, agent, and prompt_markdown",
                400,
                "invalid_execution_plan",
            )
        agent = normalize_agent(agent_raw)

        normalized_steps.append(
            {
                "role": role,
                "agent": agent,
                "prompt_markdown": prompt_markdown,
            }
        )
    return normalized_steps


def parse_policy_requirements(raw_policy: Any) -> dict[str, bool]:
    if raw_policy in (None, ""):
        return {}
    if not isinstance(raw_policy, dict):
        raise ServiceError("policy_requirements must be an object", 400, "invalid_policy_requirements")

    if "require_reviewer_step" not in raw_policy:
        return {}

    require_reviewer_step = raw_policy["require_reviewer_step"]
    if not isinstance(require_reviewer_step, bool):
        raise ServiceError(
            "policy_requirements.require_reviewer_step must be true/false",
            400,
            "invalid_policy_requirements",
        )

    return {"require_reviewer_step": require_reviewer_step}


def merge_policy_requirements(
    token_policy_floor: dict[str, bool],
    ticket_policy: dict[str, bool],
) -> dict[str, bool]:
    floor_requires_reviewer = bool(token_policy_floor.get("require_reviewer_step", False))
    ticket_has_reviewer_key = "require_reviewer_step" in ticket_policy
    ticket_requires_reviewer = bool(ticket_policy.get("require_reviewer_step", False))

    if floor_requires_reviewer and ticket_has_reviewer_key and not ticket_requires_reviewer:
        raise ServiceError(
            "Ticket policy cannot weaken submit token policy floor",
            400,
            "policy_floor_violation",
        )

    return {"require_reviewer_step": floor_requires_reviewer or ticket_requires_reviewer}


def enforce_policy_against_plan(policy_requirements: dict[str, bool], execution_plan: list[dict[str, str]]) -> None:
    if policy_requirements.get("require_reviewer_step", False):
        has_reviewer = any(step["role"].strip().lower() == "reviewer" for step in execution_plan)
        if not has_reviewer:
            raise ServiceError(
                "policy_requirements.require_reviewer_step=true requires at least one reviewer step",
                400,
                "missing_reviewer_step",
            )


class OpsGateService:
    def __init__(self, settings: OpsGateSettings) -> None:
        self.settings = settings
        self.submitters: tuple[SubmitterContext, ...] = tuple(
            SubmitterContext(
                source=policy.source,
                token=policy.token,
                require_reviewer_step_floor=policy.require_reviewer_step_floor,
            )
            for policy in settings.submitter_policies
        )

        db_parent = Path(settings.db_path).parent
        db_parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.settings.db_path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL;")
        connection.execute("PRAGMA foreign_keys=ON;")
        connection.execute("PRAGMA busy_timeout=5000;")
        try:
            yield connection
        finally:
            connection.close()

    def init_db(self) -> None:
        with self._connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS tickets (
                    id TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    task_ref TEXT,
                    title TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    execution_plan_json TEXT NOT NULL,
                    policy_requirements_json TEXT NOT NULL,
                    context_json TEXT NOT NULL,
                    payload_checksum TEXT NOT NULL,
                    approved_payload_checksum TEXT,
                    state TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    approved_by TEXT,
                    approved_at TEXT,
                    expires_at TEXT,
                    max_duration_seconds INTEGER NOT NULL,
                    tmux_sessions_json TEXT NOT NULL DEFAULT '[]',
                    runner_host TEXT,
                    last_heartbeat_at TEXT,
                    started_at TEXT,
                    finished_at TEXT,
                    result TEXT,
                    result_detail TEXT,
                    archived_at TEXT,
                    archived_by TEXT
                );

                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ticket_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT,
                    user_agent TEXT,
                    previous_state TEXT,
                    new_state TEXT,
                    metadata_json TEXT NOT NULL DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS runner_heartbeats (
                    runner_host TEXT PRIMARY KEY,
                    last_heartbeat_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_tickets_state ON tickets(state);
                CREATE INDEX IF NOT EXISTS idx_tickets_created_at ON tickets(created_at);
                CREATE INDEX IF NOT EXISTS idx_tickets_archived_at ON tickets(archived_at, created_at);

                CREATE UNIQUE INDEX IF NOT EXISTS idx_tickets_open_dedupe
                    ON tickets(source, task_ref)
                    WHERE task_ref IS NOT NULL
                      AND state IN ('pending_approval', 'approved', 'running');
                """
            )
            ticket_columns = {
                str(row["name"])
                for row in conn.execute("PRAGMA table_info(tickets)").fetchall()
            }
            if "archived_at" not in ticket_columns:
                conn.execute("ALTER TABLE tickets ADD COLUMN archived_at TEXT")
            if "archived_by" not in ticket_columns:
                conn.execute("ALTER TABLE tickets ADD COLUMN archived_by TEXT")
            conn.commit()

    def authenticate_submitter(self, token: str | None) -> SubmitterContext | None:
        if not token:
            return None
        normalized = token.strip()
        if not normalized:
            return None
        for submitter in self.submitters:
            if hmac.compare_digest(submitter.token, normalized):
                return submitter
        return None

    def is_runner_token(self, token: str | None) -> bool:
        return bool(token and hmac.compare_digest(token.strip(), self.settings.runner_token))

    def require_reviewer_step_floor_for_source(self, source: str) -> bool:
        normalized_source = source.strip().lower()
        for submitter in self.submitters:
            if submitter.source.strip().lower() == normalized_source:
                return submitter.require_reviewer_step_floor
        return False

    def _record_audit_event(
        self,
        conn: sqlite3.Connection,
        *,
        ticket_id: str,
        event_type: str,
        actor: str,
        source_ip: str | None,
        user_agent: str | None,
        previous_state: str | None,
        new_state: str | None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        conn.execute(
            """
            INSERT INTO audit_events (
                ticket_id, event_type, actor, timestamp,
                source_ip, user_agent, previous_state, new_state, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ticket_id,
                event_type,
                actor,
                isoformat_z(utc_now()),
                source_ip,
                user_agent,
                previous_state,
                new_state,
                json.dumps(metadata or {}, sort_keys=True),
            ),
        )

    def _select_ticket(self, conn: sqlite3.Connection, ticket_id: str) -> sqlite3.Row | None:
        row = conn.execute(
            "SELECT * FROM tickets WHERE id = ?",
            (ticket_id,),
        ).fetchone()
        return row

    def _serialize_ticket(self, row: sqlite3.Row) -> dict[str, Any]:
        execution_plan = json.loads(row["execution_plan_json"])
        policy_requirements = json.loads(row["policy_requirements_json"])
        context = json.loads(row["context_json"])
        tmux_sessions = json.loads(row["tmux_sessions_json"])

        return {
            "id": row["id"],
            "source": row["source"],
            "task_ref": row["task_ref"],
            "title": row["title"],
            "summary": row["summary"],
            "execution_plan": execution_plan,
            "policy_requirements": policy_requirements,
            "context": context,
            "payload_checksum": row["payload_checksum"],
            "approved_payload_checksum": row["approved_payload_checksum"],
            "state": row["state"],
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "approved_by": row["approved_by"],
            "approved_at": row["approved_at"],
            "expires_at": row["expires_at"],
            "max_duration_seconds": row["max_duration_seconds"],
            "tmux_sessions": tmux_sessions,
            "runner_host": row["runner_host"],
            "last_heartbeat_at": row["last_heartbeat_at"],
            "started_at": row["started_at"],
            "finished_at": row["finished_at"],
            "result": row["result"],
            "result_detail": row["result_detail"],
            "archived_at": row["archived_at"],
            "archived_by": row["archived_by"],
            "is_archived": bool(row["archived_at"]),
            "is_terminal": str(row["state"]) in TERMINAL_STATES,
        }

    def _ticket_payload_from_fields(
        self,
        *,
        source: str,
        task_ref: str | None,
        title: str,
        summary: str,
        execution_plan: list[dict[str, str]],
        policy_requirements: dict[str, bool],
        context: dict[str, Any],
        expires_at: str | None,
        max_duration_seconds: int,
        ) -> dict[str, Any]:
        return {
            "source": source,
            "task_ref": task_ref,
            "title": title,
            "summary": summary,
            "execution_plan": execution_plan,
            "policy_requirements": policy_requirements,
            "context": context,
            "expires_at": expires_at,
            "max_duration_seconds": max_duration_seconds,
        }

    def _normalize_new_ticket(
        self,
        payload: dict[str, Any],
        *,
        source: str,
        require_reviewer_step_floor: bool,
    ) -> dict[str, Any]:
        raw_source = str(payload.get("source", source)).strip()
        if raw_source != source:
            raise ServiceError(
                "Ticket source must match the authenticated creation path",
                403,
                "source_mismatch",
            )

        title = str(payload.get("title", "")).strip()
        summary = str(payload.get("summary", "")).strip()
        if not title or not summary:
            raise ServiceError("title and summary are required", 400, "invalid_ticket")

        task_ref_raw = payload.get("task_ref")
        task_ref = None
        if task_ref_raw is not None:
            task_ref_value = str(task_ref_raw).strip()
            task_ref = task_ref_value if task_ref_value else None

        execution_plan = parse_execution_plan(payload.get("execution_plan"))
        ticket_policy = parse_policy_requirements(payload.get("policy_requirements"))
        token_floor = {"require_reviewer_step": require_reviewer_step_floor}
        effective_policy = merge_policy_requirements(token_floor, ticket_policy)
        enforce_policy_against_plan(effective_policy, execution_plan)

        context = payload.get("context", {})
        if context is None:
            context = {}
        if not isinstance(context, dict):
            raise ServiceError("context must be an object", 400, "invalid_ticket")

        expires_at_raw = payload.get("expires_at")
        expires_at: str | None = None
        if expires_at_raw is not None:
            try:
                expires_at = isoformat_z(parse_iso_datetime(str(expires_at_raw)))
            except ValueError as exc:
                raise ServiceError(str(exc), 400, "invalid_expires_at") from exc

        max_duration_seconds_raw = payload.get("max_duration_seconds")
        if max_duration_seconds_raw is None:
            max_duration_seconds = self.settings.max_duration_seconds_default
        else:
            try:
                max_duration_seconds = int(max_duration_seconds_raw)
            except (TypeError, ValueError) as exc:
                raise ServiceError("max_duration_seconds must be an integer", 400, "invalid_ticket") from exc

        if max_duration_seconds <= 0:
            raise ServiceError("max_duration_seconds must be > 0", 400, "invalid_ticket")

        payload_for_checksum = self._ticket_payload_from_fields(
            source=raw_source,
            task_ref=task_ref,
            title=title,
            summary=summary,
            execution_plan=execution_plan,
            policy_requirements=effective_policy,
            context=context,
            expires_at=expires_at,
            max_duration_seconds=max_duration_seconds,
        )

        return {
            "source": raw_source,
            "task_ref": task_ref,
            "title": title,
            "summary": summary,
            "execution_plan": execution_plan,
            "policy_requirements": effective_policy,
            "context": context,
            "expires_at": expires_at,
            "max_duration_seconds": max_duration_seconds,
            "payload_checksum": compute_payload_checksum(payload_for_checksum),
        }

    def _insert_ticket(
        self,
        normalized_ticket: dict[str, Any],
        *,
        created_by: str,
        actor: str,
        source_ip: str | None,
        user_agent: str | None,
    ) -> dict[str, Any]:
        ticket_id = str(uuid4())
        created_at = isoformat_z(utc_now())

        with self._connection() as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO tickets (
                        id, source, task_ref, title, summary,
                        execution_plan_json, policy_requirements_json, context_json,
                        payload_checksum, approved_payload_checksum,
                        state, created_by, created_at,
                        expires_at, max_duration_seconds
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, 'pending_approval', ?, ?, ?, ?)
                    """,
                    (
                        ticket_id,
                        normalized_ticket["source"],
                        normalized_ticket["task_ref"],
                        normalized_ticket["title"],
                        normalized_ticket["summary"],
                        json.dumps(normalized_ticket["execution_plan"], sort_keys=True),
                        json.dumps(normalized_ticket["policy_requirements"], sort_keys=True),
                        json.dumps(normalized_ticket["context"], sort_keys=True),
                        normalized_ticket["payload_checksum"],
                        created_by,
                        created_at,
                        normalized_ticket["expires_at"],
                        normalized_ticket["max_duration_seconds"],
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ServiceError(
                    "Duplicate open ticket for source/task_ref",
                    409,
                    "duplicate_open_ticket",
                ) from exc

            self._record_audit_event(
                conn,
                ticket_id=ticket_id,
                event_type="ticket_created",
                actor=actor,
                source_ip=source_ip,
                user_agent=user_agent,
                previous_state=None,
                new_state="pending_approval",
                metadata={"task_ref": normalized_ticket["task_ref"]},
            )
            conn.commit()

            row = self._select_ticket(conn, ticket_id)
            if row is None:
                raise ServiceError("Ticket creation failed", 500, "db_error")
            return self._serialize_ticket(row)

    def _maybe_expire_ticket(
        self,
        conn: sqlite3.Connection,
        *,
        row: sqlite3.Row,
        actor: str,
        source_ip: str | None,
        user_agent: str | None,
    ) -> bool:
        expires_raw = row["expires_at"]
        if not expires_raw:
            return False

        expires_at = optional_iso_datetime(expires_raw)
        if expires_at is None:
            return False

        if expires_at > utc_now():
            return False

        if row["state"] == "expired":
            return True

        if row["state"] not in OPEN_TICKET_STATES:
            return False

        conn.execute(
            """
            UPDATE tickets
            SET state = 'expired',
                finished_at = ?,
                result = 'failure',
                result_detail = 'expired_before_execution'
            WHERE id = ?
            """,
            (isoformat_z(utc_now()), row["id"]),
        )
        self._record_audit_event(
            conn,
            ticket_id=row["id"],
            event_type="ticket_expired",
            actor=actor,
            source_ip=source_ip,
            user_agent=user_agent,
            previous_state=row["state"],
            new_state="expired",
            metadata={"expires_at": expires_raw},
        )
        return True

    def create_ticket(
        self,
        payload: dict[str, Any],
        submitter: SubmitterContext,
        source_ip: str | None,
        user_agent: str | None,
    ) -> dict[str, Any]:
        normalized_ticket = self._normalize_new_ticket(
            payload,
            source=submitter.source,
            require_reviewer_step_floor=submitter.require_reviewer_step_floor,
        )
        return self._insert_ticket(
            normalized_ticket,
            created_by=f"submit:{submitter.source}",
            actor=f"submit:{submitter.source}",
            source_ip=source_ip,
            user_agent=user_agent,
        )

    def create_manual_ticket(
        self,
        payload: dict[str, Any],
        *,
        creator: str,
        source_ip: str | None,
        user_agent: str | None,
    ) -> dict[str, Any]:
        normalized_ticket = self._normalize_new_ticket(
            payload,
            source="operator",
            require_reviewer_step_floor=self.require_reviewer_step_floor_for_source("operator"),
        )
        return self._insert_ticket(
            normalized_ticket,
            created_by=f"approver:{creator}",
            actor=f"approver:{creator}",
            source_ip=source_ip,
            user_agent=user_agent,
        )

    def list_tickets(
        self,
        limit: int = 100,
        *,
        archived: str = LIST_ARCHIVED_EXCLUDE,
    ) -> list[dict[str, Any]]:
        if archived == LIST_ARCHIVED_EXCLUDE:
            where_clause = "WHERE archived_at IS NULL"
        elif archived == LIST_ARCHIVED_ONLY:
            where_clause = "WHERE archived_at IS NOT NULL"
        elif archived == LIST_ARCHIVED_INCLUDE:
            where_clause = ""
        else:
            raise ServiceError("Invalid archived ticket filter", 400, "invalid_ticket_filter")

        with self._connection() as conn:
            rows = conn.execute(
                f"SELECT * FROM tickets {where_clause} ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [self._serialize_ticket(row) for row in rows]

    def get_ticket(self, ticket_id: str) -> dict[str, Any]:
        with self._connection() as conn:
            row = self._select_ticket(conn, ticket_id)
            if row is None:
                raise ServiceError("Ticket not found", 404, "ticket_not_found")
            return self._serialize_ticket(row)

    def approve_ticket(
        self,
        ticket_id: str,
        *,
        approver: str,
        source_ip: str | None,
        user_agent: str | None,
    ) -> dict[str, Any]:
        with self._connection() as conn:
            row = self._select_ticket(conn, ticket_id)
            if row is None:
                raise ServiceError("Ticket not found", 404, "ticket_not_found")
            if row["state"] != "pending_approval":
                raise ServiceError("Ticket is not pending approval", 409, "invalid_state")

            if self._maybe_expire_ticket(
                conn,
                row=row,
                actor=f"approver:{approver}",
                source_ip=source_ip,
                user_agent=user_agent,
            ):
                conn.commit()
                raise ServiceError("Ticket expired and cannot be approved", 409, "ticket_expired")

            execution_plan = parse_execution_plan(json.loads(row["execution_plan_json"]))
            policy_requirements = json.loads(row["policy_requirements_json"])
            enforce_policy_against_plan(policy_requirements, execution_plan)

            payload_for_checksum = self._ticket_payload_from_fields(
                source=row["source"],
                task_ref=row["task_ref"],
                title=row["title"],
                summary=row["summary"],
                execution_plan=execution_plan,
                policy_requirements=policy_requirements,
                context=json.loads(row["context_json"]),
                expires_at=row["expires_at"],
                max_duration_seconds=int(row["max_duration_seconds"]),
            )
            approved_checksum = compute_payload_checksum(payload_for_checksum)

            approved_at = isoformat_z(utc_now())
            conn.execute(
                """
                UPDATE tickets
                SET state = 'approved',
                    approved_by = ?,
                    approved_at = ?,
                    approved_payload_checksum = ?
                WHERE id = ?
                """,
                (approver, approved_at, approved_checksum, ticket_id),
            )

            self._record_audit_event(
                conn,
                ticket_id=ticket_id,
                event_type="ticket_approved",
                actor=f"approver:{approver}",
                source_ip=source_ip,
                user_agent=user_agent,
                previous_state="pending_approval",
                new_state="approved",
                metadata={"approved_payload_checksum": approved_checksum},
            )
            conn.commit()

            updated = self._select_ticket(conn, ticket_id)
            if updated is None:
                raise ServiceError("Ticket not found after approval", 500, "db_error")
            return self._serialize_ticket(updated)

    def reject_ticket(
        self,
        ticket_id: str,
        *,
        approver: str,
        reason: str,
        source_ip: str | None,
        user_agent: str | None,
    ) -> dict[str, Any]:
        with self._connection() as conn:
            row = self._select_ticket(conn, ticket_id)
            if row is None:
                raise ServiceError("Ticket not found", 404, "ticket_not_found")
            if row["state"] != "pending_approval":
                raise ServiceError("Ticket cannot be rejected in current state", 409, "invalid_state")

            conn.execute(
                """
                UPDATE tickets
                SET state = 'rejected',
                    finished_at = ?,
                    result = 'failure',
                    result_detail = ?
                WHERE id = ?
                """,
                (isoformat_z(utc_now()), reason or "rejected_by_approver", ticket_id),
            )
            self._record_audit_event(
                conn,
                ticket_id=ticket_id,
                event_type="ticket_rejected",
                actor=f"approver:{approver}",
                source_ip=source_ip,
                user_agent=user_agent,
                previous_state="pending_approval",
                new_state="rejected",
                metadata={"reason": reason},
            )
            conn.commit()

            updated = self._select_ticket(conn, ticket_id)
            if updated is None:
                raise ServiceError("Ticket not found after rejection", 500, "db_error")
            return self._serialize_ticket(updated)

    def cancel_ticket(
        self,
        ticket_id: str,
        *,
        approver: str,
        reason: str,
        source_ip: str | None,
        user_agent: str | None,
    ) -> dict[str, Any]:
        with self._connection() as conn:
            row = self._select_ticket(conn, ticket_id)
            if row is None:
                raise ServiceError("Ticket not found", 404, "ticket_not_found")
            if row["state"] not in {"pending_approval", "approved", "running"}:
                raise ServiceError("Ticket cannot be canceled in current state", 409, "invalid_state")

            conn.execute(
                """
                UPDATE tickets
                SET state = 'canceled',
                    finished_at = ?,
                    result = 'canceled',
                    result_detail = ?
                WHERE id = ?
                """,
                (isoformat_z(utc_now()), reason or "canceled_by_approver", ticket_id),
            )
            self._record_audit_event(
                conn,
                ticket_id=ticket_id,
                event_type="ticket_canceled",
                actor=f"approver:{approver}",
                source_ip=source_ip,
                user_agent=user_agent,
                previous_state=row["state"],
                new_state="canceled",
                metadata={"reason": reason},
            )
            conn.commit()

            updated = self._select_ticket(conn, ticket_id)
            if updated is None:
                raise ServiceError("Ticket not found after cancel", 500, "db_error")
            return self._serialize_ticket(updated)

    def archive_ticket(
        self,
        ticket_id: str,
        *,
        approver: str,
        source_ip: str | None,
        user_agent: str | None,
    ) -> dict[str, Any]:
        with self._connection() as conn:
            row = self._select_ticket(conn, ticket_id)
            if row is None:
                raise ServiceError("Ticket not found", 404, "ticket_not_found")
            if row["state"] not in TERMINAL_STATES:
                raise ServiceError("Only terminal tickets can be archived", 409, "invalid_state")
            if row["archived_at"]:
                raise ServiceError("Ticket is already archived", 409, "already_archived")

            archived_at = isoformat_z(utc_now())
            conn.execute(
                """
                UPDATE tickets
                SET archived_at = ?,
                    archived_by = ?
                WHERE id = ?
                """,
                (archived_at, approver, ticket_id),
            )
            self._record_audit_event(
                conn,
                ticket_id=ticket_id,
                event_type="ticket_archived",
                actor=f"approver:{approver}",
                source_ip=source_ip,
                user_agent=user_agent,
                previous_state=row["state"],
                new_state=row["state"],
                metadata={"archived_at": archived_at},
            )
            conn.commit()

            updated = self._select_ticket(conn, ticket_id)
            if updated is None:
                raise ServiceError("Ticket not found after archive", 500, "db_error")
            return self._serialize_ticket(updated)

    def unarchive_ticket(
        self,
        ticket_id: str,
        *,
        approver: str,
        source_ip: str | None,
        user_agent: str | None,
    ) -> dict[str, Any]:
        with self._connection() as conn:
            row = self._select_ticket(conn, ticket_id)
            if row is None:
                raise ServiceError("Ticket not found", 404, "ticket_not_found")
            if not row["archived_at"]:
                raise ServiceError("Ticket is not archived", 409, "not_archived")

            previous_archived_at = str(row["archived_at"])
            previous_archived_by = row["archived_by"]
            conn.execute(
                """
                UPDATE tickets
                SET archived_at = NULL,
                    archived_by = NULL
                WHERE id = ?
                """,
                (ticket_id,),
            )
            self._record_audit_event(
                conn,
                ticket_id=ticket_id,
                event_type="ticket_unarchived",
                actor=f"approver:{approver}",
                source_ip=source_ip,
                user_agent=user_agent,
                previous_state=row["state"],
                new_state=row["state"],
                metadata={
                    "previous_archived_at": previous_archived_at,
                    "previous_archived_by": previous_archived_by,
                },
            )
            conn.commit()

            updated = self._select_ticket(conn, ticket_id)
            if updated is None:
                raise ServiceError("Ticket not found after unarchive", 500, "db_error")
            return self._serialize_ticket(updated)

    def claim_ticket(
        self,
        *,
        runner_host: str,
        source_ip: str | None,
        user_agent: str | None,
    ) -> dict[str, Any] | None:
        if Path(self.settings.disable_file_path).exists():
            return None

        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                while True:
                    row = conn.execute(
                        """
                        SELECT * FROM tickets
                        WHERE state = 'approved'
                        ORDER BY approved_at ASC, created_at ASC
                        LIMIT 1
                        """
                    ).fetchone()

                    if row is None:
                        conn.commit()
                        return None

                    if self._maybe_expire_ticket(
                        conn,
                        row=row,
                        actor=f"runner:{runner_host}",
                        source_ip=source_ip,
                        user_agent=user_agent,
                    ):
                        continue

                    try:
                        execution_plan = parse_execution_plan(json.loads(row["execution_plan_json"]))
                        policy_requirements = json.loads(row["policy_requirements_json"])
                        enforce_policy_against_plan(policy_requirements, execution_plan)
                    except ServiceError as error:
                        conn.execute(
                            """
                            UPDATE tickets
                            SET state = 'failed',
                                finished_at = ?,
                                result = 'failure',
                                result_detail = 'invalid_stored_plan'
                            WHERE id = ?
                            """,
                            (isoformat_z(utc_now()), row["id"]),
                        )
                        self._record_audit_event(
                            conn,
                            ticket_id=row["id"],
                            event_type="ticket_failed",
                            actor=f"runner:{runner_host}",
                            source_ip=source_ip,
                            user_agent=user_agent,
                            previous_state="approved",
                            new_state="failed",
                            metadata={"reason": "invalid_stored_plan", "error": error.error_code},
                        )
                        continue

                    payload_for_checksum = self._ticket_payload_from_fields(
                        source=row["source"],
                        task_ref=row["task_ref"],
                        title=row["title"],
                        summary=row["summary"],
                        execution_plan=execution_plan,
                        policy_requirements=policy_requirements,
                        context=json.loads(row["context_json"]),
                        expires_at=row["expires_at"],
                        max_duration_seconds=int(row["max_duration_seconds"]),
                    )
                    current_checksum = compute_payload_checksum(payload_for_checksum)
                    approved_checksum = row["approved_payload_checksum"]
                    if not approved_checksum or approved_checksum != current_checksum:
                        conn.execute(
                            """
                            UPDATE tickets
                            SET state = 'failed',
                                finished_at = ?,
                                result = 'failure',
                                result_detail = 'prompt_tampered'
                            WHERE id = ?
                            """,
                            (isoformat_z(utc_now()), row["id"]),
                        )
                        self._record_audit_event(
                            conn,
                            ticket_id=row["id"],
                            event_type="ticket_failed",
                            actor=f"runner:{runner_host}",
                            source_ip=source_ip,
                            user_agent=user_agent,
                            previous_state="approved",
                            new_state="failed",
                            metadata={"reason": "prompt_tampered"},
                        )
                        continue

                    started_at = isoformat_z(utc_now())
                    cursor = conn.execute(
                        """
                        UPDATE tickets
                        SET state = 'running',
                            runner_host = ?,
                            started_at = COALESCE(started_at, ?),
                            last_heartbeat_at = ?
                        WHERE id = ? AND state = 'approved'
                        """,
                        (runner_host, started_at, started_at, row["id"]),
                    )
                    if cursor.rowcount == 0:
                        continue

                    self._record_audit_event(
                        conn,
                        ticket_id=row["id"],
                        event_type="runner_claimed",
                        actor=f"runner:{runner_host}",
                        source_ip=source_ip,
                        user_agent=user_agent,
                        previous_state="approved",
                        new_state="running",
                        metadata={"runner_host": runner_host},
                    )
                    self._update_runner_heartbeat(conn, runner_host=runner_host)
                    conn.commit()

                    updated = self._select_ticket(conn, row["id"])
                    if updated is None:
                        raise ServiceError("Ticket disappeared after claim", 500, "db_error")
                    return self._serialize_ticket(updated)
            except Exception:
                conn.rollback()
                raise

    def _update_runner_heartbeat(self, conn: sqlite3.Connection, runner_host: str) -> None:
        now = isoformat_z(utc_now())
        conn.execute(
            """
            INSERT INTO runner_heartbeats (runner_host, last_heartbeat_at, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(runner_host)
            DO UPDATE SET last_heartbeat_at=excluded.last_heartbeat_at, updated_at=excluded.updated_at
            """,
            (runner_host, now, now),
        )

    def update_runner_status(
        self,
        ticket_id: str,
        *,
        runner_host: str,
        payload: dict[str, Any],
        source_ip: str | None,
        user_agent: str | None,
    ) -> dict[str, Any]:
        event_type = str(payload.get("event", "heartbeat")).strip().lower() or "heartbeat"
        if event_type not in RUNNER_EVENT_TYPES:
            raise ServiceError("Invalid runner event", 400, "invalid_runner_event")
        new_state_raw = payload.get("state")
        new_result_raw = payload.get("result")
        result_detail = str(payload.get("result_detail", "")).strip()
        tmux_sessions_raw = payload.get("tmux_sessions")

        with self._connection() as conn:
            row = self._select_ticket(conn, ticket_id)
            if row is None:
                raise ServiceError("Ticket not found", 404, "ticket_not_found")

            previous_state = row["state"]
            if previous_state in TERMINAL_STATES:
                raise ServiceError("Ticket is in terminal state", 409, "invalid_state")
            if previous_state not in {"approved", "running"}:
                raise ServiceError("Ticket cannot receive runner status in current state", 409, "invalid_state")
            if new_state_raw is None and previous_state != "running":
                raise ServiceError("Heartbeat requires running state", 409, "invalid_state")
            if previous_state == "running":
                assigned_runner_host = str(row["runner_host"] or "").strip()
                if assigned_runner_host and assigned_runner_host != runner_host:
                    raise ServiceError("Runner host does not own this running ticket", 409, "runner_host_mismatch")

            now = isoformat_z(utc_now())

            update_fields: list[str] = ["runner_host = ?", "last_heartbeat_at = ?"]
            update_values: list[Any] = [runner_host, now]
            next_state = previous_state

            result_value: str | None = None
            if new_state_raw is not None:
                requested_state = str(new_state_raw).strip().lower()
                if requested_state not in {"running", "succeeded", "failed", "canceled"}:
                    raise ServiceError("Invalid runner state", 400, "invalid_runner_state")
                if requested_state in TERMINAL_STATES and previous_state != "running":
                    raise ServiceError("Terminal runner update requires running state", 409, "invalid_state")
                if previous_state == "running" and requested_state in TERMINAL_STATES:
                    update_fields.append("finished_at = ?")
                    update_values.append(now)
                next_state = requested_state
                update_fields.append("state = ?")
                update_values.append(requested_state)

                if requested_state == "succeeded":
                    result_value = "success"
                elif requested_state == "failed":
                    result_value = "failure"
                elif requested_state == "canceled":
                    result_value = "canceled"

            if new_result_raw is not None:
                requested_result = str(new_result_raw).strip().lower()
                if requested_result not in {"success", "failure", "timeout", "canceled"}:
                    raise ServiceError("Invalid runner result", 400, "invalid_runner_result")
                result_value = requested_result

            if result_value is not None:
                update_fields.append("result = ?")
                update_values.append(result_value)

            if result_detail:
                update_fields.append("result_detail = ?")
                update_values.append(result_detail)

            if tmux_sessions_raw is not None:
                if not isinstance(tmux_sessions_raw, list):
                    raise ServiceError("tmux_sessions must be an array", 400, "invalid_tmux_sessions")
                update_fields.append("tmux_sessions_json = ?")
                update_values.append(json.dumps(tmux_sessions_raw, sort_keys=True))

            update_values.append(ticket_id)
            conn.execute(
                f"UPDATE tickets SET {', '.join(update_fields)} WHERE id = ?",
                tuple(update_values),
            )
            self._update_runner_heartbeat(conn, runner_host=runner_host)

            self._record_audit_event(
                conn,
                ticket_id=ticket_id,
                event_type=f"runner_{event_type}",
                actor=f"runner:{runner_host}",
                source_ip=source_ip,
                user_agent=user_agent,
                previous_state=previous_state,
                new_state=next_state,
                metadata={
                    "event": event_type,
                    "result_detail": result_detail,
                },
            )
            conn.commit()

            updated = self._select_ticket(conn, ticket_id)
            if updated is None:
                raise ServiceError("Ticket not found after runner update", 500, "db_error")
            return self._serialize_ticket(updated)

    def health(self) -> dict[str, Any]:
        with self._connection() as conn:
            counters = conn.execute(
                "SELECT state, COUNT(*) AS count FROM tickets GROUP BY state"
            ).fetchall()
            ticket_counters = {row["state"]: int(row["count"]) for row in counters}

            runner = conn.execute(
                "SELECT runner_host, last_heartbeat_at FROM runner_heartbeats ORDER BY last_heartbeat_at DESC LIMIT 1"
            ).fetchone()

            return {
                "status": "ok",
                "service": self.settings.service_name,
                "db": "ok",
                "runner_last_heartbeat": runner["last_heartbeat_at"] if runner else None,
                "runner_host": runner["runner_host"] if runner else None,
                "ticket_counters": ticket_counters,
            }


def submitter_context_from_policy(policy: SubmitterPolicy) -> SubmitterContext:
    return SubmitterContext(
        source=policy.source,
        token=policy.token,
        require_reviewer_step_floor=policy.require_reviewer_step_floor,
    )
