from __future__ import annotations

import hmac
import json
import re
import secrets
from collections.abc import Callable
from datetime import timedelta
from functools import wraps
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any, ParamSpec, TypeVar, cast
from urllib.parse import urlsplit

import bcrypt
from flask import (
    Flask,
    Response,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask.typing import ResponseReturnValue
from werkzeug.middleware.proxy_fix import ProxyFix

from .config import OpsGateSettings, load_settings
from .service import (
    LIST_ARCHIVED_EXCLUDE,
    LIST_ARCHIVED_INCLUDE,
    LIST_ARCHIVED_ONLY,
    SUPPORTED_AGENTS,
    OpsGateService,
    ServiceError,
    isoformat_z,
    parse_iso_datetime,
    utc_now,
)

P = ParamSpec("P")
R = TypeVar("R")


class AccessDenied(ServiceError):
    pass


MANUAL_STEP_FIELD_PATTERN = re.compile(r"^steps-(\d+)-(role|agent|prompt_markdown)$")
TICKET_ACTION_PATH_PATTERN = re.compile(r"^/tickets/([^/]+)/(approve|reject|cancel|archive|unarchive)$")
TICKET_LOG_PATH_PATTERN = re.compile(r"^/tickets/([^/]+)/steps/\d+/log$")
TICKET_LIST_VIEW_OPTIONS = {"active", "archived", "all"}
DEFAULT_AGENT_BY_ROLE = {
    "implementer": "codex",
    "implementor": "codex",
    "reviewer": "claude",
    "investigator": "codex",
}
ROLE_PROMPT_SCAFFOLDING: dict[str, dict[str, object]] = {
    "investigator": {
        "title": "Inspect-only investigation",
        "summary": (
            "Use this role to inspect state, collect evidence, identify the owning "
            "repo/workspace, and explain next steps."
        ),
        "dos": [
            "Read code, config, logs, tickets, and deployment state.",
            "Explain findings and likely root cause in concrete terms.",
            "Point to the source repo/workspace that should own the fix.",
        ],
        "donts": [
            "Do not edit source files or commit changes.",
            "Do not deploy, restart services, or patch files on live hosts.",
            "Do not perform ad hoc remediation while acting as investigator.",
        ],
        "placeholder": (
            "Inspect current state only. Gather evidence, identify the owning "
            "repo/workspace, and propose next steps without making changes."
        ),
        "suggested_prompt": (
            "Inspect the current state only. Do not edit source files, commit changes, deploy code, restart services, "
            "or patch files on the live host.\n\n"
            "Gather the relevant logs, config, code, and deployment context. Identify the owning repo or workspace, "
            "explain the likely root cause, and end with concrete recommended next steps."
        ),
    },
    "implementer": {
        "title": "Repo-first implementation",
        "summary": (
            "Use this role to make the intended change in the source of truth, "
            "validate it, and prepare it for deploy."
        ),
        "dos": [
            "Change the correct repo or workspace, not the live host directly.",
            "Run the relevant validation commands before calling the work ready.",
            "Commit, deploy, and verify only after the reviewer loop is complete.",
        ],
        "donts": [
            "Do not patch production files ad hoc as the primary fix path.",
            "Do not skip validation or omit deploy verification.",
            "Do not treat the reviewer step as optional when policy requires it.",
        ],
        "placeholder": (
            "Implement the change in the correct repo/workspace, run validation, "
            "and prepare a clear deploy and verification path."
        ),
        "suggested_prompt": (
            "Make the intended change in the correct repo or workspace, not by "
            "patching files directly on the live host.\n\n"
            "Describe the files you changed, run the relevant validation commands, "
            "summarize the results, and prepare the change for reviewer feedback. "
            "Once the reviewer loop is complete, commit, deploy through the normal "
            "workflow, and verify the live result."
        ),
    },
    "reviewer": {
        "title": "Independent review gate",
        "summary": (
            "Use this role to inspect the proposed change, validation evidence, "
            "and rollout plan before implementation is considered ready."
        ),
        "dos": [
            "Review diffs, prompts, logs, validation output, and deploy steps.",
            "Call out risks, missing tests, or unclear assumptions.",
            "State clearly whether the implementer loop is ready to proceed.",
        ],
        "donts": [
            "Do not make independent implementation changes in the reviewer step.",
            "Do not commit or deploy while acting as reviewer.",
            "Do not approve vague prompts that lack validation or rollout detail.",
        ],
        "placeholder": (
            "Review the proposed change, validation evidence, and deploy plan. "
            "Call out risks and state whether it is ready."
        ),
        "suggested_prompt": (
            "Review the proposed change, validation evidence, and deployment plan.\n\n"
            "Do not make additional implementation changes, commit code, or deploy while acting as reviewer. "
            "Call out concrete risks, missing validation, or unclear assumptions, and state whether the implementer "
            "loop is ready to proceed."
        ),
    },
}
ROLE_PROMPT_SCAFFOLDING["implementor"] = ROLE_PROMPT_SCAFFOLDING["implementer"]
LOG_PREVIEW_LINE_LIMIT = 40


def create_app(settings: OpsGateSettings | None = None) -> Flask:
    resolved_settings = settings or load_settings()
    app = Flask(__name__, template_folder="templates")
    if resolved_settings.trust_proxy_headers:
        cast(Any, app).wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    app.config["SECRET_KEY"] = resolved_settings.session_secret
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = resolved_settings.session_cookie_secure

    service = OpsGateService(resolved_settings)
    allowed_networks = tuple(ip_network(cidr, strict=False) for cidr in resolved_settings.allowed_cidrs)

    def get_client_ip() -> str:
        return request.remote_addr or ""

    def is_allowed_network() -> bool:
        client_ip = get_client_ip()
        if not client_ip:
            return False
        ip_value = ip_address(client_ip.split("%", 1)[0])
        return any(ip_value in network for network in allowed_networks)

    def get_bearer_token() -> str | None:
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return None
        return auth_header.replace("Bearer ", "", 1).strip() or None

    def get_session_user() -> str | None:
        username = session.get("username")
        if not isinstance(username, str) or username != resolved_settings.ui_username:
            return None

        auth_at_raw = session.get("auth_at")
        if not isinstance(auth_at_raw, str):
            session.clear()
            return None

        try:
            auth_at = parse_iso_datetime(auth_at_raw)
        except ValueError:
            session.clear()
            return None

        if utc_now() - auth_at > timedelta(seconds=resolved_settings.session_timeout_seconds):
            session.clear()
            return None
        return username

    def api_error(error: ServiceError) -> ResponseReturnValue:
        return jsonify({"error": error.error_code, "message": str(error)}), error.status_code

    def sanitize_next_path(raw_next: str | None) -> str | None:
        if raw_next is None:
            return None
        next_path = raw_next.strip()
        if not next_path:
            return None
        parsed = urlsplit(next_path)
        if parsed.scheme or parsed.netloc:
            return None
        if not next_path.startswith("/") or next_path.startswith("//"):
            return None
        if any(c in next_path for c in "\r\n\t\x00"):
            return None
        return next_path

    def ticket_detail_redirect_path_for_request() -> str | None:
        match = TICKET_ACTION_PATH_PATTERN.match(request.path)
        if match is not None:
            return url_for("ui_ticket_detail", ticket_id=match.group(1))
        log_match = TICKET_LOG_PATH_PATTERN.match(request.path)
        if log_match is not None:
            return url_for("ui_ticket_detail", ticket_id=log_match.group(1))
        return None

    def ensure_csrf_token() -> str:
        token = session.get("csrf_token")
        if isinstance(token, str) and token:
            return token
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
        return token

    def default_agent_for_role(role: str) -> str:
        normalized_role = role.strip().lower()
        return DEFAULT_AGENT_BY_ROLE.get(normalized_role, "codex")

    def prompt_scaffolding_for_role(role: str) -> dict[str, object]:
        normalized_role = role.strip().lower()
        return ROLE_PROMPT_SCAFFOLDING.get(normalized_role, ROLE_PROMPT_SCAFFOLDING["investigator"])

    def default_manual_step(*, operator_requires_reviewer: bool) -> dict[str, str]:
        role = "reviewer" if operator_requires_reviewer else "investigator"
        return {
            "role": role,
            "agent": default_agent_for_role(role),
            "prompt_markdown": "",
        }

    def parse_manual_ticket_steps(*, operator_requires_reviewer: bool) -> list[dict[str, str]]:
        indexed_steps: dict[int, dict[str, str]] = {}
        for key in request.form.keys():
            match = MANUAL_STEP_FIELD_PATTERN.match(key)
            if match is None:
                continue
            step_index = int(match.group(1))
            field_name = match.group(2)
            indexed_steps.setdefault(step_index, {})[field_name] = request.form.get(key, "").strip()

        if indexed_steps:
            return [
                {
                    "role": indexed_steps[index].get("role", ""),
                    "agent": indexed_steps[index].get("agent", "")
                    or default_agent_for_role(indexed_steps[index].get("role", "")),
                    "prompt_markdown": indexed_steps[index].get("prompt_markdown", ""),
                }
                for index in sorted(indexed_steps)
            ]

        if any(key in request.form for key in ("step_role", "step_agent", "prompt_markdown")):
            default_step = default_manual_step(operator_requires_reviewer=operator_requires_reviewer)
            return [
                {
                    "role": request.form.get("step_role", default_step["role"]).strip() or default_step["role"],
                    "agent": request.form.get("step_agent", "").strip()
                    or default_agent_for_role(request.form.get("step_role", default_step["role"]).strip()),
                    "prompt_markdown": request.form.get("prompt_markdown", "").strip(),
                }
            ]

        return []

    def build_manual_ticket_payload() -> dict[str, object]:
        operator_requires_reviewer = service.require_reviewer_step_floor_for_source("operator")
        title = request.form.get("title", "").strip()
        summary = request.form.get("summary", "").strip()
        task_ref = request.form.get("task_ref", "").strip()
        expires_at = request.form.get("expires_at", "").strip()
        max_duration_raw = request.form.get("max_duration_seconds", "").strip()
        context_raw = request.form.get("context_json", "").strip()

        payload: dict[str, object] = {
            "title": title,
            "summary": summary,
            "execution_plan": parse_manual_ticket_steps(operator_requires_reviewer=operator_requires_reviewer),
        }

        if task_ref:
            payload["task_ref"] = task_ref
        if expires_at:
            payload["expires_at"] = expires_at
        if max_duration_raw:
            payload["max_duration_seconds"] = max_duration_raw
        if context_raw:
            try:
                context = json.loads(context_raw)
            except json.JSONDecodeError as exc:
                raise ServiceError(f"context_json must be valid JSON: {exc.msg}", 400, "invalid_context_json") from exc
            if not isinstance(context, dict):
                raise ServiceError("context_json must decode to an object", 400, "invalid_context_json")
            payload["context"] = context

        return payload

    def build_manual_ticket_form_data(*, operator_requires_reviewer: bool) -> dict[str, object]:
        steps = parse_manual_ticket_steps(operator_requires_reviewer=operator_requires_reviewer)
        if not steps and not request.form:
            steps = [default_manual_step(operator_requires_reviewer=operator_requires_reviewer)]

        return {
            "title": request.form.get("title", "").strip(),
            "summary": request.form.get("summary", "").strip(),
            "task_ref": request.form.get("task_ref", "").strip(),
            "max_duration_seconds": request.form.get("max_duration_seconds", "3600").strip() or "3600",
            "expires_at": request.form.get("expires_at", "").strip(),
            "context_json": request.form.get("context_json", "").strip(),
            "steps": steps,
        }

    def render_tickets_page(
        *,
        status_code: int = 200,
        form_data: dict[str, object] | None = None,
    ) -> ResponseReturnValue:
        ticket_view = str(request.args.get("view", "active")).strip().lower()
        if ticket_view not in TICKET_LIST_VIEW_OPTIONS:
            ticket_view = "active"

        archived_filter = LIST_ARCHIVED_EXCLUDE
        if ticket_view == "archived":
            archived_filter = LIST_ARCHIVED_ONLY
        elif ticket_view == "all":
            archived_filter = LIST_ARCHIVED_INCLUDE

        operator_requires_reviewer = service.require_reviewer_step_floor_for_source("operator")
        if form_data is None:
            form_data = build_manual_ticket_form_data(operator_requires_reviewer=operator_requires_reviewer)
        tickets = service.list_tickets(limit=100, archived=archived_filter)
        return Response(
            render_template(
                "tickets.html",
                tickets=tickets,
                ticket_view=ticket_view,
                form_data=form_data,
                operator_requires_reviewer=operator_requires_reviewer,
                role_agent_defaults=DEFAULT_AGENT_BY_ROLE,
                role_prompt_scaffolding=ROLE_PROMPT_SCAFFOLDING,
                supported_agents=SUPPORTED_AGENTS,
                prompt_scaffolding_for_role=prompt_scaffolding_for_role,
            ),
            status_code,
        )

    def require_approver_session(view: Callable[P, R]) -> Callable[P, R]:
        @wraps(view)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            user = get_session_user()
            if user is None:
                raise ServiceError("Authentication required", 401, "auth_required")
            request.environ["opsgate.approver"] = user
            return view(*args, **kwargs)

        return cast(Callable[P, R], wrapper)

    def require_runner_token(view: Callable[P, R]) -> Callable[P, R]:
        @wraps(view)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            token = get_bearer_token()
            if not service.is_runner_token(token):
                raise ServiceError("Runner token required", 401, "invalid_runner_token")
            return view(*args, **kwargs)

        return cast(Callable[P, R], wrapper)

    @app.before_request
    def enforce_tailscale_context() -> None:
        if request.path == "/api/v1/health":
            return
        if resolved_settings.require_tailscale_context and not is_allowed_network():
            abort(403)

    @app.before_request
    def enforce_ui_csrf() -> None:
        if request.method != "POST" or request.path.startswith("/api/"):
            return
        session_token = ensure_csrf_token()
        form_token = request.form.get("csrf_token", "")
        if not isinstance(form_token, str) or not hmac.compare_digest(session_token, form_token):
            raise ServiceError("Invalid form token", 400, "invalid_csrf")

    @app.context_processor
    def inject_template_globals() -> dict[str, str]:
        return {"csrf_token": ensure_csrf_token()}

    @app.template_filter("ui_datetime")
    def format_ui_datetime(raw: object) -> str:
        if not isinstance(raw, str):
            return "n/a"
        normalized = raw.strip()
        if not normalized:
            return "n/a"
        try:
            parsed = parse_iso_datetime(normalized)
        except ValueError:
            return normalized
        return parsed.strftime("%Y-%m-%d %H:%M UTC")

    def session_artifacts_root_for_ticket(ticket_id: str) -> Path:
        return (Path(resolved_settings.execution_data_dir) / "sessions" / ticket_id).resolve()

    def is_path_within_root(*, root: Path, candidate: Path) -> bool:
        try:
            candidate.relative_to(root)
        except ValueError:
            return False
        return True

    def read_tail_lines(path: Path, *, max_lines: int = LOG_PREVIEW_LINE_LIMIT) -> list[str]:
        if not path.exists():
            return []
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            lines = handle.readlines()
        return [line.rstrip("\n") for line in lines[-max_lines:]]

    def resolve_session_log_path(*, ticket_id: str, session_meta: dict[str, Any]) -> Path:
        raw_log_path = str(session_meta.get("log_path", "")).strip()
        if not raw_log_path:
            raise ServiceError("Log file is not available for this step", 404, "log_not_found")

        log_path = Path(raw_log_path).resolve()
        artifacts_root = session_artifacts_root_for_ticket(ticket_id)
        if not is_path_within_root(root=artifacts_root, candidate=log_path):
            raise ServiceError("Log file path is outside the ticket artifact root", 400, "invalid_log_path")
        if not log_path.exists() or not log_path.is_file():
            raise ServiceError("Log file is not available for this step", 404, "log_not_found")
        return log_path

    def build_ticket_session_views(ticket: dict[str, Any]) -> list[dict[str, Any]]:
        session_views: list[dict[str, Any]] = []
        raw_sessions = ticket.get("tmux_sessions", [])
        sessions = raw_sessions if isinstance(raw_sessions, list) else []
        ticket_id = str(ticket.get("id", "")).strip()
        for session_meta in sessions:
            if not isinstance(session_meta, dict):
                continue
            view = dict(session_meta)
            try:
                step_index = int(session_meta.get("step_index", -1))
            except (TypeError, ValueError):
                step_index = -1
            step_number = step_index + 1 if step_index >= 0 else None
            view["step_number"] = step_number
            view["log_preview"] = ""
            view["log_available"] = False
            view["log_url"] = None
            if step_number is not None:
                view["log_url"] = url_for("ui_ticket_step_log", ticket_id=ticket_id, step_number=step_number)
            try:
                log_path = resolve_session_log_path(ticket_id=ticket_id, session_meta=session_meta)
            except ServiceError:
                session_views.append(view)
                continue
            preview_lines = read_tail_lines(log_path)
            view["log_available"] = step_number is not None
            view["log_preview"] = "\n".join(preview_lines)
            session_views.append(view)
        return session_views

    def get_ticket_session_for_step(*, ticket: dict[str, Any], step_number: int) -> dict[str, Any]:
        if step_number <= 0:
            raise ServiceError("Step log does not exist", 404, "log_not_found")
        raw_sessions = ticket.get("tmux_sessions", [])
        sessions = raw_sessions if isinstance(raw_sessions, list) else []
        step_index = step_number - 1
        for session_meta in sessions:
            if not isinstance(session_meta, dict):
                continue
            try:
                session_step_index = int(session_meta.get("step_index", -1))
            except (TypeError, ValueError):
                continue
            if session_step_index == step_index:
                return dict(session_meta)
        raise ServiceError("Step log does not exist", 404, "log_not_found")

    @app.errorhandler(ServiceError)
    def handle_service_error(error: ServiceError) -> ResponseReturnValue:
        if request.path.startswith("/api/"):
            return api_error(error)
        flash(str(error), "error")
        redirect_target = ticket_detail_redirect_path_for_request() or url_for("ui_tickets")
        return redirect(redirect_target), 302

    @app.errorhandler(403)
    def handle_forbidden(_: Exception) -> ResponseReturnValue:
        if request.path.startswith("/api/"):
            return jsonify({"error": "forbidden", "message": "Access denied"}), 403
        return render_template("forbidden.html"), 403

    @app.get("/api/v1/health")
    def api_health() -> ResponseReturnValue:
        return jsonify(service.health()), 200

    @app.post("/api/v1/tickets")
    def api_create_ticket() -> ResponseReturnValue:
        token = get_bearer_token()
        submitter = service.authenticate_submitter(token)
        if submitter is None:
            raise ServiceError("Submit token required", 401, "invalid_submit_token")

        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            raise ServiceError("JSON object required", 400, "invalid_json")

        ticket = service.create_ticket(
            payload,
            submitter=submitter,
            source_ip=get_client_ip(),
            user_agent=request.headers.get("User-Agent"),
        )
        return jsonify(ticket), 201

    @app.get("/api/v1/tickets/<ticket_id>")
    def api_get_ticket(ticket_id: str) -> ResponseReturnValue:
        submitter = service.authenticate_submitter(get_bearer_token())
        approver = get_session_user()
        if submitter is None and approver is None and not service.is_runner_token(get_bearer_token()):
            raise ServiceError("Authentication required", 401, "auth_required")

        ticket = service.get_ticket(ticket_id)
        if submitter is not None and ticket["source"] != submitter.source:
            raise ServiceError("Submit token cannot access this ticket", 403, "forbidden")
        return jsonify(ticket), 200

    @app.post("/api/v1/tickets/<ticket_id>/approve")
    @require_approver_session
    def api_approve_ticket(ticket_id: str) -> ResponseReturnValue:
        approver = str(request.environ["opsgate.approver"])
        ticket = service.approve_ticket(
            ticket_id,
            approver=approver,
            source_ip=get_client_ip(),
            user_agent=request.headers.get("User-Agent"),
        )
        return jsonify(ticket), 200

    @app.post("/api/v1/tickets/<ticket_id>/reject")
    @require_approver_session
    def api_reject_ticket(ticket_id: str) -> ResponseReturnValue:
        approver = str(request.environ["opsgate.approver"])
        payload = request.get_json(silent=True) or {}
        reason = str(payload.get("reason", "")).strip()
        ticket = service.reject_ticket(
            ticket_id,
            approver=approver,
            reason=reason,
            source_ip=get_client_ip(),
            user_agent=request.headers.get("User-Agent"),
        )
        return jsonify(ticket), 200

    @app.post("/api/v1/tickets/<ticket_id>/cancel")
    @require_approver_session
    def api_cancel_ticket(ticket_id: str) -> ResponseReturnValue:
        approver = str(request.environ["opsgate.approver"])
        payload = request.get_json(silent=True) or {}
        reason = str(payload.get("reason", "")).strip()
        ticket = service.cancel_ticket(
            ticket_id,
            approver=approver,
            reason=reason,
            source_ip=get_client_ip(),
            user_agent=request.headers.get("User-Agent"),
        )
        return jsonify(ticket), 200

    @app.post("/api/v1/tickets/<ticket_id>/archive")
    @require_approver_session
    def api_archive_ticket(ticket_id: str) -> ResponseReturnValue:
        approver = str(request.environ["opsgate.approver"])
        ticket = service.archive_ticket(
            ticket_id,
            approver=approver,
            source_ip=get_client_ip(),
            user_agent=request.headers.get("User-Agent"),
        )
        return jsonify(ticket), 200

    @app.post("/api/v1/tickets/<ticket_id>/unarchive")
    @require_approver_session
    def api_unarchive_ticket(ticket_id: str) -> ResponseReturnValue:
        approver = str(request.environ["opsgate.approver"])
        ticket = service.unarchive_ticket(
            ticket_id,
            approver=approver,
            source_ip=get_client_ip(),
            user_agent=request.headers.get("User-Agent"),
        )
        return jsonify(ticket), 200

    @app.post("/api/v1/runner/claim")
    @require_runner_token
    def api_runner_claim() -> ResponseReturnValue:
        payload = request.get_json(silent=True) or {}
        runner_host = str(payload.get("runner_host", "")).strip() or get_client_ip() or "runner"
        ticket = service.claim_ticket(
            runner_host=runner_host,
            source_ip=get_client_ip(),
            user_agent=request.headers.get("User-Agent"),
        )
        if ticket is None:
            return jsonify({"ticket": None}), 200
        return jsonify({"ticket": ticket}), 200

    @app.post("/api/v1/runner/<ticket_id>/status")
    @require_runner_token
    def api_runner_status(ticket_id: str) -> ResponseReturnValue:
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            raise ServiceError("JSON object required", 400, "invalid_json")

        runner_host = str(payload.get("runner_host", "")).strip() or get_client_ip() or "runner"
        ticket = service.update_runner_status(
            ticket_id,
            runner_host=runner_host,
            payload=payload,
            source_ip=get_client_ip(),
            user_agent=request.headers.get("User-Agent"),
        )
        return jsonify(ticket), 200

    @app.get("/")
    def ui_root() -> ResponseReturnValue:
        if get_session_user() is None:
            return redirect(url_for("ui_login"))
        return redirect(url_for("ui_tickets"))

    @app.route("/login", methods=["GET", "POST"])
    def ui_login() -> ResponseReturnValue:
        next_path = sanitize_next_path(request.args.get("next"))
        if request.method == "GET":
            return Response(render_template("login.html", next_path=next_path), 200)

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        next_path = sanitize_next_path(request.form.get("next")) or next_path

        if username != resolved_settings.ui_username:
            flash("Invalid username or password", "error")
            if next_path is not None:
                return redirect(url_for("ui_login", next=next_path))
            return redirect(url_for("ui_login"))

        try:
            valid = bcrypt.checkpw(
                password.encode("utf-8"),
                resolved_settings.ui_password_bcrypt.encode("utf-8"),
            )
        except ValueError:
            valid = False

        if not valid:
            flash("Invalid username or password", "error")
            if next_path is not None:
                return redirect(url_for("ui_login", next=next_path))
            return redirect(url_for("ui_login"))

        session.clear()
        session["username"] = username
        session["auth_at"] = isoformat_z(utc_now())
        session["csrf_token"] = secrets.token_urlsafe(32)
        if next_path is not None:
            return redirect(next_path)
        return redirect(url_for("ui_tickets"))

    @app.post("/logout")
    def ui_logout() -> ResponseReturnValue:
        session.clear()
        return redirect(url_for("ui_login"))

    @app.route("/tickets", methods=["GET", "POST"])
    def ui_tickets() -> ResponseReturnValue:
        approver = get_session_user()
        if approver is None:
            return redirect(url_for("ui_login"))

        if request.method == "POST":
            operator_requires_reviewer = service.require_reviewer_step_floor_for_source("operator")
            form_data = build_manual_ticket_form_data(operator_requires_reviewer=operator_requires_reviewer)
            try:
                ticket = service.create_manual_ticket(
                    build_manual_ticket_payload(),
                    creator=approver,
                    source_ip=get_client_ip(),
                    user_agent=request.headers.get("User-Agent"),
                )
            except ServiceError as error:
                flash(str(error), "error")
                return render_tickets_page(status_code=400, form_data=form_data)
            flash("Ticket created and queued for approval", "success")
            return redirect(url_for("ui_ticket_detail", ticket_id=ticket["id"]))

        return render_tickets_page()

    @app.get("/tickets/<ticket_id>")
    def ui_ticket_detail(ticket_id: str) -> ResponseReturnValue:
        if get_session_user() is None:
            return redirect(url_for("ui_login", next=request.path))
        ticket = service.get_ticket(ticket_id)
        tickets_back_href = url_for("ui_tickets", view="archived" if ticket.get("is_archived") else "active")
        return Response(
            render_template(
                "ticket_detail.html",
                ticket=ticket,
                tickets_back_href=tickets_back_href,
                session_views=build_ticket_session_views(ticket),
            ),
            200,
        )

    @app.get("/tickets/<ticket_id>/steps/<int:step_number>/log")
    def ui_ticket_step_log(ticket_id: str, step_number: int) -> ResponseReturnValue:
        if get_session_user() is None:
            return redirect(url_for("ui_login", next=request.path))
        ticket = service.get_ticket(ticket_id)
        session_meta = get_ticket_session_for_step(ticket=ticket, step_number=step_number)
        log_path = resolve_session_log_path(ticket_id=ticket_id, session_meta=session_meta)
        log_text = log_path.read_text(encoding="utf-8", errors="replace")
        return Response(
            render_template(
                "ticket_log.html",
                ticket=ticket,
                session=session_meta,
                step_number=step_number,
                log_text=log_text,
                log_path=str(log_path),
            ),
            200,
        )

    @app.post("/tickets/<ticket_id>/approve")
    def ui_ticket_approve(ticket_id: str) -> ResponseReturnValue:
        approver = get_session_user()
        if approver is None:
            return redirect(url_for("ui_login"))
        service.approve_ticket(
            ticket_id,
            approver=approver,
            source_ip=get_client_ip(),
            user_agent=request.headers.get("User-Agent"),
        )
        return redirect(url_for("ui_ticket_detail", ticket_id=ticket_id))

    @app.post("/tickets/<ticket_id>/reject")
    def ui_ticket_reject(ticket_id: str) -> ResponseReturnValue:
        approver = get_session_user()
        if approver is None:
            return redirect(url_for("ui_login"))
        reason = request.form.get("reason", "").strip()
        service.reject_ticket(
            ticket_id,
            approver=approver,
            reason=reason,
            source_ip=get_client_ip(),
            user_agent=request.headers.get("User-Agent"),
        )
        return redirect(url_for("ui_ticket_detail", ticket_id=ticket_id))

    @app.post("/tickets/<ticket_id>/cancel")
    def ui_ticket_cancel(ticket_id: str) -> ResponseReturnValue:
        approver = get_session_user()
        if approver is None:
            return redirect(url_for("ui_login"))
        reason = request.form.get("reason", "").strip()
        service.cancel_ticket(
            ticket_id,
            approver=approver,
            reason=reason,
            source_ip=get_client_ip(),
            user_agent=request.headers.get("User-Agent"),
        )
        return redirect(url_for("ui_ticket_detail", ticket_id=ticket_id))

    @app.post("/tickets/<ticket_id>/archive")
    def ui_ticket_archive(ticket_id: str) -> ResponseReturnValue:
        approver = get_session_user()
        if approver is None:
            return redirect(url_for("ui_login"))
        service.archive_ticket(
            ticket_id,
            approver=approver,
            source_ip=get_client_ip(),
            user_agent=request.headers.get("User-Agent"),
        )
        return redirect(url_for("ui_ticket_detail", ticket_id=ticket_id))

    @app.post("/tickets/<ticket_id>/unarchive")
    def ui_ticket_unarchive(ticket_id: str) -> ResponseReturnValue:
        approver = get_session_user()
        if approver is None:
            return redirect(url_for("ui_login"))
        service.unarchive_ticket(
            ticket_id,
            approver=approver,
            source_ip=get_client_ip(),
            user_agent=request.headers.get("User-Agent"),
        )
        return redirect(url_for("ui_ticket_detail", ticket_id=ticket_id))

    return app
