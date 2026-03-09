from __future__ import annotations

import hmac
import json
import re
import secrets
from collections.abc import Callable
from datetime import timedelta
from functools import wraps
from ipaddress import ip_address, ip_network
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
from .service import SUPPORTED_AGENTS, OpsGateService, ServiceError, isoformat_z, parse_iso_datetime, utc_now

P = ParamSpec("P")
R = TypeVar("R")


class AccessDenied(ServiceError):
    pass


MANUAL_STEP_FIELD_PATTERN = re.compile(r"^steps-(\d+)-(role|agent|prompt_markdown)$")
TICKET_ACTION_PATH_PATTERN = re.compile(r"^/tickets/([^/]+)/(approve|reject|cancel)$")
DEFAULT_AGENT_BY_ROLE = {
    "implementer": "codex",
    "implementor": "codex",
    "reviewer": "claude",
    "investigator": "codex",
}


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
        if match is None:
            return None
        return url_for("ui_ticket_detail", ticket_id=match.group(1))

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
        operator_requires_reviewer = service.require_reviewer_step_floor_for_source("operator")
        if form_data is None:
            form_data = build_manual_ticket_form_data(operator_requires_reviewer=operator_requires_reviewer)
        tickets = service.list_tickets(limit=100)
        return Response(
            render_template(
                "tickets.html",
                tickets=tickets,
                form_data=form_data,
                operator_requires_reviewer=operator_requires_reviewer,
                role_agent_defaults=DEFAULT_AGENT_BY_ROLE,
                supported_agents=SUPPORTED_AGENTS,
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
        return Response(render_template("ticket_detail.html", ticket=ticket), 200)

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

    return app
