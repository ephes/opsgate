from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from functools import wraps
from ipaddress import ip_address, ip_network
from typing import ParamSpec, TypeVar, cast
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

from .config import OpsGateSettings, load_settings
from .service import OpsGateService, ServiceError, isoformat_z, parse_iso_datetime, utc_now

P = ParamSpec("P")
R = TypeVar("R")


class AccessDenied(ServiceError):
    pass


def create_app(settings: OpsGateSettings | None = None) -> Flask:
    resolved_settings = settings or load_settings()
    app = Flask(__name__, template_folder="templates")
    app.config["SECRET_KEY"] = resolved_settings.session_secret
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = False

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

    @app.errorhandler(ServiceError)
    def handle_service_error(error: ServiceError) -> ResponseReturnValue:
        if request.path.startswith("/api/"):
            return api_error(error)
        flash(str(error), "error")
        return redirect(url_for("ui_tickets")), 302

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

        session["username"] = username
        session["auth_at"] = isoformat_z(utc_now())
        if next_path is not None:
            return redirect(next_path)
        return redirect(url_for("ui_tickets"))

    @app.post("/logout")
    def ui_logout() -> ResponseReturnValue:
        session.clear()
        return redirect(url_for("ui_login"))

    @app.get("/tickets")
    def ui_tickets() -> ResponseReturnValue:
        if get_session_user() is None:
            return redirect(url_for("ui_login"))
        tickets = service.list_tickets(limit=100)
        return Response(render_template("tickets.html", tickets=tickets), 200)

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
