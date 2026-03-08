from __future__ import annotations

import os
import socket
from dataclasses import dataclass
from ipaddress import ip_network
from pathlib import Path

DEFAULT_ALLOWED_CIDRS = (
    "127.0.0.1/32",
    "::1/128",
    "100.64.0.0/10",
    "fd7a:115c:a1e0::/48",
)


@dataclass(frozen=True)
class SubmitterPolicy:
    source: str
    token: str
    require_reviewer_step_floor: bool


@dataclass(frozen=True)
class OpsGateSettings:
    service_name: str
    bind_host: str
    bind_port: int
    db_path: str
    session_secret: str
    trust_proxy_headers: bool
    session_cookie_secure: bool
    session_timeout_seconds: int
    ui_username: str
    ui_password_bcrypt: str
    max_duration_seconds_default: int
    policy_floor_require_reviewer_step: bool
    runner_token: str
    submitter_policies: tuple[SubmitterPolicy, ...]
    require_tailscale_context: bool
    allowed_cidrs: tuple[str, ...]
    execution_data_dir: str
    disable_file_path: str


@dataclass(frozen=True)
class RunnerSettings:
    service_name: str
    runner_token: str
    runner_host: str
    runner_api_base_url: str
    runner_poll_interval_seconds: int
    runner_heartbeat_interval_seconds: int
    max_parallel_jobs: int
    max_duration_seconds_default: int
    execution_data_dir: str
    tickets_dir: str
    session_artifacts_dir: str
    tmux_socket_label: str
    tmux_tmpdir: str
    disable_file_path: str


class SettingsError(RuntimeError):
    pass


def parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    normalized = value.strip().lower()
    return normalized in {"1", "true", "yes", "on"}


def parse_int(value: str | None, default: int, *, env_name: str | None = None) -> int:
    if value is None or value.strip() == "":
        return default
    try:
        return int(value.strip())
    except ValueError as exc:
        setting_name = env_name or "integer setting"
        raise SettingsError(f"{setting_name} must be an integer") from exc


def load_env_file(path: str) -> None:
    env_path = Path(path)
    if not env_path.exists():
        raise SettingsError(f"Env file does not exist: {env_path}")

    for line in env_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            continue
        key, raw_value = stripped.split("=", 1)
        key = key.strip()
        value = raw_value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        os.environ[key] = value


def _validate_cidrs(cidrs: tuple[str, ...]) -> tuple[str, ...]:
    for cidr in cidrs:
        ip_network(cidr, strict=False)
    return cidrs


def load_settings() -> OpsGateSettings:
    env_file = os.environ.get("OPSGATE_ENV_FILE", "").strip()
    if env_file:
        load_env_file(env_file)

    service_name = os.environ.get("OPSGATE_SERVICE_NAME", "opsgate").strip()
    bind_host = os.environ.get("OPSGATE_BIND_HOST", "0.0.0.0").strip()
    bind_port = parse_int(os.environ.get("OPSGATE_BIND_PORT"), 8711, env_name="OPSGATE_BIND_PORT")

    db_path = os.environ.get("OPSGATE_DB_PATH", "").strip()
    if not db_path:
        db_path = "/usr/local/var/opsgate/run/opsgate.sqlite3"

    ui_username = os.environ.get("OPSGATE_UI_USERNAME", "").strip()
    ui_password_bcrypt = os.environ.get("OPSGATE_UI_PASSWORD_BCRYPT", "").strip()
    if not ui_username or not ui_password_bcrypt:
        raise SettingsError("OPSGATE_UI_USERNAME and OPSGATE_UI_PASSWORD_BCRYPT are required")

    session_secret = os.environ.get("OPSGATE_SESSION_SECRET", "").strip()
    if len(session_secret) < 20:
        raise SettingsError("OPSGATE_SESSION_SECRET is required and must be at least 20 characters")
    trust_proxy_headers = parse_bool(os.environ.get("OPSGATE_TRUST_PROXY_HEADERS"), default=False)
    session_cookie_secure = parse_bool(os.environ.get("OPSGATE_SESSION_COOKIE_SECURE"), default=False)

    max_duration_default = parse_int(
        os.environ.get("OPSGATE_MAX_DURATION_SECONDS_DEFAULT"),
        3600,
        env_name="OPSGATE_MAX_DURATION_SECONDS_DEFAULT",
    )
    policy_floor = parse_bool(os.environ.get("OPSGATE_POLICY_FLOOR_REQUIRE_REVIEWER_STEP"), default=False)
    session_timeout_seconds = parse_int(
        os.environ.get("OPSGATE_UI_SESSION_TIMEOUT_SECONDS"),
        28800,
        env_name="OPSGATE_UI_SESSION_TIMEOUT_SECONDS",
    )

    runner_token = os.environ.get("OPSGATE_RUNNER_TOKEN", "").strip()
    if len(runner_token) < 20:
        raise SettingsError("OPSGATE_RUNNER_TOKEN is required and must be at least 20 characters")

    openclaw_token = os.environ.get("OPSGATE_SUBMIT_TOKEN_OPENCLAW", "").strip()
    nyxmon_token = os.environ.get("OPSGATE_SUBMIT_TOKEN_NYXMON", "").strip()
    operator_token = os.environ.get("OPSGATE_SUBMIT_TOKEN_OPERATOR", "").strip()

    if openclaw_token and len(openclaw_token) < 20:
        raise SettingsError("Submit token for openclaw must be at least 20 characters")
    if len(nyxmon_token) < 20:
        raise SettingsError("Submit token for nyxmon must be at least 20 characters")
    if len(operator_token) < 20:
        raise SettingsError("Submit token for operator must be at least 20 characters")

    submitter_policies_list: list[SubmitterPolicy] = []
    if openclaw_token:
        submitter_policies_list.append(
            SubmitterPolicy(
                source="openclaw",
                token=openclaw_token,
                require_reviewer_step_floor=parse_bool(
                    os.environ.get("OPSGATE_SUBMIT_POLICY_OPENCLAW_REQUIRE_REVIEWER_STEP"),
                    default=policy_floor,
                ),
            )
        )
    submitter_policies_list.append(
        SubmitterPolicy(
            source="nyxmon",
            token=nyxmon_token,
            require_reviewer_step_floor=parse_bool(
                os.environ.get("OPSGATE_SUBMIT_POLICY_NYXMON_REQUIRE_REVIEWER_STEP"),
                default=policy_floor,
            ),
        )
    )
    submitter_policies_list.append(
        SubmitterPolicy(
            source="operator",
            token=operator_token,
            require_reviewer_step_floor=parse_bool(
                os.environ.get("OPSGATE_SUBMIT_POLICY_OPERATOR_REQUIRE_REVIEWER_STEP"),
                default=policy_floor,
            ),
        )
    )
    submitter_policies = tuple(submitter_policies_list)

    require_tailscale = parse_bool(os.environ.get("OPSGATE_REQUIRE_TAILSCALE_CONTEXT"), default=True)
    allowed_cidrs_raw = os.environ.get("OPSGATE_ALLOWED_CIDRS", ",".join(DEFAULT_ALLOWED_CIDRS))
    allowed_cidrs = tuple(c.strip() for c in allowed_cidrs_raw.split(",") if c.strip())
    if not allowed_cidrs:
        raise SettingsError("OPSGATE_ALLOWED_CIDRS must contain at least one CIDR")

    execution_data_dir = os.environ.get("OPSGATE_EXECUTION_DATA_DIR", "/Users/ops/remediation").strip()
    disable_file = os.environ.get("OPSGATE_DISABLE_FILE_PATH", "").strip()
    if not disable_file:
        disable_file = f"{execution_data_dir}/.disabled"

    return OpsGateSettings(
        service_name=service_name,
        bind_host=bind_host,
        bind_port=bind_port,
        db_path=db_path,
        session_secret=session_secret,
        trust_proxy_headers=trust_proxy_headers,
        session_cookie_secure=session_cookie_secure,
        session_timeout_seconds=session_timeout_seconds,
        ui_username=ui_username,
        ui_password_bcrypt=ui_password_bcrypt,
        max_duration_seconds_default=max_duration_default,
        policy_floor_require_reviewer_step=policy_floor,
        runner_token=runner_token,
        submitter_policies=submitter_policies,
        require_tailscale_context=require_tailscale,
        allowed_cidrs=_validate_cidrs(allowed_cidrs),
        execution_data_dir=execution_data_dir,
        disable_file_path=disable_file,
    )


def load_runner_settings() -> RunnerSettings:
    env_file = os.environ.get("OPSGATE_ENV_FILE", "").strip()
    if env_file:
        load_env_file(env_file)

    service_name = os.environ.get("OPSGATE_SERVICE_NAME", "opsgate").strip()
    runner_token = os.environ.get("OPSGATE_RUNNER_TOKEN", "").strip()
    if len(runner_token) < 20:
        raise SettingsError("OPSGATE_RUNNER_TOKEN is required and must be at least 20 characters")

    bind_port = parse_int(os.environ.get("OPSGATE_BIND_PORT"), 8711, env_name="OPSGATE_BIND_PORT")
    runner_api_base_url = os.environ.get("OPSGATE_RUNNER_API_BASE_URL", f"http://127.0.0.1:{bind_port}").strip()
    if not runner_api_base_url:
        raise SettingsError("OPSGATE_RUNNER_API_BASE_URL must not be empty")
    runner_api_base_url = runner_api_base_url.rstrip("/")

    runner_poll_interval_seconds = parse_int(
        os.environ.get("OPSGATE_RUNNER_POLL_INTERVAL_SECONDS"),
        5,
        env_name="OPSGATE_RUNNER_POLL_INTERVAL_SECONDS",
    )
    runner_heartbeat_interval_seconds = parse_int(
        os.environ.get("OPSGATE_RUNNER_HEARTBEAT_INTERVAL_SECONDS"),
        30,
        env_name="OPSGATE_RUNNER_HEARTBEAT_INTERVAL_SECONDS",
    )
    max_parallel_jobs = parse_int(
        os.environ.get("OPSGATE_MAX_PARALLEL_JOBS"),
        3,
        env_name="OPSGATE_MAX_PARALLEL_JOBS",
    )
    max_duration_seconds_default = parse_int(
        os.environ.get("OPSGATE_MAX_DURATION_SECONDS_DEFAULT"),
        3600,
        env_name="OPSGATE_MAX_DURATION_SECONDS_DEFAULT",
    )
    if runner_poll_interval_seconds <= 0:
        raise SettingsError("OPSGATE_RUNNER_POLL_INTERVAL_SECONDS must be > 0")
    if runner_heartbeat_interval_seconds <= 0:
        raise SettingsError("OPSGATE_RUNNER_HEARTBEAT_INTERVAL_SECONDS must be > 0")
    if max_parallel_jobs <= 0:
        raise SettingsError("OPSGATE_MAX_PARALLEL_JOBS must be > 0")
    if max_duration_seconds_default <= 0:
        raise SettingsError("OPSGATE_MAX_DURATION_SECONDS_DEFAULT must be > 0")

    execution_data_dir = os.environ.get("OPSGATE_EXECUTION_DATA_DIR", "/Users/ops/remediation").strip()
    if not execution_data_dir:
        raise SettingsError("OPSGATE_EXECUTION_DATA_DIR must not be empty")

    tickets_dir = os.environ.get("OPSGATE_TICKETS_DIR", f"{execution_data_dir}/jobs").strip()
    session_artifacts_dir = os.environ.get("OPSGATE_SESSION_ARTIFACTS_DIR", f"{execution_data_dir}/sessions").strip()
    if not tickets_dir or not session_artifacts_dir:
        raise SettingsError("OPSGATE_TICKETS_DIR and OPSGATE_SESSION_ARTIFACTS_DIR must not be empty")

    tmux_socket_label = os.environ.get("OPSGATE_TMUX_SOCKET_LABEL", "remediation").strip()
    if not tmux_socket_label:
        raise SettingsError("OPSGATE_TMUX_SOCKET_LABEL must not be empty")
    tmux_tmpdir = os.environ.get("TMUX_TMPDIR", "").strip()

    disable_file = os.environ.get("OPSGATE_DISABLE_FILE_PATH", "").strip()
    if not disable_file:
        disable_file = f"{execution_data_dir}/.disabled"

    runner_host = os.environ.get("OPSGATE_RUNNER_HOST", "").strip() or socket.gethostname()

    return RunnerSettings(
        service_name=service_name,
        runner_token=runner_token,
        runner_host=runner_host,
        runner_api_base_url=runner_api_base_url,
        runner_poll_interval_seconds=runner_poll_interval_seconds,
        runner_heartbeat_interval_seconds=runner_heartbeat_interval_seconds,
        max_parallel_jobs=max_parallel_jobs,
        max_duration_seconds_default=max_duration_seconds_default,
        execution_data_dir=execution_data_dir,
        tickets_dir=tickets_dir,
        session_artifacts_dir=session_artifacts_dir,
        tmux_socket_label=tmux_socket_label,
        tmux_tmpdir=tmux_tmpdir,
        disable_file_path=disable_file,
    )
