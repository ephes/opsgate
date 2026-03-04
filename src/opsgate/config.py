from __future__ import annotations

import os
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


class SettingsError(RuntimeError):
    pass


def parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    normalized = value.strip().lower()
    return normalized in {"1", "true", "yes", "on"}


def parse_int(value: str | None, default: int) -> int:
    if value is None or value.strip() == "":
        return default
    return int(value)


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
    bind_port = parse_int(os.environ.get("OPSGATE_BIND_PORT"), 8711)

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

    max_duration_default = parse_int(os.environ.get("OPSGATE_MAX_DURATION_SECONDS_DEFAULT"), 3600)
    policy_floor = parse_bool(os.environ.get("OPSGATE_POLICY_FLOOR_REQUIRE_REVIEWER_STEP"), default=False)
    session_timeout_seconds = parse_int(os.environ.get("OPSGATE_UI_SESSION_TIMEOUT_SECONDS"), 28800)

    runner_token = os.environ.get("OPSGATE_RUNNER_TOKEN", "").strip()
    if len(runner_token) < 20:
        raise SettingsError("OPSGATE_RUNNER_TOKEN is required and must be at least 20 characters")

    openclaw_token = os.environ.get("OPSGATE_SUBMIT_TOKEN_OPENCLAW", "").strip()
    nyxmon_token = os.environ.get("OPSGATE_SUBMIT_TOKEN_NYXMON", "").strip()
    operator_token = os.environ.get("OPSGATE_SUBMIT_TOKEN_OPERATOR", "").strip()

    submitter_tokens = {
        "openclaw": openclaw_token,
        "nyxmon": nyxmon_token,
        "operator": operator_token,
    }
    for source, token in submitter_tokens.items():
        if len(token) < 20:
            raise SettingsError(f"Submit token for {source} must be at least 20 characters")

    submitter_policies = (
        SubmitterPolicy(
            source="openclaw",
            token=openclaw_token,
            require_reviewer_step_floor=parse_bool(
                os.environ.get("OPSGATE_SUBMIT_POLICY_OPENCLAW_REQUIRE_REVIEWER_STEP"),
                default=policy_floor,
            ),
        ),
        SubmitterPolicy(
            source="nyxmon",
            token=nyxmon_token,
            require_reviewer_step_floor=parse_bool(
                os.environ.get("OPSGATE_SUBMIT_POLICY_NYXMON_REQUIRE_REVIEWER_STEP"),
                default=policy_floor,
            ),
        ),
        SubmitterPolicy(
            source="operator",
            token=operator_token,
            require_reviewer_step_floor=parse_bool(
                os.environ.get("OPSGATE_SUBMIT_POLICY_OPERATOR_REQUIRE_REVIEWER_STEP"),
                default=policy_floor,
            ),
        ),
    )

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
