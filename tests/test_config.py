from __future__ import annotations

import os
from pathlib import Path

import pytest

from opsgate.config import SettingsError, load_env_file, load_runner_settings, load_settings


def test_load_env_file_strips_wrapping_quotes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env_file = tmp_path / "opsgate.env"
    env_file.write_text(
        "\n".join(
            (
                'OPSGATE_UI_USERNAME="opsgate-admin"',
                "OPSGATE_UI_PASSWORD_BCRYPT='bcrypt-hash'",
                "OPSGATE_BIND_HOST=127.0.0.1",
            )
        ),
        encoding="utf-8",
    )

    monkeypatch.delenv("OPSGATE_UI_USERNAME", raising=False)
    monkeypatch.delenv("OPSGATE_UI_PASSWORD_BCRYPT", raising=False)
    monkeypatch.delenv("OPSGATE_BIND_HOST", raising=False)

    load_env_file(str(env_file))

    assert Path(env_file).exists()
    assert os.environ["OPSGATE_UI_USERNAME"] == "opsgate-admin"
    assert os.environ["OPSGATE_UI_PASSWORD_BCRYPT"] == "bcrypt-hash"
    assert os.environ["OPSGATE_BIND_HOST"] == "127.0.0.1"


def test_load_settings_requires_explicit_session_secret(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env_file = tmp_path / "opsgate.env"
    env_file.write_text(
        "\n".join(
            (
                "OPSGATE_UI_USERNAME=opsgate-admin",
                "OPSGATE_UI_PASSWORD_BCRYPT=$2b$12$C6UzMDM.H6dfI/f/IKcEe.7Pj9N6byN1Nsx3Rp3XIanFkFJxux1fW",
                "OPSGATE_SUBMIT_TOKEN_OPENCLAW=openclaw-token-0000000000",
                "OPSGATE_SUBMIT_TOKEN_NYXMON=nyxmon-token-000000000000",
                "OPSGATE_SUBMIT_TOKEN_OPERATOR=operator-token-00000000000",
                "OPSGATE_RUNNER_TOKEN=runner-token-000000000000",
                "OPSGATE_DB_PATH=/tmp/opsgate-test.sqlite3",
            )
        ),
        encoding="utf-8",
    )

    monkeypatch.setenv("OPSGATE_ENV_FILE", str(env_file))
    monkeypatch.delenv("OPSGATE_SESSION_SECRET", raising=False)

    with pytest.raises(SettingsError, match="OPSGATE_SESSION_SECRET"):
        load_settings()


def test_load_runner_settings_accepts_runner_only_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env_file = tmp_path / "opsgate-runner.env"
    env_file.write_text(
        "\n".join(
            (
                "OPSGATE_RUNNER_TOKEN=runner-token-000000000000",
                "OPSGATE_RUNNER_API_BASE_URL=http://127.0.0.1:8711",
                "OPSGATE_RUNNER_HOST=macstudio",
                "OPSGATE_MAX_PARALLEL_JOBS=4",
                "OPSGATE_RUNNER_POLL_INTERVAL_SECONDS=3",
                "OPSGATE_RUNNER_HEARTBEAT_INTERVAL_SECONDS=15",
                "OPSGATE_EXECUTION_DATA_DIR=/tmp/opsgate-remediation",
                "OPSGATE_TICKETS_DIR=/tmp/opsgate-remediation/jobs",
                "OPSGATE_SESSION_ARTIFACTS_DIR=/tmp/opsgate-remediation/sessions",
                "OPSGATE_TMUX_SOCKET_LABEL=remediation",
            )
        ),
        encoding="utf-8",
    )

    monkeypatch.setenv("OPSGATE_ENV_FILE", str(env_file))
    settings = load_runner_settings()

    assert settings.runner_host == "macstudio"
    assert settings.runner_api_base_url == "http://127.0.0.1:8711"
    assert settings.max_parallel_jobs == 4
    assert settings.runner_poll_interval_seconds == 3
    assert settings.runner_heartbeat_interval_seconds == 15


def test_load_runner_settings_requires_runner_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env_file = tmp_path / "opsgate-runner.env"
    env_file.write_text("OPSGATE_RUNNER_TOKEN=short\n", encoding="utf-8")
    monkeypatch.setenv("OPSGATE_ENV_FILE", str(env_file))

    with pytest.raises(SettingsError, match="OPSGATE_RUNNER_TOKEN"):
        load_runner_settings()


def test_load_settings_allows_missing_openclaw_submit_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env_file = tmp_path / "opsgate.env"
    env_file.write_text(
        "\n".join(
            (
                "OPSGATE_UI_USERNAME=opsgate-admin",
                "OPSGATE_UI_PASSWORD_BCRYPT=$2b$12$C6UzMDM.H6dfI/f/IKcEe.7Pj9N6byN1Nsx3Rp3XIanFkFJxux1fW",
                "OPSGATE_SESSION_SECRET=session-secret-0123456789",
                "OPSGATE_SUBMIT_TOKEN_NYXMON=nyxmon-token-000000000000",
                "OPSGATE_SUBMIT_TOKEN_OPERATOR=operator-token-00000000000",
                "OPSGATE_RUNNER_TOKEN=runner-token-000000000000",
                "OPSGATE_DB_PATH=/tmp/opsgate-test.sqlite3",
            )
        ),
        encoding="utf-8",
    )

    monkeypatch.setenv("OPSGATE_ENV_FILE", str(env_file))
    monkeypatch.delenv("OPSGATE_SUBMIT_TOKEN_OPENCLAW", raising=False)

    settings = load_settings()
    submit_sources = {policy.source for policy in settings.submitter_policies}
    assert submit_sources == {"nyxmon", "operator"}


def test_load_settings_supports_secure_session_cookie(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env_file = tmp_path / "opsgate.env"
    env_file.write_text(
        "\n".join(
            (
                "OPSGATE_UI_USERNAME=opsgate-admin",
                "OPSGATE_UI_PASSWORD_BCRYPT=$2b$12$C6UzMDM.H6dfI/f/IKcEe.7Pj9N6byN1Nsx3Rp3XIanFkFJxux1fW",
                "OPSGATE_SESSION_SECRET=session-secret-0123456789",
                "OPSGATE_TRUST_PROXY_HEADERS=true",
                "OPSGATE_SESSION_COOKIE_SECURE=true",
                "OPSGATE_SUBMIT_TOKEN_NYXMON=nyxmon-token-000000000000",
                "OPSGATE_SUBMIT_TOKEN_OPERATOR=operator-token-00000000000",
                "OPSGATE_RUNNER_TOKEN=runner-token-000000000000",
            )
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("OPSGATE_ENV_FILE", str(env_file))
    settings = load_settings()
    assert settings.trust_proxy_headers is True
    assert settings.session_cookie_secure is True


def test_load_runner_settings_reports_invalid_integer_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env_file = tmp_path / "opsgate-runner.env"
    env_file.write_text(
        "\n".join(
            (
                "OPSGATE_RUNNER_TOKEN=runner-token-000000000000",
                "OPSGATE_MAX_PARALLEL_JOBS=not-a-number",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("OPSGATE_ENV_FILE", str(env_file))

    with pytest.raises(SettingsError, match="OPSGATE_MAX_PARALLEL_JOBS must be an integer"):
        load_runner_settings()


BOOLEAN_SETTINGS = (
    "OPSGATE_TRUST_PROXY_HEADERS",
    "OPSGATE_SESSION_COOKIE_SECURE",
    "OPSGATE_POLICY_FLOOR_REQUIRE_REVIEWER_STEP",
    "OPSGATE_REQUIRE_TAILSCALE_CONTEXT",
    "OPSGATE_SUBMIT_POLICY_OPENCLAW_REQUIRE_REVIEWER_STEP",
    "OPSGATE_SUBMIT_POLICY_NYXMON_REQUIRE_REVIEWER_STEP",
    "OPSGATE_SUBMIT_POLICY_OPERATOR_REQUIRE_REVIEWER_STEP",
)


@pytest.fixture
def boolean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in tuple(os.environ):
        if key.startswith("OPSGATE_"):
            monkeypatch.delenv(key)
    for key, value in {
        "OPSGATE_UI_USERNAME": "test",
        "OPSGATE_UI_PASSWORD_BCRYPT": "test-hash",
        "OPSGATE_SESSION_SECRET": "test-session-0123456789",
        "OPSGATE_RUNNER_TOKEN": "test-runner-01234567890",
        "OPSGATE_SUBMIT_TOKEN_OPENCLAW": "test-openclaw-0123456789",
        "OPSGATE_SUBMIT_TOKEN_NYXMON": "test-nyxmon-01234567890",
        "OPSGATE_SUBMIT_TOKEN_OPERATOR": "test-operator-0123456789",
    }.items():
        monkeypatch.setenv(key, value)


@pytest.mark.parametrize("setting", BOOLEAN_SETTINGS)
@pytest.mark.parametrize("value", ["treu", "flase", "2", "secret-invalid-value"])
def test_boolean_typo_rejects_settings(
    boolean_env: None, monkeypatch: pytest.MonkeyPatch, setting: str, value: str
) -> None:
    monkeypatch.setenv(setting, value)
    with pytest.raises(SettingsError) as caught:
        load_settings()
    assert setting in str(caught.value)
    assert value not in str(caught.value)


@pytest.mark.parametrize(
    "value, expected",
    [
        ("1", True),
        ("true", True),
        ("yes", True),
        ("on", True),
        (" TRUE ", True),
        ("0", False),
        ("false", False),
        ("no", False),
        ("off", False),
        (" OFF ", False),
    ],
)
def test_boolean_spellings_load_settings(
    boolean_env: None, monkeypatch: pytest.MonkeyPatch, value: str, expected: bool
) -> None:
    for setting in BOOLEAN_SETTINGS:
        monkeypatch.setenv(setting, value)
    settings = load_settings()
    assert settings.trust_proxy_headers is expected
    assert settings.session_cookie_secure is expected
    assert settings.policy_floor_require_reviewer_step is expected
    assert settings.require_tailscale_context is expected
    assert all(p.require_reviewer_step_floor is expected for p in settings.submitter_policies)


@pytest.mark.parametrize("value", [None, "", "  "])
def test_boolean_defaults_and_policy_inheritance(
    boolean_env: None, monkeypatch: pytest.MonkeyPatch, value: str | None
) -> None:
    if value is not None:
        for setting in BOOLEAN_SETTINGS:
            monkeypatch.setenv(setting, value)
    settings = load_settings()
    assert settings.trust_proxy_headers is False
    assert settings.session_cookie_secure is False
    assert settings.policy_floor_require_reviewer_step is False
    assert settings.require_tailscale_context is True
    assert all(not p.require_reviewer_step_floor for p in settings.submitter_policies)
    monkeypatch.setenv("OPSGATE_POLICY_FLOOR_REQUIRE_REVIEWER_STEP", "true")
    assert all(p.require_reviewer_step_floor for p in load_settings().submitter_policies)


def test_disabled_openclaw_policy_still_rejects_typo(boolean_env: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPSGATE_SUBMIT_TOKEN_OPENCLAW")
    monkeypatch.setenv("OPSGATE_SUBMIT_POLICY_OPENCLAW_REQUIRE_REVIEWER_STEP", "treu")
    with pytest.raises(SettingsError, match="OPSGATE_SUBMIT_POLICY_OPENCLAW_REQUIRE_REVIEWER_STEP"):
        load_settings()


@pytest.mark.parametrize("source", ["openclaw", "nyxmon", "operator"])
@pytest.mark.parametrize("floor", [True, False])
def test_explicit_submitter_policy_overrides_global_floor(
    boolean_env: None, monkeypatch: pytest.MonkeyPatch, source: str, floor: bool
) -> None:
    monkeypatch.setenv("OPSGATE_POLICY_FLOOR_REQUIRE_REVIEWER_STEP", str(floor))
    monkeypatch.setenv(f"OPSGATE_SUBMIT_POLICY_{source.upper()}_REQUIRE_REVIEWER_STEP", str(not floor))
    settings = load_settings()
    for policy in settings.submitter_policies:
        assert policy.require_reviewer_step_floor is (not floor if policy.source == source else floor)
