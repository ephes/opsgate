"""Release checks of the Rust port (rust/PLAN.md section 9).

``rust/scripts/release_checks.py`` gates the release workflow: the tag must
match the crate version, the Mach-O binary must link only system libraries,
need at most macOS 14.0, be arm64 only and carry its ad-hoc linker signature,
``--version`` must name the version and commit, ``check-config api`` and
``check-config runner`` must accept a test configuration, and the archive must
be deterministic with exactly two files.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tarfile
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "rust" / "scripts" / "release_checks.py"
COMMIT = "27cf52e7bd2525d6f8ba4b2f9be42a880c2f6e1a"

# Shapes of the Xcode 16/26 tools' output for the release binary.
OTOOL_OK = """\
target/aarch64-apple-darwin/release/opsgate:
\t/usr/lib/libiconv.2.dylib (compatibility version 7.0.0, current version 7.0.0)
\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1351.0.0)
"""
VTOOL_OK = """\
target/aarch64-apple-darwin/release/opsgate:
Load command 11
      cmd LC_BUILD_VERSION
  cmdsize 32
 platform MACOS
    minos 14.0
      sdk 15.5
   ntools 1
     tool LD
  version 1167.5
"""
CODESIGN_OK = """\
Executable=/Users/runner/work/opsgate/opsgate/rust/target/aarch64-apple-darwin/release/opsgate
Identifier=opsgate-3e3140ec3d25346c
Format=Mach-O thin (arm64)
CodeDirectory v=20400 size=50872 flags=0x20002(adhoc,linker-signed) hashes=1586+0 location=embedded
Signature=adhoc
Info.plist=not bound
TeamIdentifier=not set
Sealed Resources=none
Internal requirements=none
"""


@pytest.fixture(scope="module")
def checks() -> ModuleType:
    spec = importlib.util.spec_from_file_location("rust_release_checks", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def metadata(*packages: tuple[str, str]) -> dict[str, Any]:
    return {"packages": [{"name": name, "version": version} for name, version in packages]}


def test_version_comes_from_the_opsgate_package(checks: ModuleType) -> None:
    data = metadata(("opsgate-core", "9.9.9"), ("opsgate", "0.3.0"), ("opsgate-web", "0.3.0"))
    assert checks.package_version(data) == "0.3.0"
    assert checks.package_version(metadata(("opsgate", "1.2.3-rc.1"))) == "1.2.3-rc.1"


@pytest.mark.parametrize("version", ["0.3", "03.0.0", "0.3.0+build.5", "0.3.0-", "v0.3.0"])
def test_version_must_be_semver_without_build_metadata(checks: ModuleType, version: str) -> None:
    with pytest.raises(checks.CheckError, match="not semver"):
        checks.package_version(metadata(("opsgate", version)))


def test_version_requires_exactly_one_opsgate_package(checks: ModuleType) -> None:
    with pytest.raises(checks.CheckError, match="found 0"):
        checks.package_version(metadata(("opsgate-core", "0.3.0")))
    with pytest.raises(checks.CheckError, match="found 2"):
        checks.package_version(metadata(("opsgate", "0.3.0"), ("opsgate", "0.3.0")))


def test_tag_must_equal_the_crate_version(checks: ModuleType) -> None:
    checks.check_tag("rs-v0.3.0", "0.3.0")
    for tag in ("rs-v0.3.1", "rs-0.3.0", "v0.3.0", "rs-v0.3.0-rc.1", "agent-rs-v0.3.0", "rs-v0.3.0 "):
        with pytest.raises(checks.CheckError, match=re.escape("expected 'rs-v0.3.0'")):
            checks.check_tag(tag, "0.3.0")


def test_libraries_accept_the_system_libraries(checks: ModuleType) -> None:
    assert checks.linked_libraries(OTOOL_OK) == ["/usr/lib/libiconv.2.dylib", "/usr/lib/libSystem.B.dylib"]
    assert checks.check_libraries(OTOOL_OK) == ["/usr/lib/libiconv.2.dylib", "/usr/lib/libSystem.B.dylib"]
    framework = "\t/System/Library/Frameworks/Security.framework/Versions/A/Security (compatibility version 1.0.0, current version 61439.1.1)\n"  # noqa: E501
    assert checks.check_libraries(OTOOL_OK + framework)[-1].startswith("/System/Library/Frameworks/")


@pytest.mark.parametrize(
    "library",
    [
        "/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib",
        "/usr/local/lib/libsqlite3.dylib",
        "@rpath/libfoo.dylib",
        "@executable_path/../lib/libbar.dylib",
        "/usr/lib2/libz.dylib",
    ],
)
def test_libraries_reject_anything_outside_the_system(checks: ModuleType, library: str) -> None:
    text = OTOOL_OK + f"\t{library} (compatibility version 1.0.0, current version 1.0.0)\n"
    with pytest.raises(checks.CheckError, match=re.escape(f"outside /usr/lib and /System/Library: {library}")):
        checks.check_libraries(text)


def test_libraries_require_a_listing(checks: ModuleType) -> None:
    for text in ("", "opsgate: is not an object file\n", OTOOL_OK.replace("libSystem.B", "libSystem.C")):
        with pytest.raises(checks.CheckError, match="not an otool -L listing"):
            checks.check_libraries(text)


def test_minos_accepts_14_0_and_older(checks: ModuleType) -> None:
    assert checks.check_minos(VTOOL_OK, "14.0") == "14.0"
    assert checks.check_minos(VTOOL_OK, "14") == "14.0"
    assert checks.check_minos(VTOOL_OK.replace("minos 14.0", "minos 11.0"), "14.0") == "11.0"
    assert checks.check_minos(VTOOL_OK, "15.1") == "14.0"


@pytest.mark.parametrize(
    ("minos", "maximum"), [("14.0.1", "14.0"), ("14.1", "14.0"), ("15.0", "14.0"), ("14.10", "14.9")]
)
def test_minos_rejects_newer_versions_numerically(checks: ModuleType, minos: str, maximum: str) -> None:
    with pytest.raises(checks.CheckError, match=re.escape(f"requires macOS {minos}, newer than {maximum}")):
        checks.check_minos(VTOOL_OK.replace("minos 14.0", f"minos {minos}"), maximum)


def test_minos_rejects_other_platforms_and_shapes(checks: ModuleType) -> None:
    with pytest.raises(checks.CheckError, match="platform is IOS"):
        checks.check_minos(VTOOL_OK.replace("platform MACOS", "platform IOS"), "14.0")
    legacy = "Load command 9\n      cmd LC_VERSION_MIN_MACOSX\n  cmdsize 16\n  version 10.12\n      sdk 11.0\n"
    for text in ("", legacy, VTOOL_OK + VTOOL_OK, VTOOL_OK.replace("    minos 14.0\n", "")):
        with pytest.raises(checks.CheckError, match="exactly one LC_BUILD_VERSION"):
            checks.check_minos(text, "14.0")
    with pytest.raises(checks.CheckError, match="not a macOS version"):
        checks.check_minos(VTOOL_OK.replace("minos 14.0", "minos 14.0b"), "14.0")
    with pytest.raises(checks.CheckError, match="not a macOS version"):
        checks.check_minos(VTOOL_OK, "14.0.0.0")


def test_archs_must_be_exactly_arm64(checks: ModuleType) -> None:
    checks.check_archs("arm64\n", "arm64")
    for text in ("x86_64\n", "x86_64 arm64\n", "arm64 arm64e\n", "arm64e\n", ""):
        with pytest.raises(checks.CheckError, match="expected exactly"):
            checks.check_archs(text, "arm64")


def test_signature_must_be_the_adhoc_linker_signature(checks: ModuleType) -> None:
    checks.check_signature(CODESIGN_OK)
    unsigned = "target/aarch64-apple-darwin/release/opsgate: code object is not signed at all\n"
    developer_id = CODESIGN_OK.replace("Signature=adhoc", "Signature size=9000\nAuthority=Developer ID Application")
    for text in (unsigned, developer_id):
        with pytest.raises(checks.CheckError, match="expected the ad-hoc linker signature"):
            checks.check_signature(text)
    resigned = CODESIGN_OK.replace("flags=0x20002(adhoc,linker-signed)", "flags=0x2(adhoc)")
    with pytest.raises(checks.CheckError, match="expected adhoc and linker-signed"):
        checks.check_signature(resigned)


def test_version_output_must_name_version_and_commit(checks: ModuleType) -> None:
    checks.check_version_output(f"opsgate 0.3.0 ({COMMIT})\n", "0.3.0", COMMIT)
    for stdout in (
        "opsgate 0.3.0\n",
        f"opsgate 0.3.0 ({COMMIT})",
        "opsgate 0.3.0 (unknown)\n",
        f"opsgate 0.3.0 ({COMMIT[:12]})\n",
        f"opsgate 0.3.1 ({COMMIT})\n",
    ):
        with pytest.raises(checks.CheckError, match="--version printed"):
            checks.check_version_output(stdout, "0.3.0", COMMIT)


def test_check_config_output_must_be_exit_0_with_the_summary(checks: ModuleType) -> None:
    for target in ("api", "runner"):
        summary = checks.SMOKE_TARGETS[target][1].format(root="/tmp/smoke")
        checks.check_config_output(target, "/tmp/smoke", 0, summary, "")
        for returncode, stdout, stderr in (
            (1, "", f"opsgate check-config {target}: configuration error: OPSGATE_RUNNER_TOKEN"),
            (1, summary, ""),
            (0, "", ""),
            (0, summary, "warning\n"),
            (0, summary.replace("/tmp/smoke", "/tmp/other"), ""),
            (0, summary.replace("opsgate-release-smoke", "opsgate"), ""),
            (0, summary + "token: release-smoke-runner-token-0000000\n", ""),
        ):
            with pytest.raises(checks.CheckError, match=f"check-config {target} exited"):
                checks.check_config_output(target, "/tmp/smoke", returncode, stdout, stderr)


# The keys of ops-library's roles/opsgate_deploy/templates/opsgate-{api,runner}.env.j2, in order
# (`OPSGATE_` omitted; the openclaw token is optional there and set here).
ROLE_API_ENV = (
    "SERVICE_NAME BIND_HOST BIND_PORT DB_PATH UI_USERNAME UI_PASSWORD_BCRYPT SESSION_SECRET TRUST_PROXY_HEADERS "
    "SESSION_COOKIE_SECURE UI_SESSION_TIMEOUT_SECONDS SUBMIT_TOKEN_OPENCLAW SUBMIT_TOKEN_NYXMON "
    "SUBMIT_TOKEN_OPERATOR RUNNER_TOKEN MAX_PARALLEL_JOBS MAX_DURATION_SECONDS_DEFAULT "
    "POLICY_FLOOR_REQUIRE_REVIEWER_STEP SUBMIT_POLICY_OPENCLAW_REQUIRE_REVIEWER_STEP "
    "SUBMIT_POLICY_NYXMON_REQUIRE_REVIEWER_STEP SUBMIT_POLICY_OPERATOR_REQUIRE_REVIEWER_STEP "
    "REQUIRE_TAILSCALE_CONTEXT ALLOWED_CIDRS EXECUTION_DATA_DIR DISABLE_FILE_PATH"
).split()
ROLE_RUNNER_ENV = (
    "SERVICE_NAME RUNNER_TOKEN RUNNER_API_BASE_URL RUNNER_HOST RUNNER_POLL_INTERVAL_SECONDS "
    "RUNNER_HEARTBEAT_INTERVAL_SECONDS RUNNER_STALE_AFTER_SECONDS MAX_PARALLEL_JOBS MAX_DURATION_SECONDS_DEFAULT "
    "POLICY_FLOOR_REQUIRE_REVIEWER_STEP TMUX_SOCKET_LABEL EXECUTION_DATA_DIR TICKETS_DIR SESSION_ARTIFACTS_DIR "
    "DISABLE_FILE_PATH"
).split()


def env_keys(text: str) -> list[str]:
    return [line.split("=", 1)[0] for line in text.splitlines() if line and not line.startswith("#")]


def test_smoke_env_files_have_the_role_shape(checks: ModuleType) -> None:
    """The variables of the role's env templates (`opsgate-api.env.j2`, `opsgate-runner.env.j2`)."""
    assert env_keys(checks.SMOKE_API_ENV) == [f"OPSGATE_{name}" for name in ROLE_API_ENV]
    assert env_keys(checks.SMOKE_RUNNER_ENV) == [f"OPSGATE_{name}" for name in ROLE_RUNNER_ENV]
    # The runner reaches the API the smoke configuration binds, with the same token.
    assert "OPSGATE_RUNNER_API_BASE_URL=http://127.0.0.1:18711\n" in checks.SMOKE_RUNNER_ENV
    token = "OPSGATE_RUNNER_TOKEN=release-smoke-runner-token-0000000\n"
    assert token in checks.SMOKE_API_ENV and token in checks.SMOKE_RUNNER_ENV
    # Every path lies below the temporary directory.
    for text in (checks.SMOKE_API_ENV, checks.SMOKE_RUNNER_ENV):
        for line in text.splitlines():
            key, _, value = line.partition("=")
            if key.endswith(("_PATH", "_DIR")):
                assert value.startswith("{root}/"), line


def test_archive_is_deterministic_and_holds_binary_and_license(checks: ModuleType) -> None:
    binary, license_text = b"\xcf\xfa\xed\xfe binary", b"MIT License\n"
    first = checks.build_archive(binary, license_text, 1_700_000_000)
    assert first == checks.build_archive(binary, license_text, 1_700_000_000)
    assert first != checks.build_archive(binary, license_text, 1_700_000_001)
    checks.verify_archive(first, binary, license_text)
    # gzip header: no FNAME flag, the given mtime.
    assert first[3] & 0x08 == 0
    assert int.from_bytes(first[4:8], "little") == 1_700_000_000
    with tarfile.open(fileobj=io.BytesIO(first), mode="r:gz") as archive:
        members = {member.name: member for member in archive.getmembers()}
    assert set(members) == {"LICENSE", "opsgate"}
    assert members["opsgate"].mode == 0o755
    assert members["LICENSE"].mode == 0o644
    assert {(m.uid, m.gid, m.uname, m.gname, m.mtime) for m in members.values()} == {
        (0, 0, "root", "root", 1_700_000_000)
    }
    with pytest.raises(checks.CheckError, match="differs from its source"):
        checks.verify_archive(first, b"other", license_text)
    assert checks.archive_name("0.3.0", "aarch64-apple-darwin") == "opsgate-0.3.0-aarch64-apple-darwin.tar.gz"


def run_script(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - the script under test
        [sys.executable, "-I", str(SCRIPT), *args],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def test_cli_version_and_tag(tmp_path: Path) -> None:
    path = tmp_path / "metadata.json"
    path.write_text(json.dumps(metadata(("opsgate-core", "0.3.0"), ("opsgate", "0.3.0"))), encoding="utf-8")
    result = run_script("version", "--metadata", str(path), "--tag", "rs-v0.3.0")
    assert (result.returncode, result.stdout) == (0, "0.3.0\n")
    result = run_script("version", "--metadata", str(path))
    assert (result.returncode, result.stdout) == (0, "0.3.0\n")
    result = run_script("version", "--metadata", str(path), "--tag", "rs-v0.4.0")
    assert result.returncode == 1
    assert "release check failed: tag 'rs-v0.4.0'" in result.stderr


def test_cli_pack_writes_archive_and_checksum_line(tmp_path: Path) -> None:
    binary = tmp_path / "opsgate"
    binary.write_bytes(b"binary")
    license_path = tmp_path / "LICENSE"
    license_path.write_bytes(b"MIT\n")
    out = tmp_path / "dist"
    result = run_script(
        "pack",
        "--binary",
        str(binary),
        "--license",
        str(license_path),
        "--version",
        "0.3.0",
        "--target",
        "aarch64-apple-darwin",
        "--mtime",
        "1700000000",
        "--out-dir",
        str(out),
    )
    name = "opsgate-0.3.0-aarch64-apple-darwin.tar.gz"
    assert (result.returncode, result.stdout) == (0, f"{name}\n")
    data = (out / name).read_bytes()
    assert (out / f"{name}.sha256").read_text(encoding="utf-8") == f"{hashlib.sha256(data).hexdigest()}  {name}\n"


# A stand-in for the binary: `--version` as the release build prints it;
# `check-config` passes only with a cleared environment (nothing but
# `OPSGATE_ENV_FILE`) and an env file of mode 0600 that holds the smoke
# configuration, and prints what `opsgate check-config` prints for it.
FAKE_BINARY = """#!/bin/sh
case "$1" in
--version) echo 'opsgate 0.3.0 ({commit})' ;;
check-config)
  [ -z "${{HOME+x}}" ] && [ -z "${{OPSGATE_DB_PATH+x}}" ] || {{ echo "environment not cleared" >&2; exit 1; }}
  [ "$(stat -c %a "$OPSGATE_ENV_FILE" 2>/dev/null || stat -f %Lp "$OPSGATE_ENV_FILE")" = 600 ] || exit 1
  root=$(dirname "$OPSGATE_ENV_FILE")
  value() {{ sed -n "s/^$1=//p" "$OPSGATE_ENV_FILE"; }}
  echo "opsgate check-config $2: ok"
  echo "service_name: $(value OPSGATE_SERVICE_NAME)"
  case "$2" in
  api)
    echo "bind: $(value OPSGATE_BIND_HOST):$(value OPSGATE_BIND_PORT)"
    echo "db_path: $(value OPSGATE_DB_PATH)"
    echo "execution_data_dir: $(value OPSGATE_EXECUTION_DATA_DIR)"
    ;;
  runner)
    echo "runner_host: $(value OPSGATE_RUNNER_HOST)"
    echo "execution_data_dir: $(value OPSGATE_EXECUTION_DATA_DIR)"
    echo "tmux_socket_label: $(value OPSGATE_TMUX_SOCKET_LABEL)"
    ;;
  *) exit 2 ;;
  esac
  echo "disable_file_path: $(value OPSGATE_DISABLE_FILE_PATH)"
  {extra}
  exit 0
  ;;
*) exit 2 ;;
esac
"""


def fake_binary(tmp_path: Path, extra: str = ":") -> Path:
    fake = tmp_path / "opsgate"
    fake.write_text(FAKE_BINARY.format(commit=COMMIT, extra=extra), encoding="utf-8")
    fake.chmod(0o755)
    return fake


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell script fake")
def test_cli_smoke_runs_version_and_both_check_configs(tmp_path: Path) -> None:
    base = ["smoke", "--binary", str(fake_binary(tmp_path)), "--version"]
    result = run_script(*base, "0.3.0", "--commit", COMMIT)
    assert (result.returncode, result.stderr) == (0, "")
    lines = result.stdout.splitlines()
    assert lines[0] == f"opsgate 0.3.0 ({COMMIT})"
    assert lines[1] == "opsgate check-config api: ok"
    assert "opsgate check-config runner: ok" in lines
    assert "runner_host: release-smoke-runner" in lines
    assert run_script(*base, "0.3.1", "--commit", COMMIT).returncode == 1
    result = run_script(*base, "0.3.0", "--commit", COMMIT[:12])
    assert result.returncode == 1
    assert "40 or 64 lowercase hex digits" in result.stderr
    assert run_script(*base, "0.3.0", "--commit", COMMIT.upper()).returncode == 1


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell script fake")
@pytest.mark.parametrize(
    ("extra", "message"),
    [
        ('mkdir "$root/run"', "check-config api created ['run']"),
        ('[ "$2" = runner ] && { echo "token: secret"; }', "check-config runner exited 0"),
        ('echo "note" >&2', "check-config api exited 0"),
        ('[ "$2" = runner ] && exit 1', "check-config runner exited 1"),
    ],
)
def test_cli_smoke_fails_when_check_config_misbehaves(tmp_path: Path, extra: str, message: str) -> None:
    fake = fake_binary(tmp_path, extra)
    result = run_script("smoke", "--binary", str(fake), "--version", "0.3.0", "--commit", COMMIT)
    assert result.returncode == 1
    assert f"release check failed: {message}" in result.stderr


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell script fakes")
def test_cli_macho_runs_every_tool(tmp_path: Path) -> None:
    """`macho` calls otool, vtool, lipo and codesign from PATH and reports each check."""
    tools = tmp_path / "bin"
    tools.mkdir()
    outputs = {
        "otool": ("stdout", OTOOL_OK),
        "vtool": ("stdout", VTOOL_OK),
        "lipo": ("stdout", "arm64\n"),
        "codesign": ("stderr", CODESIGN_OK),
    }
    calls = tmp_path / "calls"
    for tool, (stream, text) in outputs.items():
        (tools / f"{tool}.out").write_text(text, encoding="utf-8")
        redirect = " >&2" if stream == "stderr" else ""
        script = f'#!/bin/sh\necho "{tool} $*" >> "{calls}"\ncat "{tools}/{tool}.out"{redirect}\n'
        (tools / tool).write_text(script, encoding="utf-8")
        (tools / tool).chmod(0o755)
    env = {"PATH": f"{tools}:/usr/bin:/bin"}
    result = run_script("macho", "--max-minos", "14.0", "--arch", "arm64", "opsgate", env=env)
    assert (result.returncode, result.stderr) == (0, "")
    assert result.stdout == (
        "opsgate: linked libraries /usr/lib/libiconv.2.dylib, /usr/lib/libSystem.B.dylib\n"
        "opsgate: minos 14.0 (at most 14.0)\n"
        "opsgate: architectures arm64\n"
        "opsgate: ad-hoc linker signature verified\n"
    )
    assert calls.read_text(encoding="utf-8").splitlines() == [
        "otool -L opsgate",
        "vtool -show-build opsgate",
        "lipo -archs opsgate",
        "codesign --verify --strict opsgate",
        "codesign -d --verbose=2 opsgate",
    ]
    # A failing tool fails the check with its output.
    (tools / "codesign").write_text('#!/bin/sh\necho "invalid signature" >&2\nexit 1\n', encoding="utf-8")
    result = run_script("macho", "--max-minos", "14.0", "--arch", "arm64", "opsgate", env=env)
    assert result.returncode == 1
    assert "codesign --verify --strict opsgate exited 1: invalid signature" in result.stderr
    result = run_script("macho", "--max-minos", "13.0", "--arch", "arm64", "opsgate", env=env)
    assert result.returncode == 1
    assert "requires macOS 14.0, newer than 13.0" in result.stderr


def test_release_workflow_runs_every_check() -> None:
    workflow = (REPO / ".github" / "workflows" / "rust-release.yml").read_text(encoding="utf-8")
    for needle in (
        "runs-on: macos-15",
        "TARGET: aarch64-apple-darwin",
        'MACOSX_DEPLOYMENT_TARGET: "14.0"',
        '- "rs-v*"',
        "workflow_dispatch:",
        "OPSGATE_GIT_COMMIT: ${{ github.sha }}",
        "release_checks.py version",
        "release_checks.py macho",
        '--max-minos "$MACOSX_DEPLOYMENT_TARGET" --arch arm64',
        "release_checks.py smoke",
        "release_checks.py pack",
        "--license ../LICENSE",
        "cargo fmt --all --check",
        "cargo clippy --workspace --all-targets --locked -- -D warnings",
        "cargo test --workspace --locked",
        'cargo build --release --locked --target "$TARGET"',
        'OPSGATE_REQUIRE_TMUX: "1"',
        "shasum -a 256 --check",
        "sha256sum --check",
        "--verify-tag",
        "--prerelease",
        "contents: write",
    ):
        assert needle in workflow, needle
    assert "actions/cache" not in workflow
    # Only the release job may write; every action is pinned to a commit.
    writes = [number for number, line in enumerate(workflow.splitlines()) if line.strip() == "contents: write"]
    assert len(writes) == 1
    assert writes[0] > workflow.splitlines().index("  release:")
    for line in workflow.splitlines():
        if "uses:" in line:
            assert re.search(r"uses: [\w./-]+@[0-9a-f]{40} # v", line), line
