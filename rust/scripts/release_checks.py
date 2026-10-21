#!/usr/bin/env python3
"""Release checks for the Rust port (rust/PLAN.md section 9).

Used by `.github/workflows/rust-release.yml` on macOS; stdlib only and Python
3.11 compatible. The pure parts are tested in
`tests/test_rust_release_checks.py`. Adapted from
`mailgun-relay:rust/scripts/release_checks.py` for a Mach-O target.

Subcommands:

- ``version``: print the version of the ``opsgate`` package from
  ``cargo metadata`` JSON; with ``--tag`` also require the tag to be
  ``rs-v<that version>``.
- ``macho``: inspect the release binary with the Xcode tools: every library
  ``otool -L`` lists lies below ``/usr/lib/`` or ``/System/Library/``;
  ``vtool -show-build`` names macOS with a ``minos`` of at most ``--max-minos``;
  ``lipo -archs`` is exactly ``--arch``; ``codesign --verify --strict`` passes
  and ``codesign -d`` shows the ad-hoc linker signature (intact after strip).
- ``smoke``: run ``<binary> --version`` and require exactly
  ``opsgate <version> (<commit>)``; then run ``<binary> check-config api`` and
  ``<binary> check-config runner`` with only ``OPSGATE_ENV_FILE`` set, pointing
  at a test env file in the shape of the role's templates (mode 0600, no real
  secrets), and require exit 0 with the summary those files give and nothing
  created next to them.
- ``pack``: write ``opsgate-<version>-<target>.tar.gz`` (binary and LICENSE at
  the archive root, owner root, fixed mtime, gzip without a file name) and its
  ``.sha256`` file.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any

PACKAGE = "opsgate"
TAG_PREFIX = "rs-v"

# Semantic Versioning 2.0.0 (the regex of semver.org without build metadata:
# a `+` in the tag would end up in the release download URL).
SEMVER = re.compile(
    r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
)
# build.rs accepts a full SHA-1 (40) or SHA-256 (64) object name.
COMMIT = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")

# PLAN.md 9: no dynamic libraries outside the system's own (rustls is not
# needed, SQLite is bundled).
ALLOWED_LIBRARY_PREFIXES = ("/usr/lib/", "/System/Library/")
REQUIRED_LIBRARY = "/usr/lib/libSystem.B.dylib"

# `otool -L` entry: `<tab><path> (compatibility version x, current version y)`.
OTOOL_ENTRY = re.compile(r"^\s+(\S.*?) \(compatibility version [^)]*\)\s*$")
# `vtool -show-build` fields of an LC_BUILD_VERSION load command.
VTOOL_CMD = re.compile(r"^\s*cmd\s+(\S+)\s*$", re.MULTILINE)
VTOOL_PLATFORM = re.compile(r"^\s*platform\s+(\S+)\s*$", re.MULTILINE)
VTOOL_MINOS = re.compile(r"^\s*minos\s+(\S+)\s*$", re.MULTILINE)
# `codesign -d --verbose=2` (written to stderr): signature kind and flags.
CODESIGN_SIGNATURE = re.compile(r"^Signature=(.+)$", re.MULTILINE)
CODESIGN_FLAGS = re.compile(r"^CodeDirectory .*\bflags=0x[0-9a-f]+\(([^)]*)\)", re.MULTILINE)

# `check-config` smoke test: the variables of the role's `opsgate-api.env.j2`
# and `opsgate-runner.env.j2` with test values (no real token, secret or
# password hash) that differ from the defaults, so the summary proves the file
# was read. `{root}` is the temporary directory; nothing below it may appear.
SMOKE_API_ENV = """\
# Release smoke test (rust/scripts/release_checks.py); no real credentials.
OPSGATE_SERVICE_NAME=opsgate-release-smoke
OPSGATE_BIND_HOST=127.0.0.1
OPSGATE_BIND_PORT=18711
OPSGATE_DB_PATH={root}/run/opsgate.sqlite3
OPSGATE_UI_USERNAME=release-smoke
OPSGATE_UI_PASSWORD_BCRYPT=$2b$12$release.smoke.test.not.a.real.bcrypt.hash.xxxxxxxxxxx
OPSGATE_SESSION_SECRET=release-smoke-session-secret-0000000000
OPSGATE_TRUST_PROXY_HEADERS=false
OPSGATE_SESSION_COOKIE_SECURE=true
OPSGATE_UI_SESSION_TIMEOUT_SECONDS=28800
OPSGATE_SUBMIT_TOKEN_OPENCLAW=release-smoke-openclaw-token-0000
OPSGATE_SUBMIT_TOKEN_NYXMON=release-smoke-nyxmon-token-000000
OPSGATE_SUBMIT_TOKEN_OPERATOR=release-smoke-operator-token-0000
OPSGATE_RUNNER_TOKEN=release-smoke-runner-token-0000000
OPSGATE_MAX_PARALLEL_JOBS=2
OPSGATE_MAX_DURATION_SECONDS_DEFAULT=3600
OPSGATE_POLICY_FLOOR_REQUIRE_REVIEWER_STEP=false
OPSGATE_SUBMIT_POLICY_OPENCLAW_REQUIRE_REVIEWER_STEP=true
OPSGATE_SUBMIT_POLICY_NYXMON_REQUIRE_REVIEWER_STEP=true
OPSGATE_SUBMIT_POLICY_OPERATOR_REQUIRE_REVIEWER_STEP=false
OPSGATE_REQUIRE_TAILSCALE_CONTEXT=true
OPSGATE_ALLOWED_CIDRS=100.64.0.0/10,127.0.0.1/32,::1/128
OPSGATE_EXECUTION_DATA_DIR={root}/execution
OPSGATE_DISABLE_FILE_PATH={root}/execution/.disabled
"""
SMOKE_RUNNER_ENV = """\
# Release smoke test (rust/scripts/release_checks.py); no real credentials.
OPSGATE_SERVICE_NAME=opsgate-release-smoke
OPSGATE_RUNNER_TOKEN=release-smoke-runner-token-0000000
OPSGATE_RUNNER_API_BASE_URL=http://127.0.0.1:18711
OPSGATE_RUNNER_HOST=release-smoke-runner
OPSGATE_RUNNER_POLL_INTERVAL_SECONDS=5
OPSGATE_RUNNER_HEARTBEAT_INTERVAL_SECONDS=30
OPSGATE_RUNNER_STALE_AFTER_SECONDS=120
OPSGATE_MAX_PARALLEL_JOBS=2
OPSGATE_MAX_DURATION_SECONDS_DEFAULT=3600
OPSGATE_POLICY_FLOOR_REQUIRE_REVIEWER_STEP=false
OPSGATE_TMUX_SOCKET_LABEL=opsgate-release-smoke
OPSGATE_EXECUTION_DATA_DIR={root}/execution
OPSGATE_TICKETS_DIR={root}/execution/tickets
OPSGATE_SESSION_ARTIFACTS_DIR={root}/execution/sessions
OPSGATE_DISABLE_FILE_PATH={root}/execution/.disabled
"""
SMOKE_API_OUTPUT = """\
opsgate check-config api: ok
service_name: opsgate-release-smoke
bind: 127.0.0.1:18711
db_path: {root}/run/opsgate.sqlite3
execution_data_dir: {root}/execution
disable_file_path: {root}/execution/.disabled
"""
SMOKE_RUNNER_OUTPUT = """\
opsgate check-config runner: ok
service_name: opsgate-release-smoke
runner_host: release-smoke-runner
execution_data_dir: {root}/execution
tmux_socket_label: opsgate-release-smoke
disable_file_path: {root}/execution/.disabled
"""
SMOKE_TARGETS = {
    "api": (SMOKE_API_ENV, SMOKE_API_OUTPUT),
    "runner": (SMOKE_RUNNER_ENV, SMOKE_RUNNER_OUTPUT),
}


class CheckError(Exception):
    """A release check failed; the message is the reason."""


def parse_macos_version(text: str) -> tuple[int, int, int]:
    """`14.0` → (14, 0, 0); anything but one to three dot-separated decimals is an error."""
    if not re.fullmatch(r"\d+(?:\.\d+){0,2}", text):
        raise CheckError(f"not a macOS version: {text!r}")
    parts = [int(part) for part in text.split(".")]
    parts += [0] * (3 - len(parts))
    return parts[0], parts[1], parts[2]


def package_version(metadata: dict[str, Any]) -> str:
    """The `opsgate` version from `cargo metadata --no-deps` output."""
    versions = [package["version"] for package in metadata.get("packages", []) if package.get("name") == PACKAGE]
    if len(versions) != 1:
        raise CheckError(f"expected one {PACKAGE} package in cargo metadata, found {len(versions)}")
    version = versions[0]
    if not isinstance(version, str) or not SEMVER.fullmatch(version):
        raise CheckError(f"{PACKAGE} version {version!r} is not semver (without build metadata)")
    return version


def check_tag(tag: str, version: str) -> None:
    expected = f"{TAG_PREFIX}{version}"
    if tag != expected:
        raise CheckError(f"tag {tag!r} does not match the {PACKAGE} version: expected {expected!r}")


def linked_libraries(otool_text: str) -> list[str]:
    """The install names `otool -L` lists (the header line is skipped)."""
    libraries = []
    for line in otool_text.splitlines():
        match = OTOOL_ENTRY.match(line)
        if match:
            libraries.append(match.group(1))
    return libraries


def check_libraries(otool_text: str) -> list[str]:
    """Every linked library is a system library; return them."""
    libraries = linked_libraries(otool_text)
    if REQUIRED_LIBRARY not in libraries:
        raise CheckError(f"{REQUIRED_LIBRARY} not among the linked libraries {libraries}: not an otool -L listing?")
    foreign = [library for library in libraries if not library.startswith(ALLOWED_LIBRARY_PREFIXES)]
    if foreign:
        raise CheckError(f"binary links to libraries outside /usr/lib and /System/Library: {', '.join(foreign)}")
    return libraries


def check_minos(vtool_text: str, maximum: str) -> str:
    """One LC_BUILD_VERSION for macOS with `minos` at most `maximum`; return it."""
    limit = parse_macos_version(maximum)
    commands = VTOOL_CMD.findall(vtool_text)
    platforms = VTOOL_PLATFORM.findall(vtool_text)
    minos = VTOOL_MINOS.findall(vtool_text)
    if commands != ["LC_BUILD_VERSION"] or len(platforms) != 1 or len(minos) != 1:
        raise CheckError(
            f"expected exactly one LC_BUILD_VERSION with platform and minos, found commands {commands}, "
            f"platforms {platforms}, minos {minos}"
        )
    if platforms[0] != "MACOS":
        raise CheckError(f"build platform is {platforms[0]}, expected MACOS")
    if parse_macos_version(minos[0]) > limit:
        raise CheckError(f"binary requires macOS {minos[0]}, newer than {maximum}")
    return minos[0]


def check_archs(lipo_text: str, expected: str) -> None:
    archs = lipo_text.split()
    if archs != [expected]:
        raise CheckError(f"lipo -archs reports {archs}, expected exactly [{expected!r}]")


def check_signature(codesign_details: str) -> None:
    """`codesign -d --verbose=2` shows an ad-hoc signature made by the linker."""
    signatures = CODESIGN_SIGNATURE.findall(codesign_details)
    flags = CODESIGN_FLAGS.findall(codesign_details)
    if signatures != ["adhoc"]:
        raise CheckError(f"code signature is {signatures}, expected the ad-hoc linker signature")
    if len(flags) != 1 or not {"adhoc", "linker-signed"} <= {flag.strip() for flag in flags[0].split(",")}:
        raise CheckError(f"code directory flags {flags}, expected adhoc and linker-signed")


def check_version_output(stdout: str, version: str, commit: str) -> None:
    expected = f"{PACKAGE} {version} ({commit})\n"
    if stdout != expected:
        raise CheckError(f"--version printed {stdout!r}, expected {expected!r}")


def check_config_output(target: str, root: str, returncode: int, stdout: str, stderr: str) -> None:
    expected = SMOKE_TARGETS[target][1].format(root=root)
    if returncode != 0 or stdout != expected or stderr != "":
        raise CheckError(
            f"check-config {target} exited {returncode} with stdout {stdout!r} and stderr "
            f"{stderr!r}, expected exit 0, {expected!r} and no stderr"
        )


def run_check_config(binary: Path, target: str) -> str:
    """Run `check-config <target>` against a test env file; return its stdout."""
    with tempfile.TemporaryDirectory(prefix="opsgate-smoke-") as directory:
        root = os.path.realpath(directory)
        env_file = Path(root) / f"opsgate-{target}.env"
        descriptor = os.open(env_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(SMOKE_TARGETS[target][0].format(root=root))
        result = subprocess.run(  # noqa: S603 - the binary under test
            [str(binary), "check-config", target],
            env={"OPSGATE_ENV_FILE": str(env_file)},
            capture_output=True,
            text=True,
            check=False,
        )
        check_config_output(target, root, result.returncode, result.stdout, result.stderr)
        left = sorted(path.name for path in Path(root).iterdir())
        if left != [env_file.name]:
            raise CheckError(f"check-config {target} created {sorted(set(left) - {env_file.name})}")
    return result.stdout


def archive_name(version: str, target: str) -> str:
    return f"{PACKAGE}-{version}-{target}.tar.gz"


def _tar_member(name: str, data: bytes, mode: int, mtime: int) -> tuple[tarfile.TarInfo, io.BytesIO]:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    info.mtime = mtime
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    info.type = tarfile.REGTYPE
    return info, io.BytesIO(data)


def build_archive(binary: bytes, license_text: bytes, mtime: int) -> bytes:
    """Deterministic tar.gz with `LICENSE` (0644) and `opsgate` (0755)."""
    tar_bytes = io.BytesIO()
    with tarfile.open(fileobj=tar_bytes, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for name, data, mode in (
            ("LICENSE", license_text, 0o644),
            (PACKAGE, binary, 0o755),
        ):
            archive.addfile(*_tar_member(name, data, mode, mtime))
    compressed = io.BytesIO()
    # filename="" and a fixed mtime keep the gzip header reproducible.
    with gzip.GzipFile(filename="", mode="wb", fileobj=compressed, compresslevel=9, mtime=mtime) as gz:
        gz.write(tar_bytes.getvalue())
    return compressed.getvalue()


def verify_archive(data: bytes, binary: bytes, license_text: bytes) -> None:
    """Read the archive back: exactly the two files, contents and modes."""
    expected = {"LICENSE": (license_text, 0o644), PACKAGE: (binary, 0o755)}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        if sorted(names) != sorted(expected):
            raise CheckError(f"archive members {names}, expected {sorted(expected)}")
        for member in members:
            content, mode = expected[member.name]
            if not member.isreg() or member.mode != mode:
                raise CheckError(f"archive member {member.name} has mode {oct(member.mode)}")
            extracted = archive.extractfile(member)
            if extracted is None or extracted.read() != content:
                raise CheckError(f"archive member {member.name} differs from its source")


def checksum_line(data: bytes, name: str) -> str:
    """`shasum -a 256` / `sha256sum` output format: `<hex>  <name>\\n`."""
    return f"{hashlib.sha256(data).hexdigest()}  {name}\n"


def _tool(*command: str) -> subprocess.CompletedProcess[str]:
    """Run an Xcode tool from PATH; a failure is a check failure with its output."""
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)  # noqa: S603
    except OSError as error:
        raise CheckError(f"cannot run {command[0]}: {error}") from None
    if result.returncode != 0:
        output = " ".join(text.strip() for text in (result.stdout, result.stderr) if text.strip())
        raise CheckError(f"{' '.join(command)} exited {result.returncode}: {output}")
    return result


def check_macho(binary: Path, max_minos: str, arch: str) -> list[str]:
    """Run every Mach-O check on `binary`; return the report lines."""
    path = str(binary)
    libraries = check_libraries(_tool("otool", "-L", path).stdout)
    minos = check_minos(_tool("vtool", "-show-build", path).stdout, max_minos)
    check_archs(_tool("lipo", "-archs", path).stdout, arch)
    _tool("codesign", "--verify", "--strict", path)
    # `codesign -d` writes its details to stderr.
    check_signature(_tool("codesign", "-d", "--verbose=2", path).stderr)
    return [
        f"{path}: linked libraries {', '.join(libraries)}",
        f"{path}: minos {minos} (at most {max_minos})",
        f"{path}: architectures {arch}",
        f"{path}: ad-hoc linker signature verified",
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)

    version = commands.add_parser("version")
    version.add_argument("--metadata", type=Path, required=True, help="cargo metadata JSON file")
    version.add_argument("--tag", help="release tag that must match the version")

    macho = commands.add_parser("macho")
    macho.add_argument("--max-minos", required=True, help="highest allowed minimum macOS version, e.g. 14.0")
    macho.add_argument("--arch", required=True, help="the only architecture allowed, e.g. arm64")
    macho.add_argument("binary", type=Path)

    smoke = commands.add_parser("smoke")
    smoke.add_argument("--binary", type=Path, required=True)
    smoke.add_argument("--version", required=True)
    smoke.add_argument("--commit", required=True, help="full commit (40 or 64 lowercase hex digits)")

    pack = commands.add_parser("pack")
    pack.add_argument("--binary", type=Path, required=True)
    pack.add_argument("--license", type=Path, required=True)
    pack.add_argument("--version", required=True)
    pack.add_argument("--target", required=True)
    pack.add_argument("--mtime", type=int, required=True, help="Unix time for all entries")
    pack.add_argument("--out-dir", type=Path, required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "version":
            metadata = json.loads(args.metadata.read_text(encoding="utf-8"))
            found = package_version(metadata)
            if args.tag is not None:
                check_tag(args.tag, found)
            print(found)
        elif args.command == "macho":
            for line in check_macho(args.binary, args.max_minos, args.arch):
                print(line)
        elif args.command == "smoke":
            if not COMMIT.fullmatch(args.commit):
                raise CheckError(f"--commit must be 40 or 64 lowercase hex digits, got {args.commit!r}")
            result = subprocess.run(  # noqa: S603 - the binary under test
                [str(args.binary), "--version"],
                env={},
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                raise CheckError(f"--version exited {result.returncode}: {result.stderr.strip()}")
            check_version_output(result.stdout, args.version, args.commit)
            print(result.stdout, end="")
            for target in SMOKE_TARGETS:
                print(run_check_config(args.binary, target), end="")
        else:
            binary = args.binary.read_bytes()
            license_text = args.license.read_bytes()
            name = archive_name(args.version, args.target)
            data = build_archive(binary, license_text, args.mtime)
            verify_archive(data, binary, license_text)
            args.out_dir.mkdir(parents=True, exist_ok=True)
            (args.out_dir / name).write_bytes(data)
            (args.out_dir / f"{name}.sha256").write_text(checksum_line(data, name), encoding="utf-8")
            print(name)
    except CheckError as error:
        print(f"release check failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
