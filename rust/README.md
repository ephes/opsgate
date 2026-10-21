# OpsGate Rust port

A Rust port of both long-running OpsGate processes (`python -m opsgate serve`
and `python -m opsgate runner`) as one binary, `opsgate`. The contract, the
intentional divergences and the slices are in [`PLAN.md`](PLAN.md); the
mapping of every Python test to its Rust test is in [`TESTMAP.md`](TESTMAP.md).

**Status:** foundations (slice S1) and part of the core library (S2a:
canonical JSON and the payload checksum, stored-JSON text, Python `str()`
and `lower`, timestamps; S2b: settings, log previews, path containment, proxy
header selection). The workspace, CI, the fixture generator and the
command-line skeleton exist; every command is still a stub that exits 2. The Python package in `src/opsgate` is the production
implementation and the oracle for the contract. Nothing deploys or runs this
code yet.

## Layout

```
rust/
  Cargo.toml            workspace (version 0.3.0; Python is 0.2.0)
  Cargo.lock            committed; every build uses --locked
  rust-toolchain.toml   pinned toolchain 1.99.0 (also the MSRV)
  deny.toml             cargo-deny policy (licenses, advisories, sources)
  crates/
    opsgate-core/       pure logic: settings, JSON canon/checksum, time, validation, log preview, path containment (S2a-S2c)
    opsgate-store/      SQLite store, check-db (S3a, S3b)
    opsgate-web/        HTTP API and web UI (S4a, S4b, S5)
    opsgate-runner/     runner (S6a, S6b)
    opsgate/            the binary: command line, build.rs (embeds the git commit)
  fixtures/
    generate.py         writes the fixtures from the Python implementation
    schema.sql          sqlite_master of a Python-initialised database (4.10)
    settings.json       settings and env-file cases (4.2)
    log_preview.json    log preview and step log cases (4.12)
    proxy_fix.json      proxy header cases (4.4)
    checksum.json       canonical JSON text and payload checksums (4.8)
    float_repr.json     CPython float repr and number tokens (4.8)
    storage_json.json   stored JSON column text (4.8)
    datetime.json       timestamp parsing and formatting, Python 3.14 (4.9)
    pystr.json          str() of JSON scalars, strip, lower (4.6)
```

`opsgate-core` has the modules of S2a: `json` (parsing like `json.loads`,
the checksum and stored-JSON formatter, depth check, PLAN.md 4.6/4.8) and
`time` (`utc_now`, `isoformat_z`, `parse_iso_datetime`, 4.9); of S2b:
`settings` (env file, API and runner settings, 4.2), `log_preview` (4.12),
`paths` (step-log containment, 4.12) and `proxy_fix` (4.4); and `pytext`
(Python's `str.strip` whitespace, `splitlines` boundaries, `str()` of JSON
scalars and `lower`). The other library crates are empty
until their slices land. Every crate forbids
`unsafe` code (workspace lint).

## Toolchain

Install [rustup](https://rustup.rs); `rust-toolchain.toml` selects 1.99.0
with rustfmt and clippy (`rustup toolchain install` inside `rust/`). A `cargo`
that is not the rustup proxy (for example Homebrew's) ignores the pin, so put
`~/.cargo/bin` first on `PATH`. `just rs-deny` needs
[cargo-deny](https://github.com/EmbarkStudios/cargo-deny) 0.20.2 on `PATH`.

## Recipes

Run from the repository root:

| Recipe | What it does |
| --- | --- |
| `just rs-check` | `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --locked` |
| `just rs-test` | `cargo test --workspace --locked` |
| `just rs-deny` | `cargo deny --locked check` against `deny.toml` |
| `just rs-fmt` | `cargo fmt --all` |
| `just rs-fixtures` | regenerate `rust/fixtures` from the Python implementation |
| `just rs-build` | release build for this host (`rust/target/release/opsgate`) |

The parity harnesses get their recipes (`rs-parity-api`, `rs-parity-runner`)
with slices S7a and S7b. `just check` stays the Python check.

## CI

The `rust` job of `.github/workflows/ci.yml` runs on `ubuntu-latest` and
`macos-15`: rustfmt, clippy, `cargo deny --locked check` (pinned, sha256
verified cargo-deny release), `cargo test --locked`, a release build, a
`--version` smoke test (version and the checked-out commit) and the release
binary size in the job summary. The fixture drift test runs in the Python job
as part of pytest.

## Fixtures

`fixtures/generate.py` imports `opsgate` and calls the real Python code on a
fixed corpus (PLAN.md 7.2). Fixtures are never edited by hand:

```bash
just rs-fixtures                                     # rewrite every fixture
uv run python rust/fixtures/generate.py --check      # exit 1 on drift
```

`tests/test_rust_fixtures.py` (pytest, so `just test` and the Python CI job)
regenerates every fixture in memory and fails when a committed file differs,
also on whitespace. A Python change that alters a fixture must regenerate it
in the same change; the Rust tests then show what to port. Each slice adds its
builders to `GENERATORS` in `generate.py`.

`datetime.json` depends on the CPython minor version (`fromisoformat`
changed after 3.11) and is generated and checked only by the production
interpreter, Python 3.14 (`PYTHON_GATED` in `generate.py`). Other versions
print `skipped fixture: datetime.json ...` and leave it alone; the 3.14 leg of
the Python CI job checks it. Regenerate it with:

```bash
UV_PYTHON=3.14 just rs-fixtures
```

| Fixture | Content | Used by |
| --- | --- | --- |
| `checksum.json` | JSON text → canonical text and `compute_payload_checksum` (552 inputs, production-shaped and adversarial; D-2 marked) | `opsgate-core/tests/checksum_fixture.rs` |
| `datetime.json` | `parse_iso_datetime` inputs → `isoformat_z` result or rejection (D-7 marked), `isoformat_z` of UTC components; Python 3.14 only | `opsgate-core/tests/datetime_fixture.rs` |
| `float_repr.json` | `repr(float)` of 10 471 doubles by bit pattern; number tokens → `repr(float(token))` | `opsgate-core/tests/float_repr_fixture.rs` |
| `log_preview.json` | file contents (as recipes) and limits → `read_tail_lines` preview lines and `read_step_log` text (long step logs by SHA-256, length, head and tail) | `opsgate-core/tests/log_preview_fixture.rs` |
| `proxy_fix.json` | request header lines → client address, scheme and `Host` the app sees in production (waitress's proxy-header middleware around the Flask app with and without `ProxyFix`): forwarded headers never apply | `opsgate-core/tests/proxy_fix_fixture.rs` |
| `pystr.json` | `str()` of JSON scalars (D-2/D-3 marked), `strip`, `lower`, Python's whitespace set, non-ASCII characters whose lowercase is ASCII | `opsgate-core/tests/pystr_fixture.rs` |
| `schema.sql` | `sqlite_master` of a database initialised by `OpsGateService.init_db`, tables then indexes; runs as one script | schema contract test (S3a) |
| `settings.json` | environment sets (with optional env file) → `load_settings` / `load_runner_settings` result or error, plus `load_env_file` parsing cases; `rust_error` gives the Rust message where Python fails with a traceback or diverges (D-8, D-10) | `opsgate-core/tests/settings_fixture.rs` |
| `storage_json.json` | JSON text → stored column text `json.dumps(value, sort_keys=True)` | `opsgate-core/tests/checksum_fixture.rs` |

## Command line

```
opsgate serve [--db PATH] [--bind-host HOST] [--bind-port PORT]
opsgate runner [--once]
opsgate check-config api|runner
opsgate check-db --db PATH
opsgate --version
```

No command (plain `opsgate`) means `serve` without overrides, as with
`python -m opsgate`; the overrides need the `serve` command. Until their slices
land, the commands print `opsgate <command>: not implemented yet` on stderr and
exit 2; usage errors also exit 2. `opsgate --version` prints
`opsgate <version> (<full commit>)`. `build.rs` takes the commit from
`OPSGATE_GIT_COMMIT` (40 or 64 lowercase hex digits; the release workflow sets
it), else from `git rev-parse HEAD`, else `unknown`, and records the choice in
`OPSGATE_GIT_COMMIT_SOURCE` (`env`, `git`, `none`) for the tests.
