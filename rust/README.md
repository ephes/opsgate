# OpsGate Rust port

A Rust port of both long-running OpsGate processes (`python -m opsgate serve`
and `python -m opsgate runner`) as one binary, `opsgate`. The contract, the
intentional divergences and the slices are in [`PLAN.md`](PLAN.md); the
mapping of every Python test to its Rust test is in [`TESTMAP.md`](TESTMAP.md).

**Status:** foundations (slice S1) and part of the core library (S2a:
canonical JSON and the payload checksum, stored-JSON text, Python `str()`
and `lower`, timestamps; S2b: settings, log previews, path containment, proxy
header selection; S2c: ticket validation), the first half of the SQLite store
(S3a: schema, ticket creation, get/list, health, session generation and
`check-db`), the runner (S6a: API client, tmux adapter, artifacts, agent
commands and the ticket executor; S6b: the supervisor and the `opsgate runner
[--once]` command), the black-box API parity harness (S7a, green against
Python) and the black-box runner parity harness (S7b, green against the
Python runner and, run locally, against the Rust runner). The workspace, CI,
the fixture generator and the command-line skeleton exist; `check-db` and
`runner` work, every other command is still a stub that exits 2. The Python
package in `src/opsgate` is the production implementation and the oracle for
the contract. Nothing deploys or runs this code yet.

## Layout

```
rust/
  Cargo.toml            workspace (version 0.3.0; Python is 0.2.0)
  Cargo.lock            committed; every build uses --locked
  rust-toolchain.toml   pinned toolchain 1.99.0 (also the MSRV)
  deny.toml             cargo-deny policy (licenses, advisories, sources)
  crates/
    opsgate-core/       pure logic: settings, JSON canon/checksum, time, validation, log preview, path containment (S2a-S2c)
    opsgate-store/      SQLite store: schema, tickets, health, session generation, check-db (S3a, S3b)
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
    validation.json     new-ticket validation and normalisation (4.7.1)
    store.json          store scenarios: creation, dedupe, expiry, reading, health, sessions (4.5.2, 4.6, 4.7.1)
  parity/
    api/                black-box API parity harness (S7a, PLAN.md 7.3)
    runner/             black-box runner parity harness (S7b, PLAN.md 7.4)
```

`opsgate-core` has the modules of S2a: `json` (parsing like `json.loads`,
the checksum and stored-JSON formatter, depth check, PLAN.md 4.6/4.8) and
`time` (`utc_now`, `isoformat_z`, `parse_iso_datetime`, 4.9); of S2b:
`settings` (env file, API and runner settings, 4.2), `log_preview` (4.12),
`paths` (step-log containment, 4.12) and `proxy_fix` (4.4); and `pytext`
(Python's `str.strip` whitespace, `splitlines` boundaries, `str()` of JSON
scalars and `lower`); of S2c: `validate` (new-ticket validation and
normalisation in Python's check order, plan/policy/floor/reviewer rules,
duration, the checksum payload, 4.7.1) and `error` (`ServiceError`: status,
code, message). `opsgate-runner` has the modules of S6a: `api` (the
HTTP client of the runner routes, PLAN.md 4.13.1), `tmux` (`tmux -L <label>`
children started with exactly the merged settings environment, 4.13.8),
`artifacts` (step paths, atomic 0600 JSON writes, 4.13.2/4.13.7),
`commands` (slugs, session names, agent command lines, the attach command
and `run_step.sh`, 4.13.3) and `executor` (one ticket's steps, heartbeats,
cancel, timeout, status retries and the resume rules, 4.13.4/4.13.5); and
of S6b: `supervisor` (the claim loop, one worker task per ticket, restart
recovery from state files, tmux sessions and artifact directories, verified
tmux cleanup, runner state files, SIGTERM/SIGINT, 4.13.6). The binary's
`runner` module wires them into `opsgate runner [--once]`.

`opsgate-store` (S3a) is the SQLite store of `service.py`, one connection per
operation (WAL, foreign keys, 5 s busy timeout) and `BEGIN IMMEDIATE` for
every write: `schema` (the DDL of `init_db`, verbatim), `Store::open`
(`init_db` and the session-state sync), the session generation
(`ui_session_generation`, `revoke_ui_sessions`), ticket creation
(`create_ticket`, `create_manual_ticket`: validation, lazy expiry, dedupe,
audit), `get_ticket`, `list_tickets`, `health`, and `check` (`check-db`).
Transitions, claim and runner status follow in S3b. The web crate is
empty until its slices land. Every crate forbids `unsafe` code (workspace
lint).

## check-db

`opsgate check-db --db <path>` checks a database before Rust serves it
(PLAN.md 3.1, 4.10): the schema must be the one `init_db` creates (tables
and indexes by their SQL text, so types, collations and constraints count;
a `tickets` table migrated by `init_db`'s archive `ALTER TABLE` is accepted
too), and every stored row must be
readable by Rust (JSON columns under the rules of 4.6 including the D-2
cases, storage classes, `expires_at`, integer durations). It prints the
result and the counts (tickets per state, audit events, approver rows,
runner heartbeats) and exits 0, or 1 when anything is wrong or the file is
not a readable SQLite database. Problems name ticket ids, audit event ids and
columns, never stored values. It opens the database read-only and never
creates, migrates, checkpoints or writes it; for a WAL database SQLite may
create the `-wal`/`-shm` side files, as for any reader.

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
| `just rs-parity-api` | API parity harness against Python and Rust, then the record diff (see below) |
| `just rs-parity-runner` | runner parity harness against Python, then Rust, then the diff of both (needs tmux) |

`just check` stays the Python check.

## Runner tests

`opsgate-runner`'s executor tests use a fake API and a scripted tmux on
paused tokio time; the API client is tested against an in-process axum
server. `tests/tmux_integration.rs` runs real `tmux` on a private socket
label and `TMUX_TMPDIR` with fake `codex`/`claude` scripts, in an isolated
environment built from an allowlist (no exported shell functions; own `HOME`, `SHELL=/bin/sh`, a `PATH` with only the fakes, a
`tmux` link and the system directories), so neither a real agent nor your
tmux configuration is reached. The executor test's tmux keeps finished
sessions (`remain-on-exit`, from a `.tmux.conf` in that `HOME`): the poll
checks `exit_code` before it probes the session, as Python does, and a fake
agent that ends within milliseconds could otherwise end between the two. The
same file runs the supervisor's session discovery and verified cleanup
against a real server. Without `tmux` these tests skip; with
`OPSGATE_REQUIRE_TMUX=1` (set in CI) they fail instead.

`tests/supervisor.rs` runs the supervisor with the real executor against a
fake API with several tickets and a scripted tmux (`tmux ls`, kills, absent
server, missing binary) on paused tokio time: the ports of the Python worker,
recovery and cleanup tests plus the claim loop, `--once` and shutdown. The
binary's own tests (`crates/opsgate/tests/binary.rs`) start `opsgate runner`
as a process: configuration errors, `--once`, the P1 claim-failure log line,
SIGTERM and SIGINT.

## CI

The `parity-api` job runs the API parity harness against Python (lint,
typecheck, scenarios); slice S4a adds the Rust leg.

The `rust` job of `.github/workflows/ci.yml` runs on `ubuntu-latest` and
`macos-15`: rustfmt, clippy, `cargo deny --locked check` (pinned, sha256
verified cargo-deny release), `cargo test --locked` (with tmux installed and
`OPSGATE_REQUIRE_TMUX=1`), a release build, a
`--version` smoke test (version and the checked-out commit) and the release
binary size in the job summary. The fixture drift test runs in the Python job
as part of pytest. The `parity-runner` job runs the runner parity harness
against the Python runner on both systems (tmux from apt or Homebrew); its
Rust leg is switched on by slice S8 (until then run `just rs-parity-runner`
locally).

## Runner parity harness

`parity/runner/` (PLAN.md 7.4) runs a real runner process (`python -m opsgate
runner` or `opsgate runner`, `--once` where a scenario needs it) as a black
box: a generated env file, a temporary execution data directory, real tmux on
a private socket label with its own `TMUX_TMPDIR`, and fake `codex`/`claude`
(`fake_agent.py`) first on `PATH`. Its API is the scripted stand-in of
`fake_api.py` (claim, status, get; scripted HTTP errors and dropped
connections; every request recorded), or in the mixed stacks a real `serve`
process.

```bash
uv run pytest rust/parity/runner                          # against the Python runner
uv run pytest rust/parity/runner --impl rust              # against rust/target/release/opsgate ($OPSGATE_RUST_BIN)
uv run pytest rust/parity/runner --records DIR            # also write one normalised record per scenario
uv run python rust/parity/runner/compare.py DIR [DIR ...] # diff the records of different stacks
just rs-parity-runner                                     # Python, Rust, diff
```

Scenarios assert the Python behaviour, which is the oracle:

| File | Scenarios |
| --- | --- |
| `test_runner_execution.py` | one and three steps (names, slugs, context, previous summary, agent command lines, env-file keys reaching the agents, file modes, claim/status request shapes), exit-code failure, unsupported agent, invalid plan, ticket timeout, cancel and other terminal states during a step, session killed externally, heartbeat cadence, `max_parallel_jobs` and state files |
| `test_runner_api_faults.py` | status retry after 503 and a dropped connection, a status outage that keeps the state file (the restarted runner fails the step as interrupted), a heartbeat outage that re-attaches the live session, permanent 4xx (session killed before the failure report), silent 409 `invalid_state`/`state_changed` and permanent other conflicts, claim errors (P1 log lines) |
| `test_runner_supervisor.py` | disable file (`--once` and paused claims), `--once` without work, recovery housekeeping (invalid state files, terminal and not-running tickets, tmux discovery, unknown tickets) |
| `test_runner_restart.py` | SIGTERM during a step (interrupted, then failed after a restart), SIGKILL and restart (adopt the exit code, re-attach the live session, interrupted) for every pair of Python/Rust runners, unreadable metadata |
| `test_runner_mixed_stacks.py` | real API and real runner, Python/Rust × Python/Rust, one two-step ticket from submission through approval to success, the API's step log pages reading the runner's artifacts |

The cross-implementation scenarios (SIGKILL one implementation, continue with
the other on the same artifacts, state files and tmux server) and the mixed
stacks are parametrised over the stacks: `--impl python` runs the all-Python
stacks, `--impl rust` every stack that contains Rust. A Rust runner runs once
`RUST_SLICES_LANDED` in `runner_harness.py` contains S6b (it does since S6b
merged), a Rust API once it contains S4a and S4b; until then those stacks are
skipped. Each record holds
the runner's API calls (consecutive identical heartbeats collapsed), the
artifact tree (names, modes, JSON values, text; timestamps masked, paths
relative to the execution data directory, shell words instead of quoting),
tmux session names, state files, P1 log lines and agent calls. `compare.py`
compares every stack of a scenario with its all-Python baseline.

The runner environment is isolated so that a real agent can never run: it is
built from an allowlist (locale, user, `TMPDIR`; no `BASH_ENV` or exported
shell functions of the caller), with a private `HOME` (whose `.tmux.conf` is production's, from the
`opsgate_deploy` role, including `remain-on-exit on`), `SHELL=/bin/sh`, and a
`PATH` of the fake agents, tmux and the system directories only. Each scenario
kills its tmux server at the end. CI runs the harness in the `parity-runner`
job on Linux and macOS.

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
| `schema.sql` | `sqlite_master` of a database initialised by `OpsGateService.init_db`, tables then indexes; runs as one script | `opsgate-store/tests/schema_contract.rs`, `check_db.rs` |
| `settings.json` | environment sets (with optional env file) → `load_settings` / `load_runner_settings` result or error, plus `load_env_file` parsing cases; `rust_error` gives the Rust message where Python fails with a traceback or diverges (D-8, D-10) | `opsgate-core/tests/settings_fixture.rs` |
| `storage_json.json` | JSON text → stored column text `json.dumps(value, sort_keys=True)` | `opsgate-core/tests/checksum_fixture.rs` |
| `store.json` | store scenarios run by `OpsGateService` (creation with lazy expiry and dedupe, manual tickets and the operator floor, validation failures, get/list/serialisation of rows written by older code, health, session generation): every step's result and the final four tables, generated ids and timestamps masked after a format check | `opsgate-store/tests/store_fixture.rs` |
| `validation.json` | request body text, source, reviewer floor and default duration → `_normalize_new_ticket`: canonical checksum text and `payload_checksum`, or error code, status and message (469 cases: the S2c Python tests, every check of 4.7.1 and their order, 240 random multi-field mutations; D-2/D-3 marked with the Rust result) | `opsgate-core/tests/validation_fixture.rs` |

## API parity harness

`parity/api/` (PLAN.md 7.3) is a pytest suite that treats an implementation as
a black box: every scenario starts its own `serve` process (`python -m opsgate
serve` or `target/release/opsgate serve`, override with `$OPSGATE_RUST_BIN`)
on a free loopback port with a generated env file, a temporary database and a
temporary execution data directory, and talks to it over HTTP with `httpx`.
Scenarios are ported from `tests/test_api.py` (same test names where they
exist) and add contract cases of the plan: validation order, JSON body rules,
explicit `null`/`false`/`0` runner fields, forwarded headers, cookie
attributes, cross-implementation databases and races.

```bash
uv run pytest rust/parity/api -rs                        # against Python (default; or OPSGATE_IMPL=python)
uv run pytest rust/parity/api -rs --impl rust            # against the Rust release binary
uv run pytest rust/parity/api --records DIR              # also write one normalised record per scenario
uv run python rust/parity/api/compare.py DIR_A DIR_B     # diff two record sets; exit 1 on unexplained differences
just rs-parity-api                                       # build, both runs, diff (records in target/parity-api/)
```

| File | Content |
| --- | --- |
| `harness.py` | process start/stop, settings profiles, HTTP clients (security headers checked on every response), page facts, normaliser, records, database snapshots; `RUST_SLICES_LANDED` |
| `conftest.py` | `--impl`, `--records`, `--target`; fixtures `stack`, `api`, `anon`, `approver`, `db`, `rec` |
| `compare.py` | record diff (standard library only) |
| `test_bearer_api.py` | health, create/read, validation, JSON body rules, bearer tokens |
| `test_lifecycle.py` | approve, reject, cancel, archive, unarchive through the cookie API |
| `test_runner_api.py` | claim, stored-JSON validation, tamper check, heartbeats, runner status |
| `test_auth.py` | login, next, sessions, revocation, throttle, both CSRF mechanisms |
| `test_gate.py` | network gate, forwarded headers, routing, security headers |
| `test_ui.py` | pages, UI actions, manual ticket form, log previews and step logs |
| `test_cross.py` | cross-implementation databases, API switch, races |

A record holds, per exchange, the status, `error` code, JSON body (ticket ids
as `<id1>`…, generated timestamps as `<ts>`, the scenario's temp directory as
`<tmp>`, error `message` texts masked: they are P2), redirect target, flash
messages, the forms and internal links of HTML pages and the session cookie
attributes, plus a snapshot of every table (JSON columns parsed). HTML bytes
are never compared. A scenario that covers a P3 divergence calls
`rec.divergence("D-n")`; `compare.py` then reports a difference as explained.

Rust switch-on: every scenario carries `@pytest.mark.rust(<slices>)` naming the
web slices it needs; against Rust it runs only when all of them are listed in
`harness.RUST_SLICES_LANDED`, otherwise it is skipped with the missing slices
as the reason. S4a, S4b and S5 each add their id there (and S4a the Rust leg
of the CI job) when they merge. `test_cross.py` runs every scenario with the
peer implementation `python` and `rust`, so a Python run covers python→python
and python→rust.

Scenarios marked `local` need their own process (settings profile, restart,
database or artifact access, claims on an empty queue, throttle state). The
others also run against an already running API, e.g. the shadow of PLAN.md
11.2: `--target http://127.0.0.1:8712 --target-env <shadow api env file>
[--target-impl rust]` with the approver password in
`$OPSGATE_PARITY_UI_PASSWORD`. Their `task_ref`s are fixed (so records stay
comparable), so each such run needs a fresh database copy.

`test_login_throttle_is_per_client_ip` connects from `127.0.0.2`, which Linux
provides and macOS does not; it is skipped on macOS and runs in CI.

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
land, the commands other than `runner` print `opsgate <command>: not
implemented yet` on stderr and exit 2; usage errors also exit 2.

`opsgate runner [--once]` reads the runner settings like `python -m opsgate
runner` (`OPSGATE_ENV_FILE`, then the variables of PLAN.md 4.2) and runs until
SIGTERM or SIGINT (exit 0), or with `--once` for one recovery pass and one
claim round. A configuration error is one stderr line naming the setting
(never its value), exit 1. It logs plain lines on stderr: an INFO startup line
(version, `implementation=rust`, runner host, socket label, worker limit),
the P1 lines `Runner claim failed: status=<s> category=<c>` and `Runner API
unavailable: status=<s> category=<c>`, and one line per unexpected worker
error instead of Python's traceback (D-12). `opsgate --version` prints
`opsgate <version> (<full commit>)`. `build.rs` takes the commit from
`OPSGATE_GIT_COMMIT` (40 or 64 lowercase hex digits; the release workflow sets
it), else from `git rev-parse HEAD`, else `unknown`, and records the choice in
`OPSGATE_GIT_COMMIT_SOURCE` (`env`, `git`, `none`) for the tests.
