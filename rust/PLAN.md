# Rust port of OpsGate (API/UI and runner) — implementation plan

Status: plan, not yet implemented. Campaign "Rust-Ports Runde 2", stream
`rust-opsgate` (umbrella work item `rust-ports-campaign`).

This document is the contract for the implementers and reviewers of the
slices in section 12. It ports both long-running Python processes of OpsGate
(`python -m opsgate serve` and `python -m opsgate runner`) to one Rust binary
`opsgate`. Every behavioural statement cites the Python code that defines it
(`src/opsgate/<file>.py:<line or function>`, repository state `c81d3cc`).
**When this document and the Python code disagree, the Python code wins and
this document must be corrected** (same rule as nyxmon `agent-rs/PLAN.md` and
mailgun-relay `rust/PLAN.md`).

Parity rule (owner decision, carried over from mailgun-relay
`handoff/parity-contract.md`, 2026-10-15): **no byte parity with Python.**
Python is the oracle for the contract and for every decision (accept/reject,
status code, error code, state transition, stored values, files). Byte-exact
equality is required only where bytes *are* the contract (section 4.8, the
payload checksum). Prefer maintained crates; no re-implementation of Python
libraries or hand-rolled protocols where a maintained crate exists. Divergences
outside the contract are not review findings; divergences inside it must be
listed in section 5.

---

## 0. Where the Rust code lives (decision)

`rust/` in this repository, a Cargo workspace next to the Python package it
replaces (as nyxmon `agent-rs/` and mailgun-relay `rust/`):

- the fixture generator imports `src/opsgate` directly and its drift test runs
  in the existing pytest job;
- the black-box parity harness starts both implementations from one checkout;
- **the Jinja templates stay where they are** (`src/opsgate/templates/*.html`)
  and the Rust binary embeds the same files at compile time (`include_str!`),
  so UI changes during the parallel period are made once for both
  implementations (section 6.3). They move into `rust/` only in the
  retirement slice S16c;
- one release location: tags `rs-v<semver>` on `github.com/ephes/opsgate`
  (public repository, no token needed to download).

Merging Rust code to `main` is safe at any time: the current role syncs the
repository with rsync into both app directories and runs `uv sync`
(`ops-library:roles/opsgate_deploy/tasks/app_source.yml`,
`app_runtime.yml`); nothing executes `rust/`. One precondition: the rsync
excludes (`opsgate_rsync_excludes`, `defaults/main.yml`) do not exclude
build output, so a local `cargo build` in the deploy checkout would ship
`rust/target/` (gigabytes) to both app directories. Slice S1o adds `rust/` to
those excludes; S1 adds `rust/target/` to `.gitignore`.

```
rust/
  Cargo.toml              # workspace; [profile.release] lto = "thin", codegen-units = 1, strip = true, panic = "abort"
  Cargo.lock              # committed; every build --locked
  rust-toolchain.toml     # 1.99.0, as nyxmon and mailgun-relay; = rust-version (MSRV)
  deny.toml               # cargo-deny: licenses, advisories, crates.io only
  PLAN.md  TESTMAP.md  README.md
  crates/
    opsgate-core/         # pure logic: settings, JSON canon/checksum, time, validation, log preview, path containment
    opsgate-store/        # rusqlite: schema, transitions, health, check-db
    opsgate-web/          # axum: gates, auth, sessions, CSRF, API + UI routes, templates
    opsgate-runner/       # runner: API client, tmux, artifacts, executor, supervisor
    opsgate/              # binary: CLI (serve | runner | check-config | check-db | --version), build.rs (commit)
  fixtures/               # Python-generated JSON fixtures + generate.py (section 7.2)
  parity/
    api/                  # black-box API scenario suite run against either implementation (7.3)
    runner/               # black-box runner harness: fake API, real tmux, fake agents (7.4)
    shadow/               # stdlib-only tools for the production-copy checks (11.2)
  scripts/release_checks.py
```

The workspace split enforces the purity boundary (everything fixture-tested
lives in `opsgate-core`) and lets the API track (store/web) and the runner
track proceed in parallel with few merge conflicts. Estimated size: 6–8k lines
of Rust including tests. `unsafe_code = "forbid"` in every crate.

Versioning: the Rust crate starts at **0.3.0** (Python is 0.2.0,
`pyproject.toml`), so `opsgate --version` and the release tag tell operators
which implementation runs.

---

## 1. Live facts (read-only, 2026-10-21)

Gathered with `ssh root@studio.tailde2ec.ts.net` (inventory `macstudio`,
`ops-control:inventories/prod/hosts.yml:14`) using `launchctl print`, `ps`,
`ls`, `footprint`, and `sqlite3 "file:…?mode=ro&immutable=1"` queries of
counts and schema only. No secrets were printed.

- **Host:** `studio` = inventory `macstudio`, macOS 27.0.1 (26A434), arm64,
  Homebrew under `/opt/homebrew`, `tmux 3.8` at `/opt/homebrew/bin/tmux`,
  `/bin/bash` 3.2.57, system `/usr/bin/sqlite3` 3.54.0. OpsGate runs only
  here (`hosts.yml` group `opsgate`: `macstudio`; `services-metadata.yml`
  `opsgate.default_host: macstudio`). It was not seen on macmini because only
  its ingress is there.
- **Processes replaced by this stream** (two LaunchDaemons, both
  `KeepAlive`/`RunAtLoad`, `runs = 3`, started 22 h before the check):

  | launchd label | user | command (pid) | RSS (`ps`) | phys_footprint |
  | --- | --- | --- | --- | --- |
  | `de.wersdoerfer.opsgate.api` | `control_service_user` (uid 505) | `/usr/bin/env bash -lc "cd /Users/control_service_user/opsgate && .venv/bin/python -m opsgate serve"` → Homebrew Python 3.14.8 (42365) | 26.0 MiB | 32 MB |
  | `de.wersdoerfer.opsgate.runner` | `ops` (uid 504) | `/usr/bin/env bash -lc "cd /Users/ops/opsgate && .venv/bin/python -m opsgate runner"` → Python 3.14.8 (42780) | 23.4 MiB | 32 MB |

  Both are `ppid 1` (bash execs the interpreter). Total ≈ 50 MiB RSS /
  64 MB footprint. No timers, no other OpsGate processes. The tmux server for
  socket label `remediation` is not running (socket file from 2026-03-29).
- **Plists:** `/Library/LaunchDaemons/de.wersdoerfer.opsgate.{api,runner}.plist`,
  logs `/var/log/opsgate/opsgate-{api,runner}{,.err}.log` (API logs empty;
  runner `.err` 73 lines incl. 2 tracebacks from a refused connection during
  an API restart).
- **Effective process environment** (variable *names* of the runner; values
  not read except `PATH`): `HOME LOGNAME OLDPWD OPSGATE_ENV_FILE
  OPSGATE_TMUX_SOCKET_LABEL OSLogRateLimit PATH PWD SHELL SHLVL TMPDIR
  TMUX_TMPDIR USER XPC_FLAGS XPC_SERVICE_NAME __CF_USER_TEXT_ENCODING
  __PYVENV_LAUNCHER__ _`. The plist sets `PATH=/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin`,
  but `bash -l` runs `/etc/profile` → `path_helper`, so the effective `PATH`
  is `/usr/local/bin:/System/Cryptexes/App/usr/bin:/usr/bin:/bin:/usr/sbin:/sbin:…:/Library/Apple/usr/bin:/opt/homebrew/bin`
  (Homebrew last). `ops` has no shell dotfiles. This environment is what the
  tmux server and the agent steps inherit (contract 4.13.8).
- **Database:** `/usr/local/var/opsgate/run/control/opsgate.sqlite3`
  (`control_service_user`, 0644, 1.9 MB, WAL per header bytes `02 02`, no
  `-wal`/`-shm` files at rest because Python closes every connection). Schema
  identical to `service.py:init_db` (tables `tickets`, `audit_events`,
  `ui_session_state`, `runner_heartbeats`, `sqlite_sequence`; indexes
  `idx_tickets_state`, `idx_tickets_created_at`, `idx_tickets_archived_at`,
  `idx_tickets_open_dedupe`). Content: 603 tickets (nyxmon 585, 2026-03-07 to
  2026-10-18; openclaw 13, March; operator 5, March): expired 478,
  pending_approval 110, succeeded 11, canceled 2, failed 1, rejected 1;
  1416 audit events; one approver row (`opsgate-admin`, generation 1);
  heartbeat rows `macstudio` (current), `manual-check`, `127.0.0.1`. All
  stored JSON is `json_valid`; contexts contain 63 JSON floats (e.g. `0.95`,
  `3.0`, `14.0` from nyxmon result data), so the checksum's float formatting
  is exercised by production data (section 4.8). Largest `context_json`
  1755 bytes, largest `execution_plan_json` 3156 bytes.
- **Runner data:** `/Users/ops/remediation/{jobs,sessions,runner-state,tmp,tmux}`
  (`ops`, 0750; `tmux` 0700); 12 session artifact directories (last
  2026-03-29); `runner-state/` empty (no in-flight ticket).
- **Config files:** `/etc/opsgate/opsgate-api.env` (root:control_service_user
  0640), `/etc/opsgate/opsgate-runner.env` (root:ops 0640).
- **Accounts:** `ops` (uid 504, groups incl. `control_service_user`),
  `control_service_user` (uid 505, groups incl. `ops`), as
  `roles/opsgate_deploy/tasks/users.yml` sets up.
- **Producers / consumers:**
  - nyxmon (macmini) posts tickets to `http://studio.tailde2ec.ts.net:8711/api/v1/tickets`
    with the nyxmon submit token and links approvals to
    `https://opsgate.home.xn--wersdrfer-47a.de/tickets/<id>`; it reads `201`
    + `id`, and `409` + `error == "duplicate_open_ticket"`
    (`nyxmon:src/nyxmon/adapters/notification.py:_create_opsgate_ticket`; the
    Rust nyxmon agent implements the same client). It is the only active
    producer (last ticket 2026-10-18).
  - nyxmon json-metrics check "OpsGate Health (JSON Metrics)" polls
    `GET /api/v1/health` every 120 s, requiring `$.status == "ok"` and
    `$.db == "ok"` (`ops-control:playbooks/deploy-opsgate.yml`, second play).
  - OpenClaw submit handler (`ops-library:roles/openclaw_deploy/templates/opsgate-submit-handler.py.j2`):
    same endpoint, reads `201`/`id`, `409 duplicate_open_ticket`, `message`,
    `error`. Optional; no tickets since 2026-03-10.
  - Operator/approver: browser through Traefik on macmini
    (`opsgate_ingress_deploy`, ClientIP allow-list, `X-Forwarded-Proto/Host`
    set), session cookie login.
  - The runner itself (HTTP client of the API, `127.0.0.1:8711`).
  - `just backup-opsgate` / `just restore-opsgate`
    (`playbooks/run-studio-sqlite-snapshot.yml`,
    `restore-studio-sqlite-snapshot.yml`): SQLite online backup of the DB path;
    restore boots out both launchd labels by name. **DB path and launchd
    labels are therefore contract.**
  - Work items `opsgate-ssh-key-rotation` / `authorize-root-ssh` and the
    playbooks `authorize-opsgate-root-ssh.yml`, `remove-root-ssh-key.yml`
    concern the `ops` account's keys on target hosts; the read-only GitHub
    deploy keys and SSH aliases `github-<repo>` (ops-library 2.54.0,
    `tasks/ops_credentials.yml`, `templates/ops.ssh.config.j2`) are rendered
    by the role. The port does not touch any of them; agent steps keep
    finding `~/.ssh/config` because the runner keeps running as `ops` with
    `HOME=/Users/ops`.

Not applicable to this stream (listed in the brief as campaign-wide
constraints): the echoport remote command guard (`.timeout`/`.backup`),
graphyard ingest tokens and `graphyard_vector` (studio runs it; untouched),
nyxmon check upserts via stdin (the opsgate playbook's upsert is unchanged).

---

## 2. Deploy mechanism today (and how the port uses it)

- Entry point: `just deploy-one opsgate` in ops-control
  (`justfiles/deploy.just`, case `opsgate)`): resolves the target host from
  `services-metadata.yml` (`default_host: macstudio`) and runs
  `ansible-playbook -i inventories/prod/hosts.yml playbooks/deploy-opsgate.yml -e target_host=macstudio`
  with `SOPS_AGE_KEY_FILE`.
- **Engine: Ansible.** `services-metadata.yml` has no `engine:` for
  `opsgate` (default `ansible`); macOS hosts are outside the pyinfra port
  until its Phase 8 (`docs/PYINFRA.md`). The port deploys exactly through
  this playbook and role; no new mechanism.
- Play 1 (`hosts: macstudio`): roles `uv_install` and `opsgate_deploy`
  (rsync of the opsgate checkout into `/Users/control_service_user/opsgate`
  and `/Users/ops/opsgate`, `uv sync --frozen --no-dev` as each user, env
  files from SOPS `secrets/prod/opsgate.yml`, ops credentials and workspace
  repos, tmux.conf, two plists, `launchctl bootout/bootstrap/kickstart` on
  change). The opsgate source is resolved from `OPSGATE_SOURCE_PATH`,
  `PROJECTS_ROOT/opsgate`, the sibling of ops-control, or
  `~/projects/opsgate`.
- Play 2 (`hosts: macmini`): `opsgate_ingress_deploy` (Traefik dynamic file
  `/etc/traefik/dynamic/opsgate.yml`) and the nyxmon health-check upsert
  (Python on stdin, no secrets in `environment:`). Both are idempotent and
  unchanged by the port; every `deploy-one opsgate` still runs them.
- Version pin: the playbook gains a pre-task asserting the installed
  ops-library version, as `deploy-nyxmon.yml` does (`collections/…/MANIFEST.json`).
- **Shared deploy lock (binding):** every production deploy step of this
  stream runs under the controller lock
  `/tmp/ops-control-deploy.lock` on the machine that runs ops-control:

  ```bash
  mkdir /tmp/ops-control-deploy.lock || { cat /tmp/ops-control-deploy.lock/owner; exit 1; }  # held: wait, never remove
  printf '%s %s %s\n' "<session>" "rust-opsgate <slice>" "$(date -u +%FT%TZ)" > /tmp/ops-control-deploy.lock/owner
  OPSGATE_SOURCE_PATH=<clean opsgate checkout at origin/main> just deploy-one opsgate   # in tmux
  rm /tmp/ops-control-deploy.lock/owner && rmdir /tmp/ops-control-deploy.lock              # only our own lock
  ```

  A lock we did not create is never removed. `OPSGATE_SOURCE_PATH` must point
  to a clean checkout of `origin/main` so the Python rollback target that the
  role syncs matches `main`.
- Secrets: env files are rendered as files (`service_env.yml`, `no_log`); no
  task passes a secret through `environment:` under `become_user`
  (ops-control `just test-become-environment-secrets`, ops-library
  `tests/test_become_environment_secrets.py`, 2.55.0+). New role tasks
  (validation commands run as the service users) pass only the env-file
  *path* (`OPSGATE_ENV_FILE`), never values.
- ops-control `main` CI is red at `test-software-inventory` for unrelated
  reasons (eMudhra work). S11 changes `software-sources.yml`/`software-estate.yml`
  and may be unable to show a green run of that job; it reports the job state
  and does not fix the unrelated failure.

---

## 3. Scope, non-goals, parity classes

### 3.1 Scope

One Rust binary `opsgate` replacing both processes:

- `opsgate serve`: JSON API, web UI, SQLite store (all of `app.py`,
  `service.py`, `config.py:load_settings`, `log_preview.py`, the five
  templates);
- `opsgate runner [--once]`: the runner (`runner.py`,
  `config.py:load_runner_settings`);
- Rust-only operational subcommands: `opsgate --version`,
  `opsgate check-config api|runner` (load settings exactly like the server or
  runner would, print nothing secret, exit 0/1), `opsgate check-db --db <path>`
  (read-only: schema matches 4.10, every stored JSON column parses under the
  Rust rules of 4.6, report counts; exit 0/1).

The API and the runner can be cut over **independently**: the runner never
touches SQLite; its only contract with the API is HTTP (`/api/v1/runner/*`,
`GET /api/v1/tickets/<id>`) plus the artifact tree it shares with the UI's log
views. Section 7.4 tests all four combinations (Python/Rust API × Python/Rust
runner). The SQLite schema contract matters only between API implementations
over time (cutover and rollback on the same file), never concurrently: one API
process owns the database.

### 3.2 Non-goals

- No feature changes, no "fixes" of Python behaviour except the
  divergences in section 5. Quirks are reproduced (examples: `str()` of JSON
  scalars in text fields, 404-before-403 on `GET /api/v1/tickets/<id>` for a
  foreign source, whole-second timestamps sorting after fractional ones,
  section 4.9).
- No change to the security model (Tailscale/CIDR gate, one approver, bearer
  tokens, generation-based revocation, CSRF rules, reviewer-floor policy).
- No change to the role's account model, ops credentials, deploy keys, SSH
  aliases, workspace repos, tmux.conf, env files, paths, launchd labels.
- No change to producers (nyxmon, OpenClaw) or the ingress.
- No Windows/Linux production target (Linux is a CI test platform only).
- The Python package stays runnable and is the rollback target until S16.

### 3.3 Parity classes

Every reviewer finding about parity names the class.

**P1 — exact contract** (pinned by fixtures and the parity harness):
routes, methods, auth decisions, status codes, JSON field names/types/values
(not formatting), `error` codes, state transitions and their guards, every
column value written to SQLite (modulo generated ids/timestamps), audit
events, the payload checksum bytes (4.8), timestamp text format (4.9),
environment variable names/defaults/validation, CLI and exit codes, launchd
behaviour, runner HTTP calls and their payload semantics, artifact file
names/locations/JSON keys/permissions, tmux session names, the agent command
lines and the step script semantics, cookie attributes and session semantics
(not cookie format, D-1), security headers, redirect targets.

**P2 — equivalent**: free-text `message` strings of errors, HTML bytes
(markup, escaping style, whitespace) as long as the page shows the same
information, forms post the same fields, and links/actions are the same;
JSON whitespace and key order in responses, stored JSON text formatting,
artifact JSON formatting; shell quoting style; log line formatting except the
lines in 4.15; framework-generated 404/405/500 bodies.

**P3 — intentional divergence**: exhaustively listed in section 5. Anything
else that differs is a bug.

---

## 4. The contract

### 4.1 Processes, CLI, exit codes, signals

- `python -m opsgate [serve|runner] [--once]` (`__main__.py`): default
  `serve`; `--once` only for the runner. Rust: `opsgate serve`,
  `opsgate runner [--once]` with the same meaning; the launchd plists call
  these (10.1).
- `serve`: loads settings (4.2), opens/initialises the database (4.10),
  serves HTTP on `OPSGATE_BIND_HOST:OPSGATE_BIND_PORT` (waitress, 8 threads,
  `expose_tracebacks=False`). Rust-only test/shadow flags `--db <path>`,
  `--bind-host`, `--bind-port` override the env file (D-15).
- Configuration errors: Python raises `SettingsError` (traceback on stderr,
  exit 1). Rust: one stderr line naming the setting, never its value, exit 1
  (P1: non-zero exit and setting name; P2: text).
- `serve` stops on SIGTERM/SIGINT (waitress default). Rust: graceful
  shutdown, in-flight requests finish (≤ 5 s), exit 0.
- `runner`: SIGTERM/SIGINT set the stop flag (`runner.py:install_signal_handlers`);
  workers observe it at their next 1 s poll, the supervisor after its current
  `time.sleep(poll_interval)` (default 5 s), and an HTTP request in flight
  finishes first (≤ 15 s timeout); the process exits 0 after all workers
  stopped (`_wait_for_workers`). What happens at shutdown (4.13.4: kill the
  active session, metadata `interrupted`, or leave an existing exit code for
  adoption) is P1; Rust may observe the flag sooner (stop-aware sleeps and
  cancellable requests, D-16). launchd sends
  SIGTERM on `bootout`/`kickstart -k`, SIGKILL after its exit timeout.
- `runner --once`: one recovery pass, one claim round; exits after the
  started workers finished, or immediately if nothing was claimed or the
  disable file exists (`run_forever`).

### 4.2 Configuration (`config.py`)

Env-file semantics (`load_env_file`): `OPSGATE_ENV_FILE` is read first if set;
missing file → `SettingsError("Env file does not exist: <path>")`. Lines are
`.strip()`ped; empty and `#` lines skipped; lines without `=` skipped;
`key, value = split("=", 1)`, both stripped; a value wrapped in matching
single or double quotes loses one pair. **File values overwrite the process
environment** (`os.environ[key] = value`), so the env file wins over launchd
variables, and every key of the file becomes part of the process environment
that child processes inherit (runner: 4.13.8). Rust loads the file the same
way before starting any thread and applies it to its own process environment
(or passes the identical set to children explicitly).

Parsing rules (P1, fixture `settings.json`): `parse_bool` (blank/missing →
default; `1/true/yes/on`, `0/false/no/off`, case-insensitive after strip;
else `SettingsError` naming the variable); `parse_int` = Python
`int(value.strip())` for ASCII (sign, digits, single underscores between
digits; D-8); strings `.strip()` with **Python's** whitespace set (as
mailgun-relay `pystr.rs`); CIDRs via `ip_network(strict=False)` (D-8).

API settings (`load_settings`):

| Variable | Default | Rule |
| --- | --- | --- |
| `OPSGATE_SERVICE_NAME` | `opsgate` | stripped; shown in `/api/v1/health` |
| `OPSGATE_BIND_HOST` | `0.0.0.0` | stripped |
| `OPSGATE_BIND_PORT` | `8711` | `parse_int` |
| `OPSGATE_DB_PATH` | `/usr/local/var/opsgate/run/opsgate.sqlite3` | blank → default (production sets `/usr/local/var/opsgate/run/control/opsgate.sqlite3`) |
| `OPSGATE_UI_USERNAME`, `OPSGATE_UI_PASSWORD_BCRYPT` | — | both required (stripped non-empty) |
| `OPSGATE_SESSION_SECRET` | — | ≥ 20 chars |
| `OPSGATE_TRUST_PROXY_HEADERS` | false | bool |
| `OPSGATE_SESSION_COOKIE_SECURE` | false | bool |
| `OPSGATE_MAX_DURATION_SECONDS_DEFAULT` | 3600 | int, 1..31 536 000 (`validate_duration_default`) |
| `OPSGATE_POLICY_FLOOR_REQUIRE_REVIEWER_STEP` | false | bool |
| `OPSGATE_UI_SESSION_TIMEOUT_SECONDS` | 28800 | int (README says `OPSGATE_SESSION_TIMEOUT_SECONDS`; the code name wins; S8 fixes the README) |
| `OPSGATE_RUNNER_TOKEN` | — | ≥ 20 chars |
| `OPSGATE_SUBMIT_TOKEN_OPENCLAW` | "" | optional; if set ≥ 20 chars |
| `OPSGATE_SUBMIT_TOKEN_NYXMON`, `…_OPERATOR` | — | ≥ 20 chars each |
| `OPSGATE_SUBMIT_POLICY_{OPENCLAW,NYXMON,OPERATOR}_REQUIRE_REVIEWER_STEP` | global floor | bool; OPENCLAW parsed (and validated) even without its token |
| `OPSGATE_REQUIRE_TAILSCALE_CONTEXT` | true | bool |
| `OPSGATE_ALLOWED_CIDRS` | `127.0.0.1/32,::1/128,100.64.0.0/10,fd7a:115c:a1e0::/48` | comma list, stripped, empties dropped; none → error; each must parse |
| `OPSGATE_EXECUTION_DATA_DIR` | `/Users/ops/remediation` | stripped |
| `OPSGATE_DISABLE_FILE_PATH` | `<execution_data_dir>/.disabled` | blank → default |

Submitter order (P1, `authenticate_submitter` iterates it): openclaw (if
token set), nyxmon, operator.

Runner settings (`load_runner_settings`): `OPSGATE_SERVICE_NAME`,
`OPSGATE_RUNNER_TOKEN` (≥ 20), `OPSGATE_BIND_PORT` (8711, only for the default
base URL), `OPSGATE_RUNNER_API_BASE_URL` (default `http://127.0.0.1:<port>`,
non-empty, `rstrip("/")`), `OPSGATE_RUNNER_POLL_INTERVAL_SECONDS` (5, > 0),
`OPSGATE_RUNNER_HEARTBEAT_INTERVAL_SECONDS` (30, > 0),
`OPSGATE_MAX_PARALLEL_JOBS` (3, > 0), `OPSGATE_MAX_DURATION_SECONDS_DEFAULT`
(3600, 1..31 536 000), `OPSGATE_EXECUTION_DATA_DIR` (non-empty),
`OPSGATE_TICKETS_DIR` (`<exec>/jobs`), `OPSGATE_SESSION_ARTIFACTS_DIR`
(`<exec>/sessions`), `OPSGATE_TMUX_SOCKET_LABEL` (`remediation`, non-empty),
`TMUX_TMPDIR` (optional, only used in the attach command),
`OPSGATE_DISABLE_FILE_PATH`, `OPSGATE_RUNNER_HOST` (default
`socket.gethostname()`). Variables the env file contains but Python ignores
(`OPSGATE_RUNNER_STALE_AFTER_SECONDS`, `OPSGATE_POLICY_FLOOR_…` in the runner
file) are ignored by Rust too.

### 4.3 HTTP surface (`app.py`)

All routes, with their auth and the order of checks. "gate" = network gate
(4.4); "UI-CSRF" = form token check (4.5.4); "API-CSRF" = 4.5.4.

| Method, path | Auth / checks (in order) | Success |
| --- | --- | --- |
| `GET /api/v1/health` | none, **exempt from the gate** | 200 health JSON (4.6) |
| `POST /api/v1/tickets` | gate; submitter bearer (401 `invalid_submit_token`); JSON object body (400 `invalid_json`); validation (4.7.1) | 201 ticket |
| `GET /api/v1/tickets/<id>` | gate; submitter bearer **or** approver session **or** runner bearer (401 `auth_required`); 404 `ticket_not_found`; then submitter of another source → 403 `forbidden` | 200 ticket |
| `POST /api/v1/tickets/<id>/approve` | gate; approver session (401 `auth_required`); API-CSRF (403 `csrf_required`/`invalid_csrf`) | 200 ticket |
| `POST /api/v1/tickets/<id>/reject` | as approve; body optional JSON `{reason}` | 200 ticket |
| `POST /api/v1/tickets/<id>/cancel` | as reject | 200 ticket |
| `POST /api/v1/tickets/<id>/archive`, `/unarchive` | as approve | 200 ticket |
| `POST /api/v1/runner/claim` | gate; runner bearer (401 `invalid_runner_token`); body optional `{runner_host}` | 200 `{"ticket": null\|ticket}` |
| `POST /api/v1/runner/<id>/status` | gate; runner bearer; JSON object (400 `invalid_json`) | 200 ticket |
| `GET /` | gate | 302 `/login` (no session) or `/tickets` |
| `GET\|HEAD /login` | gate; `next` sanitised | 200 login page, no side effects except the session CSRF token |
| `POST /login` | gate; UI-CSRF; throttle (429); credentials | 302 `next` or `/tickets`; failure 302 `/login[?next=…]` with flash |
| `POST /logout` | gate; UI-CSRF | revoke if authenticated; clear session; 302 `/login` |
| `GET /tickets` | gate; session else 302 `/login` | 200 list (`view=active\|archived\|all`, else active; 100 newest by `created_at`) |
| `POST /tickets` | gate; UI-CSRF; session else 302 `/login` | 302 `/tickets/<id>` + flash "Ticket created and queued for approval"; error → 400 re-rendered page with sticky form + flash |
| `GET /tickets/<id>` | gate; session else 302 `/login?next=<path>` | 200 detail |
| `GET /tickets/<id>/steps/<int:n>/log` | gate; session else 302 `/login?next=<path>` | 200 log page |
| `POST /tickets/<id>/{approve,reject,cancel}` | gate; UI-CSRF; session else 302 `/login` | 302 `/tickets/<id>` |
| `POST /tickets/<id>/{archive,unarchive}` | as above | 302 `redirect_to` if it sanitises and starts with `/tickets`, else `/tickets/<id>` |

Routing details (P1): `<id>` matches one path segment; `<int:n>` matches ASCII
digits only (`0` matches and then fails `log_not_found`); no trailing-slash
variants. Unknown routes 404, wrong methods 405 (bodies P2). `HEAD` works for
every `GET` route.

### 4.4 Request processing order, gates, headers, errors

1. **Proxy fix** (`trust_proxy_headers`): Werkzeug `ProxyFix(x_for=1,
   x_proto=1, x_host=1)` — the client address is the **last** value of
   `X-Forwarded-For` (comma-split, stripped), the scheme the last
   `X-Forwarded-Proto`, the host the last `X-Forwarded-Host`; a header with
   fewer values than trusted is ignored. P1, fixture-tested against Werkzeug.
   Without the setting, the socket peer address is used and headers are
   ignored.
2. **Network gate** (`enforce_tailscale_context`, before every request except
   `/api/v1/health`): if `require_tailscale_context` and the client address
   (scope id `%…` removed) is in none of the CIDRs → 403. Empty address →
   denied. IPv4-mapped IPv6 addresses are not matched against IPv4 networks
   (Python `ipaddress` semantics).
3. **UI-CSRF** (`enforce_ui_csrf`): every `POST` whose path does not start
   with `/api/` (also unknown paths), before authentication (4.5.4).
4. Route handler with its auth checks (4.3, 4.5).
5. **Security headers** on every response incl. redirects, errors, 403/404
   (`SECURITY_HEADERS`): `X-Frame-Options: DENY`,
   `Content-Security-Policy: frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'`,
   `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`,
   `Cache-Control: no-store`.

Error mapping (`handle_service_error`, `handle_forbidden`, `api_error`):

- `ServiceError` on `/api/…` → JSON `{"error": code, "message": text}` with
  its status.
- `ServiceError` elsewhere → flash(message, "error") and 302 to
  `/tickets/<id>` when the path matches `^/tickets/([^/]+)/(approve|reject|cancel|archive|unarchive)$`
  or `^/tickets/([^/]+)/steps/\d+/log$`, else `/tickets`. Exception:
  `POST /tickets` renders the page with status 400 (4.3).
- Gate 403: `/api/…` → `{"error": "forbidden", "message": "Access denied"}`;
  else `forbidden.html` with 403.
- Unhandled errors (corrupt stored JSON on read, SQLite busy beyond the
  timeout): 500, no traceback (P1 status; P2 body).

### 4.5 Authentication and sessions

#### 4.5.1 Bearer tokens

`Authorization: Bearer <token>` — prefix exactly `Bearer `, the rest with the
first `Bearer ` removed and stripped; empty → none (`get_bearer_token`).
Submitter: compare the stripped token with each configured token using a
constant-time **byte** comparison (non-ASCII never raises,
`test_api_bearer_endpoints_reject_non_ascii_token`). Runner token likewise.

#### 4.5.2 Approver session (`get_session_user`)

Session state (the content of the signed cookie in Python): `username`,
`auth_at` (ISO, 4.9), `session_generation` (int), `csrf_token`,
`_flashes`. A request is authenticated iff `username` equals the configured
username, `auth_at` parses and `now - auth_at <= OPSGATE_UI_SESSION_TIMEOUT_SECONDS`,
and `session_generation` is an int (not bool) equal to the generation stored
in `ui_session_state` for that user. Any failure clears the session (P1
semantics).

Cookie (P1 attributes, D-1 format): name `session`, `HttpOnly`,
`SameSite=Lax`, `Secure` iff `OPSGATE_SESSION_COOKIE_SECURE`, `Path=/`, no
`Expires`/`Max-Age` (browser-session cookie, as Flask's non-permanent session);
set only when the session changed; an emptied session deletes the cookie
(`Vary: Cookie` when the session was read is P2). Rust stores the state in an
authenticated-encrypted cookie (`axum-extra` `PrivateCookieJar`, AES-256-GCM)
keyed from `OPSGATE_SESSION_SECRET` via HKDF-SHA256 with a fixed info label;
a cookie that does not decrypt is an empty session.

Generation (`_sync_ui_session_state`, `revoke_ui_sessions`): at API start the
row for the configured username is created with generation 1 and
`password_fingerprint = sha256_hex(bcrypt_hash_string)`, or the generation is
incremented when the fingerprint changed (constant-time compare). Logout of an
authenticated session increments it. Rust uses the identical fingerprint so
switching implementations with an unchanged password does not revoke (but
see D-1).

#### 4.5.3 Login, logout, throttle (`ui_login`, `ui_logout`, `LoginThrottle`)

- `GET/HEAD /login`: renders the form with `next` (sanitised); never counts
  as an attempt, never flashes.
- `next` sanitising (`sanitize_next_path`): strip; empty → none; any scheme or
  netloc (`urlsplit`) → none; must start with `/` and not `//`; any of
  `\r \n \t \0` → none. Form `next` wins over query `next`.
- `POST /login`: key = client address or `"unknown"`. If locked → 429 with the
  login page and flash "Too many failed login attempts. Try again later.",
  even for correct credentials. Otherwise constant-time byte comparison of the
  stripped username **and always** `bcrypt.checkpw(password, hash)` (bcrypt
  `ValueError` → false). Failure → record failure, flash "Invalid username or
  password", 302 `/login` (with `?next=` if any). Success → generation must
  exist (else 500 `session_state_missing`), reset throttle, clear session, set
  `username`, `auth_at=now`, generation, new `csrf_token`
  (`secrets.token_urlsafe(32)`), 302 to `next` or `/tickets`.
- bcrypt parity (fixture): `$2a$`, `$2b$`, `$2y$` hashes; passwords longer
  than 72 bytes are truncated (pyca bcrypt 4.3, pinned `<5.0`); passwords
  with embedded NUL bytes are passed unchanged and **verify against a matching
  hash** (pyca 4.3 accepts them; the fixture includes matching and
  non-matching NUL passwords); malformed hashes → false.
- Throttle: per key, failures within 15 min; locked when ≥ 5 recent failures;
  a failure keeps the last 5 stamps; success resets; at most 10 000 tracked
  keys — on overflow first expired entries are dropped, then the keys whose
  newest failure is oldest. In memory, monotonic clock, lost on restart.
- `POST /logout`: revoke only if `get_session_user()` is authenticated; clear
  session; 302 `/login`.

#### 4.5.4 CSRF

- UI-CSRF: session token is created if absent (`ensure_csrf_token`, also on
  every template render); the form field `csrf_token` must equal it
  (constant-time over UTF-8 bytes) → else `ServiceError("Invalid form token",
  400, "invalid_csrf")` handled as UI error (flash + redirect).
- API-CSRF (`enforce_api_session_csrf`, after the 401 check, only for
  non-`GET/HEAD/OPTIONS`): if the session has a token and `X-CSRF-Token` is
  non-empty → equal (constant-time bytes) passes, else 403 `invalid_csrf`; if
  no header: `Sec-Fetch-Site` present → passes iff stripped/lowercased equals
  `same-origin`; else `Origin` present → passes iff lowercased equals
  `<scheme>://<host>` of the request (after proxy fix); else 403
  `csrf_required`.

### 4.6 JSON contract

Input (`parse_request_json`): Flask `get_json(silent=True)`: only when the
`Content-Type` mimetype is `application/json` or `application/*+json`
(parameters ignored); otherwise "no JSON". Undecodable JSON → no JSON.
Endpoints that require an object answer 400 `invalid_json` ("JSON object
required") for no JSON or a non-object; nesting deeper than 64 object/array
levels (root counts) → 400 `invalid_json` before any mutation
(`check_json_depth`). Reject/cancel/claim treat a falsy body (`null`, `{}`,
`[]`, `0`, `""`, `false`) as `{}` (D-4 for truthy non-objects). A UTF-8 BOM is
accepted; integer tokens longer than 4300 digits are undecodable (CPython
limit).

`str()` conversions (P1 for JSON scalars): where Python applies `str()` to a
JSON value — ticket `source`, `title`, `summary`, `task_ref`, `expires_at`;
`reason`; runner `runner_host`, `event`, `state`, `result`, `result_detail` —
Rust renders: string → itself; integer → decimal; float → Python `repr`
(4.8); `true/false` → `True/False`; `null` → `None` (so `{"reason": null}`
stores `None`). Arrays/objects: D-3.

Output shapes (P1 fields and types; formatting P2 — Rust uses the same
compact sorted-key serializer as Flask's `jsonify` because it has it anyway):

- ticket (`_serialize_ticket`): `id, source, task_ref, title, summary,
  execution_plan, policy_requirements, context, payload_checksum,
  approved_payload_checksum, state, created_by, created_at, approved_by,
  approved_at, expires_at, max_duration_seconds, tmux_sessions, runner_host,
  last_heartbeat_at, started_at, finished_at, result, result_detail,
  archived_at, archived_by, is_archived, is_terminal, is_archivable`
  (JSON columns parsed; booleans derived as in Python);
- error: `{"error": <code>, "message": <text>}`;
- health (`health`): `{"status": "ok", "service": <service_name>, "db":
  "ok", "runner_last_heartbeat": <newest heartbeat or null>, "runner_host":
  <its host or null>, "ticket_counters": {<state>: <count>}}`;
- claim: `{"ticket": null}` or `{"ticket": <ticket>}`.

### 4.7 Ticket lifecycle and SQL semantics (`service.py`)

All mutating operations run in one connection inside `BEGIN IMMEDIATE`; every
transition `UPDATE` also matches the state it read (compare-and-set); a CAS
that changes no row → 409 `state_changed`, nothing written
(`_require_row_changed`). Connections: WAL, `foreign_keys=ON`,
`busy_timeout=5000` ms (`_connection`). Audit events record the replaced
state; their `metadata_json` content is P1 (format P2). ids: `uuid4()` text.

#### 4.7.1 Create (`create_ticket`, `create_manual_ticket`, `_normalize_new_ticket`, `_insert_ticket`)

Validation order (P1; the first failing check decides the code):

1. `source` (`str(payload.get("source", <auth source>)).strip()`) must equal the
   authenticated source → 403 `source_mismatch`.
2. `title`, `summary` stripped non-empty → 400 `invalid_ticket`.
3. `task_ref`: `None` stays none; else stripped, empty → none.
4. UTF-8 validity of source/title/summary/task_ref → 400 `invalid_ticket`
   "<field> must be valid UTF-8 text" (D-2 for lone surrogates).
5. `execution_plan` (`parse_execution_plan`): non-empty list → else
   `invalid_execution_plan`; each item an object with non-blank string `role`,
   `agent`, `prompt_markdown`; trimmed; agent lowercased ∈ {`codex`,`claude`}.
6. `policy_requirements` (`parse_policy_requirements`): `None`/`""` → `{}`;
   non-object → `invalid_policy_requirements`; only `require_reviewer_step`
   (bool) is kept. Merge with the token floor (`merge_policy_requirements`):
   floor true + explicit false → 400 `policy_floor_violation`; effective
   `{"require_reviewer_step": floor or ticket}`. Enforce: requires a step whose
   role stripped/lowercased is `reviewer` → 400 `missing_reviewer_step`.
7. `context`: absent/`null` → `{}`; non-object → 400 `invalid_ticket`.
8. `expires_at`: if not null → `isoformat_z(parse_iso_datetime(str(x)))`,
   errors → 400 `invalid_expires_at` (4.9).
9. `max_duration_seconds`: null/absent → configured default; must be a JSON
   integer (not bool, not float — `900.0` and `1e309` fail) in
   1..31 536 000 → 400 `invalid_ticket`.
10. checksum of the normalised payload (4.8).
11. `created_by`/`actor` = `submit:<source>` or `approver:<user>`;
    `source_ip`, `user_agent` (request header) → UTF-8 check →
    400 `invalid_ticket`.
12. Transaction: lazily expire open tickets with the same `(source, task_ref)`
    in `pending_approval`/`approved`, not archived, ordered by `created_at`
    (`_expire_open_tickets_for_task_ref` → `_maybe_expire_ticket`: only if
    `expires_at` parses and `<= now`; `UPDATE … state='expired',
    finished_at, result='failure', result_detail='expired_before_execution'
    WHERE id=? AND state=?`; audit `ticket_expired` with `{"expires_at": raw}`);
    then insert (`state='pending_approval'`, JSON columns written with
    `json.dumps(sort_keys=True)`); unique-index violation → 409
    `duplicate_open_ticket`; audit `ticket_created`
    `{"task_ref": …}`; commit; return the row.

The open-ticket dedupe index (`OPEN_TICKET_DEDUPE_INDEX`) is the enforcement
of "one open ticket per `(source, task_ref)`" outside archived tickets.

#### 4.7.2 Transitions

| Operation | Preconditions (error) | Write | Audit (event, prev → new, metadata) |
| --- | --- | --- | --- |
| approve | exists (404 `ticket_not_found`); not archived (409 `archived_ticket`); `pending_approval` (409 `invalid_state`); lazily expired → commit expiry, 409 `ticket_expired`; stored plan re-validated (`parse_execution_plan`), policy re-enforced | `approved`, `approved_by`, `approved_at`, `approved_payload_checksum` = checksum of stored fields; CAS on `pending_approval` and not archived | `ticket_approved`, pending→approved, `{approved_payload_checksum}` |
| reject | exists; not archived; `pending_approval` | `rejected`, `finished_at`, `result='failure'`, `result_detail = reason or 'rejected_by_approver'` | `ticket_rejected`, `{reason}` |
| cancel | exists; not archived; state ∈ pending/approved/running | `canceled`, `finished_at`, `result='canceled'`, `result_detail = reason or 'canceled_by_approver'`; CAS on read state | `ticket_canceled`, prev→canceled, `{reason}` |
| archive | exists; state ∈ terminal ∪ {pending} (409 `invalid_state`); not archived (409 `already_archived`) | `archived_at`, `archived_by` | `ticket_archived`, state→state, `{archived_at}` |
| unarchive | exists; archived (409 `not_archived`) | clear both; CAS also on `archived_at`/`archived_by IS ?`; unique violation → 409 `duplicate_open_ticket` | `ticket_unarchived`, `{previous_archived_at, previous_archived_by}` |

States: open `pending_approval, approved, running`; terminal `succeeded,
failed, rejected, canceled, expired`; archivable terminal ∪ pending.

#### 4.7.3 Claim (`claim_ticket`)

- If the disable file exists → `{"ticket": null}` without touching the DB
  (and without a heartbeat).
- In one `BEGIN IMMEDIATE`, loop: oldest `approved`, not archived ticket by
  `approved_at ASC, created_at ASC`. None → upsert heartbeat for
  `runner_host`, commit, null.
- Lazily expired → next. Stored JSON validation (`parse_stored_json`: decode,
  depth ≤ 64; plan via `parse_execution_plan`; policy must be an object and
  pass `parse_policy_requirements` without dropping keys; enforce; context
  object; tmux sessions array) — failure → `failed`, `result='failure'`,
  `result_detail='invalid_stored_plan'`, audit `ticket_failed`
  `{"reason": "invalid_stored_plan", "error": <code>}`, next ticket.
- Recomputed checksum ≠ `approved_payload_checksum` (or none) → `failed`,
  `prompt_tampered`, audit `ticket_failed` `{"reason": "prompt_tampered"}`,
  next.
- Else `running`, `runner_host`, `started_at = COALESCE(started_at, now)`,
  `last_heartbeat_at = now`; audit `runner_claimed` `{runner_host}`;
  heartbeat upsert; commit; return the ticket.
- `runner_host` = body `runner_host` stripped, else client address, else
  `"runner"`. Every CAS miss (`rowcount 0`) continues the loop.

#### 4.7.4 Runner status (`update_runner_status`)

`event = str(payload.get("event", "heartbeat")).strip().lower() or "heartbeat"`
(only a *missing* key defaults; explicit `null`/`false`/`0` become `none`/
`false`/`0` and are rejected; an empty or blank string becomes `heartbeat`) ∈
{`heartbeat, step_started, step_finished, step_failed, timeout, failed,
ticket_succeeded, invalid_plan`} else 400 `invalid_runner_event` (before the
transaction). In the transaction: 404; terminal → 409 `invalid_state`; not
approved/running → 409; no `state` and not running → 409 ("Heartbeat requires
running state"); running and assigned host differs → 409
`runner_host_mismatch`. Requested `state` ∈ {running, succeeded, failed,
canceled} else 400 `invalid_runner_state`; terminal from non-running → 409;
terminal from running sets `finished_at`. Result derived from state
(success/failure/canceled) or given `result` ∈ {success, failure, timeout,
canceled} and compatible (succeeded→success; failed→failure|timeout;
canceled→canceled) else 400 `invalid_runner_result` — without any write.
`state: null` and `result: null` count as absent (`is not None` checks);
`result_detail = str(payload.get("result_detail", "")).strip()` (so `null`
stores `None`) is written only if non-empty; `tmux_sessions: null` or absent
leaves the column unchanged, any other non-list → 400 `invalid_tmux_sessions`,
a list replaces the column. The parity harness has cases for each explicit
`null`/`false`/`0` value of `event`, `state`, `result`, `result_detail`,
`tmux_sessions` and `runner_host`. `runner_host` and
`last_heartbeat_at` always written; CAS on `(id, previous state)`; heartbeat
upsert; audit `runner_<event>` `{event, result_detail}`.

### 4.8 Canonical JSON and the payload checksum (P1, byte-exact)

`compute_payload_checksum` = `sha256_hex(json.dumps(payload, sort_keys=True,
separators=(",", ":"), ensure_ascii=True).encode())` over
`{source, task_ref, title, summary, execution_plan, policy_requirements,
context, expires_at, max_duration_seconds}` (`_ticket_payload_from_fields`).
It is stored at creation (`payload_checksum`), recomputed from the stored
columns at approval (`approved_payload_checksum`) and again at every claim
(tamper check). **A ticket approved by one implementation and claimed by the
other must pass**, and production contexts contain floats (section 1), so the
bytes must match CPython exactly:

- keys sorted by code point (Rust `String` order is identical);
- `ensure_ascii`: every character outside U+0020..U+007E is escaped; `"` and
  `\\` escaped; `\n \r \t \b \f` short forms; other controls and U+007F as
  `\u00XX`; non-BMP as a lowercase-hex UTF-16 surrogate pair;
- integers as decimal digits (any size up to the 4300-digit input limit);
- floats as CPython `repr` (shortest round-trip digits; scientific notation
  when the decimal exponent is < -4 or ≥ 16, e.g. `1e+16`, `1e-05`, `3.0`,
  `0.0001`);
- non-finite floats are D-2.

Implementation: `serde_json` (`arbitrary_precision`, so number tokens survive
parsing) with a custom `serde_json::ser::Formatter` (string escaping and float
formatting) and `ryu` for the shortest digits. This is a formatter on top of
the maintained crate, not a JSON re-implementation. Pinned by
`fixtures/checksum.json` (≥ 500 payloads from production-shaped and adversarial
contexts) and `fixtures/float_repr.json` (≥ 10 000 values incl. subnormals,
powers of ten, exponent boundaries) generated by CPython.

Stored JSON columns (`json.dumps(x, sort_keys=True)`, separators `", "`/
`": "`) and audit metadata use the same formatter with the default separators
(P2, but free with the formatter).

### 4.9 Timestamps

- Written: `isoformat_z(utc_now())` = Python `datetime.isoformat()` of an
  aware UTC datetime with `+00:00` replaced by `Z`: `YYYY-MM-DDTHH:MM:SS.ffffffZ`,
  **without the fraction when microseconds are 0** (P1: `ORDER BY created_at`
  and `approved_at` compare these strings; the quirk that a whole-second value
  sorts after fractional values of the same second is kept).
- Parsed (`parse_iso_datetime`): strip; trailing `Z` → `+00:00`;
  `datetime.fromisoformat`; naive → `ValueError` ("Datetime must include
  timezone information"); conversion overflow → `ValueError`. Rust accepts the
  ISO 8601 extended forms `YYYY-MM-DD[T| ]HH:MM[:SS[.f{1,6}]]` with offset `Z`
  or `±HH:MM[:SS[.ffffff]]`, plus the forms Python's `isoformat` produces;
  everything else → `invalid_expires_at` (D-7). Results normalise to the
  same instant as Python (fixture `datetime.json`, generated by CPython 3.14
  incl. year 1/9999 boundaries and offset overflows).
- UI filter `ui_datetime`: non-string or blank → `n/a`; unparsable → the raw
  string; else `%Y-%m-%d %H:%M UTC`.

### 4.10 Database schema and ownership

The API process owns the schema and runs the idempotent `init_db` at start:
`CREATE TABLE IF NOT EXISTS` for the four tables, the two indexes, `ALTER
TABLE … ADD COLUMN archived_at/archived_by` when missing,
`idx_tickets_archived_at`, `DROP INDEX IF EXISTS idx_tickets_open_dedupe` +
re-create, then `_sync_ui_session_state`; the DB parent directory is created
(`mkdir -p`). Rust runs **the same DDL text** (copied verbatim into
`opsgate-store`), so a database initialised by either implementation is
identical (contract test: `sqlite_master` of a Python-initialised and a
Rust-initialised database compared after whitespace normalisation, and Rust
start on a Python database is a no-op except the index re-creation Python also
does). `check-db` verifies the schema read-only. Journal mode WAL is set per
connection. Rust opens one connection per request inside `spawn_blocking`,
like Python, so locking behaviour (writers serialised by `BEGIN IMMEDIATE`,
5 s busy timeout) is unchanged.

### 4.11 UI pages

Pages and their information are P1 at the level of: which tickets/fields are
shown, which actions (forms with `csrf_token`, action URLs, field names) are
offered in which state, flash messages, links (`url_for` targets), the manual
ticket form (multi-step editor field names `steps-<n>-role|agent|prompt_markdown`,
legacy `step_role`, `step_agent`, `prompt_markdown`, `title`, `summary`,
`task_ref`, `max_duration_seconds` (default `3600`), `expires_at`,
`context_json`), role defaults (`DEFAULT_AGENT_BY_ROLE`: implementer/implementor/
investigator → codex, reviewer → claude, unknown → codex) and scaffolding
(`ROLE_PROMPT_SCAFFOLDING`, `implementor` = implementer, unknown →
investigator), the default step (reviewer if the operator floor requires it,
else investigator). Manual form parsing (`parse_manual_ticket_steps`): step
keys by `int(n)` ascending, first value per key, empty agent → role default;
`max_duration_seconds` must match `[0-9]+`; `context_json` must decode
(`invalid_context_json`, nesting ≤ 64) to an object. Ticket list: 100 newest,
`view` filter; detail: plan, policy/context as indented JSON, session views
with log previews (4.12), action forms by state/archive flags, back link to the
archived or active view. HTML bytes are P2 because the same template files are
rendered (section 6.3).

### 4.12 Log previews and path containment (`log_preview.py`, `app.py:resolve_session_log_path`)

- Preview: final 64 KiB of the file; normalise `\r\n`/`\r` to `\n`; drop a
  trailing empty line; last 40 lines; each line keeps its final 2048 bytes;
  UTF-8 decode with replacement; `[log preview truncated]` prepended when bytes
  or lines were omitted; missing file → no lines.
- Step log page: final 2 MiB, decoded with replacement, newlines normalised,
  `[step log truncated]\n` prepended when earlier bytes were omitted.
- Containment: `log_path` from the ticket's `tmux_sessions` entry; blank →
  404 `log_not_found`; `Path(raw).resolve()` (symlinks resolved, non-strict)
  must lie under `(<execution_data_dir>/sessions/<ticket_id>).resolve()` → else
  400 `invalid_log_path`; then must exist and be a regular file → else 404.
  The order (containment before existence) is P1. Step lookup: entries whose
  `int(step_index)` equals `n - 1`; `n <= 0` → 404. Session views skip
  non-object entries; `step_number = step_index + 1` if ≥ 0.

### 4.13 Runner (`runner.py`)

#### 4.13.1 API client (`RunnerApiClient._request`)

`Authorization: Bearer <runner token>`; JSON body (`Content-Type:
application/json`) for claim/status; 15 s timeout. Responses: 2xx body decoded
(empty → `{}`); undecodable → error `(502, invalid_response)`; non-object →
`(500, invalid_response)`. HTTP error → `(status, code)` where code is the
body's `error` only if it is one of `invalid_state`, `state_changed`,
`runner_host_mismatch`, else `http_error`. Transport failures (connect,
timeout, protocol) → `(503, transport_error)`. Error texts never contain
response bodies or exception text. Claim body `{"runner_host": <host>}`; a
`ticket` that is neither null nor an object → `(500, invalid_ticket)`.
Plain HTTP only (D-10).

#### 4.13.2 Paths and names (P1)

- Artifacts root `<session_artifacts_dir>/<ticket_id>/`; ticket root
  `<tickets_dir>/<ticket_id>/`.
- Step dir `<artifacts>/steps/<NN>-<role_slug>` where `NN = step_index + 1`
  zero-padded to 2 and `_slugify` = lowercase, runs of `[^a-z0-9]` → `-`,
  trimmed of `-`, empty → `step`.
- Files: `prompt.md`, `previous_step_summary.md`, `session.log`,
  `summary.json`, `session_metadata.json`, `run_step.sh`, `exit_code` in the
  step dir; `context.json` in the artifacts root **and** the ticket root.
- tmux session `job-<ticket_id>-<NN>-<role_slug>` on socket label
  `OPSGATE_TMUX_SOCKET_LABEL` (`tmux -L <label> …`).
- Runner state files `<execution_data_dir>/runner-state/<ticket_id>.json`
  `{ticket_id, runner_host, updated_at}`.
- `attach_command`: `sudo -u ops [env TMUX_TMPDIR=<q>] tmux -L <q> attach -t <q>`
  (quoting P2: any POSIX-correct quoting).

#### 4.13.3 Agent commands and step script (P1, security-relevant)

- `codex` → `codex exec --skip-git-repo-check --dangerously-bypass-approvals-and-sandbox - < <prompt>`;
  `claude` → `claude -p --dangerously-skip-permissions < <prompt>`; other →
  step fails `unsupported_agent_<slug>` (`_build_agent_command`). Agents are
  resolved through the inherited `PATH` (4.13.8).
- `run_step.sh` (mode 0750), same text as Python:

  ```bash
  #!/bin/bash
  set -uo pipefail
  <command> 2>&1 | tee -a <log>
  cmd_rc=${PIPESTATUS[0]}
  printf "%s\n" "$cmd_rc" > <exit_code>
  exit "$cmd_rc"
  ```
- Launched with `tmux -L <label> new-session -d -s <session> "/bin/bash <script>"`
  (non-zero exit of tmux → exception, 4.13.6). Probes: `has-session -t`,
  `kill-session -t`, `ls`.

#### 4.13.4 Executor (`TicketExecutor.run`, `_run_step`)

- Starts only for state `running`; `started_at` from the ticket (else now);
  `max_duration = int(max_duration_seconds or default)`, ≤ 0 → default;
  deadline = started_at + max_duration (ticket-wide).
- Empty/non-list plan → status `invalid_plan`/`failed`/`failure`/
  `invalid_execution_plan`/`tmux_sessions: []`.
- Per step: stop flag → return; `GET` ticket, terminal → kill sessions marked
  running, return; a `summary.json` with status `succeeded` → collect it once
  into prior summaries and skip.
- Fresh start: write `context.json` (both places) `{ticket_id, step_index,
  step_role, step_agent, prior_step_summaries}`, `prompt.md` = prompt + `\n`,
  `previous_step_summary.md` = last prior summary as `json.dumps(sort_keys,
  indent=2)` + `\n` (if any); metadata `{step_index, role, agent,
  session_name, attach_command, prompt_path, context_path, log_path,
  summary_path, status: "running", started_at}` written **before** launch;
  `step_started` status with `step_<n>_started`; script; tmux launch.
- Poll loop every 1 s until `exit_code` exists: stop flag (exit code present →
  return canceled without touching metadata; else kill session, metadata
  `interrupted` + `finished_at`, return); deadline → kill, metadata `timeout`,
  outcome timeout `max_duration_seconds_exceeded`; `GET` ticket (API error →
  assume running): `canceled` → kill, metadata `canceled`, return;
  other terminal → kill, fail `ticket_entered_<state>`; exit code appeared →
  break; session gone → fail `session_terminated_without_exit_code`;
  heartbeat every `max(1, interval)` s: `heartbeat` with
  `running_step_<n>_of_<total>`.
- Finish: exit code `int(text.strip())` else 1; entry gets `finished_at`,
  `log_path`, `log_size_bytes` (0 if missing), `log_sha256` (null if missing);
  `summary.json` `{ticket_id, step_index, role, agent, session_name,
  started_at, finished_at, exit_code, status: succeeded|failed, log_path,
  log_size_bytes, log_sha256, summary_markdown: <preview lines joined>}`;
  success → metadata `succeeded` + `summary_path`, status `step_finished`
  `step_<n>_finished`; failure → metadata `failed`, outcome
  `step_<n>_exit_code_<rc>`.
- Ticket end: all steps → `ticket_succeeded`/`succeeded`/`success`/
  `completed_<k>_steps`; timeout → kill running sessions, `timeout`/`failed`/
  `timeout`/detail; failure → `step_failed`/`failed`/`failure`/detail;
  canceled → nothing posted.
- `tmux_sessions` sent with every status is the executor's list of metadata
  entries upserted by `step_index`.
- `_post_status`: payload `{runner_host, event[, state][, result][,
  result_detail][, tmux_sessions]}`; up to 3 attempts, 1 s apart (stop-aware
  wait); 409 `invalid_state`/`state_changed` → silently done; status < 500 or
  last attempt → raise.

#### 4.13.5 Resume rules (`_run_step`, README "Runner restart recovery")

`resuming = metadata exists or exit_code exists or session alive` (exit code
re-checked after a negative session probe). Resuming never relaunches:
exit code → adopt (keep original `started_at`, add `resumed_at`); live session
→ re-attach and poll (`step_<n>_resumed`); neither → metadata `interrupted`
+ `finished_at`, fail `step_<n>_interrupted`. Unreadable metadata still counts
as present (fail closed). Cross-implementation adoption (Python-written
artifacts read by Rust and vice versa) is P1 and tested (7.4).

#### 4.13.6 Supervisor (`OpsGateRunner`)

- Start: create `runner-state/`; recovery pass including artifact directories
  (once per process); then loop until stopped: reap finished workers (remove
  state files of workers marked for cleanup), recovery pass (state files +
  tmux), disable file → sleep poll interval (or end with `--once`), claim
  while active workers < `max_parallel_jobs` (claim error → log
  `Runner claim failed: status=<s> category=<c>`, stop claiming this round;
  null → stop; missing id → skip), write state file, start worker; sleep poll
  interval.
- Recovery (`_recover_inflight_tickets`): candidates = ids from state files
  (invalid JSON/non-object/no id → file deleted), tmux sessions matching
  `^job-([0-9a-fA-F-]{36})-\d{2}-` whose id matches the UUID pattern, and
  (first pass) artifact directories named like a UUID; sorted; stop when the
  worker limit is reached; `GET` error → skip; terminal or not running → kill
  that ticket's sessions (verified), delete state file; running → write state
  file, start worker (one per ticket).
- Worker failure (`_run_worker`): API error ≥ 500 → log
  `Runner API unavailable: status=<s> category=<c>`, keep state; other
  exception → kill and **verify** the ticket's sessions are gone, then post
  `failed`/`failed`/`failure`/`runner_unhandled_exception:<Type>`; if cleanup
  or reporting fails → keep the state file. Finally, if not marked for
  cleanup: `GET` ticket; terminal → kill sessions, mark for cleanup.
- Session cleanup verification (`_tmux_sessions_for_ticket`): `tmux ls`
  missing binary → error; non-zero exit with "no server running", "No such
  file or directory" or "Connection refused" in stderr → no sessions; other
  failure → error; after kills a re-list must be empty.
- Rust maps the exception classes to the same outcomes; the `<Type>` in
  `runner_unhandled_exception:<Type>` is P2 (Rust error kind names).

#### 4.13.7 Artifact writing and permissions

JSON artifacts and state files are published by same-directory atomic
replacement with a 0600 temporary file (`_atomic_write_json`); on failure the
destination is untouched and the temporary file removed (cleanup failure
keeps the original error). `prompt.md`, `previous_step_summary.md` are
written in place with the process umask; `run_step.sh` chmod 0750;
directories `mkdir -p` with the umask. The API (group `ops`) reads
`session.log` written by `tee` under the step's umask.

#### 4.13.8 Process environment of steps (P1)

The tmux server for the socket label is started by the runner's first
`new-session` when none runs and inherits the runner's environment: the
launchd variables after the `bash -lc` login shell (`path_helper` PATH,
`SHELL`, `USER`, `TMPDIR`, …) **plus every key of the runner env file**
(4.2), including `OPSGATE_RUNNER_TOKEN` (pre-existing exposure, Q6). The Rust
runner keeps the same launch wrapper (10.1) and the same env-file application,
so agents see the same environment (minus `__PYVENV_LAUNCHER__`, D-11).

### 4.14 Files, users, permissions (role-owned, unchanged)

API runs as `control_service_user` (`WorkingDirectory`
`/Users/control_service_user/opsgate`), runner as `ops` (`/Users/ops/remediation`);
DB `/usr/local/var/opsgate/run/control/opsgate.sqlite3`; env files
`/etc/opsgate/*.env`; logs `/var/log/opsgate/*`; tmux.conf
`/Users/ops/.tmux.conf`; disable file `/Users/ops/remediation/.disabled`
(checked by both API claim and runner). The Rust binary is installed
root-owned (10.1), so neither service user can modify the executable (the
Python venvs are owned by the service users).

### 4.15 Logging

Python logs nothing on the API side (empty logs) and, on the runner side,
WARNING lines through the `lastResort` handler on stderr (bare message) plus
`traceback.print_exc()` for unexpected worker exceptions. P1 lines (text):
`Runner claim failed: status=<s> category=<c>`, `Runner API unavailable:
status=<s> category=<c>`. Rust writes these to stderr (`tracing`, plain
format, timestamp prefix allowed), adds one INFO startup line (version,
implementation, bind address / runner host, no secrets) and replaces
tracebacks by one line with the error kind (D-12). No machine consumer parses
these logs (checked: ops-control/ops-library reference them only in runbooks).

---

## 5. Intentional divergences (P3, exhaustive)

- **D-1 Session cookie format.** Flask's itsdangerous-signed cookie is
  replaced by an encrypted `PrivateCookieJar` cookie of the same name and
  attributes. Cookies of one implementation are empty sessions for the other:
  **approvers sign in again after every API cutover and rollback**, and forms
  rendered before the switch fail the UI-CSRF check once (flash "Invalid form
  token"). Semantics of 4.5.2 are unchanged. (Q1.) Rejected alternative:
  reimplementing itsdangerous + Flask's tagged JSON serializer (a Python
  library re-implementation for a one-time re-login).
- **D-2 JSON corners.** Rust answers 400 `invalid_json` (UI form:
  `invalid_context_json`) where Python accepted or answered differently:
  `NaN`/`Infinity`/`-Infinity` literals (Python stores them); lone UTF-16
  surrogate escapes (Python: 400 `invalid_ticket` in direct text fields,
  accepted inside `context`/`execution_plan`); UTF-16/UTF-32 encoded bodies
  (Python auto-detects); floats that overflow to ±inf when the payload is
  canonicalised (Python stores `Infinity`). Validation order is otherwise
  kept, so `{"max_duration_seconds": 1e309}` still answers `invalid_ticket`.
  `check-db` reports stored rows Rust cannot read; production has none
  (section 1: every column `json_valid`, no non-finite numbers).
- **D-3 `str()` of arrays/objects.** Where Python stores the `repr` of a JSON
  array/object passed in a text field (4.6), Rust answers 400 with the field's
  code (`invalid_ticket` for ticket fields, `invalid_runner_event`/
  `invalid_runner_state`/`invalid_runner_result` for runner fields,
  `invalid_json` for `reason`/`runner_host`/`result_detail`). No producer
  sends them.
- **D-4 Truthy non-object bodies** on reject/cancel/claim (e.g. `[1]`, `"x"`):
  Rust 400 `invalid_json`; Python 500 (`AttributeError`).
- **D-5 Request body limit** 8 MiB → 413 (Python: waitress' 1 GiB default).
  Largest production plan 3 KB.
- **D-6 HTTP server limits and headers**: waitress' header/URL size limits,
  `Server` header and connection handling differ from hyper's; no client
  depends on them.
- **D-7 `expires_at` formats.** Rust accepts the ISO 8601 extended subset of
  4.9; Python's `fromisoformat` additionally accepts basic format
  (`20261021T1000Z`), week and ordinal dates, `,` as decimal separator,
  hour-only offsets and other rarities → Rust 400 `invalid_expires_at`.
  Producers send `isoformat()` output.
- **D-8 Settings parsing.** Non-ASCII digits in integers, netmask/hostmask
  CIDR notation, integers outside `i64` → `SettingsError` at startup (Python
  accepted or failed later). Production values are plain.
- **D-9 Framework responses** (unknown route 404, 405, `OPTIONS`, 500 pages)
  differ in body and `Allow` details.
- **D-10 Runner base URL** must be `http://` (production
  `http://127.0.0.1:8711`); `https://` is a startup `SettingsError`.
- **D-11 `__PYVENV_LAUNCHER__`** (a Python launcher artefact) is no longer in
  the runner's and thus the agents' environment.
- **D-12 Logging**: tracebacks replaced by single lines (4.15).
- **D-13 Unhandled-exception detail**: `runner_unhandled_exception:<Type>`
  names a Rust error kind.
- **D-14 Concurrency inside one process**: Python serves 8 requests in
  parallel (waitress threads); Rust is not limited to 8. SQLite serialises
  writers in both.
- **D-15 Rust-only CLI**: `--version`, `check-config`, `check-db`,
  `serve --db/--bind-host/--bind-port` (tests and shadow only).
- **D-16 Faster shutdown observation**: the Rust runner's sleeps and HTTP
  requests are cancellable, so SIGTERM is observed sooner than Python's
  poll-interval sleep and 15 s request timeout; the shutdown actions
  themselves are unchanged (4.1, 4.13.4).

---

## 6. Architecture and crate choices

### 6.1 Runtime shape

One binary, one tokio runtime (`rt-multi-thread`, 2 worker threads; SQLite
and filesystem work in `spawn_blocking`).

- `serve`: axum router → middleware stack in the order of 4.4 → handlers
  calling `opsgate-store` functions (one connection per call, `BEGIN
  IMMEDIATE` closures) → minijinja for pages.
- `runner`: supervisor task + one task per ticket (Python: threads); the stop
  flag is a `tokio::sync::watch`/`CancellationToken`; 1 s polls and the 1 s
  retry wait are stop-aware; tmux and probes via `tokio::process::Command`;
  HTTP via `reqwest`.

### 6.2 Crate choices

| Need | Crate | Why |
| --- | --- | --- |
| async runtime, signals, processes | `tokio` | standard; precedents |
| HTTP server | `axum` (+ `axum-extra` cookie-private) | tokio-native, tower middleware, mailgun-relay precedent |
| session cookie | `cookie` private jar (AES-256-GCM) via `axum-extra`, `hkdf` + `sha2` | authenticated encryption, no server-side session store needed (generation gives revocation) |
| templates | `minijinja` (feature `json`) | Jinja2-compatible: renders the **same template files** as Flask (`with`, `set`, `loop.index0`, `tojson(indent=2)`, `in` lists, conditional expressions); no second template dialect to keep in sync. `askama` rejected: compile-time checks, but a rewrite of five templates into another dialect and two copies during the parallel period |
| SQLite | `rusqlite` (`bundled`) | synchronous API fits the read-check-CAS-write closures in `BEGIN IMMEDIATE`; bundled pins the SQLite version on macOS; `sqlx` rejected (async driver and compile-time DB add nothing here) |
| JSON | `serde`, `serde_json` (`arbitrary_precision`), `ryu` | custom `Formatter` for the checksum (4.8); tokens preserved for integer/float classification |
| password hashes | `bcrypt` | maintained; `$2a/$2b/$2y`, verify with 72-byte truncation (fixture) |
| constant-time compare | `subtle` | |
| ids | `uuid` (v4) | |
| time | `chrono` | UTC now, microsecond formatting; the narrow ISO parser of 4.9 is ~100 lines on top |
| CIDR | `ipnet` | |
| form bodies | `form_urlencoded` | ordered pairs, first-value semantics (Werkzeug `MultiDict.get`) |
| runner HTTP client | `reqwest` (default features off, no TLS) | async, timeouts; D-10 |
| atomic files | `tempfile` | `NamedTempFile::new_in` (0600) + `persist` = Python's publish |
| shell quoting | `shlex` | attach command (P2) |
| patterns | `regex` | the few Python patterns (UUID, tmux names, step fields) |
| CLI | `clap` (derive) | |
| logging | `tracing`, `tracing-subscriber` (fmt) | |
| tests | `tempfile`, `tower` (`ServiceExt::oneshot` as the Flask test client), `tokio` test utilities with paused time | |

No hand-rolled protocols. The only Python-compatibility code is small and
fixture-pinned: the checksum formatter (4.8), Python `str.strip` whitespace,
Python `int()` for ASCII, the ISO subset parser, Werkzeug ProxyFix selection,
and the non-strict path resolution of 4.12 (canonicalise the longest existing
prefix, then normalise the rest lexically).

### 6.3 Templates

`opsgate-web` embeds `../../../src/opsgate/templates/*.html` with
`include_str!` and registers Flask's globals/filters: `url_for(endpoint,
**kwargs)` (endpoint → path table from 4.3; extra kwargs → query string),
`get_flashed_messages(with_categories=true)` (pops the session flashes),
`csrf_token`, `ui_datetime`, `tojson` (HTML-safe, sorted keys, `indent`).
Autoescape for `.html`. A test renders every template with representative
contexts (each ticket state × archived flag, flashes, form errors) and checks
the P1 elements of 4.11 with an HTML parser, never bytes. Template edits
during the parallel period are made once and verified against both
implementations by the parity harness.

---

## 7. Test strategy

### 7.1 Rust tests

- `opsgate-core`: fixture-driven unit tests (7.2) plus property tests for
  the formatter (round trip through `serde_json`).
- `opsgate-store`: every operation of 4.7 against temp databases; race tests
  porting `tests/test_ticket_transition_races.py` with two connections and a
  hook between the read and the CAS write; schema contract test (4.10).
- `opsgate-web`: in-process tests with `tower::ServiceExt::oneshot` (the
  Flask test-client equivalent) for every route, gate, header, auth, CSRF,
  throttle (injected clock) and session case of `tests/test_api.py`.
- `opsgate-runner`: executor and supervisor with a fake API (in-process axum)
  and a fake tmux trait, paused tokio time; `tmux` integration tests with a
  private socket label and `TMUX_TMPDIR` (skipped only if `tmux` is absent;
  CI installs it).
- Every slice updates `rust/TESTMAP.md` (Python test → Rust test, section
  7.5).

### 7.2 Fixtures (Python as the oracle)

`rust/fixtures/generate.py` (run with the project's uv environment, imports
`opsgate`) writes JSON fixtures; a pytest drift test regenerates them in a temp
dir and fails on any difference (fixtures are never edited by hand). Files:
`checksum.json`, `float_repr.json`, `storage_json.json` (stored-column values, compared semantically),
`datetime.json` (parse/normalise/format, accepted and rejected inputs, with
the D-7 subset marked), `pystr.json` (`str()` of scalars, `strip`, `lower`),
`settings.json` (env sets → settings or `SettingsError` setting name; env-file
parsing cases), `validation.json` (payload → normalised ticket or error code;
covers 4.7.1 order), `log_preview.json`, `proxy_fix.json` (headers → client
address/scheme/host via Werkzeug), `bcrypt.json` (hash/password → result,
generated with pyca bcrypt 4.3 incl. long and NUL passwords),
`throttle.json` (event sequences with clock → locked/unlocked), `schema.sql`
(Python-initialised `sqlite_master`).

### 7.3 API parity harness (`rust/parity/api/`, black box)

pytest suite (dev dependency `httpx`) that starts an implementation as a
subprocess on a free loopback port with a generated env file and a temp
database (`OPSGATE_IMPL=python|rust`), then runs scenarios ported from
`tests/test_api.py` and the races where they are observable over HTTP:
create/dedupe/expiry/approve/reject/cancel/archive/unarchive/claim/status
flows, every error code, gate and proxy cases (`trust_proxy_headers` with
`X-Forwarded-*`), login/throttle/logout/generation, both CSRF mechanisms,
security headers, manual form, log previews against a prepared artifact tree.
Each scenario records (status, `error`, normalised JSON, redirect target,
flash texts via the next page, normalised DB snapshot: ids mapped, timestamps
masked, JSON columns parsed). `just rs-parity-api` runs the suite against both
and diffs the records; CI runs it on every push (Python always; Rust once S4a
is merged). Cross-implementation DB scenarios: tickets created/approved by
Python, claimed by Rust (checksum, 4.8) and vice versa; restart on the other
implementation's database (schema no-op, generation kept).

### 7.4 Runner parity harness (`rust/parity/runner/`, black box)

Stdlib fake API (scripted claim/status/get responses incl. 409/5xx/transport
outage, records every request), real `tmux` with a private socket label and
`TMUX_TMPDIR`, fake `codex`/`claude` scripts first on `PATH` (exit code,
output size and duration read from the prompt). Scenarios: one/multi-step
success, failure exit code, unsupported agent, ticket timeout, cancel during a
step, terminal state during a step, session killed externally, heartbeat
cadence, status retry/outage, permanent 4xx, disable file, `max_parallel_jobs`,
`--once`, SIGTERM during a step (interrupted), SIGKILL + restart (adopt exit
code / re-attach live session / interrupted), unreadable metadata. Compared:
the sequence of API calls (event, state, result, result_detail, tmux session
entry keys and statuses), artifact tree (names, JSON keys and values except
times/hashes, file modes), tmux session names, state files. **Cross-
implementation recovery**: start with Python, SIGKILL, continue with Rust (and
the reverse). **Mixed stacks**: real API + real runner for Python/Rust ×
Python/Rust with one multi-step ticket each, proving the cutover order does
not matter. CI runs it on Linux and macOS (`brew install tmux`).

### 7.5 TESTMAP

`rust/TESTMAP.md` maps all 187 Python tests to their Rust test and slice; a
row is checked off with the Rust test path when its slice merges. The parity
harness column says whether a black-box scenario also covers it.

### 7.6 CI and recipes

`.github/workflows/ci.yml` gains a `rust` job (matrix `ubuntu-latest`,
`macos-15`): `cargo fmt --check`, `clippy -D warnings`, `cargo test --locked`,
`cargo deny check` (pinned, sha256-verified cargo-deny as in nyxmon),
binary-size report; and a `parity` job running 7.3/7.4. `justfile`:
`rs-check`, `rs-test`, `rs-fixtures`, `rs-parity-api`, `rs-parity-runner`,
`rs-build`. The Python jobs stay unchanged.

---

## 8. Lean goals (measured like nyxmon section 4.4)

Baseline (section 1): API 26.0 MiB RSS / 32 MB footprint; runner 23.4 MiB /
32 MB; Python + venvs on disk per app dir.

- Release binary (stripped, `lto=thin`, `panic=abort`) ≤ 15 MiB.
- `serve` idle: phys_footprint ≤ 12 MB; peak while rendering `/tickets?view=all`
  (100 tickets) and the step log page of a 2 MiB log ≤ 24 MB.
- `runner` idle (polling): footprint ≤ 8 MB; with 3 active tickets ≤ 12 MB.
- Startup to listening / first claim ≤ 1 s.
- Measurement on studio: `footprint <pid>` (phys_footprint, the macOS
  counterpart of the cgroup/RssAnon numbers) and `ps -o rss= -p <pid>`
  (includes the shared binary mapping), sampled in the shadow run (S12) and
  after each cutover at +1 h and +24 h; recorded in the cutover report and
  `docs/OPSGATE_RUST.md`.

---

## 9. Build and release

- Target `aarch64-apple-darwin` (studio). `MACOSX_DEPLOYMENT_TARGET=14.0`.
  No dynamic libraries outside `/usr/lib` and `/System/Library` (rustls not
  needed: no TLS in the binary; SQLite bundled).
- Workflow `.github/workflows/rust-release.yml`, trigger tag `rs-v<semver>`
  (release) or `workflow_dispatch` (artifact only); runs on `macos-15`
  (arm64); actions pinned to SHAs; no cargo cache; `contents: write` only in
  the release job. Steps: tag equals crate version; fmt, clippy, test
  `--locked`; `cargo build --release --locked --target aarch64-apple-darwin`;
  `scripts/release_checks.py` (stdlib, unit-tested): `otool -L` allow-list,
  `vtool -show-build` minos ≤ 14.0, `lipo -archs` = `arm64`,
  `codesign --verify` (ad-hoc linker signature intact after strip), smoke
  `opsgate --version` = `opsgate <version> (<full commit>)`, `opsgate
  check-config api` against a test env; deterministic archive
  `opsgate-<ver>-aarch64-apple-darwin.tar.gz` (`opsgate` + `LICENSE`, fixed
  owner and mtime, gzip without name) + `.sha256`; `gh release create
  --verify-tag`.
- First release `rs-v0.3.0` after S8.

---

## 10. Deployment through the role

### 10.1 ops-library `opsgate_deploy` (S10)

New defaults:

```yaml
opsgate_api_impl: python          # python | rust (independent switches)
opsgate_runner_impl: python       # python | rust
opsgate_rust_version: ""          # e.g. "0.3.0"; required when any impl is rust
opsgate_rust_sha256: ""           # sha256 of the release archive
opsgate_rust_release_url: >-
  https://github.com/ephes/opsgate/releases/download/rs-v{{ opsgate_rust_version }}/opsgate-{{ opsgate_rust_version }}-aarch64-apple-darwin.tar.gz
opsgate_rust_local_archive: ""    # controller path (development)
opsgate_rust_install_root: /usr/local/libexec/opsgate-rs
opsgate_rust_keep_versions: 3     # never prunes the active or the previous version
```

New `tasks/rust_binary.yml` after `service_env.yml`, before `launchd.yml`:

1. Assert impl values; any `rust` needs a version with a 64-hex sha256 (or a
   local archive plus version).
2. With a version set (independent of the impls, so the binary can be
   installed ahead of a switch): download with `get_url` + checksum (or copy),
   unpack into `<root>/<version>/` (root:wheel, 0755); an existing version
   directory is never modified; a different archive for an existing version
   fails.
3. Validate the candidate by its versioned path before anything points at it:
   `--version` reports the version; as `control_service_user`
   (`sudo -u … env OPSGATE_ENV_FILE=/etc/opsgate/opsgate-api.env <bin>
   check-config api`), as `ops` (`… check-config runner` with the runner env
   file), and `check-db --db <db_path>` as `control_service_user` (read-only).
   Only the env-file **path** is passed, never secret values (guard tests).
   Failure stops the play; plists and running units are untouched.
4. Plist rendering per unit: `python` → today's `ProgramArguments`; `rust` →
   `/usr/bin/env bash -lc "cd <working dir> && exec <root>/<version>/opsgate serve"`
   (resp. `runner`), keeping the login-shell environment of 4.13.8 and all
   `EnvironmentVariables`, `UserName`, `GroupName`, `WorkingDirectory`, logs,
   labels. A version change or impl flip changes only that plist, so the
   existing `manage_launchd_unit.yml` boots out/in and kickstarts only that
   unit. Python source sync, `uv sync` and env files stay for both impls (the
   rollback path) until S16; a Python-only change no longer force-restarts a
   unit that runs Rust (`opsgate_launchd_force_restart` considers the source
   and venv changes only for `python`).
5. Verify each managed unit after the change (retry ≤ 30 s): `launchctl
   print system/<label>` running with a pid; `rust` → `ps -o comm= -p <pid>`
   equals the versioned binary path; `python` → `ps -o args=` contains `-m
   opsgate serve|runner`; API → `GET http://127.0.0.1:<port>/api/v1/health`
   answers `status == "ok"`.
6. After verification: prune old versions beyond `keep_versions`, never the
   active or previous one.

README section "Implementation: Python or Rust", CHANGELOG under
"Unreleased" (galaxy.yml is not bumped by this stream), unit tests in
`tests/` rendering both plists for each impl, the guard tests green.

### 10.2 ops-control (S11)

- `inventories/prod/host_vars/macstudio.yml`: `opsgate_api_impl`,
  `opsgate_runner_impl`, `opsgate_rust_version`, `opsgate_rust_sha256` (only
  here; `deploy-opsgate.yml` must not set them as role vars, which would
  override host vars).
- `playbooks/deploy-opsgate.yml`: pre-task asserting the ops-library version
  that knows the switch (pattern of `deploy-nyxmon.yml`); the four variables
  are **not** set in the playbook (host vars override role defaults on their
  own; role vars in the playbook would override the inventory).
- `software-sources.yml` `opsgate_rust_version` (manual upstream, `rs-v*`),
  `software-estate.yml` note for `opsgate` (Rust selected per component; verify
  the live executable as in `docs/OPSGATE_RUST.md`).
- `docs/OPSGATE_RUST.md`: switch table, install, shadow, cutover, verification,
  rollback, measurements; CHANGELOG.

### 10.3 Rollback

- Normal (per component): set `opsgate_api_impl` or `opsgate_runner_impl` to
  `python` in host vars; `just deploy-one opsgate` under the lock. The plist
  returns to the venv command, launchd restarts that unit; the database and
  artifacts are shared and implementation-neutral (approvers re-login, D-1).
- Emergency on the host (root, without Ansible): the role also renders the
  Python variant of each plist to `/etc/opsgate/launchd-python/<label>.plist`
  (root:wheel 0644, never loaded) on every deploy. Runbook:
  `launchctl bootout system/<label>; cp /etc/opsgate/launchd-python/<label>.plist /Library/LaunchDaemons/; launchctl bootstrap system /Library/LaunchDaemons/<label>.plist`;
  then flip the inventory before the next deploy (the next run with `rust`
  would reinstate the Rust plist).
- Rust-to-Rust: pin the previous version and sha256; its directory is still
  installed.

---

## 11. Rollout

### 11.1 Install without switching (S11)

Deploy with both impls `python` and the release pinned: binary at
`/usr/local/libexec/opsgate-rs/0.3.0/`, check-config/check-db pass, plists
unchanged, no unit restarted unless Python source or lock changed on `main`.

### 11.2 Shadow on studio (S12, owner approval Q3)

Root SSH session in tmux, no production unit touched:

1. **Data parity on a copy**: SQLite online backup of the production DB into
   `/usr/local/var/opsgate/shadow/` (0700, `control_service_user`); as
   `control_service_user`: `parity/shadow/serialize_python.py` (imports the
   deployed venv's `opsgate.service`) and `opsgate check-db --dump` write every
   ticket's serialisation, recomputed checksum and `approved_payload_checksum`
   comparison; the comparison must show zero differences and every
   `approved_payload_checksum` that matched in Python matches in Rust.
2. **Shadow API**: `opsgate serve --db <copy> --bind-host 127.0.0.1
   --bind-port 8712` as `control_service_user` with **shadow env files** (API
   and runner, root-owned 0640 with the service group, in the shadow
   directory) containing fresh random tokens, a fresh bcrypt hash and session
   secret (never the production secrets), production values for the CIDRs and
   policy floors, and deliberately for this isolated plain-HTTP loopback test:
   `OPSGATE_TRUST_PROXY_HEADERS=false`, `OPSGATE_SESSION_COOKIE_SECURE=false`
   (a `Secure` cookie would not be sent over `http://127.0.0.1`), and
   `OPSGATE_EXECUTION_DATA_DIR=/Users/ops/remediation-shadow` with
   `OPSGATE_DISABLE_FILE_PATH` inside it — the **same artifact root as the
   shadow runner**, so log views of shadow tickets resolve. Production
   tickets in the copy reference `/Users/ops/remediation/sessions/…` and are
   therefore expected to show `invalid_log_path` in the shadow (checked as such,
   and identically for the Python serialisation of step 1). Run the API parity
   suite (7.3) against it (the suite accepts an external base URL and
   credentials), plus reads of every production ticket through the shadow
   runner token.
3. **Shadow runner**: `opsgate runner` as `ops` against the shadow API, with
   the same `OPSGATE_EXECUTION_DATA_DIR=/Users/ops/remediation-shadow`
   (`ops`:`ops` 0750, so `control_service_user` can read logs through the
   group), socket label `remediation-shadow`, `TMUX_TMPDIR` under that dir,
   and the fake agents of 7.4 first on `PATH`: one multi-step ticket, one
   SIGTERM, one SIGKILL + restart adoption, one timeout — on the real macOS
   tmux/bash/launchd-like environment (started through `bash -lc` as in 10.1).
4. Memory (section 8) for both shadow processes.
5. Clean up: stop processes, kill the shadow tmux server, delete the copy, the
   shadow env file and the shadow directories. Report to `docs/OPSGATE_RUST.md`.

### 11.3 API cutover (S13)

Preconditions: S12 report accepted; window agreed with the coordinator (no
other deploy on macstudio or macmini Traefik in progress; the production
Traefik ACME move is on `production`, not affected); owner available for the
re-login.

1. Under the lock: `opsgate_api_impl: rust`, deploy. Record T1.
2. Verify: pid → versioned binary; `GET /api/v1/health` ok locally and via
   the nyxmon "OpsGate Health" check (next result after T1 ok);
   `runner_last_heartbeat` keeps advancing (Python runner claiming against the
   Rust API); owner logs in through `https://opsgate.home.xn--wersdrfer-47a.de`,
   opens list (all three views), a detail page with log previews, a step log,
   creates a manual single-step investigator ticket and cancels it (audit
   events visible in the DB, read-only query); nyxmon's next real ticket gets
   `201` (or the duplicate path).
3. **Rollback drill**: flip to `python`, deploy, verify Python pid, health,
   heartbeat, login; flip back to `rust`, deploy, re-verify. Release the lock.
4. Memory at +1 h, +24 h. Soak ≥ 24 h before S14.

### 11.4 Runner cutover (S14)

Preconditions: S13 soaked ≥ 24 h (Q2).

Claims are paused with the existing kill switch for the whole switch, so the
old runner cannot claim between the drain check and its restart: the API's
claim returns `null` and the runner loop skips claiming while
`OPSGATE_DISABLE_FILE_PATH` (`/Users/ops/remediation/.disabled`) exists
(4.7.3, 4.13.6).

1. Under the lock: create the disable file (`ops`:`ops`, empty); wait until no
   ticket is `running` (read-only query; the Rust runner could adopt one, but
   a switch during a privileged step is avoided) and `runner-state/` is empty;
   set `opsgate_runner_impl: rust`, deploy. Verify pid → versioned binary, no
   errors in the err log, health reachable. Remove the disable file; verify the
   heartbeat advances again (idle claims record heartbeats only without the
   disable file).
2. Real execution (Q4): the owner approves one operator ticket with a single
   `investigator` step, agent `claude`, prompt "Report hostname, uptime and
   the tmux version. Do not change anything." → state `succeeded`, artifacts
   with the expected names and modes, UI preview and step log, attach command
   shown.
3. **Rollback drill** with the same pause procedure each way: disable file,
   drain, flip to `python`, deploy, verify the Python pid, remove the disable
   file, verify the heartbeat and (optional, owner) a second test ticket; then
   disable, drain, flip back to `rust`, deploy, re-enable, re-verify.
4. Memory +1 h / +24 h.
5. If any step fails, the disable file stays until the runner is verified (a
   paused runner only delays tickets; it never runs one twice).

### 11.5 Soak and acceptance (S15)

7 days, daily: health ok, heartbeat age < 2 min, `launchctl print` `runs`
unchanged (no crash loop), err logs, nyxmon ticket submissions accepted (nyxmon
journal shows no `OpsGate ticket submit returned status=5xx`), memory trend.
Roll back the affected component immediately on any of these failing or on a
security-relevant misbehaviour (auth bypass, CSRF, a step started twice).
Acceptance report in `docs/OPSGATE_RUST.md` and the coordinator item.

### 11.6 Python retirement (S16, ≥ 30 days after S14, Q5)

Removes the Python implementation from role, inventory and repository and
deletes the venvs/app dirs on studio (production change, owner approval).
Order is strict, because the deployed role keeps syncing the opsgate checkout
and running `uv sync` for both users until it is retired:

1. S16a (ops-library): when both impls are `rust`, the role no longer syncs
   the Python source or runs `uv sync`; the plists' `WorkingDirectory` and the
   `cd` of the launch wrapper move off the app dirs (API:
   `/usr/local/var/opsgate/run/control`, runner: `execution_data_dir`
   unchanged); a guarded task removes `/Users/control_service_user/opsgate`
   and `/Users/ops/opsgate` only after the units were verified running from
   the new working directories; the `python` impl value is removed.
2. S16b (ops-control): inventory/playbook cleanup and the production deploy of
   that role release under the lock; verify both units, health, heartbeat and
   that the app dirs are gone.
3. S16c (opsgate repository) only **after S16b is verified in production**:
   until then `origin/main` must keep the Python package, because any deploy
   with the older role would sync `main` and run `uv sync`.

---

## 12. Implementation slices

Rules: one branch per slice (`rust-opsgate/<id>-<name>`) in its own worktree,
reviewed by `gpt-6.1-sol` at **high** reasoning through the codex review loop
(this PLAN.md and the slice's Python sources go along as context), merged to
the default branch and pushed. Every slice keeps the Python checks
(`just check`) and the Rust checks green, updates `rust/TESTMAP.md`, lists the
Python functions it ports, and stays ≤ ~2.5k changed lines excluding
generated fixtures. Production steps run under the deploy lock (section 2).
ops-library slices put changelog entries under "Unreleased" and never bump
`galaxy.yml`; the ops-library release that S11 asserts is made by the
coordinator/owner.

| ID | Slice | Repo | Depends on | Parallel | h | Prod |
| --- | --- | --- | --- | --- | --- | --- |
| S1 | Foundations: workspace, toolchain 1.99.0, deny.toml, CI `rust` job (Linux+macOS), justfile recipes, `.gitignore`, build.rs, CLI skeleton (`--version`, stub subcommands exit 2), fixture generator + drift test, README, TESTMAP | opsgate | — | — | 3 | no |
| S1o | Exclude `rust/` from the Python app rsync (`opsgate_rsync_excludes`), test, CHANGELOG | ops-library | — | yes (with all) | 1 | no |
| S2a | Core JSON/time/str: checksum formatter, stored-JSON formatter, `py_str`, depth check, number classification, Python `strip`/`lower`, ISO subset parse + `isoformat_z`; fixtures `checksum`, `float_repr`, `storage_json`, `datetime`, `pystr` | opsgate | S1 | yes (S2b, S6-, S7a/b, S9, S10) | 4 | no |
| S2b | Core settings and files: env-file loader, API and runner settings with all rules of 4.2, log preview + step log, non-strict path containment, ProxyFix selection; fixtures `settings`, `log_preview`, `proxy_fix` | opsgate | S1 | yes (S2a, …) | 3 | no |
| S2c | Core validation: ticket normalisation of 4.7.1 steps 1–10, plan/policy/merge/enforce, duration, D-2/D-3 rules; fixture `validation` | opsgate | S2a | yes (S2b, S6a) | 3 | no |
| S3a | Store I: DDL verbatim, connection setup, `init_db`, session-state sync/generation/revoke, create (lazy expiry + dedupe + unique mapping), get/list/serialise, health, `check-db`; schema contract test | opsgate | S2a, S2b, S2c | yes (S6a/S6b) | 3 | no |
| S3b | Store II: approve, reject, cancel, archive, unarchive, claim (validation, tamper, expiry loop, heartbeat), runner status; race tests | opsgate | S3a | yes (S6b) | 4 | no |
| S4a | Web I (shared foundations): `serve`, router, proxy fix, gate, security headers, error mapping (API JSON, UI flash + redirect, `forbidden.html`), JSON body rules, body limit, session cookie storage + approver extractor + flashes + a test helper that mints an authenticated session, the minijinja environment with the embedded templates, globals and filters (6.3) and the `GET/HEAD /login` page, bearer routes (create, get incl. approver session, runner claim/status, health) | opsgate | S3b | yes (S6b) | 4 | no |
| S4b | Web II: `POST /login` (next, bcrypt, throttle), logout/revocation, UI-CSRF layer, API-CSRF, cookie-authenticated API actions | opsgate | S4a | yes (S5) | 4 | no |
| S5 | Web III: remaining UI pages and UI action routes, manual form, log views (rendered through the S4a environment; authenticated in tests through the S4a session helper with the session's CSRF token in forms) | opsgate | S4a | yes (S4b) | 4 | no |
| S6a | Runner I: API client, tmux adapter, artifacts/atomic writes, commands/script, executor (fresh path, heartbeats, cancel, timeout, post-status retry) | opsgate | S2a, S2b | yes (S2c, S3-, S4-, S5) | 4 | no |
| S6b | Runner II: resume rules, shutdown, supervisor loop, recovery, worker failure + verified cleanup, state files, `--once`, log lines, `runner` wiring | opsgate | S6a | yes (S3-, S4-, S5) | 4 | no |
| S7a | API parity harness (7.3), green against Python; Rust target switched on as routes land | opsgate | S1 | yes (all) | 4 | no |
| S7b | Runner parity harness (7.4) incl. cross-implementation recovery and mixed stacks, green against Python | opsgate | S1 | yes (all) | 4 | no |
| S8 | Integration: both harnesses green for Rust and all mixed combinations, fixes, TESTMAP complete, docs (README runtime/config sections incl. the timeout variable name, `rust/README.md`, CHANGELOG) | opsgate | S4b, S5, S6b, S7a, S7b | no | 3 | no |
| S9 | Release pipeline (section 9) + `release_checks.py` and tests; tag `rs-v0.3.0` after S8 | opsgate | S1 (workflow), S8 (tag) | yes (from W1) | 3 | no |
| S10 | Role switch (10.1) incl. Python-plist copy for emergencies, tests, README, CHANGELOG | ops-library | S1o; archive format of section 9 | yes (from W1) | 4 | no |
| S11 | ops-control wiring (10.2) + install deploy (11.1) under the lock | ops-control | S9 tag, S10 in an ops-library release | no | 2 | yes (no switch) |
| S12 | Shadow on studio (11.2) and report | ops-control docs | S11 | no | 3 | host only, not the service |
| S13 | API cutover + rollback drill (11.3) | ops-control | S12 | no | 2 | yes |
| S14 | Runner cutover + rollback drill (11.4) | ops-control | S13 + 24 h | no | 2 | yes |
| S15 | Soak 7 days and acceptance (11.5) | ops-control docs | S14 | no | 1 | read-only |
| S16a | Retire Python in the role (no source sync/uv sync with both impls rust, working directories moved, guarded app-dir removal, `python` impl removed) | ops-library | S15 + 30 days | no | 2 | no |
| S16b | Retire in ops-control (vars, playbook source resolution, docs) + deploy of the S16a release removing venvs/app dirs (owner approval) | ops-control | S16a in an ops-library release | no | 2 | yes |
| S16c | Retire in the repository: templates into `rust/`, Python package/tests removed, fixtures frozen (generator and drift test removed), CI/README/AGENTS updated | opsgate | S16b verified in production | no | 2 | no |

Parallel waves (maximum concurrency):

- **W0:** S1, S1o.
- **W1** (after S1): S2a, S2b, S7a, S7b, S9 (workflow without tag), S10
  (against a locally built archive; needs only S1o).
- **W2:** S2c (S2a), S6a (S2a, S2b).
- **W3:** S3a (S2a–S2c), S6b (S6a).
- **W4:** S3b.
- **W5:** S4a.
- **W6:** S4b ∥ S5.
- **W7:** S8 → tag (S9) → S11 → S12 → S13 → S14 → S15 → (30 days) S16a → S16b → S16c.

The runner track (S6a/S6b) runs alongside the whole API track (S2c–S5); the
harnesses (S7a/S7b), the release workflow (S9) and the role (S10) run from W1.

Acceptance criteria (beyond green checks and a clean review):

- **S1:** CI job green on both OSes; `opsgate --version` prints version and
  commit; drift test fails on a hand-edited fixture.
- **S1o:** a deploy dry run (`--check`) of the role shows `rust/` excluded.
- **S2a:** checksum and float-repr fixtures match **byte-exactly** (the
  only byte-level contract, 4.8); `py_str` fixtures match exactly (they are
  stored values); stored-JSON fixtures match semantically (parsed values
  equal; text formatting is P2); datetime fixtures match for every input Rust
  accepts, and every rejected input is listed as D-7 or rejected by Python
  too.
- **S2b:** settings fixture (≥ 80 cases incl. every row of 4.2 and the
  env-file override rule) and log-preview fixture match; containment tests for
  symlink escape, missing-inside, missing-outside.
- **S2c:** validation fixture (≥ 150 payloads) yields the same normalised
  ticket/checksum or the same error code (D-2/D-3 cases marked).
- **S3a/S3b:** every store row of TESTMAP passes; race tests pass 100 runs;
  schema contract test; Python→Rust and Rust→Python database round trip
  (create in one, approve in the other, claim in the first).
- **S4a/S4b/S5:** every web row of TESTMAP owned by the slice passes
  in-process (S5 authenticates through the S4a session helper, so it does not
  need S4b's login to merge). Black-box parity per slice only where the
  scenario needs no other open slice: S4a the bearer/gate/header/health
  scenarios, S4b the login/logout/throttle/CSRF scenarios; the authenticated
  UI scenarios run against Rust from S8, which needs both S4b and S5.
- **S6a/S6b:** every runner row of TESTMAP passes; `tmux` integration tests
  pass on macOS and Linux.
- **S7a/S7b:** suites green against Python, documented in `rust/README.md`.
- **S8:** both harnesses green against Rust with zero unexplained differences
  and all four mixed stacks; docs reviewed.
- **S9:** a `workflow_dispatch` run produces archive + checksum passing all
  checks; release `rs-v0.3.0` exists.
- **S10:** unit tests render both plists per impl; guard tests green; README
  documents switch and rollback.
- **S11:** live: binary installed by versioned path, `check-config`/`check-db`
  ok, plists unchanged, no unit restarted (pids unchanged) unless Python
  changed.
- **S12:** report with data-parity numbers (0 differences over 603+ tickets),
  harness results, runner scenarios, memory.
- **S13/S14:** all checks of 11.3/11.4 recorded with times, rollback drills
  done, memory within section 8.
- **S15:** 7-day report; owner acceptance.
- **S16:** no Python process, venv or app dir for OpsGate on studio; docs
  state Rust is the only implementation.

---

## 13. Risks

- **R1 Checksum drift** (float repr, escaping) → every Python-approved ticket
  claimed by Rust fails as `prompt_tampered`. Fail-closed, but blocks
  execution. Mitigation: byte-exact fixtures (4.8), cross-implementation
  claim tests, S12 data parity over all production tickets.
- **R2 Security regressions** in auth/CSRF/session/gate code. Mitigation: all
  security rows of TESTMAP as in-process tests *and* black-box scenarios,
  review at high reasoning per slice, ProxyFix fixtures, owner login during
  S13, immediate rollback criterion.
- **R3 Privileged execution twice** after a crash/cutover. Mitigation: resume
  rules as P1 contract with cross-implementation recovery tests, S12 SIGKILL
  drill on the real host, runner cutover only with no running ticket.
- **R4 Step environment drift** (PATH, missing variables) breaks agents.
  Mitigation: same `bash -lc` wrapper and env-file application (4.13.8), real
  agent test in S14.
- **R5 macOS specifics** (code signature after strip, `tmux` from Homebrew on
  PATH, bash 3.2). Mitigation: macOS CI, release checks, S12 on the host.
- **R6 Session cutover friction** (D-1): one re-login per switch; documented.
- **R7 Pre-existing exposure**: agent steps can read the runner token
  (environment and group-readable env file). Kept as-is by the port (Q6).
- **R8 Supply chain**: Cargo.lock, `--locked`, cargo-deny, pinned actions,
  sha256 pinned in the inventory, root-owned install directory.
- **R9 Coordination**: ops-control CI red for unrelated reasons may hide new
  failures in S11 (report job states explicitly); deploys of macstudio and the
  macmini Traefik dynamic directory must be coordinated (deploy lock, coordinator
  announcement for cutover windows).
- **R10 Template coupling**: a template change for Python could use a Jinja
  feature minijinja lacks. Mitigation: the template render test runs in CI for
  every change under `src/opsgate/templates/`.

---

## 14. Owner questions (with recommendations)

- **Q1 Re-login on every API switch (D-1).** Accept that approvers sign in
  again after the API cutover and after each rollback? *Recommended: yes* —
  one approver, rare switches; re-implementing Flask's cookie format contradicts
  the "no Python library re-implementations" rule.
- **Q2 Cutover order.** API first (S13), runner at least 24 h later (S14), each
  with its own rollback drill? *Recommended: yes* — the proven Python runner
  then validates the Rust API's claim/status contract in production first, and
  each step can be rolled back alone.
- **Q3 Shadow run on studio (S12).** Approve a ~2 h shadow: a DB copy, a second
  API on `127.0.0.1:8712` with throwaway credentials, a shadow runner as `ops`
  with separate directories, socket label and fake agents, all removed
  afterwards? *Recommended: yes.*
- **Q4 Real agent execution during S14.** Approve one operator ticket with a
  single read-only `investigator` step (`claude`) to prove the full path, plus
  optionally one during the rollback drill? *Recommended: yes* (alternative:
  wait for the next natural ticket, which can take weeks).
- **Q5 Python retirement.** Retire the Python implementation (and delete the
  venvs/app dirs on studio) 30 days after the runner cutover, as its own
  slices? *Recommended: yes*, matching the mailgun-relay rollback window
  practice.
- **Q6 Runner token visible to agent steps (pre-existing).** Keep exact parity
  in the port and track hardening (not exporting `OPSGATE_RUNNER_TOKEN` to
  steps *and* tightening `/etc/opsgate/opsgate-runner.env` access) as a
  separate item after S15? *Recommended: yes* — changing it during the port
  would mix a security change into a parity migration.
