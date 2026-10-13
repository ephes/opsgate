# OpsGate

OpsGate is a unified control service for ticketed privileged execution.

Phase 4B implementation scope in this repository:

- One process provides JSON API endpoints and web UI routes.
- SQLite storage with WAL mode.
- Username/password approver login using bcrypt hash from config.
- Submit-token auth for producer endpoints.
- Runner process (`python -m opsgate runner`) claims and executes approved tickets.
- Ticket steps execute sequentially per ticket; parallelism is across tickets up to `OPSGATE_MAX_PARALLEL_JOBS`.
- Runner uses tmux sessions per step and writes disk artifacts (`context.json`, `prompt.md`, `session.log`, `summary.json`).
- Runner enforces ticket-wide timeout and deterministic timeout results.
- Runner supports restart recovery from local runner state files under `{{ execution_data_dir }}/runner-state`.
- Runner restart recovery never launches a step a second time; see [Runner restart recovery](#runner-restart-recovery).
- OpenClaw submit token is optional for this slice (Nyxmon producer is primary).
- Login supports safe deep-link redirect (`/login?next=/tickets/<id>`) for approval-link UX.
- Authenticated approvers can create manual tickets in the web UI with a mobile-first multi-step workflow editor.
- Manual create flow supports per-step role/agent/prompt editing with role-based agent defaults (`implementer` -> `codex`, `reviewer` -> `claude`) and sticky validation errors.
- The create form shows role-specific guidance and suggested prompt scaffolds for `investigator`, `implementer`, and `reviewer` steps.
- Manual/operator tickets may be single-step investigation tickets or multi-step change/review workflows; OpsGate does not require a reviewer step for every operator-created ticket.
- Authenticated approvers can inspect per-step runner logs in the web UI via inline previews and dedicated log pages on ticket detail.
- Authenticated approvers can archive `pending_approval` or terminal tickets out of the default `/tickets` queue and restore them later without deleting ticket history, logs, or artifact references.
- New submissions reconcile expired matching open tickets before dedupe, so a stale expired recurrence does not block a fresh approvable ticket for the same `source` + `task_ref`.
- Supported step agents are `codex` and `claude` only.
- Cookie-authenticated API actions require CSRF proof, logout revokes the session server-side, and failed logins are throttled per client IP (see [API authentication](#api-authentication) and [Approver sessions](#approver-sessions)).
- Login keeps passive `GET`/`HEAD` probes side-effect free and uses password-manager/autofill-friendly form markup without relaxing session or CSRF protections.

## Operator workflow guidance

OpsGate step roles are guidance for ticket authors and approvers. In the current product they are not hard
runtime permission boundaries beyond the existing reviewer-floor policy.

Only three roles are part of the intended workflow model:

- `investigator`: inspect state, read code/config, collect logs, explain findings, propose next steps. Do not use this role for source edits, deployments, service restarts, or direct live-host patching.
- `implementer`: make the intended change in the proper source of truth, iterate with the reviewer until ready, run validation, commit the agreed change, and deploy through the normal workflow when the ticket calls for a live change.
- `reviewer`: review the proposed work, validation, logs, and rollout plan. Do not treat this role as an independent implementation or deployment step.

The backend does not currently reject other non-empty role strings submitted via the API. The three-role
model above is the intended operator workflow and is enforced today through UI controls, prompting, and
review discipline rather than strict API validation.

Expected change workflow for durable fixes:

1. `investigator` may inspect the problem first and identify the owning repo/workspace.
2. `implementer` makes the fix in source, not by editing files ad hoc on the target host.
3. `reviewer` reviews the proposed fix.
4. `implementer` revises as needed.
5. Repeat the implementer-reviewer loop until both agree the change is ready.
6. `implementer` runs the relevant validation commands locally.
7. `implementer` commits the agreed change.
8. `implementer` deploys through the normal service workflow.
9. `implementer` verifies the live result and records any follow-up work.

Break-glass live edits are exceptional. If a ticket ever requires direct live intervention, the outcome should
say so explicitly and explain how source-of-truth will be reconciled afterward.

## Runtime model

- API/UI process is expected to run as `control_service_user`.
- Runner process is expected to run as `ops`.
- v1 access assumptions are Tailscale-only context.

## Runner restart recovery

Step sessions run in a separate tmux server, so a step can keep running, or finish, while the runner is down.
On restart the runner re-drives every `running` ticket it finds (runner state files, live `job-<ticket>-*` tmux
sessions, and session artifact directories). Steps whose `summary.json` says `succeeded` are skipped and their
summaries are passed once to later steps. For the first unfinished step the runner writes
`session_metadata.json` (status `running`, `started_at`) before it ever launches the step, and uses it as the
resume marker:

- `exit_code` exists: the runner adopts it, writes `summary.json` from the existing log and continues or fails
  the ticket by that code. The step is not launched again.
- The step's tmux session is still alive: the runner re-attaches, polls it and keeps tracking it for
  cancel/timeout.
- Metadata exists (even if unreadable), but there is no `exit_code` and no session: the step is failed as interrupted. Its metadata
  status becomes `interrupted` and the ticket fails with `result_detail = step_<n>_interrupted`. Nothing is
  re-run; to retry, submit and approve a new ticket after checking what the half-run step already changed.

A graceful runner shutdown (SIGTERM/SIGINT) kills the active step session and marks the step `interrupted`, so
the restarted runner fails that ticket rather than repeating the step. A step that wrote its `exit_code` before
shutdown is adopted on restart. A crash between writing the metadata and starting the tmux session is also
treated as interrupted, even though the agent may never have run; this errs on the side of not running a
privileged step twice.

Status reports retry server failures up to three attempts, one second apart. If reporting remains
unavailable, the worker leaves its state and session artifacts for recovery to adopt the existing execution.
Transport failures and invalid JSON responses are normalized to safe runner API errors; recovery skips
unavailable tickets and continues with independent tickets. API error diagnostics omit raw bodies and
transport exception text. A genuine executor exception is reported as terminal failure only after owned
tmux sessions have been stopped and their absence verified. If cleanup cannot be verified, the ticket's
state file remains for retry; operators should inspect the retained session artifacts. Permanent API
rejections follow this same cleanup-and-failure path rather than outage recovery. Swallowed reporting
and claim errors log only their safe HTTP status and error category.

Runner JSON state and artifacts are published by same-directory atomic replacement with private (0600)
files. Failed serialization, writes or replacement leave the previous destination intact and remove the
owned temporary file. If the filesystem also refuses cleanup, the original publication error is preserved
and operators may need to remove the leftover temporary file.

There is no setting to restore automatic re-runs. One could be added later (off by default); it would still
need to adopt an existing `exit_code` rather than relaunch.

## Configuration

The service reads `OPSGATE_ENV_FILE` first (if set), then environment variables.

Boolean configuration accepts `1`, `true`, `yes`, `on` and `0`, `false`, `no`, `off`,
case-insensitively with surrounding whitespace ignored. Missing or blank values use the documented
default (submitter reviewer policies inherit the global floor). Other values fail startup with
`SettingsError` naming the setting, without echoing its value. This applies to proxy trust, secure
cookies, Tailscale context and all reviewer-policy booleans.

Required keys:

- `OPSGATE_UI_USERNAME`
- `OPSGATE_UI_PASSWORD_BCRYPT`
- `OPSGATE_SESSION_SECRET`
- `OPSGATE_TRUST_PROXY_HEADERS` (default `false`; set `true` behind a trusted reverse proxy)
- `OPSGATE_SESSION_COOKIE_SECURE` (default `false`; set `true` behind HTTPS ingress)
- `OPSGATE_SUBMIT_TOKEN_NYXMON`
- `OPSGATE_SUBMIT_TOKEN_OPERATOR`
- `OPSGATE_RUNNER_TOKEN`

Useful keys:

- `OPSGATE_SUBMIT_TOKEN_OPENCLAW` (optional in the current slice)
- `OPSGATE_DB_PATH` (default `/usr/local/var/opsgate/run/opsgate.sqlite3`)
- `OPSGATE_BIND_HOST` (default `0.0.0.0`)
- `OPSGATE_BIND_PORT` (default `8711`)
- `OPSGATE_MAX_DURATION_SECONDS_DEFAULT` (default `3600`; integer from `1` to `31536000`)
- `OPSGATE_MAX_PARALLEL_JOBS` (default `3`)
- `OPSGATE_POLICY_FLOOR_REQUIRE_REVIEWER_STEP` (default `false`)
- `OPSGATE_SUBMIT_POLICY_*_REQUIRE_REVIEWER_STEP`
- `OPSGATE_REQUIRE_TAILSCALE_CONTEXT` (default `true`)
- `OPSGATE_ALLOWED_CIDRS` (default loopback + Tailscale ranges)
- `OPSGATE_RUNNER_API_BASE_URL` (default `http://127.0.0.1:<bind_port>`)
- `OPSGATE_RUNNER_HOST` (default hostname)
- `OPSGATE_RUNNER_POLL_INTERVAL_SECONDS` (default `5`)
- `OPSGATE_RUNNER_HEARTBEAT_INTERVAL_SECONDS` (default `30`)
- `OPSGATE_TICKETS_DIR` (default `{{ execution_data_dir }}/jobs`)
- `OPSGATE_SESSION_ARTIFACTS_DIR` (default `{{ execution_data_dir }}/sessions`)
- `OPSGATE_TMUX_SOCKET_LABEL` (default `remediation`)
- `OPSGATE_DISABLE_FILE_PATH` (default `{{ execution_data_dir }}/.disabled` equivalent)

## API endpoints

- `POST /api/v1/tickets`
- `GET /api/v1/tickets/:id`
- `POST /api/v1/tickets/:id/approve`
- `POST /api/v1/tickets/:id/reject`
- `POST /api/v1/tickets/:id/cancel`
- `POST /api/v1/tickets/:id/archive`
- `POST /api/v1/tickets/:id/unarchive`
- `POST /api/v1/runner/claim`
- `POST /api/v1/runner/:id/status`
- `GET /api/v1/health`

### Ticket input validation

JSON deeper than 64 object/array levels (including the root) is rejected with `400 invalid_json` before API mutations.
The manual form rejects excessively nested context JSON with `400 invalid_context_json`.

`execution_plan` must be a nonempty array of objects. Each step requires `role`, `agent`,
and `prompt_markdown` as strings containing non-whitespace text. Surrounding whitespace
is trimmed; agents are lowercased and must be `codex` or `claude`. Other JSON types
return `400 invalid_execution_plan`. The same validation applies before approving or
claiming persisted plans; invalid claimed plans fail with `invalid_stored_plan`.
Runner claims also validate stored policy, context and tmux-session JSON before
starting a ticket. Malformed JSON, invalid shapes/types or nesting beyond 64 levels fail
only that ticket with `invalid_stored_plan` and a `ticket_failed` audit event;
the same claim continues to the next approved ticket. Audit diagnostics contain
an error category, never the corrupt JSON. Corrupt stored values are retained
for investigation; ticket detail reads may still fail until storage is repaired.

`max_duration_seconds` must be a JSON integer from 1 to 31,536,000 seconds (365 days).
Booleans, strings, all floating-point numbers (including integral values such as `900.0`)
and out-of-range integers return
`400 invalid_ticket` before any ticket or audit write. Missing or null values use the
configured default, which must satisfy the same bounds for both service and runner.
The manual form accepts decimal integer text and applies the same bounds.

`expires_at` is optional. Supplied timestamps must include a timezone and normalize
to a UTC datetime within years 0001 through 9999 (inclusive). Offset conversions
outside those bounds return `400 invalid_expires_at` without creating a ticket.
The shared timestamp parser reports invalid formats, missing timezones and UTC overflow
as `ValueError` for session, UI and runner readers.

### API authentication

- `POST /api/v1/tickets` takes a submitter bearer token; `GET /api/v1/tickets/:id` takes a submitter
  token, the runner token, or an approver session.
- `/api/v1/runner/*` takes the runner bearer token.
- `approve`, `reject`, `cancel`, `archive` and `unarchive` take the approver **session cookie** from
  `/login`. Because a cookie is sent automatically, these `POST`s also need CSRF proof:
  - the session's CSRF token in an `X-CSRF-Token` header (the same value the UI forms post as
    `csrf_token`), or
  - a browser-reported same-origin request (`Sec-Fetch-Site: same-origin`, or, when the browser does not send
    `Sec-Fetch-Site`, an `Origin` equal to the OpsGate origin).

  Otherwise they answer `403` with `csrf_required` (no proof) or `invalid_csrf` (wrong token). Bearer-token
  callers are unaffected. The web UI uses its own form routes (`/tickets/:id/<action>`), which already carry
  the form token.

### Runner status contract

Runner status `result` values must match the terminal transition: `succeeded` accepts
`success`, `failed` accepts `failure` or `timeout`, and `canceled` accepts `canceled`.
Omitting `result` derives the canonical result from the terminal state. Running updates
and heartbeats must omit terminal results. Incompatible pairs return `400 invalid_runner_result`
without changing the ticket, heartbeat or audit history.

### Concurrent ticket transitions

Approve, reject, cancel, archive, unarchive, runner claim and runner status updates each run in a single
SQLite write transaction (`BEGIN IMMEDIATE`): the ticket is read, checked and written while the write lock is
held, so two actions on the same ticket are applied one after the other. Every transition `UPDATE` also
matches the state it read (compare-and-set).

- The second of two conflicting actions sees the first one's result. For example, a cancel that races an
  approve cancels the now-approved ticket, and the runner cannot claim it afterwards; a second approve gets
  `409 invalid_state`.
- If a write ever matches no row because the ticket changed after it was read, nothing is written and the
  request answers `409 state_changed`. Reload the ticket and retry. The runner treats `state_changed` like
  `invalid_state`: the ticket moved on, so it stops reporting for it.
- Audit events record the state that was actually replaced.

### Approver sessions

- Sessions expire after `OPSGATE_SESSION_TIMEOUT_SECONDS`.
- Sessions are also revoked server-side: the database keeps a session generation for the approver, and every
  session cookie records the generation it was issued under. `POST /logout` from an authenticated session bumps
  the generation, so a copied cookie stops working too. This signs the approver out of **every** browser.
  Changing `OPSGATE_UI_PASSWORD_BCRYPT` bumps the generation when the service next starts.
- Session cookies issued before this mechanism existed carry no generation; approvers sign in once more after
  upgrading.
- Failed logins are throttled per client IP. After 5 failures within 15 minutes, `/login` answers `429` until the
  oldest failure is 15 minutes old, even for the correct password. A successful login clears the counter. The
  counter is held in memory and resets when the service restarts.

### Response headers

Every response (UI pages, redirects, errors and API answers) carries:

- `X-Frame-Options: DENY` and `Content-Security-Policy: frame-ancestors 'none'; base-uri 'self'; form-action
  'self'; object-src 'none'`: the approval UI never renders inside another page, and its forms only post back
  to OpsGate. The pages use inline styles and scripts, so the policy does not restrict `script-src`.
- `X-Content-Type-Options: nosniff` and `Referrer-Policy: same-origin`.
- `Cache-Control: no-store`: ticket pages, logs and API answers are not kept by browsers or proxies.

A reverse proxy in front of OpsGate must not remove these headers.

## Log previews

Ticket detail previews and runner step summaries read only the final 64 KiB of a log,
show up to 40 lines, and retain at most the final 2 KiB of each line. Omitted bytes
or lines add a `[log preview truncated]` notice. UTF-8 characters split by a byte
boundary are safely replaced. The dedicated **Open step log** page shows the
final 2 MiB with a `[step log truncated]` notice when earlier bytes are omitted.
Smaller logs appear in full; retained files on disk are unchanged.

## Local development

```bash
just check
just run
just run-runner
```

GitHub Actions (`.github/workflows/ci.yml`) runs the `just check` commands (tests,
mypy, ruff) on Python 3.11 and 3.14 for every push and pull request. It needs no
secrets.

The dev lock uses pytest 9 and Pygments 2.21 to address development dependency
advisories. To audit the locked runtime and dev dependencies (excluding the local
project), run:

```bash
uv export --frozen --extra dev --no-emit-project --format requirements-txt -o /tmp/opsgate-dev-requirements.txt
uvx pip-audit -r /tmp/opsgate-dev-requirements.txt --no-deps --disable-pip
```

Default UI routes:

- `GET /login`
- `GET /tickets`
- `POST /tickets`
- `GET /tickets/:id`
