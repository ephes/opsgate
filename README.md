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

## Configuration

The service reads `OPSGATE_ENV_FILE` first (if set), then environment variables.

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
- `OPSGATE_MAX_DURATION_SECONDS_DEFAULT` (default `3600`)
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

## Local development

```bash
just check
just run
just run-runner
```

Default UI routes:

- `GET /login`
- `GET /tickets`
- `POST /tickets`
- `GET /tickets/:id`
