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
- Authenticated approvers can create manual tickets in the web UI.

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
- `POST /api/v1/runner/claim`
- `POST /api/v1/runner/:id/status`
- `GET /api/v1/health`

## Local development

```bash
just test
just typecheck
just lint
just run
just run-runner
```

Default UI routes:

- `GET /login`
- `GET /tickets`
- `POST /tickets`
- `GET /tickets/:id`
