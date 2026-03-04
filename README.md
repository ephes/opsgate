# OpsGate

OpsGate is a unified control service for ticketed privileged execution.

Phase 2 implementation scope in this repository:

- One process provides JSON API endpoints and web UI routes.
- SQLite storage with WAL mode.
- Username/password approver login using bcrypt hash from config.
- Submit-token auth for producer endpoints.
- Runner-facing claim/status endpoints are present for Phase 3 integration, but no runner loop is implemented in this repository.

## Runtime model

- API/UI process is expected to run as `control_service_user`.
- Runner process remains a launchd placeholder/stub in Phase 2.
- v1 access assumptions are Tailscale-only context.

## Configuration

The service reads `OPSGATE_ENV_FILE` first (if set), then environment variables.

Required keys:

- `OPSGATE_UI_USERNAME`
- `OPSGATE_UI_PASSWORD_BCRYPT`
- `OPSGATE_SESSION_SECRET`
- `OPSGATE_SUBMIT_TOKEN_OPENCLAW`
- `OPSGATE_SUBMIT_TOKEN_NYXMON`
- `OPSGATE_SUBMIT_TOKEN_OPERATOR`
- `OPSGATE_RUNNER_TOKEN`

Useful keys:

- `OPSGATE_DB_PATH` (default `/usr/local/var/opsgate/run/opsgate.sqlite3`)
- `OPSGATE_BIND_HOST` (default `0.0.0.0`)
- `OPSGATE_BIND_PORT` (default `8711`)
- `OPSGATE_MAX_DURATION_SECONDS_DEFAULT` (default `3600`)
- `OPSGATE_POLICY_FLOOR_REQUIRE_REVIEWER_STEP` (default `false`)
- `OPSGATE_SUBMIT_POLICY_*_REQUIRE_REVIEWER_STEP`
- `OPSGATE_REQUIRE_TAILSCALE_CONTEXT` (default `true`)
- `OPSGATE_ALLOWED_CIDRS` (default loopback + Tailscale ranges)
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
```

Default UI routes:

- `GET /login`
- `GET /tickets`
- `GET /tickets/:id`
