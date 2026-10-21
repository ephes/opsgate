# Changelog

## Unreleased

### Development

- Add the black-box runner parity harness `rust/parity/runner` (Rust port plan slice S7b): real
  runner processes with real tmux on a private socket, fake `codex`/`claude` agents and a scripted
  stand-in API (HTTP errors, dropped connections), covering execution, retries and outages,
  recovery, shutdown, SIGKILL and restart across Python and Rust runners, and real API × real runner
  stacks; `compare.py` diffs the normalised records of different stacks. Green against the Python
  runner; Rust stacks are skipped until their slices land. New recipe `just rs-parity-runner` and CI
  job `parity-runner` (Linux and macOS). The Python implementation is unchanged.
- Start the Rust port in `rust/` (plan slice S1): Cargo workspace with toolchain 1.99.0, `deny.toml`,
  an `opsgate` command-line skeleton (`--version` prints version and git commit; `serve`, `runner`,
  `check-config` and `check-db` are stubs that exit 2), the fixture generator
  `rust/fixtures/generate.py` with its first fixture `schema.sql` and a pytest drift test, the
  `rust` CI job on Linux and macOS, and `just rs-*` recipes. `rust/target/` is ignored. Nothing
  deploys or runs the Rust code yet; the Python implementation is unchanged.
- Rust port slice S2b (`rust/crates/opsgate-core`): the env-file loader and the API and runner
  settings with every rule of `config.py` (same check order and messages), step log previews and
  the step log page, step-log path containment with CPython's non-strict `Path.resolve()`, and the
  client address/scheme/host selection. The latter documents that in production waitress removes
  `X-Forwarded-*` before Werkzeug's `ProxyFix` runs, so `OPSGATE_TRUST_PROXY_HEADERS` has no effect;
  the Rust port keeps that behaviour. New Python-generated fixtures
  `settings.json`, `log_preview.json` and `proxy_fix.json` pin them. Nothing calls this code yet.
- Rust port slice S2a: `opsgate-core` gains the payload checksum formatter (byte-exact
  `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True)` incl. CPython float `repr`),
  the stored-JSON text, `json.loads` number and depth rules, Python `str()`/`strip`/`lower`, and
  `isoformat_z`/`parse_iso_datetime` (CPython 3.14 semantics on the extended ISO 8601 forms). New
  Python-generated fixtures `checksum.json`, `float_repr.json`, `storage_json.json`, `datetime.json`
  and `pystr.json`; `datetime.json` is generated and checked only by Python 3.14 (`PYTHON_GATED`),
  other interpreters skip it.
- Add the black-box API parity harness `rust/parity/api` (plan slice S7a): a pytest suite (new dev
  dependency `httpx`) that starts a real `serve` process per scenario and runs more than 500
  scenarios ported from `tests/test_api.py` plus contract cases, writes normalised records, and
  diffs a Python and a Rust run (`compare.py`, `just rs-parity-api`). It is green against Python;
  scenarios switch on for Rust as the web slices land. New CI job `parity-api`. Its forwarded-header
  scenarios confirm against a running server that `X-Forwarded-*` never reaches the app (plan
  4.4). No runtime change.

### Documentation

- Add the Rust port plan (`rust/PLAN.md`) and its test map (`rust/TESTMAP.md`): contract,
  divergences, slices, release, role switch, shadow run, cutover and rollback for replacing the
  Python API/UI and runner processes, with the owner decisions of 2026-10-21 (re-login per API
  switch, API before runner, studio shadow run, one real read-only cutover ticket, Python retirement
  after 30 days, runner-token hardening as a separate item). No runtime change.

### Security

- Refresh the development lock to pytest 9.1.1 and Pygments 2.21.0 to resolve known
  advisories; allow pytest versions below 10. Runtime dependencies are unchanged.

- Dedicated step log pages read at most the final 2 MiB and mark truncated logs, bounding web-worker memory.
- Security boolean configuration now rejects unrecognized values at startup instead of silently disabling
  protections. Missing or blank values use defaults; explicit true and false spellings remain supported.
- Cookie-authenticated API actions (`POST /api/v1/tickets/<id>/approve|reject|cancel|archive|unarchive`) now
  need CSRF proof: an `X-CSRF-Token` header with the session token, or a browser-reported same-origin request
  (`Sec-Fetch-Site: same-origin`, falling back to `Origin`). Before, `SameSite=Lax` alone let any page on a
  sibling subdomain post an approval with the approver's cookie. Bearer-token callers are unchanged.
- `POST /logout` now revokes approver sessions server-side through a session generation stored in SQLite. A
  copied cookie no longer stays valid until the session timeout. Logout signs the approver out of every
  browser. Changing the UI password hash revokes existing sessions on the next start.
- `/login` locks a client IP out for 15 minutes after 5 failed attempts (`429`).
- Every response now carries `X-Frame-Options: DENY`, a `Content-Security-Policy` with
  `frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin` and `Cache-Control: no-store`. Before, no
  such header was sent, so a page on a same-site origin could show the approval UI in a frame and collect a
  disguised click on *Approve*. API clients are unaffected.
- `/login` runs the password check for every attempt, also when the username is wrong, so response time no
  longer tells whether a username is the approver name.

### Upgrade notes

- If `OPSGATE_MAX_DURATION_SECONDS_DEFAULT` is set, check it is an integer from 1 to
  31,536,000 for both service and runner before upgrading; unsupported defaults now prevent startup.
  Unset or blank values still use 3600.
- Submitters must send `max_duration_seconds` as a JSON integer in that range, rather than
  a string, boolean or float. Missing/null values still use the configured default.
- Runner reports must omit terminal results on running/heartbeat updates and match terminal
  states: succeeded/success, failed/failure or timeout, canceled/canceled. Other pairs now return 400.
- These duration bounds apply to new tickets; previously stored durations are not migrated or
  revalidated by this change. Inspect `max_duration_seconds` through `GET /api/v1/tickets/<id>`
  for legacy pending, approved and running tickets. Check unsupported durations before approving
  or allowing queued legacy tickets to run.

- Check boolean settings in env files before upgrading: unrecognized nonempty values now prevent startup.
  Values such as `y`, `enabled`, or `true # comment` are invalid; use the documented spellings without inline
  comments. Blank values now use defaults rather than always disabling a setting: blank Tailscale context enables its default check, and blank
  submitter reviewer policies inherit the global floor.

- Existing approver sessions are invalidated once on deploy; sign in again.
- Any script that calls the approve/reject/cancel/archive/unarchive API with a session cookie must send the
  `X-CSRF-Token` header. Nothing in ops-control or nyxmon does this today.

### Changed

- **Behaviour change:** after a runner restart, a step that was interrupted (no `exit_code`, no live tmux
  session, but `session_metadata.json` shows it was started) is no longer re-run. It is marked `interrupted` and
  the ticket fails with `result_detail = step_<n>_interrupted`; retrying needs a new, explicitly approved
  ticket. A graceful runner shutdown now records the killed step as `interrupted`. There is no setting to
  restore the old re-run behaviour. See "Runner restart recovery" in the README.

### Fixed

- Ticket creation rejects unpaired Unicode surrogates in direct ticket and audit
  text columns with `400 invalid_ticket` before persistence, avoiding SQLite
  encoding failures. Valid non-ASCII titles, summaries, task references and prompts
  remain unchanged.

- Runner claims isolate corrupt stored plan, policy, context and tmux-session JSON:
  fail and audit the affected ticket with `invalid_stored_plan`, then continue to
  the next approved ticket without launching the invalid plan. The existing intake
  limit of 64 JSON container levels now also applies at claim time. Legacy tickets
  stored above that limit may still be approved, but are failed when claimed.

- New ticket durations now require integers from 1 to 31,536,000 seconds; invalid API values cannot
  truncate, overflow or create audit data. Service and runner defaults enforce the same bounds.

- Runner status rejects contradictory state/result pairs before writing ticket or audit data; failed/timeout remains supported.

- JSON nesting beyond 64 object/array levels and decoder recursion errors now return a bounded validation error in API requests and manual context forms.

- Runner JSON publication cleans up owned temporary files on failure while preserving the prior destination
  and original error.

- Execution-plan role, agent and prompt fields now require nonempty strings instead of
  coercing arbitrary JSON values to text, including when revalidating persisted plans.
- Expiry timestamps whose timezone offsets overflow UTC datetime bounds now return
  `400 invalid_expires_at` instead of an internal error; shared timestamp readers receive `ValueError`.

- Ticket log previews and runner summaries now read a bounded 64 KiB tail and cap each
  line at 2 KiB, with a truncation notice; dedicated step log pages show at most the final 2 MiB.

- Runner status reporting retries temporary server failures and retains recovery state after exhausted
  reports. Executor exceptions stop and verify owned sessions before publishing terminal failure;
  unsuccessful cleanup retains evidence for retry.
- Runner API transport, timeout and malformed-response failures now use safe `RunnerApiError` categories,
  allowing recovery to continue across independent tickets without discarding their state files.

- `runner_last_heartbeat` in `GET /api/v1/health` now advances on every runner claim poll. Before, it was only
  written when the runner claimed a ticket or posted a status, so a live runner with nothing approved looked
  dead since its last ticket. A runner paused by the disable file does not poll and so does not heartbeat.
- A submit or runner bearer token, or a UI form CSRF token, with non-ASCII characters no longer causes a
  500. `hmac.compare_digest` raises `TypeError` on non-ASCII `str`, so these checks now compare UTF-8 bytes,
  like the API CSRF header check already did. Such tokens get the normal 401 or invalid-form-token response.
- Ticket transitions no longer overwrite a concurrent change. Approve, reject, cancel, archive, unarchive and
  runner status updates read the ticket and then wrote it without a guard, so a cancel racing an approve
  could end as `approved` and get claimed and run, and a cancel of a running ticket could be overwritten by a
  runner `succeeded`/`failed` update. These methods (and ticket creation) now run under `BEGIN IMMEDIATE`, and
  every transition `UPDATE` matches the state it read. A write that no longer matches answers
  `409 state_changed` and changes nothing. The runner treats `state_changed` like `invalid_state`.
- The runner no longer relaunches a step whose `exit_code` already exists after a restart. Previously it started
  a second, untracked agent session for the finished step and then reported the old result.
- Summaries of steps resumed from an existing `summary.json` are passed to later steps once instead of twice.
