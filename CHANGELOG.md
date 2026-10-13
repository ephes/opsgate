# Changelog

## Unreleased

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
