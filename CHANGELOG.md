# Changelog

## Unreleased

### Security

- Cookie-authenticated API actions (`POST /api/v1/tickets/<id>/approve|reject|cancel|archive|unarchive`) now
  need CSRF proof: an `X-CSRF-Token` header with the session token, or a browser-reported same-origin request
  (`Sec-Fetch-Site: same-origin`, falling back to `Origin`). Before, `SameSite=Lax` alone let any page on a
  sibling subdomain post an approval with the approver's cookie. Bearer-token callers are unchanged.
- `POST /logout` now revokes approver sessions server-side through a session generation stored in SQLite. A
  copied cookie no longer stays valid until the session timeout. Logout signs the approver out of every
  browser. Changing the UI password hash revokes existing sessions on the next start.
- `/login` locks a client IP out for 15 minutes after 5 failed attempts (`429`).

### Upgrade notes

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

- The runner no longer relaunches a step whose `exit_code` already exists after a restart. Previously it started
  a second, untracked agent session for the finished step and then reported the old result.
- Summaries of steps resumed from an existing `summary.json` are passed to later steps once instead of twice.
