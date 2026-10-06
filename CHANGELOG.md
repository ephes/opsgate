# Changelog

## Unreleased

### Fixed

- A submit or runner bearer token, or a UI form CSRF token, with non-ASCII characters no longer causes a
  500. `hmac.compare_digest` raises `TypeError` on non-ASCII `str`, so these checks now compare UTF-8 bytes,
  like the API CSRF header check already did. Such tokens get the normal 401 or invalid-form-token response.
- Ticket transitions no longer overwrite a concurrent change. Approve, reject, cancel, archive, unarchive and
  runner status updates read the ticket and then wrote it without a guard, so a cancel racing an approve
  could end as `approved` and get claimed and run, and a cancel of a running ticket could be overwritten by a
  runner `succeeded`/`failed` update. These methods (and ticket creation) now run under `BEGIN IMMEDIATE`, and
  every transition `UPDATE` matches the state it read. A write that no longer matches answers
  `409 state_changed` and changes nothing. The runner treats `state_changed` like `invalid_state`.

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
