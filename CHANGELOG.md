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
