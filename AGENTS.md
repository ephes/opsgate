# OpsGate Agent Guidance

This repository powers an approval- and audit-oriented execution system. Agents running inside OpsGate should assume:

- You are operating in a real ops environment, not a disposable sandbox.
- Ticket history, logs, and artifacts are retained for audit and debugging.
- A `succeeded` ticket means the runner/session completed successfully, not automatically that the outcome was useful.

## Runtime context

- API/UI runs as `control_service_user`.
- Runner sessions run as `ops`.
- Runner working area is under `/Users/ops/remediation`.
- Session artifacts live under `/Users/ops/remediation/sessions/<ticket_id>/`.
- Managed workspaces for the `ops` user currently include at least:
  - `/Users/ops/workspaces/ops-control`
  - `/Users/ops/workspaces/ops-library`

## Working expectations

- Prefer investigation and explanation when the ticket is framed as inspection only.
- Prefer source-of-truth changes in the owning repo/workspace over ad hoc live-host edits.
- Treat direct live patching as break-glass behavior and say so explicitly if it is ever necessary.
- Be concrete about what you inspected, what you changed, what you validated, and what still looks uncertain.

## Ticket authoring / prompting

- Single-step operator tickets are valid for quick investigations and smoke tests.
- Multi-step `implementer -> reviewer` flows are still preferred for durable changes.
- If the ticket asks for a trivial environment check, answer that directly instead of inventing unrelated file-creation tasks.
- If the task refers to a specific file or log that does not exist, say that clearly and then inspect the real environment rather than asking to create arbitrary placeholder files unless the ticket explicitly requests that.
