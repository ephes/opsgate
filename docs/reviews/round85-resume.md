# Round 85 resume checkpoint

Stopped on 2026-11-08 because the required Opus review failed authentication:
“OAuth session expired and could not be refreshed.” The review harness reported
PROVIDER_ERROR / api_error, with no verdict. No changes were merged. This branch
is parked under the owner's explicit OAuth-failure exception to the branch-push
restriction. Do not merge until a successful required review and local checks.

Source: ~/workspaces/ws-work-planning/reviews/scout-round85.md, all five opsgate
slices. Fresh SSH clone verified origin git@github.com:ephes/opsgate.git and
origin/main at 57e0685927598adeedffdf01c3a9c30e258e5a94. All five findings were
re-verified as present; none were skipped.

## Implemented, awaiting validation completion and review: B25

In report bundle order:
1. opsgate-status-start-reuses-claim-admission: reject status-start on approved
   tickets with 409 invalid_state; require claim. Both runtimes, shared generated
   store fixtures, API parity tests and documentation updated.
2. opsgate-claim-numeric-poison-row-isolation: stored duration must be a SQLite
   INTEGER from 1 to 31536000. Invalid values are failed/audited once via
   invalid_stored_plan / invalid_ticket; continue the queue. Tests cover legacy
   NULL, text, infinities, fractional, BLOB and range corruption, plus audit
   insert failure rollback in both runtimes.
3. opsgate-claim-invalid-prefix-work-budget: examine at most 100 candidates per
   transaction, commit recovery and heartbeat then return null. Tests use 1001
   corrupt/expired rows before valid work; later polls reach it. Python variants
   cover expired, tampered and numeric corruption.

Evidence before parking:
- Original Python code fails the status-start regression (200 instead of 409),
  all nine invalid-duration cases, and the backlog regression.
- Fixed targeted Python set: 23 passed (before adding two backlog variants).
- Rust targeted claim/status set: 29 passed. Shared store fixture: passed after
  correcting Rust terminal-state error-message ordering to match Python.
- Full Python suite: 601 passed, 4 failed. All four failures are
  tests/test_runner.py::test_log_copy_failure_fails_ticket
  ([0-0-0], [3-0-3], [0-7-7], [3-7-3]): expected summary.json is missing.
  These runner files were untouched by B25. Determine the cause on resumption;
  no claim that the full Python gate passes.
- Ruff src/tests and parity/scripts: passed. Mypy src/tests and API/shadow/scripts:
  passed. Parity formatting check: passed. cargo deny: all checks passed.
- Full just rs-check was rerun after fixing fixture message ordering; check the
  local workspace log b25-rust-final.log for its final outcome.
- Full API parity Python leg: 569 passed, 1 existing skip (127.0.0.2 unavailable).
  Rust leg and full runner parity were still running when review authentication
  failed. Runner parity Python leg: 47 passed, 15 deselected. Consult local logs
  b25-parity-api.log and b25-parity-runner.log, then rerun as needed. Rust parity
  binary was built before the message-order fix, so rebuild before final parity.
- Review: Opus 5.5, high effort, via installed claude-review-loop. Failed before
  review with expired OAuth. No findings or clean verdict. Local artifacts are
  ../reviews/b25-r1 relative to this clone; logs are workspace-local, not committed.

## Not implemented: B26

After B25 is reviewed and merged, re-verify these against current main:
4. opsgate-claim-receipt-persistence-compensation.
5. opsgate-worker-thread-start-supervision.
Read their complete descriptions and validation requirements in the scout report.
B26 needs runner-authenticated discovery and Python/Rust parity; recovery without
local execution evidence must never authorize a duplicate launch.

## Resume procedure

Repair the owner's Claude OAuth session externally; never substitute the reviewer.
Fetch origin, confirm ephes origin, rebase this branch onto current origin/main,
and inspect upstream overlap before continuing. Complete the local checks:
UV_PYTHON=3.14 just check; just rs-check; just rs-parity-api;
just rs-parity-runner; cargo deny --locked check in rust. Set UV_CACHE_DIR to
this workspace's .cache/uv. Check Python 3.11 as required by repository CI.
Resolve the four runner test failures without platform-dependent tests.
Run a fresh whole-bundle review with --model claude-opus-5-5 --effort high.
The failed attempt consumed no review round. Continue repairs under the owner's
four-round / recurring-finding limit. Fetch immediately before every merge;
if origin moved, rebase and rerun checks. Only reviewed-clean bundles may merge
locally with --no-ff, followed by full local checks, default-branch push and
ls-remote verification. No Actions, PRs, deploys, tags/releases, remote deletion,
host access, work-app writes or ~/projects writes.
