# Changelog

## Unreleased

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
