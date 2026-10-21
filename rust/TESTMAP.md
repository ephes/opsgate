# TESTMAP: Python tests → Rust tests

Plan section 7.5. Every Python test of `tests/` (187 at `c81d3cc`) maps to the
Rust test that ports it and to the slice that owns it (`rust/PLAN.md`
section 12). When a slice merges, it replaces the target with the actual test
path (`crates/<crate>/…::<test>`) and checks the row (`<slice> ✓`). Columns:

- **Rust target**: planned module (`core` = `opsgate-core`, `store` =
  `opsgate-store`, `web` = `opsgate-web`, `runner` = `opsgate-runner`).
- **Parity**: `A` = also covered by a black-box scenario of the API parity
  harness (`rust/parity/api`, plan 7.3), `R` = runner parity harness
  (`rust/parity/runner`, plan 7.4), `-` = unit level only (pure function,
  pinned by a fixture instead).

Tests that assert Python-only error codes for inputs listed as P3
divergences (plan section 5) are ported with the divergent expectation and a
comment naming the divergence (e.g. D-2 for lone surrogates).

Rust-only tests that have no Python counterpart (checksum and float fixtures,
schema contract, cross-implementation database round trips and recovery,
mixed stacks, template render test, release checks) are listed per slice in
the plan's acceptance criteria; once landed, they are listed in the last
section ("Rust-only tests") with their paths.

### `tests/test_api.py`

| Python test | Rust target | Slice | Parity |
| --- | --- | --- | --- |
| `test_ui_ticket_detail_redirects_to_login_with_next` | `web::login` | S4b | A |
| `test_login_redirects_to_requested_next_path` | `web::login` | S4b | A |
| `test_manual_ticket_creation_from_ui` | `web::ui::manual_form` | S5 | A |
| `test_manual_ticket_form_defaults_investigator_to_codex` | `web::ui::manual_form` | S5 | A |
| `test_manual_ticket_form_renders_role_scaffolding` | `web::ui::manual_form` | S5 | A |
| `test_ticket_list_renders_compact_created_at_timestamp` | `web::ui` | S5 | A |
| `test_api_archive_and_unarchive_preserve_ticket_access_and_audit` | `store::archive` | S3b | A |
| `test_archive_rejects_non_archivable_active_states` | `store::archive` | S3b | A |
| `test_archive_allowed_for_all_terminal_states` | `store::archive` | S3b | A |
| `test_archive_allowed_for_pending_approval_state` | `store::archive` | S3b | A |
| `test_archive_rejects_double_archive` | `store::archive` | S3b | A |
| `test_unarchive_rejects_non_archived_ticket` | `store::archive` | S3b | A |
| `test_unarchive_rejects_when_replacement_open_ticket_exists` | `store::archive` | S3b | A |
| `test_ui_archive_and_restore_controls_manage_ticket_visibility` | `web::ui` | S5 | A |
| `test_ticket_list_shows_archive_and_restore_actions_with_list_redirect` | `web::ui` | S5 | A |
| `test_pending_approval_ticket_shows_archive_action_in_list_and_detail` | `web::ui` | S5 | A |
| `test_archived_pending_ticket_hides_approve_reject_and_cancel_actions` | `web::ui` | S5 | A |
| `test_archived_pending_ticket_blocks_lifecycle_actions` | `store::archive` | S3b | A |
| `test_runner_does_not_claim_archived_approved_ticket` | `store::claim` | S3b | A |
| `test_ticket_list_archive_redirect_sanitizes_invalid_targets` | `web::ui` | S5 | A |
| `test_ui_archive_routes_require_csrf_token` | `web::csrf (needs S4b login/logout and S5 routes)` | S8 | A |
| `test_ticket_detail_renders_log_preview_and_full_log_link` | `web::ui` | S5 | A |
| `test_ticket_step_log_view_renders_bounded_log` | `web::ui` | S5 | A |
| `test_ticket_step_log_view_rejects_paths_outside_ticket_artifacts` | `web::ui` | S5 | A |
| `test_ticket_detail_hides_full_log_link_for_session_without_numeric_step_index` | `web::ui` | S5 | A |
| `test_ticket_step_log_view_rejects_missing_step_number` | `web::ui` | S5 | A |
| `test_ticket_detail_shows_log_unavailable_message_for_missing_file` | `web::ui` | S5 | A |
| `test_manual_ticket_creation_defaults_agent_from_role` | `web::ui::manual_form` | S5 | A |
| `test_manual_ticket_creation_supports_legacy_single_step_fields` | `web::ui::manual_form` | S5 | A |
| `test_manual_ticket_creation_rejects_empty_execution_plan_from_ui` | `web::ui::manual_form` | S5 | A |
| `test_manual_ticket_form_uses_implementer_guidance_for_legacy_implementor_role` | `web::ui::manual_form` | S5 | A |
| `test_manual_ticket_creation_enforces_operator_reviewer_floor_when_enabled` | `web::ui::manual_form` | S5 | A |
| `test_manual_ticket_creation_rejects_invalid_context_json` | `web::ui::manual_form` | S5 | A |
| `test_manual_ticket_creation_rejects_unsupported_agent_from_ui` | `web::ui::manual_form` | S5 | A |
| `test_manual_ticket_creation_requires_csrf_token` | `web::ui::manual_form` | S5 | A |
| `test_manual_ticket_creation_rejects_tampered_csrf_token` | `web::ui::manual_form` | S5 | A |
| `test_ui_ticket_action_failure_redirects_back_to_ticket_detail` | `web::ui` | S5 | A |
| `test_api_ticket_creation_rejects_unsupported_agent` | `core::validate` | S2c | A |
| `test_approval_revalidates_stored_agent_allowlist` | `store::transitions` | S3b | A |
| `test_approval_revalidates_stored_reviewer_requirement` | `store::transitions` | S3b | A |
| `test_api_ticket_creation_normalizes_agent_case` | `core::validate` | S2c | A |
| `test_runner_claim_fails_invalid_stored_agent_and_moves_on` | `store::claim` | S3b | A |
| `test_runner_claim_isolates_corrupt_stored_json` | `store::claim` | S3b | A |
| `test_runner_claim_accepts_stored_json_at_depth_limit` | `store::claim` | S3b | A |
| `test_ui_post_routes_require_csrf_token` | `web::csrf (needs S4b login/logout and S5 routes)` | S8 | A |
| `test_trusted_proxy_headers_restore_client_ip_for_access_and_audit` | `web::gate` | S4a | A |
| `test_login_ignores_external_next_path` | `web::login` | S4b | A |
| `test_login_form_uses_autofill_friendly_fields` | `web::login` | S4b | A |
| `test_login_head_is_side_effect_free` | `web::login` | S4b | A |
| `test_login_ignores_protocol_relative_next_path` | `web::login` | S4b | A |
| `test_login_ignores_javascript_next_path` | `web::login` | S4b | A |
| `test_login_ignores_control_chars_in_next_path` | `web::login` | S4b | A |
| `test_create_and_get_ticket_submit_token` | `web::api` | S4a | A |
| `test_dedupe_enforced_for_open_task_ref` | `store::create` | S3a | A |
| `test_dedupe_ignores_archived_pending_ticket` | `store::create + store::transitions` | S3b | A |
| `test_dedupe_expires_stale_pending_ticket_before_replacement_submit` | `store::create` | S3a | A |
| `test_dedupe_expires_stale_approved_ticket_before_replacement_submit` | `store::create + store::transitions` | S3b | A |
| `test_dedupe_not_applied_when_task_ref_missing` | `store::create` | S3a | A |
| `test_operator_submitter_may_explicitly_require_reviewer_step` | `core::validate` | S2c | A |
| `test_operator_submitter_omitted_ticket_policy_defaults_to_no_reviewer_floor` | `core::validate` | S2c | A |
| `test_lazy_expiry_blocks_approval` | `store::transitions` | S3b | A |
| `test_approve_and_reject_flow` | `store::transitions` | S3b | A |
| `test_cancel_flow` | `store::transitions` | S3b | A |
| `test_runner_claim_happy_path` | `store::claim` | S3b | A |
| `test_runner_claim_detects_checksum_tamper` | `store::claim` | S3b | A |
| `test_runner_status_rejects_terminal_state_regression` | `store::runner_status` | S3b | A |
| `test_runner_status_accepts_timeout_result_and_tmux_sessions` | `store::runner_status` | S3b | A |
| `test_runner_status_rejects_invalid_tmux_sessions_payload` | `store::runner_status` | S3b | A |
| `test_runner_status_rejects_runner_host_mismatch` | `store::runner_status` | S3b | A |
| `test_runner_status_rejects_invalid_event_type` | `store::runner_status` | S3b | A |
| `test_runner_status_accepts_step_failed_event` | `store::runner_status` | S3b | A |
| `test_get_ticket_forbidden_for_other_submitter_source` | `web::api` | S4a | A |
| `test_health_endpoint_reports_ok` | `store::health + web::api` | S4a | A |
| `test_health_reports_no_runner_heartbeat_before_first_poll` | `store::health + web::api` | S4a | A |
| `test_idle_runner_claim_poll_records_heartbeat` | `store::claim` | S3b | A |
| `test_runner_claim_without_token_records_no_heartbeat` | `store::claim` | S3b | A |
| `test_api_rejects_non_tailscale_source_ip` | `web::gate` | S4a | A |
| `test_cookie_api_action_without_csrf_header_is_rejected` | `web::csrf` | S4b | A |
| `test_cookie_approve_with_wrong_csrf_header_is_rejected` | `web::csrf` | S4b | A |
| `test_cookie_approve_with_csrf_header_succeeds` | `web::csrf` | S4b | A |
| `test_cookie_approve_same_origin_fallback` | `web::csrf` | S4b | A |
| `test_bearer_callers_are_unaffected_by_api_csrf` | `web::csrf` | S4b | A |
| `test_unauthenticated_api_action_reports_auth_before_csrf` | `web::csrf` | S4b | A |
| `test_cookie_replayed_after_logout_is_rejected` | `web::session` | S4b | A |
| `test_logout_revokes_other_sessions_and_fresh_login_works` | `web::session` | S4b | A |
| `test_anonymous_logout_does_not_revoke_sessions` | `web::session` | S4b | A |
| `test_password_change_revokes_existing_sessions` | `web::session` | S4b | A |
| `test_restart_with_same_password_keeps_sessions` | `web::session` | S4b | A |
| `test_session_without_generation_is_treated_as_logged_out` | `web::session` | S4b | A |
| `test_login_locks_after_repeated_failures` | `web::login::throttle` | S4b | A |
| `test_unknown_username_counts_toward_throttle` | `web::login::throttle` | S4b | A |
| `test_successful_login_resets_failure_count` | `web::login::throttle` | S4b | A |
| `test_login_throttle_is_per_client_ip` | `web::login::throttle` | S4b | A |
| `test_login_throttle_bounds_tracked_clients` | `web::login::throttle` | S4b | A |
| `test_api_bearer_endpoints_reject_non_ascii_token` | `web::auth` | S4a | A |
| `test_api_session_actions_reject_non_ascii_csrf_header` | `web::csrf` | S4b | A |
| `test_ui_ticket_actions_reject_non_ascii_form_token` | `web::csrf (UI-CSRF layer from S4a)` | S5 | A |
| `test_ui_forms_reject_non_ascii_form_token` | `web::csrf (needs S4b login/logout and S5 routes)` | S8 | A |
| `test_api_rejects_non_text_plan_fields` | `core::validate` | S2c | A |
| `test_claim_rejects_non_text_stored_plan` | `store::claim` | S3b | A |
| `test_api_rejects_utc_expiry_overflow` | `core::time + core::validate` | S2a | A |
| `test_datetime_overflow_is_value_error` | `core::time + core::validate` | S2a | A |
| `test_api_accepts_trimmed_plan_and_optional_expiry` | `core::validate` | S2c | A |
| `test_ui_pages_cannot_be_framed` | `web::headers` | S4a | A |
| `test_api_error_and_redirect_responses_carry_security_headers` | `web::headers` | S4a | A |
| `test_forbidden_network_response_carries_security_headers` | `web::headers` | S4a | A |
| `test_wrong_username_still_runs_the_password_check` | `web::login` | S4b | A |
| `test_non_ascii_username_is_rejected_without_error` | `web::login` | S4b | A |
| `test_json_decode_errors_are_domain_responses` | `core::json + web::api` | S4a | A |
| `test_manual_context_rejects_excessive_nesting` | `web::ui::manual_form` | S5 | A |
| `test_real_json_nesting_limit` | `core::json + web::api` | S4a | A |
| `test_real_manual_context_nesting_limit` | `web::ui::manual_form` | S5 | A |
| `test_malformed_required_json_retains_domain_response` | `core::json + web::api` | S4a | A |
| `test_runner_state_result_matrix` | `store::runner_status` | S3b | A |
| `test_ticket_duration_rejects_invalid_values` | `core::validate` | S2c | A |
| `test_ticket_duration_accepts_boundaries` | `core::validate` | S2c | A |
| `test_ticket_duration_rejects_json_exponent_overflow` | `core::validate` | S2c | A |
| `test_manual_ticket_duration_rejects_invalid_values` | `web::ui::manual_form` | S5 | A |
| `test_direct_settings_duration_default_is_validated` | `crates/opsgate-core/tests/settings_fixture.rs::direct_settings_duration_default_is_validated` | S2b ✓ | - |
| `test_ticket_text_rejects_unpaired_surrogates` | `core::validate (P3 D-5: Rust answers invalid_json for lone surrogates)` | S2c | A |
| `test_ticket_unicode_text_persists_and_passes_checksum_validation` | `core::validate + store::claim` | S3b | A |
| `test_ticket_creation_metadata_rejects_unpaired_surrogates` | `core::validate (P3 D-5: Rust answers invalid_json for lone surrogates)` | S2c | A |

### `tests/test_ticket_transition_races.py`

| Python test | Rust target | Slice | Parity |
| --- | --- | --- | --- |
| `test_cancel_during_approve_is_not_overwritten` | `store::races (two connections, hook between read and write)` | S3b | A |
| `test_cancel_during_runner_completion_is_reported` | `store::races (two connections, hook between read and write)` | S3b | A |
| `test_double_approve_has_one_winner` | `store::races (two connections, hook between read and write)` | S3b | A |
| `test_reject_during_approve_is_not_overwritten` | `store::races (two connections, hook between read and write)` | S3b | A |
| `test_approve_with_stale_read_after_cancel_returns_state_changed` | `store::races (two connections, hook between read and write)` | S3b | A |
| `test_runner_completion_with_stale_read_after_cancel_returns_state_changed` | `store::races (two connections, hook between read and write)` | S3b | A |
| `test_lifecycle_action_with_stale_read_returns_state_changed` | `store::races (two connections, hook between read and write)` | S3b | A |
| `test_archive_with_stale_read_returns_state_changed` | `store::races (two connections, hook between read and write)` | S3b | A |
| `test_unarchive_with_stale_read_returns_state_changed` | `store::races (two connections, hook between read and write)` | S3b | A |

### `tests/test_config.py`

| Python test | Rust target | Slice | Parity |
| --- | --- | --- | --- |
| `test_load_env_file_strips_wrapping_quotes` | `crates/opsgate-core/tests/settings_fixture.rs::env_file_cases_match_python` (fixture `settings.json`, `env_file_cases`) | S2b ✓ | - |
| `test_load_settings_requires_explicit_session_secret` | `crates/opsgate-core/tests/settings_fixture.rs::settings_cases_match_python` (fixture `settings.json`) | S2b ✓ | - |
| `test_load_runner_settings_accepts_runner_only_env` | `crates/opsgate-core/tests/settings_fixture.rs::settings_cases_match_python` (fixture `settings.json`) | S2b ✓ | - |
| `test_load_runner_settings_requires_runner_token` | `crates/opsgate-core/tests/settings_fixture.rs::settings_cases_match_python` (fixture `settings.json`) | S2b ✓ | - |
| `test_load_settings_allows_missing_openclaw_submit_token` | `crates/opsgate-core/tests/settings_fixture.rs::settings_cases_match_python` (fixture `settings.json`) | S2b ✓ | - |
| `test_load_settings_supports_secure_session_cookie` | `crates/opsgate-core/tests/settings_fixture.rs::settings_cases_match_python` (fixture `settings.json`) | S2b ✓ | - |
| `test_load_runner_settings_reports_invalid_integer_env` | `crates/opsgate-core/tests/settings_fixture.rs::settings_cases_match_python` (fixture `settings.json`) | S2b ✓ | - |
| `test_boolean_typo_rejects_settings` | `crates/opsgate-core/tests/settings_fixture.rs::settings_cases_match_python` (fixture `settings.json`) | S2b ✓ | - |
| `test_boolean_spellings_load_settings` | `crates/opsgate-core/tests/settings_fixture.rs::settings_cases_match_python` (fixture `settings.json`) | S2b ✓ | - |
| `test_boolean_defaults_and_policy_inheritance` | `crates/opsgate-core/tests/settings_fixture.rs::settings_cases_match_python` (fixture `settings.json`) | S2b ✓ | - |
| `test_disabled_openclaw_policy_still_rejects_typo` | `crates/opsgate-core/tests/settings_fixture.rs::settings_cases_match_python` (fixture `settings.json`) | S2b ✓ | - |
| `test_explicit_submitter_policy_overrides_global_floor` | `crates/opsgate-core/tests/settings_fixture.rs::settings_cases_match_python` (fixture `settings.json`) | S2b ✓ | - |
| `test_duration_default_validates_supported_bounds` | `crates/opsgate-core/tests/settings_fixture.rs::settings_cases_match_python` (fixture `settings.json`) | S2b ✓ | - |

### `tests/test_log_preview.py`

| Python test | Rust target | Slice | Parity |
| --- | --- | --- | --- |
| `test_large_log_reads_only_bounded_tail` | `crates/opsgate-core/tests/log_preview_fixture.rs::cases_match_python` (fixture `log_preview.json`) | S2b ✓ | - |
| `test_normal_final_40_lines` | `crates/opsgate-core/tests/log_preview_fixture.rs::cases_match_python` (fixture `log_preview.json`) | S2b ✓ | - |
| `test_utf8_fragments_and_huge_single_line` | `crates/opsgate-core/tests/log_preview_fixture.rs::cases_match_python` (fixture `log_preview.json`) | S2b ✓ | - |
| `test_small_logs` | `crates/opsgate-core/tests/log_preview_fixture.rs::cases_match_python` (fixture `log_preview.json`) | S2b ✓ | - |
| `test_tail_window_splits_utf8_character` | `crates/opsgate-core/tests/log_preview_fixture.rs::cases_match_python` (fixture `log_preview.json`) | S2b ✓ | - |
| `test_step_log_boundaries` | `crates/opsgate-core/tests/log_preview_fixture.rs::cases_match_python` (fixture `log_preview.json`) | S2b ✓ | - |

### `tests/test_atomic_json.py`

| Python test | Rust target | Slice | Parity |
| --- | --- | --- | --- |
| `test_failed_publication_cleans_temp` | `runner::artifacts::atomic_write` | S6a | - |
| `test_successful_publication_is_private` | `runner::artifacts::atomic_write` | S6a | - |
| `test_cleanup_refusal_preserves_publication_error` | `runner::artifacts::atomic_write` | S6a | - |
| `test_success_does_not_unlink_released_temp_name` | `runner::artifacts::atomic_write` | S6a | - |

### `tests/test_runner.py`

| Python test | Rust target | Slice | Parity |
| --- | --- | --- | --- |
| `test_ticket_executor_runs_steps_sequentially` | `runner::executor` | S6a | R |
| `test_ticket_executor_reports_timeout_result` | `runner::executor` | S6a | R |
| `test_ticket_executor_reports_step_failure_detail` | `runner::executor` | S6a | R |
| `test_ticket_executor_resumes_from_existing_step_summary` | `runner::supervisor / runner::resume` | S6b | R |
| `test_worker_keeps_state_file_when_status_update_unavailable` | `runner::supervisor / runner::resume` | S6b | R |
| `test_worker_exception_report_includes_runner_host` | `runner::supervisor / runner::resume` | S6b | R |
| `test_worker_success_marks_state_for_cleanup` | `runner::supervisor / runner::resume` | S6b | R |
| `test_reap_finished_workers_cleans_state_files` | `runner::supervisor / runner::resume` | S6b | R |
| `test_recovery_restarts_only_running_tickets` | `runner::supervisor / runner::resume` | S6b | R |
| `test_discover_ticket_ids_from_tmux_handles_missing_binary` | `runner::supervisor / runner::resume` | S6b | R |
| `test_build_agent_command_rejects_unsupported_agent` | `runner::commands` | S6a | - |
| `test_build_agent_command_uses_codex_exec_with_stdin` | `runner::commands` | S6a | - |
| `test_build_agent_command_uses_claude_print_with_bypass_permissions` | `runner::commands` | S6a | - |
| `test_build_attach_command_includes_tmux_tmpdir` | `runner::commands` | S6a | - |
| `test_ticket_executor_rejects_unsupported_agent` | `runner::executor` | S6a | R |
| `test_resume_adopts_existing_exit_code_without_relaunch` | `runner::supervisor / runner::resume` | S6b | R |
| `test_resume_fails_interrupted_step_without_relaunch` | `runner::supervisor / runner::resume` | S6b | R |
| `test_resume_reattaches_live_session_without_relaunch` | `runner::supervisor / runner::resume` | S6b | R |
| `test_resumed_summary_appears_once_in_next_step_context` | `runner::supervisor / runner::resume` | S6b | R |
| `test_runner_shutdown_marks_running_step_interrupted` | `runner::supervisor / runner::resume` | S6b | R |
| `test_resume_fails_closed_on_unreadable_metadata` | `runner::supervisor / runner::resume` | S6b | R |
| `test_resume_adopts_exit_code_written_during_session_probe` | `runner::supervisor / runner::resume` | S6b | R |
| `test_post_status_ignores_conflict_when_ticket_moved_on` | `runner::executor` | S6a | R |
| `test_post_status_raises_other_conflicts` | `runner::executor` | S6a | R |
| `test_worker_cleans_session_before_terminal_failure` | `runner::supervisor / runner::resume` | S6b | R |
| `test_status_outage_retries_and_retains_execution` | `runner::supervisor / runner::resume` | S6b | R |
| `test_api_normalizes_transport_and_response_errors` | `runner::api_client` | S6a | R |
| `test_recovery_transport_outage_isolated_and_state_retained` | `runner::supervisor / runner::resume` | S6b | R |
| `test_running_heartbeat_outage_never_fails_live_session` | `runner::supervisor / runner::resume` | S6b | R |
| `test_permanent_api_error_stops_session_before_failure` | `runner::supervisor / runner::resume` | S6b | R |
| `test_cleanup_accepts_absent_tmux_server` | `runner::supervisor / runner::resume` | S6b | R |
| `test_cleanup_rejects_unverifiable_tmux` | `runner::supervisor / runner::resume` | S6b | R |
| `test_cleanup_verifies_sessions_are_gone` | `runner::supervisor / runner::resume` | S6b | R |

## Rust-only tests

Tests without a Python counterpart, by the slice that landed them. Paths are
relative to `rust/` (Rust) or the repository root (pytest).

| Test | Covers | Slice |
| --- | --- | --- |
| `crates/opsgate/src/cli.rs::tests` | command-line parsing: default `serve`, `serve` overrides, `runner --once`, `check-config api\|runner`, `check-db --db`, usage errors exit 2, `--version` text (4.1, D-15) | S1 |
| `crates/opsgate/tests/binary.rs` | the binary: `--version`/`-V` print `opsgate <version> (<commit>)` with the checked-out commit, every command is a stub exiting 2, usage errors exit 2, `--help` | S1 |
| `crates/opsgate/tests/build_script.rs` | `build.rs`: full-commit validation, watched git paths (packed refs, nested branches, linked worktrees, detached HEAD, no git) | S1 |
| `tests/test_rust_fixtures.py` | fixture drift: committed fixtures equal a fresh render byte for byte, every fixture has a generator, a hand-edited or missing fixture is detected, `generate.py --check` exits 1 on drift, `schema.sql` runs and yields the Python schema's objects (7.2, 4.10) | S1 |
| `crates/opsgate-core/tests/settings_fixture.rs` | `settings.json`: 490 environment sets (every variable and rule of 4.2, check order, env-file override, D-8/D-10 cases) and 21 env-file parsing cases; coverage of every 4.2 variable; the merged environment children get (4.13.8) | S2b |
| `crates/opsgate-core/tests/log_preview_fixture.rs` | `log_preview.json`: preview and step log for 31 contents (window and line cuts, CR/LF forms, invalid UTF-8 replacement, 2 MiB boundary) (4.12) | S2b |
| `crates/opsgate-core/tests/proxy_fix_fixture.rs` | `proxy_fix.json`: 26 header sets through waitress and Werkzeug `ProxyFix` (last value, joined lines, quoted items, unclosed quotes, latin-1 bytes) (4.4) | S2b |
| `crates/opsgate-core/tests/containment.rs` | step-log containment (4.12): symlink escapes (file, directory, dangling, relative), missing inside → `log_not_found`, missing outside → `invalid_log_path`, containment before existence, `..` escapes, symlink loops, CPython 3.14 `realpath` corner cases | S2b |
| `crates/opsgate-core/src/{pytext,settings,log_preview}.rs` unit tests | Python whitespace and line-boundary sets, `int()` grammar and the 4300-digit limit, non-UTF-8 values, redacted `Debug`, CIDR prefixes, directories and missing files | S2b |
