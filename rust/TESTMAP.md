# TESTMAP: Python tests → Rust tests

Plan section 7.5. Every Python test of `tests/` (187 at `c81d3cc`) maps to the
Rust test that ports it and to the slice that owns it (`rust/PLAN.md`
section 12). When a slice merges, it replaces the target with the actual test
path (`crates/<crate>/…::<test>`) and checks the row (`<slice> ✓`). Columns:

- **Rust target**: planned module (`core` = `opsgate-core`, `store` =
  `opsgate-store`, `web` = `opsgate-web`, `runner` = `opsgate-runner`).
- **Parity**: `A` = also covered by a black-box scenario of the API parity
  harness (`rust/parity/api`, plan 7.3; same test name where the scenario
  ports it, races and the cases the HTTP surface cannot reach are `-`), `R` = runner parity harness
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
| `test_api_ticket_creation_rejects_unsupported_agent` | `crates/opsgate-core/tests/validation.rs::test_api_ticket_creation_rejects_unsupported_agent` (cases also in fixture `validation.json`) | S2c ✓ | A |
| `test_approval_revalidates_stored_agent_allowlist` | `store::transitions` | S3b | A |
| `test_approval_revalidates_stored_reviewer_requirement` | `store::transitions` | S3b | A |
| `test_api_ticket_creation_normalizes_agent_case` | `crates/opsgate-core/tests/validation.rs::test_api_ticket_creation_normalizes_agent_case` (cases also in fixture `validation.json`) | S2c ✓ | A |
| `test_runner_claim_fails_invalid_stored_agent_and_moves_on` | `store::claim` | S3b | A |
| `test_runner_claim_isolates_corrupt_stored_json` | `store::claim` | S3b | A |
| `test_runner_claim_accepts_stored_json_at_depth_limit` | `store::claim` | S3b | A |
| `test_ui_post_routes_require_csrf_token` | `web::csrf (needs S4b login/logout and S5 routes)` | S8 | A |
| `test_trusted_proxy_headers_restore_client_ip_for_access_and_audit` | `web::gate` (production expectation: forwarded headers ignored behind waitress, PLAN.md 4.4 step 1; the Python test bypasses waitress) | S4a | A |
| `test_login_ignores_external_next_path` | `web::login` | S4b | A |
| `test_login_form_uses_autofill_friendly_fields` | `web::login` | S4b | A |
| `test_login_head_is_side_effect_free` | `web::login` | S4b | A |
| `test_login_ignores_protocol_relative_next_path` | `web::login` | S4b | A |
| `test_login_ignores_javascript_next_path` | `web::login` | S4b | A |
| `test_login_ignores_control_chars_in_next_path` | `web::login` | S4b | A |
| `test_create_and_get_ticket_submit_token` | `web::api` | S4a | A |
| `test_dedupe_enforced_for_open_task_ref` | `crates/opsgate-store/tests/create.rs::test_dedupe_enforced_for_open_task_ref` (also scenario `dedupe` of fixture `store.json`) | S3a ✓ | A |
| `test_dedupe_ignores_archived_pending_ticket` | `store::create + store::transitions` | S3b | A |
| `test_dedupe_expires_stale_pending_ticket_before_replacement_submit` | `crates/opsgate-store/tests/create.rs::test_dedupe_expires_stale_pending_ticket_before_replacement_submit` (also scenario `lazy_expiry` of fixture `store.json`) | S3a ✓ | A |
| `test_dedupe_expires_stale_approved_ticket_before_replacement_submit` | `store::create + store::transitions` | S3b | A |
| `test_dedupe_not_applied_when_task_ref_missing` | `crates/opsgate-store/tests/create.rs::test_dedupe_not_applied_when_task_ref_missing` (also scenario `create_get_list` of fixture `store.json`) | S3a ✓ | A |
| `test_operator_submitter_may_explicitly_require_reviewer_step` | `crates/opsgate-core/tests/validation.rs::test_operator_submitter_may_explicitly_require_reviewer_step` (cases also in fixture `validation.json`) | S2c ✓ | A |
| `test_operator_submitter_omitted_ticket_policy_defaults_to_no_reviewer_floor` | `crates/opsgate-core/tests/validation.rs::test_operator_submitter_omitted_ticket_policy_defaults_to_no_reviewer_floor` (cases also in fixture `validation.json`) | S2c ✓ | A |
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
| `test_health_endpoint_reports_ok` | `crates/opsgate-store/tests/create.rs::test_health_endpoint_reports_ok` (store half) + `web::api` | S3a ✓ + S4a | A |
| `test_health_reports_no_runner_heartbeat_before_first_poll` | `crates/opsgate-store/tests/create.rs::test_health_reports_no_runner_heartbeat_before_first_poll` (store half) + `web::api` | S3a ✓ + S4a | A |
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
| `test_session_without_generation_is_treated_as_logged_out` | `web::session` | S4b | - |
| `test_login_locks_after_repeated_failures` | `web::login::throttle` | S4b | A |
| `test_unknown_username_counts_toward_throttle` | `web::login::throttle` | S4b | A |
| `test_successful_login_resets_failure_count` | `web::login::throttle` | S4b | A |
| `test_login_throttle_is_per_client_ip` | `web::login::throttle` | S4b | A |
| `test_login_throttle_bounds_tracked_clients` | `web::login::throttle` | S4b | - |
| `test_api_bearer_endpoints_reject_non_ascii_token` | `web::auth` | S4a | A |
| `test_api_session_actions_reject_non_ascii_csrf_header` | `web::csrf` | S4b | A |
| `test_ui_ticket_actions_reject_non_ascii_form_token` | `web::csrf (UI-CSRF layer from S4a)` | S5 | A |
| `test_ui_forms_reject_non_ascii_form_token` | `web::csrf (needs S4b login/logout and S5 routes)` | S8 | A |
| `test_api_rejects_non_text_plan_fields` | `crates/opsgate-core/tests/validation.rs::test_api_rejects_non_text_plan_fields` (cases also in fixture `validation.json`) | S2c ✓ | A |
| `test_claim_rejects_non_text_stored_plan` | `store::claim` | S3b | A |
| `test_api_rejects_utc_expiry_overflow` | `crates/opsgate-core/src/time.rs::tests::utc_overflow_is_out_of_range` (time half, S2a) + `crates/opsgate-core/tests/validation.rs::test_api_rejects_utc_expiry_overflow` (`invalid_expires_at`, S2c) | S2a ✓ + S2c ✓ | A |
| `test_datetime_overflow_is_value_error` | `crates/opsgate-core/src/time.rs::tests::utc_overflow_is_out_of_range` | S2a | A |
| `test_api_accepts_trimmed_plan_and_optional_expiry` | `crates/opsgate-core/tests/validation.rs::test_api_accepts_trimmed_plan_and_optional_expiry` (cases also in fixture `validation.json`) | S2c ✓ | A |
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
| `test_ticket_duration_rejects_invalid_values` | `crates/opsgate-core/tests/validation.rs::test_ticket_duration_rejects_invalid_values` (P3 D-2 for the `Infinity` literal: Rust answers `invalid_json`) (cases also in fixture `validation.json`) | S2c ✓ | A |
| `test_ticket_duration_accepts_boundaries` | `crates/opsgate-core/tests/validation.rs::test_ticket_duration_accepts_boundaries` (cases also in fixture `validation.json`) | S2c ✓ | A |
| `test_ticket_duration_rejects_json_exponent_overflow` | `crates/opsgate-core/tests/validation.rs::test_ticket_duration_rejects_json_exponent_overflow` (cases also in fixture `validation.json`) | S2c ✓ | A |
| `test_manual_ticket_duration_rejects_invalid_values` | `web::ui::manual_form` | S5 | A |
| `test_direct_settings_duration_default_is_validated` | `crates/opsgate-core/tests/settings_fixture.rs::direct_settings_duration_default_is_validated` | S2b ✓ | - |
| `test_ticket_text_rejects_unpaired_surrogates` | `crates/opsgate-core/tests/validation.rs::test_ticket_text_rejects_unpaired_surrogates` (P3 D-2: Rust answers `invalid_json` for lone surrogates) (cases also in fixture `validation.json`) | S2c ✓ | A |
| `test_ticket_unicode_text_persists_and_passes_checksum_validation` | `core::validate + store::claim` | S3b | A |
| `test_ticket_creation_metadata_rejects_unpaired_surrogates` | `crates/opsgate-core/tests/validation.rs::test_ticket_creation_metadata_rejects_unpaired_surrogates` (P3 D-2: lone surrogates cannot reach Rust strings; the body path answers `invalid_json`) (cases also in fixture `validation.json`) | S2c ✓ | - |

### `tests/test_ticket_transition_races.py`

| Python test | Rust target | Slice | Parity |
| --- | --- | --- | --- |
| `test_cancel_during_approve_is_not_overwritten` | `store::races (two connections, hook between read and write)` | S3b | A |
| `test_cancel_during_runner_completion_is_reported` | `store::races (two connections, hook between read and write)` | S3b | A |
| `test_double_approve_has_one_winner` | `store::races (two connections, hook between read and write)` | S3b | A |
| `test_reject_during_approve_is_not_overwritten` | `store::races (two connections, hook between read and write)` | S3b | A |
| `test_approve_with_stale_read_after_cancel_returns_state_changed` | `store::races (two connections, hook between read and write)` | S3b | - |
| `test_runner_completion_with_stale_read_after_cancel_returns_state_changed` | `store::races (two connections, hook between read and write)` | S3b | - |
| `test_lifecycle_action_with_stale_read_returns_state_changed` | `store::races (two connections, hook between read and write)` | S3b | - |
| `test_archive_with_stale_read_returns_state_changed` | `store::races (two connections, hook between read and write)` | S3b | - |
| `test_unarchive_with_stale_read_returns_state_changed` | `store::races (two connections, hook between read and write)` | S3b | - |

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
| `test_failed_publication_cleans_temp` | `crates/opsgate-runner/src/artifacts.rs::tests::failed_publication_cleans_temp` + `crates/opsgate-runner/src/artifacts.rs::tests::failed_replace_cleans_temp` | S6a ✓ | - |
| `test_successful_publication_is_private` | `crates/opsgate-runner/src/artifacts.rs::tests::successful_publication_is_private` | S6a ✓ | - |
| `test_cleanup_refusal_preserves_publication_error` | `crates/opsgate-runner/src/artifacts.rs::tests::cleanup_refusal_preserves_publication_error` | S6a ✓ | - |
| `test_success_does_not_unlink_released_temp_name` | `crates/opsgate-runner/src/artifacts.rs::tests::success_does_not_unlink_released_temp_name` | S6a ✓ | - |

### `tests/test_runner.py`

`R` rows are covered by the runner parity harness (S7b, `rust/parity/runner`):
executor rows by `test_runner_execution.py`, API error and outage rows by
`test_runner_api_faults.py`, recovery and cleanup rows by
`test_runner_supervisor.py`, resume and shutdown rows by
`test_runner_restart.py`. Not reproducible as a black box and left to the unit
port: `test_resume_adopts_exit_code_written_during_session_probe` (a race
between two probes) and the `cleanup_fails=True` case of
`test_worker_cleans_session_before_terminal_failure`.

| Python test | Rust target | Slice | Parity |
| --- | --- | --- | --- |
| `test_ticket_executor_runs_steps_sequentially` | `crates/opsgate-runner/tests/executor.rs::ticket_executor_runs_steps_sequentially` | S6a ✓ | R |
| `test_ticket_executor_reports_timeout_result` | `crates/opsgate-runner/tests/executor.rs::ticket_executor_reports_timeout_result` | S6a ✓ | R |
| `test_ticket_executor_reports_step_failure_detail` | `crates/opsgate-runner/tests/executor.rs::ticket_executor_reports_step_failure_detail` | S6a ✓ | R |
| `test_ticket_executor_resumes_from_existing_step_summary` | `crates/opsgate-runner/tests/executor.rs::ticket_executor_resumes_from_existing_step_summary` | S6a ✓ | R |
| `test_worker_keeps_state_file_when_status_update_unavailable` | `crates/opsgate-runner/tests/supervisor.rs::worker_keeps_state_file_when_status_update_unavailable` | S6b ✓ | R |
| `test_worker_exception_report_includes_runner_host` | `crates/opsgate-runner/tests/supervisor.rs::worker_exception_report_includes_runner_host` | S6b ✓ | R |
| `test_worker_success_marks_state_for_cleanup` | `crates/opsgate-runner/tests/supervisor.rs::worker_success_marks_state_for_cleanup` | S6b ✓ | R |
| `test_reap_finished_workers_cleans_state_files` | `crates/opsgate-runner/tests/supervisor.rs::reap_finished_workers_cleans_state_files` | S6b ✓ | R |
| `test_recovery_restarts_only_running_tickets` | `crates/opsgate-runner/tests/supervisor.rs::recovery_restarts_only_running_tickets` | S6b ✓ | R |
| `test_discover_ticket_ids_from_tmux_handles_missing_binary` | `crates/opsgate-runner/tests/supervisor.rs::discover_ticket_ids_from_tmux` + `crates/opsgate-runner/tests/tmux_integration.rs::missing_tmux_binary_is_an_error` | S6b ✓ | R |
| `test_build_agent_command_rejects_unsupported_agent` | `crates/opsgate-runner/src/commands.rs::tests::build_agent_command_rejects_unsupported_agent` | S6a ✓ | - |
| `test_build_agent_command_uses_codex_exec_with_stdin` | `crates/opsgate-runner/src/commands.rs::tests::build_agent_command_uses_codex_exec_with_stdin` | S6a ✓ | - |
| `test_build_agent_command_uses_claude_print_with_bypass_permissions` | `crates/opsgate-runner/src/commands.rs::tests::build_agent_command_uses_claude_print_with_bypass_permissions` | S6a ✓ | - |
| `test_build_attach_command_includes_tmux_tmpdir` | `crates/opsgate-runner/src/commands.rs::tests::build_attach_command_includes_tmux_tmpdir` | S6a ✓ | - |
| `test_ticket_executor_rejects_unsupported_agent` | `crates/opsgate-runner/tests/executor.rs::ticket_executor_rejects_unsupported_agent` | S6a ✓ | R |
| `test_resume_adopts_existing_exit_code_without_relaunch` | `crates/opsgate-runner/tests/executor.rs::resume_adopts_existing_exit_code_without_relaunch` | S6a ✓ | R |
| `test_resume_fails_interrupted_step_without_relaunch` | `crates/opsgate-runner/tests/executor.rs::resume_fails_interrupted_step_without_relaunch` | S6a ✓ | R |
| `test_resume_reattaches_live_session_without_relaunch` | `crates/opsgate-runner/tests/executor.rs::resume_reattaches_live_session_without_relaunch` | S6a ✓ | R |
| `test_resumed_summary_appears_once_in_next_step_context` | `crates/opsgate-runner/tests/executor.rs::resumed_summary_appears_once_in_next_step_context` | S6a ✓ | R |
| `test_runner_shutdown_marks_running_step_interrupted` | `crates/opsgate-runner/tests/executor.rs::runner_shutdown_marks_running_step_interrupted` | S6a ✓ | R |
| `test_resume_fails_closed_on_unreadable_metadata` | `crates/opsgate-runner/tests/executor.rs::resume_fails_closed_on_unreadable_metadata` | S6a ✓ | R |
| `test_resume_adopts_exit_code_written_during_session_probe` | `crates/opsgate-runner/tests/executor.rs::resume_adopts_exit_code_written_during_session_probe` | S6a ✓ | R |
| `test_post_status_ignores_conflict_when_ticket_moved_on` | `crates/opsgate-runner/tests/executor.rs::post_status_ignores_conflict_when_ticket_moved_on` | S6a ✓ | R |
| `test_post_status_raises_other_conflicts` | `crates/opsgate-runner/tests/executor.rs::post_status_raises_other_conflicts` | S6a ✓ | R |
| `test_worker_cleans_session_before_terminal_failure` | `crates/opsgate-runner/tests/supervisor.rs::worker_cleans_session_before_terminal_failure` | S6b ✓ | R |
| `test_status_outage_retries_and_retains_execution` | `crates/opsgate-runner/tests/supervisor.rs::status_outage_retries_and_retains_execution` | S6b ✓ | R |
| `test_api_normalizes_transport_and_response_errors` | `crates/opsgate-runner/tests/api_client.rs::api_normalizes_transport_and_response_errors` | S6a ✓ | R |
| `test_recovery_transport_outage_isolated_and_state_retained` | `crates/opsgate-runner/tests/supervisor.rs::recovery_transport_outage_isolated_and_state_retained` | S6b ✓ | R |
| `test_running_heartbeat_outage_never_fails_live_session` | `crates/opsgate-runner/tests/supervisor.rs::running_heartbeat_outage_never_fails_live_session` | S6b ✓ | R |
| `test_permanent_api_error_stops_session_before_failure` | `crates/opsgate-runner/tests/supervisor.rs::permanent_api_error_stops_session_before_failure` | S6b ✓ | R |
| `test_cleanup_accepts_absent_tmux_server` | `crates/opsgate-runner/tests/supervisor.rs::cleanup_accepts_absent_tmux_server` + `crates/opsgate-runner/tests/tmux_integration.rs::supervisor_discovers_and_cleans_real_sessions` | S6b ✓ | R |
| `test_cleanup_rejects_unverifiable_tmux` | `crates/opsgate-runner/tests/supervisor.rs::cleanup_rejects_unverifiable_tmux` | S6b ✓ | R |
| `test_cleanup_verifies_sessions_are_gone` | `crates/opsgate-runner/tests/supervisor.rs::cleanup_verifies_sessions_are_gone` + `crates/opsgate-runner/tests/tmux_integration.rs::supervisor_discovers_and_cleans_real_sessions` | S6b ✓ | R |

## Rust-only tests

Tests without a Python counterpart, by the slice that landed them. Paths are
relative to `rust/` (Rust) or the repository root (pytest).

| Test | Covers | Slice |
| --- | --- | --- |
| `crates/opsgate/src/cli.rs::tests` | command-line parsing: default `serve`, `serve` overrides, `runner --once`, `check-config api\|runner`, `check-db --db`, usage errors exit 2, `--version` text (4.1, D-15) | S1 |
| `crates/opsgate/tests/binary.rs` | the binary: `--version`/`-V` print `opsgate <version> (<commit>)` with the checked-out commit, every command is a stub exiting 2 (`runner` no longer since S6b), usage errors exit 2, `--help` | S1 |
| `crates/opsgate/tests/binary.rs` (runner cases) | `opsgate runner [--once]` as a process: configuration errors (one stderr line naming the setting, never its value, exit 1), `--once` with the disable file (no claim, `runner-state/` created, startup line without secrets), the P1 log line of a failed claim (4.15), SIGTERM and SIGINT during the poll-interval sleep end the runner at once with exit 0 (4.1, D-16) | S6b |
| `crates/opsgate/tests/build_script.rs` | `build.rs`: full-commit validation, watched git paths (packed refs, nested branches, linked worktrees, detached HEAD, no git) | S1 |
| `parity/api/` (pytest, `just rs-parity-api`) | black-box API parity harness: 520+ scenarios against a real `serve` process per scenario (Python green; Rust switched on per landed slice through `harness.RUST_SLICES_LANDED`), records and `compare.py` diff, cross-implementation databases, races over HTTP, `--target` mode for the shadow (7.3) | S7a |
| `tests/test_rust_fixtures.py` | fixture drift: committed fixtures equal a fresh render byte for byte, every fixture has a generator, a hand-edited or missing fixture is detected, `generate.py --check` exits 1 on drift, `schema.sql` runs and yields the Python schema's objects (7.2, 4.10) | S1 |
| `crates/opsgate-core/tests/settings_fixture.rs` | `settings.json`: 490 environment sets (every variable and rule of 4.2, check order, env-file override, D-8/D-10 cases) and 21 env-file parsing cases; coverage of every 4.2 variable; the merged environment children get (4.13.8) | S2b |
| `crates/opsgate-core/tests/log_preview_fixture.rs` | `log_preview.json`: preview and step log for 31 contents (window and line cuts, CR/LF forms, invalid UTF-8 replacement, 2 MiB boundary) (4.12) | S2b |
| `crates/opsgate-core/tests/proxy_fix_fixture.rs` | `proxy_fix.json`: 26 header sets through waitress's proxy-header middleware and Werkzeug `ProxyFix`, with and without `OPSGATE_TRUST_PROXY_HEADERS`: the socket view is kept; `Host` joining and latin-1 (4.4) | S2b |
| `crates/opsgate-core/tests/containment.rs` | step-log containment (4.12): symlink escapes (file, directory, dangling, relative), missing inside → `log_not_found`, missing outside → `invalid_log_path`, containment before existence, `..` escapes, symlink loops, CPython 3.14 `realpath` corner cases | S2b |
| `crates/opsgate-core/src/{pytext,settings,log_preview}.rs` unit tests | Python whitespace and line-boundary sets, `int()` grammar and the 4300-digit limit, non-UTF-8 values, redacted `Debug`, CIDR prefixes, directories and missing files | S2b |
| `crates/opsgate-core/tests/checksum_fixture.rs` | `checksum.json`: canonical text and payload checksum byte-exact for 552 inputs (production-shaped and adversarial, incl. objects keyed by serde_json's internal number key and an overlong integer hidden by a duplicate key), D-2 and undecodable inputs rejected; `storage_json.json`: stored-column text equal to Python's (4.8) | S2a |
| `crates/opsgate-core/tests/float_repr_fixture.rs` | `float_repr.json`: `repr(float)` of 10 471 doubles (subnormals, powers of ten and neighbours, exponent boundaries, random bits) and the reading of number tokens incl. overflow (4.8) | S2a |
| `crates/opsgate-core/tests/datetime_fixture.rs` | `datetime.json` (CPython 3.14): every accepted input normalises to Python's instant, every rejected input is rejected by Python or marked D-7; `isoformat_z` (4.9) | S2a |
| `crates/opsgate-core/tests/pystr_fixture.rs` | `pystr.json`: `str()` of JSON scalars (D-2/D-3 rejected), `strip`, `lower`, Python's whitespace set over all code points, the non-ASCII characters whose lowercase is ASCII (4.6) | S2a |
| `crates/opsgate-core/tests/formatter_properties.rs` | property test: canonical and stored texts are ASCII, parse back to the same value and are fixed points (7.1) | S2a |
| `crates/opsgate-core/src/{json,pytext,time}.rs::tests` (S2a parts) | unit tests: escapes, separators, number classification, 4300-digit limit, BOM and UTF-8 handling of bodies, depth limit at 64 (and serde_json's 128), float `repr` examples, ISO parsing corners | S2a |
| `crates/opsgate-core/tests/validation_fixture.rs` | `validation.json`: 469 request bodies → the same canonical checksum text and `payload_checksum`, or the same error code, status and (where both stop at the same check) message as `_normalize_new_ticket`; every check of 4.7.1 steps 1–10 and their order (hand cases plus 240 random multi-field mutations), sources and floors, configured default durations; D-2/D-3 cases with the decided Rust result | S2c |
| `crates/opsgate-core/tests/validation.rs::{normalised_ticket_and_checksum_payload,text_field_divergences}` | the normalised fields and the checksum payload; D-2/D-3 of the text fields, `source` and `expires_at` containers answered as Python does | S2c |
| `crates/opsgate-core/src/validate.rs::tests` | Python truthiness of stored policies (approval, 4.7.2), floor lookup by source (manual tickets), the merge rules | S2c |
| `tests/test_rust_fixtures.py::test_python_gated_fixtures_follow_the_interpreter` | fixtures gated to another CPython version (`PYTHON_GATED`) are neither written nor checked, and are checked on their own version (7.2) | S2a |
| `crates/opsgate-store/tests/schema_contract.rs` | schema contract (4.10): a Rust-initialised database renders to `fixtures/schema.sql` byte for byte (and whitespace-normalised); Rust's start on a Python database changes nothing but the approver row; `init_db` idempotent; a pre-archive database gains the two columns; parent directory created; WAL, foreign keys, 5 s busy timeout | S3a |
| `crates/opsgate-store/tests/store_fixture.rs` | `store.json`: 7 scenarios replayed against the store, every step result (ticket, error code/status/message, unhandled error) and the final four tables equal to Python's: creation with lazy expiry (pending and approved, offsets, blank and unparsable stored expiry, archived and foreign-source tickets untouched), dedupe incl. stripped `task_ref`, manual tickets and the operator floor, validation failures writing nothing, get/list/serialisation of rows written by older code (non-integer durations, empty `archived_at`, compact JSON text, whole-second ordering), health, session generation sync/revoke/restart (4.5.2, 4.6, 4.7.1) | S3a |
| `crates/opsgate-store/tests/create.rs` (other tests) | ticket shape and `ticket_created` audit row, manual tickets, an unparsable stored expiry fails without writing, get/list, unreadable stored JSON (incl. D-2 `NaN`) is an error, session generation and fingerprint | S3a |
| `crates/opsgate-store/tests/check_db.rs` | `check-db` (3.1, D-15): counts, the database file never written (also with uncheckpointed WAL content, which is read), the Python schema fixture passes, missing/extra/changed tables (columns, collations, constraints) and indexes, unreadable rows (JSON, D-2 overflow, BLOBs, `expires_at`, durations, audit metadata, session and heartbeat rows) reported without their values, a capped problem list, write-protected file, missing or foreign file | S3a |
| `crates/opsgate/tests/binary.rs::check_db_reports_and_exits_0_or_1` | `opsgate check-db --db`: report on stdout, exit 0/1, an unreadable file is one stderr line and exit 1, never creates the file | S3a |
| `tests/test_rust_fixtures.py::test_rust_store_ddl_is_the_python_ddl` | the DDL constants of `opsgate-store/src/schema.rs` are the statements of `init_db`, in order (4.10) | S3a |
| `rust/parity/runner/test_runner_execution.py` | runner black box over a fake API (7.4): one/three steps, names and slugs, context and previous summary, agent command lines, env-file keys in the agents' environment (4.13.8), file modes, request shapes, exit-code failure, unsupported agent, invalid plan, timeout, cancel/terminal state during a step, session killed externally, heartbeat cadence, `max_parallel_jobs`, state files | S7b |
| `rust/parity/runner/test_runner_api_faults.py` | status retry (503, dropped connection), status and heartbeat outages (state kept, live session re-attached), permanent 4xx, 409 conflicts, claim errors and their P1 log lines (4.13.1, 4.15) | S7b |
| `rust/parity/runner/test_runner_supervisor.py` | disable file, `--once`, recovery housekeeping (state files, tmux discovery, terminal/not-running/unknown tickets, no tmux server, no tmux binary, GET outage) | S7b |
| `rust/parity/runner/test_runner_restart.py` | SIGTERM (interrupted), SIGKILL + restart (adopt exit code, re-attach, interrupted, skip finished steps) for every Python/Rust runner pair (cross-implementation recovery), unreadable metadata | S7b |
| `rust/parity/runner/test_runner_mixed_stacks.py` | real API × real runner, Python/Rust × Python/Rust, one two-step ticket end to end incl. the step log pages | S7b |
| `tests/test_runner_parity_compare.py` | `rust/parity/runner/compare.py`: equal records pass, differences reported with their path, types compared, failed stacks and missing baselines fail, `--require-rust` | S7b |
| `crates/opsgate-runner/tests/executor.rs` (Rust-only cases) | executor against a fake API and tmux on paused time: status sequence, artifact names, keys and modes (`context.json` in both roots, `prompt.md`, `previous_step_summary.md`, `run_step.sh` 0750, JSON artifacts 0600), invalid plan, non-running tickets, terminal ticket before a step, cancel and other terminal states during a step, session lost without exit code, heartbeat cadence, post-status retries and the stop-aware retry wait, shutdown after the exit code appeared, error kinds (4.13.4, 4.13.5) | S6a |
| `crates/opsgate-runner/tests/api_client.rs` (Rust-only cases) | HTTP client against an in-process axum server: bearer header, JSON bodies and paths, claim results, empty bodies, the three passed-on error codes and `http_error` otherwise, no redirects, redacted `Debug` (4.13.1) | S6a |
| `crates/opsgate-runner/tests/tmux_integration.rs` | real `tmux` on a private socket label and `TMUX_TMPDIR` with fake agents in an isolated environment: a two-step ticket (agent command lines, prompt on stdin, env-file variables reach the step, `session.log`, `exit_code`), `has-session`/`kill-session`, failing `new-session`, missing `tmux` binary (4.13.3, 4.13.8); S6b: the supervisor's discovery and verified cleanup on a real server and without one, and without a `tmux` binary (4.13.6) | S6a, S6b |
| `crates/opsgate-runner/src/{commands,artifacts,executor,values}.rs::tests` | slugs and names, shell quoting round trips, the step script text, artifact JSON text, `_load_summary` rules, SHA-256, Python path joining, session-entry upsert, exit-code parsing, Python `str()`/truthiness/`int()` of ticket values | S6a |
| `crates/opsgate-runner/tests/supervisor.rs` (Rust-only cases) | supervisor against a fake API with several tickets and a scripted tmux on paused time (4.13.6): `--once` (claims, waits for the workers, removes their state files; disable file; empty and failed claims), a claimed ticket without id, claims up to `max_parallel_jobs` with state files and the shutdown that interrupts the steps and removes the state files, recovery at the worker limit and with live workers, the first pass over the artifact directories (symlinks followed, once per process), the `_run_worker` `finally` (terminal ticket after an outage, cleanup verified), a failing state-file write ending the supervisor | S6b |
| `crates/opsgate-runner/src/supervisor.rs::tests` | the ticket-id and tmux-session patterns as Python's `re` (`$` before a final newline, Unicode `\d`), `tmux ls` line splitting, state-file reading (hidden files, invalid files deleted, non-UTF-8 and directories are errors, a missing directory has none) | S6b |
