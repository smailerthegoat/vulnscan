# Scorecard: realvuln-clean

Generated 2026-09-29T13:40:49Z · strict scoring · 2000 bootstrap resamples (seed 1)
Ground truth: RealVuln 3.1.0 @ `7a710251f55c` (97 repositories, 3082 labeled vulnerabilities, 159 false-positive traps)

## Headline

Micro-averaged over repositories. Brackets: 95% bootstrap confidence interval. F3 weights recall 9× over precision (RealVuln's primary metric); wF3 weights each vulnerability by its CVSS score.

| View | Repos | TP | FP | FN | Precision | Recall | F1 | F3 | wF3 | FP rate on traps |
|---|---|---|---|---|---|---|---|---|---|---|
| Plain Semgrep | 97/97 | 354 | 1763 | 2728 | 16.7 [14.7–19.4] | 11.5 [10.3–12.8] | 13.6 | **11.9** [10.7–13.0] | 13.4 | 91.7 |
| vulnscan scanner leads (no LLM) | 97/97 | 437 | 2549 | 2645 | 14.6 [12.6–17.2] | 14.2 [12.8–15.5] | 14.4 | **14.2** [12.9–15.4] | 15.8 | 94.1 |

## Head to head (paired by repository)

Per-repo F3 difference on repositories both views cover; the sign test asks whether wins and losses could be a coin flip.

| Comparison | Repos | Mean ΔF3 | Wins / ties / losses | Sign test p |
|---|---|---|---|---|
| vulnscan scanner leads (no LLM) vs Plain Semgrep | 97 | +2.1 [1.3–3.0] | 59 / 3 / 35 | 0.0172 |

## Recall by vulnerability class

| Class | Plain Semgrep | vulnscan scanner leads (no LLM) |
|---|---|---|
| admin_configured_webhook_ssrf | 0/1 (0%) | 0/1 (0%) |
| admin_export_unbounded_memory_buffer | 0/1 (0%) | 0/1 (0%) |
| api_key_accepted_in_query_string | 0/1 (0%) | 0/1 (0%) |
| api_key_in_query_string | 0/1 (0%) | 0/1 (0%) |
| api_token_plaintext_session_storage | 0/1 (0%) | 0/1 (0%) |
| appointment_cancel_bola | 0/1 (0%) | 0/1 (0%) |
| appointment_export_csv_formula_injection | 0/2 (0%) | 1/2 (50%) |
| arbitrary_file_write | 32/63 (51%) | 36/63 (57%) |
| attachment_upload_mime_spoofing | 0/1 (0%) | 0/1 (0%) |
| attachment_upload_without_content_validation | 0/1 (0%) | 0/1 (0%) |
| auth_endpoint_brute_force_exposure | 0/33 (0%) | 0/33 (0%) |
| auth_session_cookie_secure_flag_disabled | 3/3 (100%) | 0/3 (0%) |
| auth_session_cookie_secure_flag_missing | 3/3 (100%) | 0/3 (0%) |
| auth_tokens_disclosed_by_console_email | 0/1 (0%) | 0/1 (0%) |
| authentication_proof_not_verified | 0/9 (0%) | 0/9 (0%) |
| borrower_can_replace_reviewed_or_final_documents | 0/1 (0%) | 0/1 (0%) |
| borrower_registration_missing_rate_limit | 0/1 (0%) | 0/1 (0%) |
| broken_access_control | 0/29 (0%) | 0/29 (0%) |
| broken_authentication | 0/1 (0%) | 0/1 (0%) |
| broken_object_level_authorization | 0/114 (0%) | 0/114 (0%) |
| business_logic_validation_gap | 0/34 (0%) | 0/34 (0%) |
| business_value_rule_bypass | 0/2 (0%) | 0/2 (0%) |
| care_team_clinician_can_cancel_other_provider_appointment | 0/1 (0%) | 0/1 (0%) |
| cbc_padding_oracle | 0/43 (0%) | 0/43 (0%) |
| cleartext_credential_transmission | 0/48 (0%) | 0/48 (0%) |
| cleartext_webhook_transport | 0/1 (0%) | 0/1 (0%) |
| client_asserted_authorization_bypass | 0/43 (0%) | 0/43 (0%) |
| client_controlled_access_control_bypass | 0/4 (0%) | 0/4 (0%) |
| client_edit_cross_client_authorization_bypass | 0/1 (0%) | 0/1 (0%) |
| client_modifiable_session_state | 0/2 (0%) | 0/2 (0%) |
| client_shared_documents_cross_client_exposure | 0/1 (0%) | 0/1 (0%) |
| clinician_schedule_board_overexposure | 0/1 (0%) | 0/1 (0%) |
| clinician_self_assigns_patient_by_creating_appointment | 0/1 (0%) | 0/1 (0%) |
| code_execution | 20/20 (100%) | 20/20 (100%) |
| code_injection | 12/38 (32%) | 13/38 (34%) |
| command_injection | 13/31 (42%) | 31/31 (100%) |
| cookie_cleartext_transport_exposure | 6/37 (16%) | 1/37 (3%) |
| cookie_script_access_exposure | 6/37 (16%) | 0/37 (0%) |
| cors_misconfiguration | 0/1 (0%) | 0/1 (0%) |
| course_resource_upload_without_content_validation | 0/2 (0%) | 0/2 (0%) |
| crm_document_upload_without_content_validation | 0/1 (0%) | 0/1 (0%) |
| crm_export_csv_formula_injection | 0/2 (0%) | 2/2 (100%) |
| cross_site_scripting | 11/52 (21%) | 30/52 (58%) |
| cross_tenant_data_exposure | 0/1 (0%) | 0/1 (0%) |
| csrf | 0/4 (0%) | 0/4 (0%) |
| csv_formula_injection | 0/10 (0%) | 3/10 (30%) |
| csv_formula_injection_employee_exports | 0/2 (0%) | 0/2 (0%) |
| csv_formula_injection_exports | 0/1 (0%) | 0/1 (0%) |
| database_connection_tls_not_required | 0/1 (0%) | 0/1 (0%) |
| debug_media_file_exposure | 0/4 (0%) | 0/4 (0%) |
| debug_media_route_bypasses_document_authorization | 0/3 (0%) | 0/3 (0%) |
| debug_media_route_bypasses_hr_document_authorization | 0/2 (0%) | 0/2 (0%) |
| debug_media_route_bypasses_patient_document_authorization | 0/2 (0%) | 0/2 (0%) |
| debug_mode_default_enabled | 0/1 (0%) | 0/1 (0%) |
| debug_mode_enabled | 0/2 (0%) | 0/2 (0%) |
| debug_mode_enabled_by_default | 0/11 (0%) | 0/11 (0%) |
| debug_mode_exposure | 0/48 (0%) | 0/48 (0%) |
| denial_of_service | 0/15 (0%) | 0/15 (0%) |
| denial_of_service_unbounded_resource | 0/4 (0%) | 0/4 (0%) |
| disabled_admin_api_key_remains_valid | 0/1 (0%) | 0/1 (0%) |
| disabled_profile_not_enforced_across_routes | 0/1 (0%) | 0/1 (0%) |
| dispatch_report_csv_formula_injection | 0/1 (0%) | 0/1 (0%) |
| dispatch_vault_path_traversal_file_write | 1/1 (100%) | 0/1 (0%) |
| dispatcher_bulk_user_directory_exposure | 0/1 (0%) | 0/1 (0%) |
| dispatcher_cross_region_location_create | 0/1 (0%) | 0/1 (0%) |
| dispatcher_cross_region_worker_directory_exposure | 0/1 (0%) | 0/1 (0%) |
| dispatcher_unscoped_job_export | 0/1 (0%) | 0/1 (0%) |
| document_request_without_application_scope_check | 0/1 (0%) | 0/1 (0%) |
| document_upload_mime_spoofing | 0/1 (0%) | 0/1 (0%) |
| document_upload_trusts_client_content_type | 0/2 (0%) | 0/2 (0%) |
| document_upload_unbounded_disk_consumption | 0/1 (0%) | 0/1 (0%) |
| document_upload_without_content_validation | 0/2 (0%) | 0/2 (0%) |
| employee_detail_lists_documents_without_document_authorization | 0/1 (0%) | 0/1 (0%) |
| employee_import_fixed_default_password | 1/1 (100%) | 1/1 (100%) |
| employee_import_unbounded_csv_rows | 0/1 (0%) | 0/1 (0%) |
| employee_profile_mass_assignment_user_binding | 0/1 (0%) | 0/1 (0%) |
| employee_self_edit_hr_controlled_fields | 0/1 (0%) | 0/1 (0%) |
| error_detail_disclosure | 0/18 (0%) | 0/18 (0%) |
| escalation_update_bola | 0/1 (0%) | 0/1 (0%) |
| excessive_sensitive_borrower_profile_exposure | 0/2 (0%) | 0/2 (0%) |
| former_tenant_can_create_ticket_for_old_unit | 0/1 (0%) | 0/1 (0%) |
| front_desk_document_status_bypass | 0/1 (0%) | 0/1 (0%) |
| frontend_catchall_path_traversal | 0/1 (0%) | 0/1 (0%) |
| grade_export_csv_formula_injection | 0/2 (0%) | 1/2 (50%) |
| hardcoded_credential | 6/121 (5%) | 22/121 (18%) |
| hardcoded_cryptographic_key | 0/110 (0%) | 1/110 (1%) |
| hardcoded_cryptographic_secret | 0/3 (0%) | 0/3 (0%) |
| hardcoded_default_application_secret_key | 0/1 (0%) | 0/1 (0%) |
| hardcoded_default_django_secret_key | 0/16 (0%) | 0/16 (0%) |
| hardcoded_default_hmac_secret | 0/1 (0%) | 0/1 (0%) |
| hardcoded_default_jwt_hmac_secret | 0/7 (0%) | 0/7 (0%) |
| hardcoded_default_password | 1/1 (100%) | 1/1 (100%) |
| hardcoded_default_session_signing_secret | 0/4 (0%) | 0/4 (0%) |
| hardcoded_secret_literal | 0/5 (0%) | 0/5 (0%) |
| hr_document_upload_mime_spoofing | 0/1 (0%) | 0/1 (0%) |
| hr_document_upload_without_content_validation | 0/1 (0%) | 0/1 (0%) |
| hr_exports_csv_formula_injection | 0/1 (0%) | 1/1 (100%) |
| idor | 0/11 (0%) | 0/11 (0%) |
| incorrect_authorization | 0/17 (0%) | 0/17 (0%) |
| insecure_cookie_flags | 19/31 (61%) | 12/31 (39%) |
| insecure_cookie_flags_default_debug | 0/1 (0%) | 0/1 (0%) |
| insecure_deserialization | 21/21 (100%) | 21/21 (100%) |
| insecure_password_recovery | 0/3 (0%) | 0/3 (0%) |
| insecure_session_cookie_default | 0/1 (0%) | 0/1 (0%) |
| insecure_session_cookie_default_environment | 0/1 (0%) | 0/1 (0%) |
| insecure_session_cookie_flags | 1/1 (100%) | 0/1 (0%) |
| insufficient_session_invalidation | 0/54 (0%) | 0/54 (0%) |
| integration_application_status_idor | 0/1 (0%) | 0/1 (0%) |
| integration_status_update_idor | 0/1 (0%) | 0/1 (0%) |
| integration_ticket_status_idor | 0/1 (0%) | 0/1 (0%) |
| internal_document_metadata_search_leak | 0/1 (0%) | 0/1 (0%) |
| internal_error_disclosure_via_http | 0/33 (0%) | 0/33 (0%) |
| internal_hr_comments_visible_to_non_hr_roles | 0/1 (0%) | 0/1 (0%) |
| internal_note_application_bola | 0/1 (0%) | 0/1 (0%) |
| internal_note_write_without_application_scope_check | 0/1 (0%) | 0/1 (0%) |
| invalid_workflow_transition | 0/19 (0%) | 0/19 (0%) |
| invite_flow_reassigns_existing_users_across_tenants | 0/1 (0%) | 0/1 (0%) |
| job_audit_log_bola | 0/1 (0%) | 0/1 (0%) |
| jwt_signature_verification_bypass | 0/39 (0%) | 0/39 (0%) |
| ldap_injection | 0/11 (0%) | 0/11 (0%) |
| lead_import_unbounded_memory_and_rows | 0/1 (0%) | 0/1 (0%) |
| legal_document_upload_without_content_validation | 0/1 (0%) | 0/1 (0%) |
| legal_export_csv_formula_injection | 0/1 (0%) | 0/1 (0%) |
| llm_prompt_injection | 0/6 (0%) | 0/6 (0%) |
| loan_decision_allows_unreviewed_uploaded_documents | 0/1 (0%) | 0/1 (0%) |
| loan_export_csv_formula_injection | 0/2 (0%) | 0/2 (0%) |
| log_injection | 0/39 (0%) | 0/39 (0%) |
| login_missing_rate_limit | 0/14 (0%) | 0/14 (0%) |
| login_missing_rate_limit_or_lockout | 0/3 (0%) | 0/3 (0%) |
| maintenance_export_csv_formula_injection | 0/1 (0%) | 0/1 (0%) |
| maintenance_user_directory_scope_bypass | 0/1 (0%) | 0/1 (0%) |
| manager_can_assign_ticket_to_unscoped_worker | 0/1 (0%) | 0/1 (0%) |
| manager_can_create_lease_for_arbitrary_tenant | 0/1 (0%) | 0/1 (0%) |
| manager_can_reject_unrelated_compensation_request | 0/1 (0%) | 0/1 (0%) |
| manager_user_directory_unscoped | 0/1 (0%) | 0/1 (0%) |
| marketplace_export_csv_formula_injection | 0/1 (0%) | 0/1 (0%) |
| marketplace_upload_trusts_client_content_type | 0/1 (0%) | 0/1 (0%) |
| mass_assignment | 13/127 (10%) | 13/127 (10%) |
| matter_detail_bola | 0/1 (0%) | 0/1 (0%) |
| matter_edit_assignment_mass_assignment | 0/1 (0%) | 0/1 (0%) |
| message_detail_bola_for_staff_roles | 0/1 (0%) | 0/1 (0%) |
| missing_authentication | 0/55 (0%) | 0/55 (0%) |
| missing_authorization | 0/20 (0%) | 0/20 (0%) |
| missing_rate_limit_login | 0/1 (0%) | 0/1 (0%) |
| missing_rate_limit_open_registration | 0/1 (0%) | 0/1 (0%) |
| missing_rate_limit_password_reset | 0/2 (0%) | 0/2 (0%) |
| missing_rate_limiting | 0/17 (0%) | 0/17 (0%) |
| missing_rate_limiting_on_auth | 0/43 (0%) | 0/43 (0%) |
| missing_rate_limiting_on_password_reset_flow | 0/1 (0%) | 0/1 (0%) |
| missing_security_event_logging | 0/48 (0%) | 0/48 (0%) |
| missing_server_side_business_validation | 0/9 (0%) | 0/9 (0%) |
| missing_session_expiration | 0/22 (0%) | 0/22 (0%) |
| non_expiring_invitation_token | 0/1 (0%) | 0/1 (0%) |
| nosql_injection | 3/35 (9%) | 3/35 (9%) |
| notification_next_open_redirect | 0/1 (0%) | 0/1 (0%) |
| object_authorization_bypass | 0/1 (0%) | 0/1 (0%) |
| observable_response_discrepancy | 0/24 (0%) | 0/24 (0%) |
| onboarding_evidence_unrestricted_upload | 0/1 (0%) | 0/1 (0%) |
| open_course_preview_leaks_unpublished_assignments | 0/1 (0%) | 0/1 (0%) |
| open_redirect | 21/75 (28%) | 28/75 (37%) |
| open_registration_missing_rate_limit | 0/2 (0%) | 0/2 (0%) |
| ops_vault_ref_path_traversal_write | 1/2 (50%) | 0/2 (0%) |
| organization_name_self_registration_tenant_takeover | 0/1 (0%) | 0/1 (0%) |
| os_command_injection | 64/80 (80%) | 64/80 (80%) |
| overbroad_support_role_field_authorization | 0/1 (0%) | 0/1 (0%) |
| password_change_does_not_revoke_existing_sessions | 0/1 (0%) | 0/1 (0%) |
| password_reset_complete_missing_rate_limit | 0/1 (0%) | 0/1 (0%) |
| password_reset_confirm_missing_rate_limit | 0/3 (0%) | 0/3 (0%) |
| password_reset_missing_rate_limit | 0/6 (0%) | 0/6 (0%) |
| password_reset_old_tokens_remain_valid | 0/2 (0%) | 0/2 (0%) |
| password_reset_request_missing_rate_limit | 0/8 (0%) | 0/8 (0%) |
| password_reset_token_and_account_existence_disclosed | 0/1 (0%) | 0/1 (0%) |
| password_reset_token_disclosed_in_default_dev_response | 0/1 (0%) | 0/1 (0%) |
| password_reset_token_in_http_response | 0/3 (0%) | 0/3 (0%) |
| password_reset_token_logged | 0/2 (0%) | 0/2 (0%) |
| password_reset_token_not_verified | 0/1 (0%) | 0/1 (0%) |
| password_reset_token_written_to_log_file | 0/1 (0%) | 0/1 (0%) |
| password_reset_token_written_to_runtime_log | 0/1 (0%) | 0/1 (0%) |
| password_reset_tokens_disclosed_by_console_email | 0/2 (0%) | 0/2 (0%) |
| password_reset_tokens_emitted_to_console_logs | 0/3 (0%) | 0/3 (0%) |
| path_traversal | 32/65 (49%) | 38/65 (58%) |
| path_traversal_arbitrary_file_write | 0/2 (0%) | 0/2 (0%) |
| path_traversal_file_write | 0/1 (0%) | 0/1 (0%) |
| patient_document_upload_mime_spoofing | 0/1 (0%) | 0/1 (0%) |
| patient_document_upload_without_content_validation | 1/1 (100%) | 1/1 (100%) |
| patient_document_visibility_bypass | 0/1 (0%) | 0/1 (0%) |
| patient_import_unbounded_memory_and_rows | 0/1 (0%) | 0/1 (0%) |
| patient_profile_form_exposes_staff_controlled_fields | 0/1 (0%) | 0/1 (0%) |
| patient_registration_missing_rate_limit | 0/2 (0%) | 0/2 (0%) |
| patient_visible_staff_notes_and_tamperable_hidden_field | 0/1 (0%) | 0/1 (0%) |
| payout_detail_bola | 0/1 (0%) | 0/1 (0%) |
| payroll_can_view_unapproved_compensation_by_direct_id | 0/1 (0%) | 0/1 (0%) |
| payroll_role_can_administer_all_hr_requests | 0/1 (0%) | 0/1 (0%) |
| payroll_specialist_overbroad_exports | 0/1 (0%) | 0/1 (0%) |
| plaintext_api_key_storage | 0/2 (0%) | 0/2 (0%) |
| plaintext_api_key_storage_and_display | 0/1 (0%) | 0/1 (0%) |
| plaintext_clinic_api_key_storage_and_display | 0/1 (0%) | 0/1 (0%) |
| plaintext_clinic_phi_storage | 0/2 (0%) | 0/2 (0%) |
| plaintext_customer_document_storage | 0/1 (0%) | 0/1 (0%) |
| plaintext_hr_payroll_document_storage | 0/1 (0%) | 0/1 (0%) |
| plaintext_invitation_token_storage | 0/1 (0%) | 0/1 (0%) |
| plaintext_legal_document_storage | 0/1 (0%) | 0/1 (0%) |
| plaintext_lms_document_storage | 0/1 (0%) | 0/1 (0%) |
| plaintext_loan_document_storage | 0/1 (0%) | 0/1 (0%) |
| plaintext_payroll_bank_and_tax_identifiers | 0/1 (0%) | 0/1 (0%) |
| plaintext_property_document_storage | 0/1 (0%) | 0/1 (0%) |
| plaintext_reset_token_outbox | 0/1 (0%) | 0/1 (0%) |
| plaintext_reset_token_storage | 0/1 (0%) | 0/1 (0%) |
| plaintext_sensitive_data_at_rest | 0/6 (0%) | 0/6 (0%) |
| plaintext_sensitive_document_storage | 0/1 (0%) | 0/1 (0%) |
| plaintext_sensitive_hr_documents | 0/1 (0%) | 0/1 (0%) |
| plaintext_sensitive_storage | 0/24 (0%) | 0/24 (0%) |
| plaintext_sensitive_token_storage | 0/1 (0%) | 0/1 (0%) |
| plaintext_sensitive_uploaded_documents | 0/1 (0%) | 0/1 (0%) |
| plaintext_ticket_attachment_storage | 0/1 (0%) | 0/1 (0%) |
| plaintext_webhook_secret_at_rest | 0/2 (0%) | 0/2 (0%) |
| plaintext_webhook_secret_storage | 0/1 (0%) | 0/1 (0%) |
| plaintext_webhook_signing_secret_storage | 0/4 (0%) | 0/4 (0%) |
| policy_audience_not_enforced | 0/1 (0%) | 0/1 (0%) |
| predictable_security_token | 0/23 (0%) | 0/23 (0%) |
| prescription_create_persists_before_authorization | 0/1 (0%) | 0/1 (0%) |
| prescription_edit_missing_authorization | 0/1 (0%) | 0/1 (0%) |
| privileged_note_create_missing_matter_authorization | 0/1 (0%) | 0/1 (0%) |
| product_image_upload_mime_spoofing | 0/1 (0%) | 0/1 (0%) |
| proof_upload_without_content_validation | 0/1 (0%) | 0/1 (0%) |
| property_export_csv_formula_injection | 0/1 (0%) | 0/1 (0%) |
| property_manager_user_detail_bola | 0/1 (0%) | 0/1 (0%) |
| prototype_pollution | 0/15 (0%) | 0/15 (0%) |
| public_api_worker_can_cancel_assigned_job | 0/1 (0%) | 0/1 (0%) |
| public_registration_role_escalation | 0/3 (0%) | 0/3 (0%) |
| public_review_internal_metadata_exposure | 0/1 (0%) | 0/1 (0%) |
| public_upload_directory_bypasses_attachment_authorization | 0/1 (0%) | 0/1 (0%) |
| public_upload_directory_bypasses_document_authorization | 0/1 (0%) | 0/1 (0%) |
| public_upload_directory_bypasses_file_authorization | 0/1 (0%) | 0/1 (0%) |
| public_upload_directory_bypasses_proof_authorization | 0/1 (0%) | 0/1 (0%) |
| public_vendor_payout_metadata_exposure | 0/1 (0%) | 0/1 (0%) |
| reflected_xss | 6/24 (25%) | 6/24 (25%) |
| registration_bypasses_configured_password_validators | 0/1 (0%) | 0/1 (0%) |
| registration_existing_email_enumeration | 0/2 (0%) | 0/2 (0%) |
| registration_missing_rate_limit | 0/5 (0%) | 0/5 (0%) |
| regular_expression_query_injection | 0/4 (0%) | 0/4 (0%) |
| replayable_business_operation | 0/3 (0%) | 0/3 (0%) |
| role_authorization_bypass | 0/1 (0%) | 0/1 (0%) |
| route_assigned_to_worker_outside_region | 0/1 (0%) | 0/1 (0%) |
| security_misconfiguration | 29/127 (23%) | 29/127 (23%) |
| security_misconfiguration_misc | 0/1 (0%) | 0/1 (0%) |
| self_registration_missing_rate_limit | 0/3 (0%) | 0/3 (0%) |
| self_registration_role_escalation | 0/1 (0%) | 0/1 (0%) |
| sensitive_credential_material_written_to_log_file | 0/1 (0%) | 0/1 (0%) |
| sensitive_data_exposure | 1/30 (3%) | 0/30 (0%) |
| sensitive_data_in_logs | 0/40 (0%) | 0/40 (0%) |
| sensitive_information_exposure_via_http | 0/34 (0%) | 0/34 (0%) |
| sensitive_information_exposure_via_logs | 0/42 (0%) | 0/42 (0%) |
| sensitive_token_disclosure_via_console_email | 0/1 (0%) | 0/1 (0%) |
| server_side_template_injection | 2/8 (25%) | 2/8 (25%) |
| session_and_csrf_cookie_secure_flags_missing | 0/6 (0%) | 0/6 (0%) |
| session_cookie_secure_flag_disabled | 1/1 (100%) | 0/1 (0%) |
| session_cookie_secure_flag_disabled_by_default | 0/1 (0%) | 0/1 (0%) |
| session_fixation | 0/8 (0%) | 0/8 (0%) |
| session_token_exposure | 0/20 (0%) | 0/20 (0%) |
| session_tokens_without_expiry_or_server_revocation | 0/1 (0%) | 0/1 (0%) |
| shared_default_credential | 0/1 (0%) | 0/1 (0%) |
| spa_path_traversal_file_read | 0/1 (0%) | 0/1 (0%) |
| sql_injection | 3/41 (7%) | 13/41 (32%) |
| ssrf | 2/64 (3%) | 21/64 (33%) |
| ssti | 0/36 (0%) | 0/36 (0%) |
| staff_document_download_bola | 0/1 (0%) | 0/1 (0%) |
| stale_api_key_remains_authorized_after_account_disable | 0/1 (0%) | 0/1 (0%) |
| standalone_resource_download_idor | 0/1 (0%) | 0/1 (0%) |
| stored_xss | 1/2 (50%) | 1/2 (50%) |
| submission_upload_extension_only_validation | 0/1 (0%) | 0/1 (0%) |
| support_agent_assignment_grants_overbroad_org_access | 0/1 (0%) | 0/1 (0%) |
| support_agent_document_bola | 0/1 (0%) | 0/1 (0%) |
| support_role_can_read_all_orders | 0/1 (0%) | 0/1 (0%) |
| suspended_vendor_product_import_bypass | 0/1 (0%) | 0/1 (0%) |
| ta_grade_export_cohort_bola | 0/1 (0%) | 0/1 (0%) |
| tenant_maintenance_privileged_field_update | 0/1 (0%) | 0/1 (0%) |
| tenant_registration_email_enumeration | 0/1 (0%) | 0/1 (0%) |
| tenant_registration_missing_rate_limit | 0/1 (0%) | 0/1 (0%) |
| ticket_exports_csv_formula_injection | 0/2 (0%) | 0/2 (0%) |
| ticket_update_privilege_escalation | 0/1 (0%) | 0/1 (0%) |
| unauthenticated_application_status_endpoint | 0/1 (0%) | 0/1 (0%) |
| unbound_api_key_can_update_any_ticket_status | 0/1 (0%) | 0/1 (0%) |
| uncontrolled_resource_consumption | 0/40 (0%) | 0/40 (0%) |
| underwriter_application_update_bola | 0/1 (0%) | 0/1 (0%) |
| underwriter_can_view_other_assigned_applications | 0/1 (0%) | 0/1 (0%) |
| underwriter_self_assignment_without_object_scope_check | 0/1 (0%) | 0/1 (0%) |
| unrestricted_file_upload | 0/45 (0%) | 0/45 (0%) |
| unrestricted_file_upload_no_validation | 0/7 (0%) | 0/7 (0%) |
| unsafe_deserialization | 1/3 (33%) | 1/3 (33%) |
| unsafe_file_upload | 0/30 (0%) | 0/30 (0%) |
| unscoped_staff_ticket_export | 0/1 (0%) | 0/1 (0%) |
| unverified_password_change | 0/1 (0%) | 0/1 (0%) |
| user_controlled_resource_id_without_ownership_check | 0/4 (0%) | 0/4 (0%) |
| user_enumeration | 0/37 (0%) | 0/37 (0%) |
| user_enumeration_via_lockout_response | 0/1 (0%) | 0/1 (0%) |
| visit_summary_create_rebinds_patient_and_appointment | 0/1 (0%) | 0/1 (0%) |
| visit_summary_edit_mass_assignment_reassigns_patient | 0/1 (0%) | 0/1 (0%) |
| weak_cryptographic_construction | 0/1 (0%) | 0/1 (0%) |
| weak_hash | 0/17 (0%) | 17/17 (100%) |
| weak_invite_recovery_flow | 0/1 (0%) | 0/1 (0%) |
| weak_password_hashing | 0/35 (0%) | 0/35 (0%) |
| weak_prng | 0/32 (0%) | 0/32 (0%) |
| xpath_injection | 0/12 (0%) | 0/12 (0%) |
| xxe | 17/50 (34%) | 3/50 (6%) |

## Per repository (F3)

| Repo | Vulns | Traps | semgrep | vulnscan-leads | vulnscan-raw | vulnscan | Pipeline cost (USD eq.) | Note |
|---|---|---|---|---|---|---|---|---|
| realvuln-ivna | 19 | 0 | 5.0 | 13.9 | - | - | 1.59 |  |
| realvuln-juice-shop-goof | 51 | 0 | 15.9 | 23.6 | - | - | - |  |
| realvuln-nextjs-vulnerable-app | 1 | 0 | 0.0 | 0.0 | - | - | - |  |
| realvuln-oss-oopssec-store | 40 | 0 | 5.3 | 20.2 | - | - | - |  |
| realvuln-vuln-node-express-swagger | 49 | 0 | 16.6 | 28.0 | - | - | 3.26 |  |
| realvuln-vulnerable-react-fatih | 7 | 0 | 14.5 | 13.0 | - | - | - |  |
| realvuln-vulnerable-rest-api-owasp-2023 | 15 | 0 | 0.0 | 16.7 | - | - | - |  |
| vc-claude-code-seeded-v2-crm-saas-django | 28 | 4 | 11.1 | 13.9 | - | - | - |  |
| vc-claude-code-seeded-v2-education-lms-django | 32 | 4 | 13.0 | 16.1 | - | - | - |  |
| vc-claude-code-seeded-v2-fintech-lending-fastapi | 29 | 4 | 14.8 | 11.2 | - | - | - |  |
| vc-claude-code-seeded-v2-healthcare-clinic-django | 29 | 4 | 18.1 | 17.7 | - | - | - |  |
| vc-claude-code-seeded-v2-hr-payroll-django | 27 | 4 | 18.9 | 18.7 | - | - | - |  |
| vc-claude-code-seeded-v2-legal-case-django | 31 | 4 | 16.7 | 16.1 | - | - | - |  |
| vc-claude-code-seeded-v2-logistics-dispatch-fastapi | 33 | 4 | 13.1 | 6.6 | - | - | - |  |
| vc-claude-code-seeded-v2-marketplace-commerce-fastapi | 32 | 4 | 3.4 | 6.8 | - | - | - |  |
| vc-claude-code-seeded-v2-property-management-fastapi | 33 | 4 | 6.6 | 9.9 | - | - | - |  |
| vc-claude-code-seeded-v2-support-desk-fastapi | 34 | 4 | 6.5 | 9.6 | - | - | - |  |
| vc-claude-code-seeded-v3-crm-saas-nestjs-angular | 49 | 0 | 8.7 | 12.7 | - | - | - |  |
| vc-claude-code-seeded-v3-education-lms-nextjs | 38 | 0 | 8.4 | 11.0 | - | - | - |  |
| vc-claude-code-seeded-v3-fintech-lending-express | 40 | 0 | 17.4 | 20.6 | - | - | - |  |
| vc-claude-code-seeded-v3-healthcare-clinic-nextjs | 43 | 0 | 12.3 | 12.2 | - | - | - |  |
| vc-claude-code-seeded-v3-hr-payroll-remix | 37 | 0 | 2.9 | 5.8 | - | - | - |  |
| vc-claude-code-seeded-v3-legal-case-remix | 28 | 0 | 3.8 | 14.9 | - | - | - |  |
| vc-claude-code-seeded-v3-logistics-dispatch-fastify-vue | 51 | 0 | 12.4 | 22.0 | - | - | - |  |
| vc-claude-code-seeded-v3-marketplace-commerce-express | 40 | 0 | 16.6 | 21.8 | - | - | - |  |
| vc-claude-code-seeded-v3-property-management-fastify-vue | 32 | 0 | 15.9 | 18.3 | - | - | - |  |
| vc-claude-code-seeded-v3-support-desk-nestjs-angular | 41 | 0 | 7.6 | 12.2 | - | - | - |  |
| vc-codex-high-seeded-v2-crm-saas-django | 25 | 4 | 8.5 | 16.1 | - | - | - |  |
| vc-codex-high-seeded-v2-education-lms-django | 25 | 4 | 12.7 | 16.7 | - | - | - |  |
| vc-codex-high-seeded-v2-fintech-lending-fastapi | 29 | 4 | 14.8 | 14.9 | - | - | - |  |
| vc-codex-high-seeded-v2-healthcare-clinic-django | 26 | 4 | 16.2 | 16.0 | - | - | - |  |
| vc-codex-high-seeded-v2-hr-payroll-django | 25 | 4 | 16.9 | 20.6 | - | - | - |  |
| vc-codex-high-seeded-v2-legal-case-django | 25 | 4 | 21.0 | 20.8 | - | - | - |  |
| vc-codex-high-seeded-v2-logistics-dispatch-fastapi | 29 | 4 | 18.5 | 14.9 | - | - | - |  |
| vc-codex-high-seeded-v2-marketplace-commerce-fastapi | 25 | 4 | 8.8 | 8.8 | - | - | - |  |
| vc-codex-high-seeded-v2-property-management-fastapi | 26 | 4 | 8.4 | 8.3 | - | - | - |  |
| vc-codex-high-seeded-v2-support-desk-fastapi | 28 | 4 | 0.0 | 7.9 | - | - | - |  |
| vc-codex-high-seeded-v3-crm-saas-nestjs-angular | 37 | 0 | 18.1 | 18.6 | - | - | - |  |
| vc-codex-high-seeded-v3-education-lms-nextjs | 48 | 0 | 0.0 | 6.7 | - | - | - |  |
| vc-codex-high-seeded-v3-fintech-lending-express | 39 | 0 | 17.8 | 19.4 | - | - | - |  |
| vc-codex-high-seeded-v3-healthcare-clinic-nextjs | 42 | 0 | 12.2 | 15.0 | - | - | - |  |
| vc-codex-high-seeded-v3-hr-payroll-remix | 42 | 0 | 10.3 | 7.8 | - | - | - |  |
| vc-codex-high-seeded-v3-legal-case-remix | 47 | 0 | 2.3 | 4.6 | - | - | - |  |
| vc-codex-high-seeded-v3-logistics-dispatch-fastify-vue | 45 | 0 | 4.8 | 9.6 | - | - | - |  |
| vc-codex-high-seeded-v3-marketplace-commerce-express | 44 | 0 | 16.5 | 25.1 | - | - | - |  |
| vc-codex-high-seeded-v3-property-management-fastify-vue | 42 | 0 | 5.2 | 10.1 | - | - | - |  |
| vc-codex-high-seeded-v3-support-desk-nestjs-angular | 35 | 0 | 11.5 | 16.3 | - | - | - |  |
| vc-codex-seeded-v2-crm-saas-django | 34 | 4 | 15.8 | 21.5 | - | - | 0.00 |  |
| vc-codex-seeded-v2-education-lms-django | 35 | 4 | 9.3 | 15.3 | - | - | - |  |
| vc-codex-seeded-v2-fintech-lending-fastapi | 37 | 4 | 11.8 | 8.8 | - | - | 0.00 |  |
| vc-codex-seeded-v2-healthcare-clinic-django | 41 | 4 | 13.2 | 13.1 | - | - | - |  |
| vc-codex-seeded-v2-hr-payroll-django | 39 | 4 | 16.5 | 19.1 | - | - | - |  |
| vc-codex-seeded-v2-legal-case-django | 33 | 4 | 16.3 | 18.8 | - | - | - |  |
| vc-codex-seeded-v2-logistics-dispatch-fastapi | 30 | 4 | 14.5 | 7.2 | - | - | - |  |
| vc-codex-seeded-v2-marketplace-commerce-fastapi | 29 | 4 | 11.2 | 7.5 | - | - | - |  |
| vc-codex-seeded-v2-property-management-fastapi | 31 | 4 | 10.5 | 10.6 | - | - | - |  |
| vc-codex-seeded-v2-support-desk-fastapi | 30 | 3 | 3.7 | 7.4 | - | - | - |  |
| vc-deepseek-v4-flash-seeded-v3-crm-saas-nestjs-angular | 22 | 0 | 9.5 | 13.3 | - | - | - |  |
| vc-deepseek-v4-flash-seeded-v3-education-lms-nextjs | 28 | 0 | 11.0 | 10.9 | - | - | - |  |
| vc-deepseek-v4-flash-seeded-v3-fintech-lending-express | 22 | 0 | 11.7 | 13.7 | - | - | - |  |
| vc-deepseek-v4-flash-seeded-v3-healthcare-clinic-nextjs | 24 | 0 | 12.7 | 8.5 | - | - | - |  |
| vc-deepseek-v4-flash-seeded-v3-hr-payroll-remix | 18 | 0 | 11.6 | 11.2 | - | - | - |  |
| vc-deepseek-v4-flash-seeded-v3-legal-case-remix | 22 | 0 | 9.3 | 14.0 | - | - | - |  |
| vc-deepseek-v4-flash-seeded-v3-logistics-dispatch-fastify-vue | 28 | 0 | 3.8 | 7.6 | - | - | - |  |
| vc-deepseek-v4-flash-seeded-v3-marketplace-commerce-express | 21 | 0 | 17.0 | 20.3 | - | - | - |  |
| vc-deepseek-v4-flash-seeded-v3-property-management-fastify-vue | 25 | 0 | 0.0 | 0.0 | - | - | - |  |
| vc-deepseek-v4-flash-seeded-v3-support-desk-nestjs-angular | 24 | 0 | 4.3 | 7.9 | - | - | - |  |
| vc-deepseek-v4-pro-seeded-v3-crm-saas-nestjs-angular | 30 | 0 | 6.9 | 6.7 | - | - | - |  |
| vc-deepseek-v4-pro-seeded-v3-education-lms-nextjs | 27 | 0 | 7.5 | 10.3 | - | - | - |  |
| vc-deepseek-v4-pro-seeded-v3-fintech-lending-express | 27 | 0 | 10.9 | 11.2 | - | - | - |  |
| vc-deepseek-v4-pro-seeded-v3-healthcare-clinic-nextjs | 26 | 0 | 16.0 | 15.6 | - | - | - |  |
| vc-deepseek-v4-pro-seeded-v3-hr-payroll-remix | 26 | 0 | 4.1 | 3.8 | - | - | - |  |
| vc-deepseek-v4-pro-seeded-v3-legal-case-remix | 25 | 0 | 0.0 | 0.0 | - | - | - |  |
| vc-deepseek-v4-pro-seeded-v3-logistics-dispatch-fastify-vue | 30 | 0 | 10.2 | 9.9 | - | - | - |  |
| vc-deepseek-v4-pro-seeded-v3-marketplace-commerce-express | 26 | 0 | 18.0 | 17.5 | - | - | - |  |
| vc-deepseek-v4-pro-seeded-v3-property-management-fastify-vue | 19 | 0 | 14.3 | 16.1 | - | - | - |  |
| vc-deepseek-v4-pro-seeded-v3-support-desk-nestjs-angular | 19 | 0 | 16.0 | 20.7 | - | - | - |  |
| vc-kimi-code-seeded-v2-crm-saas-django | 27 | 4 | 15.2 | 22.4 | - | - | - |  |
| vc-kimi-code-seeded-v2-education-lms-django | 28 | 4 | 15.0 | 14.9 | - | - | - |  |
| vc-kimi-code-seeded-v2-fintech-lending-fastapi | 33 | 4 | 13.1 | 9.8 | - | - | - |  |
| vc-kimi-code-seeded-v2-healthcare-clinic-django | 30 | 4 | 17.3 | 20.4 | - | - | - |  |
| vc-kimi-code-seeded-v2-hr-payroll-django | 29 | 4 | 17.7 | 17.5 | - | - | - |  |
| vc-kimi-code-seeded-v2-legal-case-django | 26 | 4 | 15.4 | 15.3 | - | - | - |  |
| vc-kimi-code-seeded-v2-logistics-dispatch-fastapi | 31 | 4 | 14.0 | 10.5 | - | - | - |  |
| vc-kimi-code-seeded-v2-marketplace-commerce-fastapi | 27 | 4 | 8.1 | 8.0 | - | - | - |  |
| vc-kimi-code-seeded-v2-property-management-fastapi | 30 | 4 | 10.8 | 10.9 | - | - | - |  |
| vc-kimi-code-seeded-v2-support-desk-fastapi | 28 | 4 | 11.7 | 11.6 | - | - | - |  |
| vc-kimi-code-seeded-v3-crm-saas-nestjs-angular | 40 | 0 | 12.7 | 17.2 | - | - | - |  |
| vc-kimi-code-seeded-v3-education-lms-nextjs | 46 | 0 | 13.6 | 17.8 | - | - | - |  |
| vc-kimi-code-seeded-v3-fintech-lending-express | 42 | 0 | 27.6 | 20.8 | - | - | - |  |
| vc-kimi-code-seeded-v3-healthcare-clinic-nextjs | 36 | 0 | 11.7 | 14.5 | - | - | - |  |
| vc-kimi-code-seeded-v3-hr-payroll-remix | 36 | 0 | 11.2 | 11.5 | - | - | - |  |
| vc-kimi-code-seeded-v3-legal-case-remix | 41 | 0 | 2.7 | 7.8 | - | - | - |  |
| vc-kimi-code-seeded-v3-logistics-dispatch-fastify-vue | 44 | 0 | 18.6 | 21.7 | - | - | - |  |
| vc-kimi-code-seeded-v3-marketplace-commerce-express | 43 | 0 | 18.3 | 17.2 | - | - | - |  |
| vc-kimi-code-seeded-v3-property-management-fastify-vue | 32 | 0 | 15.1 | 12.6 | - | - | - |  |
| vc-kimi-code-seeded-v3-support-desk-nestjs-angular | 32 | 0 | 15.6 | 17.9 | - | - | - |  |

## Reproduce

```
python3 -m vulnscan.bench fetch realvuln --ref 7a710251f55c17d32d3adcb13d37468e2e3b9e4a
python3 -m vulnscan.bench clone <suite> && python3 -m vulnscan.bench baseline <suite>
python3 -m vulnscan.bench sast <suite> && python3 -m vulnscan.bench run <suite>
python3 -m vulnscan.scorecard realvuln-clean --strict
```

vulnscan 0.3.0 · Python 3.12.3 · curated rules `e0998a0096fe` · ground truth `7a5ab343eb4e` · baselines: RealVuln published Semgrep results · agent models: vuln-discloser=opus, vuln-hunter=sonnet, vuln-patcher=sonnet, vuln-reach=sonnet, vuln-recon=sonnet, vuln-validator=opus
