# Scorecard: realvuln-holdout

Generated 2026-09-29T13:40:02Z · standard scoring · 2000 bootstrap resamples (seed 1)
Ground truth: RealVuln 3.1.0 @ `7a710251f55c` (35 repositories, 856 labeled vulnerabilities, 98 false-positive traps)

## Headline

Micro-averaged over repositories. Brackets: 95% bootstrap confidence interval. F3 weights recall 9× over precision (RealVuln's primary metric); wF3 weights each vulnerability by its CVSS score.

| View | Repos | TP | FP | FN | Precision | Recall | F1 | F3 | wF3 | FP rate on traps |
|---|---|---|---|---|---|---|---|---|---|---|
| Plain Semgrep | 35/35 | 171 | 1123 | 685 | 13.2 [7.9–21.3] | 20.0 [16.0–25.0] | 15.9 | **19.0** [15.4–23.6] | 21.2 | 92.4 |
| vulnscan scanner leads (no LLM) | 35/35 | 209 | 1017 | 647 | 17.0 [12.3–23.3] | 24.4 [19.9–30.0] | 20.1 | **23.4** [19.0–28.6] | 26.1 | 91.6 |

## Head to head (paired by repository)

Per-repo F3 difference on repositories both views cover; the sign test asks whether wins and losses could be a coin flip.

| Comparison | Repos | Mean ΔF3 | Wins / ties / losses | Sign test p |
|---|---|---|---|---|
| vulnscan scanner leads (no LLM) vs Plain Semgrep | 35 | +5.8 [2.4–9.9] | 25 / 3 / 7 | 0.0021 |

## Recall by vulnerability class

| Class | Plain Semgrep | vulnscan scanner leads (no LLM) |
|---|---|---|
| arbitrary_file_write | 0/7 (0%) | 0/7 (0%) |
| auth_endpoint_brute_force_exposure | 0/3 (0%) | 0/3 (0%) |
| broken_access_control | 0/12 (0%) | 0/12 (0%) |
| broken_authentication | 1/6 (17%) | 1/6 (17%) |
| broken_object_level_authorization | 0/14 (0%) | 0/14 (0%) |
| brute_force | 0/1 (0%) | 0/1 (0%) |
| business_logic_flaw | 0/1 (0%) | 0/1 (0%) |
| cleartext_credential_transmission | 0/2 (0%) | 0/2 (0%) |
| cleartext_transmission | 0/1 (0%) | 0/1 (0%) |
| clickjacking | 0/1 (0%) | 0/1 (0%) |
| client_asserted_authorization_bypass | 0/2 (0%) | 0/2 (0%) |
| code_injection | 14/18 (78%) | 14/18 (78%) |
| command_injection | 5/17 (29%) | 11/17 (65%) |
| cookie_cleartext_transport_exposure | 1/11 (9%) | 5/11 (45%) |
| cookie_cross_site_request_exposure | 1/2 (50%) | 0/2 (0%) |
| cookie_script_access_exposure | 1/5 (20%) | 1/5 (20%) |
| cors_misconfiguration | 0/2 (0%) | 0/2 (0%) |
| credential_enumeration | 0/2 (0%) | 0/2 (0%) |
| cross_site_scripting | 13/33 (39%) | 14/33 (42%) |
| csrf | 18/38 (47%) | 17/38 (45%) |
| csrf_bypass | 0/1 (0%) | 0/1 (0%) |
| debug_mode_exposure | 0/4 (0%) | 0/4 (0%) |
| denial_of_service | 0/19 (0%) | 0/19 (0%) |
| dom_xss | 2/7 (29%) | 1/7 (14%) |
| hardcoded_credential | 1/23 (4%) | 3/23 (13%) |
| hardcoded_credentials | 1/48 (2%) | 1/48 (2%) |
| hardcoded_cryptographic_key | 0/14 (0%) | 0/14 (0%) |
| http_header_injection | 1/1 (100%) | 1/1 (100%) |
| idor | 0/9 (0%) | 0/9 (0%) |
| improper_certificate_validation | 0/1 (0%) | 0/1 (0%) |
| incorrect_authorization | 0/1 (0%) | 0/1 (0%) |
| information_disclosure | 0/1 (0%) | 0/1 (0%) |
| insecure_cookie | 4/7 (57%) | 4/7 (57%) |
| insecure_deserialization | 16/17 (94%) | 15/17 (88%) |
| insecure_random | 0/4 (0%) | 0/4 (0%) |
| insecure_session | 1/1 (100%) | 1/1 (100%) |
| insufficient_session_invalidation | 0/3 (0%) | 0/3 (0%) |
| internal_error_disclosure_via_http | 0/46 (0%) | 0/46 (0%) |
| log_injection | 0/6 (0%) | 0/6 (0%) |
| mass_assignment | 0/7 (0%) | 0/7 (0%) |
| missing_access_control | 0/6 (0%) | 0/6 (0%) |
| missing_auth | 0/1 (0%) | 0/1 (0%) |
| missing_authentication | 0/36 (0%) | 0/36 (0%) |
| missing_authorization | 0/11 (0%) | 0/11 (0%) |
| missing_rate_limiting | 0/13 (0%) | 0/13 (0%) |
| missing_server_side_business_validation | 0/2 (0%) | 0/2 (0%) |
| missing_session_expiration | 0/3 (0%) | 0/3 (0%) |
| nosql_injection | 7/13 (54%) | 8/13 (62%) |
| observable_response_discrepancy | 0/2 (0%) | 0/2 (0%) |
| open_redirect | 4/8 (50%) | 4/8 (50%) |
| os_command_injection | 5/6 (83%) | 4/6 (67%) |
| padding_oracle | 0/1 (0%) | 0/1 (0%) |
| path_traversal | 6/28 (21%) | 7/28 (25%) |
| plaintext_password_storage | 0/2 (0%) | 0/2 (0%) |
| predictable_security_token | 0/1 (0%) | 0/1 (0%) |
| prototype_pollution | 0/3 (0%) | 0/3 (0%) |
| race_condition | 0/1 (0%) | 0/1 (0%) |
| reflected_xss | 13/39 (33%) | 22/39 (56%) |
| regular_expression_query_injection | 0/1 (0%) | 0/1 (0%) |
| security_misconfiguration | 6/45 (13%) | 6/45 (13%) |
| sensitive_cookie_misconfiguration | 1/2 (50%) | 1/2 (50%) |
| sensitive_data_exposure | 3/59 (5%) | 3/59 (5%) |
| sensitive_information_exposure_via_http | 0/14 (0%) | 0/14 (0%) |
| server_side_template_injection | 0/4 (0%) | 3/4 (75%) |
| session_fixation | 0/2 (0%) | 0/2 (0%) |
| session_hijacking | 0/1 (0%) | 0/1 (0%) |
| session_management | 0/1 (0%) | 0/1 (0%) |
| session_token_exposure | 0/2 (0%) | 0/2 (0%) |
| sql_injection | 27/47 (57%) | 31/47 (66%) |
| ssrf | 3/26 (12%) | 4/26 (15%) |
| ssti | 0/4 (0%) | 1/4 (25%) |
| stored_xss | 1/17 (6%) | 4/17 (24%) |
| supply_chain | 0/1 (0%) | 0/1 (0%) |
| uncontrolled_resource_consumption | 0/2 (0%) | 0/2 (0%) |
| unrestricted_file_upload | 0/3 (0%) | 0/3 (0%) |
| unsafe_deserialization | 3/4 (75%) | 4/4 (100%) |
| vulnerable_dependency | 0/1 (0%) | 0/1 (0%) |
| weak_cryptography | 6/15 (40%) | 8/15 (53%) |
| weak_hash | 1/3 (33%) | 3/3 (100%) |
| weak_password_hashing | 0/8 (0%) | 0/8 (0%) |
| weak_password_recovery | 0/1 (0%) | 0/1 (0%) |
| xpath_injection | 0/4 (0%) | 0/4 (0%) |
| xss | 1/4 (25%) | 1/4 (25%) |
| xxe | 4/11 (36%) | 6/11 (55%) |

## Per repository (F3)

| Repo | Vulns | Traps | semgrep | vulnscan-leads | vulnscan-raw | vulnscan | Pipeline cost (USD eq.) | Note |
|---|---|---|---|---|---|---|---|---|
| realvuln-damn-vulnerable-flask-application | 14 | 5 | 34.0 | 42.6 | - | - | - |  |
| realvuln-damn-vulnerable-graphql-application | 36 | 4 | 6.0 | 5.7 | - | - | - |  |
| realvuln-djangoat | 52 | 6 | 21.3 | 25.1 | - | - | - |  |
| realvuln-dsvpwa | 32 | 6 | 19.9 | 23.0 | - | - | - |  |
| realvuln-dvblab | 22 | 4 | 35.1 | 35.6 | - | - | - |  |
| realvuln-dvpwa | 23 | 4 | 9.2 | 9.5 | - | - | - |  |
| realvuln-dvws-node | 77 | 0 | 12.1 | 14.4 | - | - | - |  |
| realvuln-extremely-vulnerable-flask-app | 32 | 4 | 19.9 | 25.6 | - | - | - |  |
| realvuln-insecure-web | 9 | 2 | 51.5 | 54.3 | - | - | - |  |
| realvuln-intentionally-vulnerable-python-application | 7 | 2 | 29.4 | 44.1 | - | - | - |  |
| realvuln-juice-shop | 81 | 0 | 11.2 | 15.2 | - | - | - |  |
| realvuln-lets-be-bad-guys | 24 | 4 | 38.6 | 58.6 | - | - | - |  |
| realvuln-ninjasworkout | 22 | 0 | 18.7 | 28.6 | - | - | - |  |
| realvuln-node-api-goat | 7 | 0 | 81.4 | 87.5 | - | - | - |  |
| realvuln-nodejs-goof | 17 | 0 | 15.2 | 22.1 | - | - | - |  |
| realvuln-owasp-web-playground | 28 | 6 | 16.6 | 16.3 | - | - | - |  |
| realvuln-pygoat | 78 | 10 | 29.9 | 31.7 | - | - | - |  |
| realvuln-python-app | 21 | 4 | 34.9 | 48.2 | - | - | - |  |
| realvuln-python-insecure-app | 8 | 2 | 0.0 | 0.0 | - | - | - |  |
| realvuln-pythonssti | 2 | 1 | 52.6 | 100.0 | - | - | - |  |
| realvuln-react-security | 7 | 0 | 14.7 | 14.5 | - | - | - |  |
| realvuln-react-test-bench | 1 | 0 | 0.0 | 0.0 | - | - | - |  |
| realvuln-reactvulna | 1 | 0 | 0.0 | 0.0 | - | - | - |  |
| realvuln-simply-vulnerable-react | 1 | 0 | 0.0 | 32.3 | - | - | - |  |
| realvuln-threatbyte | 26 | 5 | 12.0 | 19.2 | - | - | - |  |
| realvuln-vfapi | 9 | 2 | 12.2 | 11.9 | - | - | - |  |
| realvuln-vulnerable-api | 14 | 3 | 29.4 | 29.9 | - | - | - |  |
| realvuln-vulnerable-app-angular | 8 | 0 | 22.5 | 12.2 | - | - | - |  |
| realvuln-vulnerable-node | 21 | 0 | 21.3 | 24.5 | - | - | - |  |
| realvuln-vulnerable-nodejs | 19 | 0 | 0.0 | 11.1 | - | - | - |  |
| realvuln-vulnerable-python-apps | 22 | 5 | 9.5 | 27.3 | - | - | - |  |
| realvuln-vulnerable-tornado-app | 14 | 3 | 7.4 | 7.5 | - | - | - |  |
| realvuln-vulnnodeapp | 29 | 0 | 12.8 | 12.2 | - | - | - |  |
| realvuln-vulnpy | 80 | 16 | 17.2 | 24.2 | - | - | - |  |
| realvuln-xvna | 12 | 0 | 16.1 | 0.0 | - | - | - | no source files at the pinned commit; code is inside xvna.zip |

## Reproduce

```
python3 -m vulnscan.bench fetch realvuln --ref 7a710251f55c17d32d3adcb13d37468e2e3b9e4a
python3 -m vulnscan.bench clone <suite> && python3 -m vulnscan.bench baseline <suite>
python3 -m vulnscan.bench sast <suite> && python3 -m vulnscan.bench run <suite>
python3 -m vulnscan.scorecard realvuln-holdout
```

vulnscan 0.3.0 · Python 3.12.3 · curated rules `e0998a0096fe` · ground truth `71d2c45449a3` · baselines: RealVuln published Semgrep results · agent models: vuln-discloser=opus, vuln-hunter=sonnet, vuln-patcher=sonnet, vuln-reach=sonnet, vuln-recon=sonnet, vuln-validator=opus
