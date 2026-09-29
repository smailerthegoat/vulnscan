# Scorecard: realvuln-sample

Generated 2026-09-29T13:40:03Z · standard scoring · 2000 bootstrap resamples (seed 1)
Ground truth: RealVuln 3.1.0 @ `7a710251f55c` (8 repositories, 200 labeled vulnerabilities, 23 false-positive traps)

## Headline

Micro-averaged over repositories. Brackets: 95% bootstrap confidence interval. F3 weights recall 9× over precision (RealVuln's primary metric); wF3 weights each vulnerability by its CVSS score.

| View | Repos | TP | FP | FN | Precision | Recall | F1 | F3 | wF3 | FP rate on traps |
|---|---|---|---|---|---|---|---|---|---|---|
| Plain Semgrep | 8/8 | 36 | 108 | 164 | 25.0 [15.3–36.7] | 18.0 [7.9–25.9] | 20.9 | **18.5** [8.5–25.9] | 19.7 | 82.4 |
| vulnscan scanner leads (no LLM) | 8/8 | 56 | 166 | 144 | 25.2 [17.9–33.0] | 28.0 [20.0–33.3] | 26.5 | **27.7** [20.0–32.9] | 30.7 | 89.2 |

## Head to head (paired by repository)

Per-repo F3 difference on repositories both views cover; the sign test asks whether wins and losses could be a coin flip.

| Comparison | Repos | Mean ΔF3 | Wins / ties / losses | Sign test p |
|---|---|---|---|---|
| vulnscan scanner leads (no LLM) vs Plain Semgrep | 8 | +8.4 [3.4–15.0] | 7 / 1 / 0 | 0.0156 |

## Recall by vulnerability class

| Class | Plain Semgrep | vulnscan scanner leads (no LLM) |
|---|---|---|
| auth_endpoint_brute_force_exposure | 0/1 (0%) | 0/1 (0%) |
| broken_access_control | 0/6 (0%) | 0/6 (0%) |
| broken_authentication | 0/1 (0%) | 0/1 (0%) |
| broken_object_level_authorization | 0/3 (0%) | 0/3 (0%) |
| brute_force | 0/1 (0%) | 0/1 (0%) |
| cleartext_credential_transmission | 0/1 (0%) | 0/1 (0%) |
| code_injection | 1/2 (50%) | 1/2 (50%) |
| command_injection | 0/1 (0%) | 1/1 (100%) |
| cookie_cleartext_transport_exposure | 0/2 (0%) | 2/2 (100%) |
| cross_site_scripting | 3/11 (27%) | 4/11 (36%) |
| csrf | 6/13 (46%) | 6/13 (46%) |
| denial_of_service | 0/3 (0%) | 0/3 (0%) |
| dom_xss | 0/1 (0%) | 0/1 (0%) |
| hardcoded_credential | 2/4 (50%) | 2/4 (50%) |
| hardcoded_credentials | 1/18 (6%) | 1/18 (6%) |
| hardcoded_cryptographic_key | 0/3 (0%) | 0/3 (0%) |
| http_header_injection | 0/1 (0%) | 0/1 (0%) |
| http_parameter_pollution | 0/1 (0%) | 0/1 (0%) |
| idor | 0/3 (0%) | 0/3 (0%) |
| insecure_cookie | 0/3 (0%) | 0/3 (0%) |
| insecure_deserialization | 1/2 (50%) | 2/2 (100%) |
| insecure_randomness | 0/1 (0%) | 0/1 (0%) |
| insecure_session | 0/1 (0%) | 0/1 (0%) |
| internal_error_disclosure_via_http | 0/3 (0%) | 0/3 (0%) |
| log_injection | 1/1 (100%) | 0/1 (0%) |
| mass_assignment | 0/1 (0%) | 0/1 (0%) |
| missing_authentication | 0/4 (0%) | 0/4 (0%) |
| missing_authorization | 0/1 (0%) | 0/1 (0%) |
| missing_rate_limiting | 0/6 (0%) | 0/6 (0%) |
| missing_security_event_logging | 0/1 (0%) | 0/1 (0%) |
| observable_response_discrepancy | 0/2 (0%) | 0/2 (0%) |
| open_redirect | 3/4 (75%) | 3/4 (75%) |
| os_command_injection | 1/1 (100%) | 1/1 (100%) |
| password_complexity_bypass | 0/1 (0%) | 0/1 (0%) |
| path_traversal | 0/3 (0%) | 1/3 (33%) |
| plaintext_password_storage | 0/2 (0%) | 0/2 (0%) |
| plaintext_sensitive_storage | 0/1 (0%) | 0/1 (0%) |
| predictable_security_token | 0/1 (0%) | 0/1 (0%) |
| reflected_xss | 0/8 (0%) | 4/8 (50%) |
| remote_file_inclusion | 0/1 (0%) | 1/1 (100%) |
| security_misconfiguration | 5/8 (62%) | 5/8 (62%) |
| sensitive_data_exposure | 0/28 (0%) | 0/28 (0%) |
| session_fixation | 0/2 (0%) | 0/2 (0%) |
| sql_injection | 8/13 (62%) | 11/13 (85%) |
| ssrf | 1/2 (50%) | 1/2 (50%) |
| ssti | 0/2 (0%) | 2/2 (100%) |
| stored_xss | 0/8 (0%) | 5/8 (62%) |
| uncontrolled_resource_consumption | 0/1 (0%) | 0/1 (0%) |
| unsafe_deserialization | 1/1 (100%) | 1/1 (100%) |
| user_enumeration | 0/1 (0%) | 0/1 (0%) |
| weak_cryptography | 1/1 (100%) | 1/1 (100%) |
| weak_hash | 0/1 (0%) | 0/1 (0%) |
| weak_password_hashing | 0/1 (0%) | 0/1 (0%) |
| weak_prng | 0/3 (0%) | 0/3 (0%) |
| xpath_injection | 0/1 (0%) | 0/1 (0%) |
| xxe | 1/3 (33%) | 1/3 (33%) |

## Per repository (F3)

| Repo | Vulns | Traps | semgrep | vulnscan-leads | vulnscan-raw | vulnscan | Pipeline cost (USD eq.) | Note |
|---|---|---|---|---|---|---|---|---|
| realvuln-dsvw | 27 | 4 | 0.0 | 27.0 | - | - | - |  |
| realvuln-dvna | 17 | 0 | 38.9 | 44.2 | - | - | - |  |
| realvuln-flask-xss | 30 | 5 | 10.9 | 27.6 | - | - | - |  |
| realvuln-nodegoat | 28 | 0 | 20.0 | 23.5 | - | - | - |  |
| realvuln-vampi | 15 | 4 | 0.0 | 0.0 | - | - | - |  |
| realvuln-vuln-node-express | 5 | 0 | 19.6 | 20.8 | - | - | - |  |
| realvuln-vulnerable-flask-app | 21 | 4 | 14.8 | 22.6 | - | - | - |  |
| realvuln-vulpy | 57 | 6 | 28.7 | 34.4 | - | - | - |  |

## Reproduce

```
python3 -m vulnscan.bench fetch realvuln --ref 7a710251f55c17d32d3adcb13d37468e2e3b9e4a
python3 -m vulnscan.bench clone <suite> && python3 -m vulnscan.bench baseline <suite>
python3 -m vulnscan.bench sast <suite> && python3 -m vulnscan.bench run <suite>
python3 -m vulnscan.scorecard realvuln-sample
```

vulnscan 0.3.0 · Python 3.12.3 · curated rules `e0998a0096fe` · ground truth `2c6032b9c4d1` · baselines: RealVuln published Semgrep results · agent models: vuln-discloser=opus, vuln-hunter=sonnet, vuln-patcher=sonnet, vuln-reach=sonnet, vuln-recon=sonnet, vuln-validator=opus
