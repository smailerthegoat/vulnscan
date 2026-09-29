# Playbook: dependency reachability

A vulnerable library version only matters if the target exercises the vulnerable code. Your job is to
decide that for one advisory at a time, from the advisory text and the target's own code.

## 1. Pin down what is vulnerable
From the advisory (`summary`, `details`, CWE, fixed version), name the vulnerable unit as precisely as you can:
- a function or method (`yaml.load` without `Loader`, `jwt.decode` with `algorithms` from the token, `_.merge`, `ObjectMapper` default typing),
- a feature or code path (multipart parsing, proxy handling, redirect following, `.netrc` lookup, HTTP/2 server, cookie parsing),
- or a configuration that enables it (`FullLoader`, `trust_remote_code`, `ALLOW_URL_INCLUDE`, a non-default option).

If the advisory is too vague to name any of these, the verdict is `unknown`; say what is missing.

## 2. Find how the target uses the package
Start from `import_sites` in `show`. Then Grep the sanitized mirror (`reports/<t>/sanitized/`) for the
vulnerable function or option, including aliases (`from yaml import load as yl`), wrappers the project
defines around it, and configuration files. Exclude tests, examples and scripts that aren't shipped.

## 3. Decide
| Verdict | When |
|---|---|
| `reachable` | first-party code calls the vulnerable function / uses the vulnerable feature or configuration on a shipped path. Cite the call site. |
| `reachable` (framework path) | the vulnerable code runs on the framework's normal request path and the app uses that feature: e.g. a request-parsing bug in `qs`/`body-parser`/`werkzeug` multipart for an app with body-parsing routes, a server-level bug in the server that runs the app. Cite the route or config that exercises it. |
| `unreachable` | you identified the vulnerable unit and the target never uses it (only `yaml.safe_load`; `requests` without proxies or `.netrc`; JWT decoding with a fixed `algorithms` list when the bug needs attacker-chosen algorithms). Name what you searched for. |
| `unknown` | the vulnerable unit can't be identified, or use depends on runtime configuration outside the repo. |

A reachable verdict is about the code path, not exploitability alone. In the reason, say whether
attacker-controlled input reaches it (e.g. "request body -> yaml.load") or only trusted data
(e.g. "loads a bundled config file"); the report keeps both, but the difference drives priority.

## Common traps
- A package listed but only imported by tests, fixtures, scripts or build tooling: `unreachable` (not shipped).
- Safe variants of a dangerous API (`safe_load`, `defusedxml`, parameterized queries): `unreachable` for the unsafe-API advisory.
- Transitive packages used by a directly imported library: check whether the target calls the library feature that uses the vulnerable code (e.g. `requests` uses `urllib3` for every request, so a `urllib3` bug in response parsing is reachable when the target makes requests).
- Client-side packages (bundled for the browser) with server-side advisories, and vice versa.
