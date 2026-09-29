# vulnscan: a multi-agent AI security auditor

Clone any repository into `targets/`, type `/vuln-audit <name>` in Claude Code, and a team of
specialised agents audits it. Recon maps the attack surface, hunters trace attacker input to
dangerous sinks in parallel, an independent validator tries to disprove every claim, a reachability
agent drops vulnerable dependencies the code never calls, a patcher writes verified fixes, and a
discloser re-checks each bug against the latest upstream release and drafts an advisory for the
maintainers. You get a Markdown report, SARIF for GitHub code scanning, disclosure drafts, and
precision/recall against labeled ground truth, including the 140-repo RealVuln benchmark.

It runs on your **Claude Code subscription** (no API key needed) and scales from one repo to a batch of repos or a CI job per pull request.

```
                       ┌────────────────────────────────── deterministic, no LLM cost ──────────────────────────────────┐
 targets/<repo> ─────▶ │ sanitize (comment-stripped mirror) · stacks (languages/frameworks → packs, rules, playbooks)    │
                       │ sast: Semgrep packs + curated taint rules + Bandit + Gitleaks → leads · deps: lockfiles → OSV    │
                       └──────────────────────────────────────────────┬───────────────────────────────────────────────────┘
                                                                      ▼
 ┌──────────────┐  threat model   ┌───────────────────────┐  candidates  ┌─────────────────────────┐  confirmed  ┌──────────────┐
 │  vuln-recon  │ ──────────────▶ │ vuln-hunter × N       │ ───────────▶ │ vuln-validator × M      │ ──────────▶ │ vuln-patcher │
 │  (Sonnet)    │  work units +   │ one per class × scope │  evidence-   │ (Opus, different model) │             │  (Sonnet)    │
 │              │  project rules  │ parallel, "break it"  │  checked on  │ blind, kill mandate     │             │ diff+check   │
 └──────────────┘                 └───────────────────────┘  insert      └─────────────────────────┘             └──────┬───────┘
 ┌──────────────┐  vulnerable deps that the code reaches (call site cited)                                               ▼
 │  vuln-reach  │ ───────────────────────────────────────────────────────────┐        latest release still vulnerable? ┌────────────────┐
 │  (Sonnet)    │                                                            │        advisory.py upstream + check  ──▶ │ vuln-discloser │
 └──────────────┘                                                            │                                          │ (Opus) drafts  │
         │                                                                   ▼                                          └────────────────┘
         └──────────────────────────────── reports/<repo>/state.db (SQLite) ─┴──────────────────────────────────────────────────┘
                                                              ▼
            report.md · findings.json · results.sarif · patches/*.diff · advisories/*.md + *.osv.json · eval.md
```

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt                       # semgrep + bandit (optional but recommended)

python3 -m vulnscan.targets add examples/demo_target  # bundled vulnerable app with ground truth
python3 -m vulnscan.targets add https://github.com/<owner>/<repo>.git [--ref <tag|branch|commit>]

claude
> /vuln-audit demo_target
> /vuln-audit <repo> focus on auth and the REST API
> /vuln-audit <repo> --diff origin/main                # only what changed (PR-style)
> /vuln-audit <repo> --quick                           # cheap pass: 5 work units, validate high+ only
> /vuln-audit <repo> --no-disclose                     # skip the disclosure drafts
```

Unattended, across many repos (headless `claude -p`, bounded concurrency, resumable):

```bash
python3 -m vulnscan.batch --parallel 3 demo_target https://github.com/org/a.git https://github.com/org/b.git
python3 -m vulnscan.batch --list repos.txt --diff origin/main
```

CI: `examples/ci/vulnscan-pr.yml` reviews each pull request incrementally and uploads SARIF to GitHub code scanning.

## What each stage adds

### Languages and frameworks
`python3 -m vulnscan.stacks <t>` detects languages and frameworks from file types and manifests, and
picks three things per stack: Semgrep registry packs, **curated taint rules** (`rules/*.yml`) and a
**stack playbook** (`playbooks/stacks/*.md`) that hunters and validators read.

| Stack | Curated rules | Covers |
|---|---|---|
| Go (net/http, mux, chi, gin, echo, fiber) | 7 | SQLi incl. gorm, command, path, SSRF, open redirect, XSS, template injection |
| Java / Spring (MVC, Servlets) | 9 | SQL/JPQL, command, path, SSRF, redirect, XSS, deserialization, SpEL/OGNL, Thymeleaf view-name injection |
| Node / TypeScript (Express, Koa, Fastify, NestJS, Next.js) | 14 | SQL/NoSQL, command, code, SSTI, path, SSRF, redirect, reflected + DOM XSS, React/Angular raw HTML, deserialization, ReDoS, prototype pollution |
| Ruby (Rails, Sinatra) | 11 | ActiveRecord SQLi, command incl. `Kernel#open`, eval, unsafe reflection, path, SSRF, redirect, `html_safe`/`raw`, `render inline:`, Marshal/YAML, `permit!` |
| PHP (plain, Laravel, Symfony, WordPress) | 12 | SQLi incl. `whereRaw`/`$wpdb`, command, eval, file inclusion, path, SSRF, redirect, XSS, `unserialize`, XXE, `extract()`, mass assignment |

Every rule has `# ruleid:` / `# ok:` fixtures in `tests/rules/`, covering the vulnerable idiom and
the safe idioms that must not match (placeholders, `escapeshellarg`, `filepath.Base`, constant-origin
URLs, `String()` casts, `Long` path variables and so on). `semgrep --test --config rules tests/rules`
runs them (53/53 pass), and so does the pytest suite.

### Dependencies: reported only when reached
`python3 -m vulnscan.deps <t> scan` reads lockfiles (pip, Poetry, Pipenv, uv, npm, Yarn, pnpm, Go,
Maven, Gradle, Bundler, Composer, Cargo), looks up each pinned version on OSV, and merges the aliases
of one bug (GHSA/PYSEC/GO/CVE) into one entry. A deterministic pre-pass then classifies each advisory:

| Status | Meaning | Reported? |
|---|---|---|
| `dev-only` | dev/test dependency, not shipped | no |
| `not-imported` | no first-party import, and not a server or framework-internal package | no |
| `reachable` | OSV names the affected symbols (Go) and first-party code calls one | **yes** |
| `unreachable` | affected symbols known, none called | no |
| `pending` | imported (or run by the framework), advisory names no symbols → **vuln-reach** agent decides | only if the agent finds a call site |

A `reachable` verdict must cite the call site, and it is evidence-checked like any finding. Everything
not reported stays visible, with its reason, in a collapsed section of the report.

### Disclosure: still vulnerable in the latest release?
For each confirmed finding, `python3 -m vulnscan.advisory <t> upstream` mirrors the target's upstream
repository (bare, blob-less, hooks disabled) and finds the latest stable release. `check` then locates
the vulnerable code there and on the default branch (`present`, `moved`, `changed` or `absent`) and
bisects the release tags for the first affected version. The **vuln-discloser** agent re-walks the
whole path at the latest release, checks already-published advisories (OSV and GitHub) for duplicates,
and writes the draft. `render` computes the CVSS 3.1 score from the vector, decides the status, and writes a
GHSA-style `advisories/<id>.md` plus an OSV record.

| Status | When |
|---|---|
| `ready` | vulnerable code present in the latest release and re-verified there |
| `fixed-unreleased` | fixed on the default branch, still in the latest release (ask for a release) |
| `fixed-upstream` | gone from both: don't report |
| `duplicate` | an already-published advisory covers it |
| `needs-review` | code changed upstream, no upstream to check, or not re-verified |

Nothing is ever sent. Drafts include the project's security contact (from its `SECURITY.md`) and the
GitHub private-reporting link; submitting is the operator's decision.

## Evaluation

### Scoring is RealVuln's
`vulnscan/scoring.py` implements RealVuln's matcher: file, a CWE in the entry's acceptable set, line
within ±10 of the labeled range, each entry consumed once, a vulnerable entry preferred over a co-located
trap, and non-scoring entries withheld. Scored on RealVuln's own published Semgrep results, it
reproduces RealVuln's leaderboard numbers **exactly on all 140 repositories** (TP/FP/FN/TN identical
per repo; 410 TP, 3,145 FP, 3,728 FN overall). A vendored fixture pins this in the test suite. The CVSS 3.1
calculator agrees with the most common score for 150 of RealVuln's 153 distinct vectors. The other
3 are ties inside the dataset, where RealVuln scores the same vector two ways.

### Benchmark workflow
```bash
python3 -m vulnscan.bench fetch realvuln --with-reference   # 140 repos, 4,138 labeled vulns, pinned commit
python3 -m vulnscan.bench clone realvuln                    # each repo at its pinned commit
python3 -m vulnscan.bench baseline realvuln [--reference]   # plain Semgrep (yours, or RealVuln's published run)
python3 -m vulnscan.bench sast realvuln                     # vulnscan's deterministic stages (no LLM)
python3 -m vulnscan.bench run realvuln --parallel 2         # the full /vuln-audit pipeline (uses your subscription)
python3 -m vulnscan.scorecard realvuln [--strict]           # eval/scorecards/realvuln/scorecard.md
```

The scorecard compares four views per repository: plain Semgrep, vulnscan's scanner leads, all
candidates before validation, and validator-confirmed findings. It reports micro-averaged
precision/recall/F1/F3 (F3 is RealVuln's headline metric), CVSS-weighted F3, 95% bootstrap confidence
intervals over repositories (fixed seed), per-repo paired comparisons with an exact sign test,
recall per vulnerability class, cost per repo, and a provenance block (benchmark commit, ground-truth
hash, rule hash, tool versions, agent models). `--strict` counts repos without results as misses.

### Results so far

Scanner stage only (no LLM): what the deterministic part of the pipeline hands to the agents, compared
with plain Semgrep as RealVuln published it (Semgrep 1.150, same pinned commits, file paths corrected;
see the note below). F3 in percent, 95% bootstrap CI.

| Suite | Repos (labeled vulns) | Plain Semgrep F3 (P / R) | vulnscan leads F3 (P / R) | Paired W/T/L, sign test |
|---|---|---|---|---|
| **Clean: never inspected, measured once, blind** | 97 (3,082) | 11.9 [10.7–13.0] (16.7 / 11.5) | **14.2** [12.9–15.4] (14.6 / 14.2) | 59 / 3 / 35, p = 0.017 |
| Held-out (diagnosed after its first blind run) | 35 (856) | 19.0 [15.4–23.6] (13.2 / 20.0) | 23.4 [19.0–28.6] (17.0 / 24.4) | 25 / 3 / 7, p = 0.002 |
| Tuning sample | 8 (200) | 18.5 (25.0 / 18.0) | 27.7 (25.2 / 28.0) | — |

**How to read these numbers.** The clean suite is the honest headline: the 97 RealVuln repositories outside
the other two suites (mostly LLM-generated apps), scored once after all development was done. There, vulnscan's
leads find 24% more of the labeled vulnerabilities than Semgrep (recall 14.2% vs 11.5%) at slightly lower
precision. The held-out suite's first run was blind (F3 22.2 vs 18.1). Diagnosing its gaps then exposed four
general-purpose bugs that were fixed:
- Identical sink lines in one file (repeated `@csrf_exempt`, repeated `cursor.execute(query)`) were
  collapsed into one finding.
- Scanner hits on adjacent lines were merged, which hid separate sinks.
- The lead budget was taken purely by severity, so one flooded class crowded the others out. It is now
  shared round-robin across classes.
- Folders named like build output (Maven's, Gradle's, npm's) were skipped even when they held the
  application's source.

**A data issue in the benchmark.** For 40 of RealVuln's Python repositories, the published Semgrep results
carry a `repos/<name>/` path prefix, so no finding can match the ground truth and Semgrep scores 0 there on
RealVuln's own leaderboard. vulnscan strips that prefix when scoring the baseline (so Semgrep gets credit for
what it found). `python3 -m vulnscan.scorecard realvuln --as-published` reproduces the leaderboard exactly.

Remaining gaps and caveats:
- Recall is still low in absolute terms. Scanners miss logic, access-control and configuration bugs by
  design; those are the hunters' job.
- Both tools flag about 90% of RealVuln's traps. Filtering those out is the validator's job.
- One repository (xvna) ships its code only inside a `.zip`, so vulnscan scans nothing there. The
  scorecard flags it.
- **The validated-pipeline row is not published yet.** The first `bench run` on four clean repositories
  stopped at the Claude session limit before doing any work, and will be rerun.

### Demo target
`python3 -m vulnscan.evaluate demo_target` scores the bundled app (11 labeled vulnerabilities, 7
look-alike traps). Run `/vuln-audit demo_target` first; `reports/demo_target/eval.md` then shows each
stage's contribution and what the validator killed.

## Why it's built this way

Each design decision comes from recent research or production systems:

| Design choice | Where it comes from | Where it lives |
|---|---|---|
| **Recon → Hunt → Validate** stages with shared state; one hunter per vulnerability class, told to *break* the code; a validator that can't file its own findings | Cloudflare's vulnerability-harness write-up; OpenAI Aardvark (threat model first, then scan and validate) | `.claude/agents/`, `vulnscan/db.py` |
| Validator is **adversarial, context-isolated, and on a different model**: it sees only the claim (`show --blind`), defaults to *refuted*, and must cite `file:line` for every link | *Refute-or-Promote* (arXiv 2604.19049): kill mandates, context asymmetry and cross-model critics killed about 80% of candidates, and what survived yielded CVEs | `vuln-validator.md` |
| Hunters form a **hypothesis** (source → path → sink), then verify each condition | *VulAgent* (ACL 2026): hypothesis validation cut false positives 36% | `vuln-hunter.md` |
| Recon writes **project-specific Semgrep taint rules** on top of curated per-stack rules | *IRIS* (ICLR 2025): LLM-inferred taint specs doubled CodeQL's detections | `vuln-recon.md`, `rules/`, `vulnscan/sast.py` |
| SAST output becomes **leads for an agentic triage**, not findings | *Sifting the Noise* (arXiv 2601.22952): agents cut SAST false positives from 92% to 6.3% | `vulnscan/sast.py` |
| **Reachability before reporting** dependencies: symbol-level where OSV has it, an agent with a cited call site otherwise | Go's govulncheck (symbol reachability); most SCA alerts are for code the app never calls | `vulnscan/deps.py`, `vuln-reach.md` |
| **Re-verify at the latest release** before disclosure; affected range from tag bisection; score computed from the vector | Coordinated-disclosure practice (GHSA/OSV formats); stale or already-fixed reports waste maintainers' time | `vulnscan/advisory.py`, `vuln-discloser.md` |
| Agents read a **comment-stripped mirror**; comments that address AI reviewers are flagged | *ALIBI* (arXiv 2607.24964): adversarial comments fooled LLM detectors in over 90% of cases; comment sanitization and architectural isolation were the defenses that held | `vulnscan/sanitize.py` |
| **Deterministic before LLM** (scanners, dedup, evidence checks, reachability pre-pass, SARIF); LLMs only where tools fall short | Trail of Bits' *Buttercup* (2nd place, DARPA AIxCC): deterministic workflows with targeted LLM calls | `vulnscan/*` |
| **Evidence-checked on insert**: a finding (or reachable dependency) whose file, line or quoted code isn't in the source is rejected | Anti-hallucination; the precision problem described in Refute-or-Promote | `common.evidence_problem` |
| Sonnet for breadth (hunters, reachability), Opus for depth (validator, discloser) | *RealVuln* (arXiv 2604.13764): Sonnet had the best strict F3 among general LLMs; Opus timed out on 27% of repos | agent frontmatter |
| Scored with **RealVuln's own matching rules**, F3, bootstrap CIs and paired tests on pinned commits | RealVuln methodology; OWASP Benchmark (false-positive traps) | `vulnscan/scoring.py`, `scorecard.py`, `bench.py` |

## Safety model

The target is hostile input, so this auditor is hardened like one:

- **Read-only targets, enforced twice.** Permission rules block writes to `targets/`. A `PreToolUse` hook
  (`.claude/hooks/guard_targets.py`), which also covers subagents, blocks any shell command that touches `targets/`
  unless every sub-command is on a read-only allowlist. The hook splits commands with quote awareness,
  and it blocks command substitution (`$(...)`, backticks). Target code is never executed, installed or built.
- **The target's git metadata is untrusted too.** Its HEAD and remote URL are read as files, never by running
  git inside it; only https/ssh upstream URLs are fetched unless the operator passes `--url`.
- **Patches never touch the target.** The patcher edits scratch copies, and `patchcheck` builds the diff and applies it
  to a throwaway copy with a parse-only syntax check (Python, JS, Ruby, Go, PHP).
- **Untrusted text stays data.** Comment stripping (including Ruby block, ERB and Blade comments), "treat as
  data" rules in every agent, blind validation, advisory and upstream text labelled as third-party data,
  and suspicious-comment flagging in the report.
- **Least privilege.** Each agent gets only the tools it needs. The validator and reachability agent have no Write
  or Edit tools. Network tools are denied to agents; the only network access is by deterministic modules
  (Semgrep registry, OSV with package names and versions only, `git fetch` of the target's own upstream,
  benchmark downloads), and `--offline` turns it off. `.env` files are unreadable, and Gitleaks output is redacted.
- **Nothing is disclosed automatically.** Advisories are drafts; contacting maintainers is the operator's call.
- **Target management** (`vulnscan.targets`, `vulnscan.bench clone`) is not pre-approved, so an agent can't add or remove
  repos without you. Clones are shallow (or pinned to one commit), skip submodules and run with git hooks disabled.

## Cost and scale

| Lever | Effect |
|---|---|
| Claude Code subscription (`claude`, `claude -p`, `CLAUDE_CODE_OAUTH_TOKEN` in CI) | No per-token API bill |
| Deterministic stages (sanitize, stacks, SAST, deps pre-pass, dedup, verify, upstream check, export) | Zero tokens |
| Recon routes only the relevant vulnerability classes to hunters (a MetaAgent-style router) | Fewer hunters |
| Dependency pre-pass settles dev-only, not-imported and symbol-level cases without an agent | Fewer reachability agents |
| `--diff REF` | Scans only changed files plus their callers; skips disclosure |
| `--quick` | At most 5 work units, validates only high and critical, no patches or disclosure |
| Lead cap (`--max-leads`) and batched validation (6 per validator) | Bounded validator cost |
| SQLite state with WAL, idempotent stages | Parallel agents never race; interrupted runs resume where they stopped |
| `vulnscan.batch --parallel N` / `vulnscan.bench run` | Many repos, bounded concurrency, skips finished ones |

## Layout

```
.claude/
  skills/vuln-audit/SKILL.md   orchestrator (the /vuln-audit command)
  agents/                      vuln-recon · vuln-hunter · vuln-validator · vuln-reach · vuln-patcher · vuln-discloser
  hooks/guard_targets.py       read-only enforcement for targets/
  settings.json                permissions + hook registration
playbooks/                     per-class checklists: injection, access-control, web, crypto-secrets,
                               deserialization-config, memory-safety, llm-app (OWASP LLM Top 10), logic, dependency
playbooks/stacks/              go, java-spring, node-express, ruby-rails, php
rules/                         curated Semgrep taint rules per stack (fixtures in tests/rules/)
vulnscan/
  db.py          SQLite state store + CLI (plan, add, show --blind, verdict, export, reset)
  stacks.py      language/framework detection → packs, rules, playbooks
  sast.py        Semgrep/Bandit/Gitleaks → leads (incl. curated and recon-written rules)
  deps.py        lockfiles → OSV → reachability pre-pass → agent verdicts
  advisory.py    upstream mirror, latest-release check, affected range, advisory + OSV rendering
  cvss.py        CVSS 3.0/3.1 base score calculator
  sanitize.py    comment-stripped, line-preserving mirror + steering-comment detection
  patchcheck.py  prepare → edit → diff → apply-check + syntax-check on a throwaway copy
  scoring.py     RealVuln-compatible ground-truth loading and matching
  evaluate.py    per-target evaluation (all views)
  bench.py       RealVuln suites: fetch, pinned clone, baselines, runs
  scorecard.py   multi-repo scorecard with CIs and paired tests
  sarif.py       SARIF 2.1.0 with stable fingerprints (findings + reachable dependencies)
  batch.py       headless multi-repo runner
  targets.py     safe add/remove of audit targets (branch, tag or exact commit)
  agent.py, tools.py, __main__.py   standalone single-agent mode via the Anthropic API
eval/ground_truth/             labeled vulnerabilities and traps (native or RealVuln format)
eval/suites/                   pinned benchmark suites
eval/scorecards/               scorecards (markdown, JSON, per-repo CSV)
examples/demo_target/          intentionally vulnerable Flask app (do not deploy)
examples/ci/vulnscan-pr.yml    GitHub Actions template
tests/                         pytest suite (evidence checks, sanitizer, store, guard, patches, scoring,
                               rules, stacks, dependencies, disclosure, benchmark)
```

## Tests

```bash
.venv/bin/python -m pytest -q
```

## Roadmap

- Run the full pipeline across RealVuln and publish the validated-findings row of the scorecard
- Sandboxed dynamic validation (Aardvark/Big Sleep style): the validator writes a reproduction test that runs
  in a network-less, read-only container against a copy of the target
- Symbol-level reachability beyond Go (call graphs for Python and JavaScript)
- A cross-family critic (a second-opinion model from another vendor) for critical findings
- CVSS 4.0 vectors in advisories

Benchmark data: RealVuln (https://github.com/kolega-ai/Real-Vuln-Benchmark, Apache-2.0) by Kolega.ai.
