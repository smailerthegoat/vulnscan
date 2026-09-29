"""Deterministic lead generation: run SAST/SCA/secret scanners and import leads into the state store.

Scanner hits are only *leads*: they enter the store as candidates and every one is judged by the
independent validator. Hunters can add candidates but cannot dismiss scanner leads, so a lead can
only disappear through an explicit, reasoned verdict.

    python3 -m vulnscan.sast <target> [--changed-since REF] [--project-rules-only] [--offline] [--max-leads 150]

Project-specific Semgrep rules written by the recon agent (reports/<target>/rules/*.yml, IRIS-style
LLM-inferred sources/sinks) are validated and run alongside the registry packs, plus the curated rules
in rules/*.yml for the stacks vulnscan.stacks detects.
--offline skips the registry packs (downloaded from
semgrep.dev). Dependency advisories: vulnscan.deps.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from .common import (CWE_GROUPS, ROOT, SEVERITIES, canonical_cwe, cwe_group, normalize_cwe, read_lines,
                     report_dir, resolve_in, target_dir)
from .db import add_candidate, connect
from .stacks import detect

# p/default is Semgrep's recommended set (incl. template rules: EJS/Pug unescaped output, missing CSRF
# tokens in forms); the others add audit-level rules. Duplicate rule ids across packs run once.
SEMGREP_PACKS = ["p/default", "p/security-audit", "p/owasp-top-ten", "p/secrets"]
# Semgrep has two severity scales (ERROR/WARNING/INFO and CRITICAL/HIGH/MEDIUM/LOW); INFO/LOW are not leads.
SEMGREP_SEVERITY = {"CRITICAL": "critical", "ERROR": "high", "HIGH": "high", "WARNING": "medium", "MEDIUM": "medium"}
SEARCH_PATH = os.pathsep.join([os.environ.get("PATH", ""), str(ROOT / ".venv" / "bin")])
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def tool(name: str) -> str | None:
    return shutil.which(name, path=SEARCH_PATH)


def run(cmd: list[str], timeout: int = 900) -> subprocess.CompletedProcess:
    env = {**os.environ, "PATH": SEARCH_PATH, "SEMGREP_SEND_METRICS": "off"}
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)


def rel(path: str, root: Path) -> str:
    p = Path(path)
    if not p.is_absolute():
        p = (Path.cwd() / p)
    try:
        return str(p.resolve().relative_to(root.resolve()))
    except ValueError:
        return path


def line_text(root: Path, file: str, line: int) -> str:
    try:
        return read_lines(resolve_in(root, file))[line - 1].strip()
    except (IndexError, OSError, ValueError):
        return ""


RULE_CWE_HINTS = [
    (r"sql", "CWE-89"), (r"subprocess|command|shell|os-system|exec-detected", "CWE-78"),
    (r"ssrf|request-forgery", "CWE-918"), (r"xss|html|markup|template-autoescape", "CWE-79"),
    (r"path-traversal|directory-traversal|path-join", "CWE-22"), (r"pickle|deserial|yaml-load|marshal", "CWE-502"),
    (r"redirect", "CWE-601"), (r"jwt", "CWE-347"), (r"secret|password|api-key|token|credential", "CWE-798"),
    (r"debug", "CWE-489"), (r"eval|code-injection", "CWE-94"), (r"xxe|xml", "CWE-611"),
]


def infer_cwe(rule_id: str, cwe: str | None) -> str:
    """Rules sometimes carry an unhelpful CWE (e.g. tainted-sql-string -> CWE-704); prefer a security family."""
    c = normalize_cwe(cwe)
    if any(c in g for g in CWE_GROUPS):
        return c
    for pattern, hint in RULE_CWE_HINTS:
        if re.search(pattern, rule_id, re.I):
            return hint
    return c


def changed_files(root: Path, ref: str) -> list[str]:
    r = run(["git", "-C", str(root), "diff", "--name-only", "--diff-filter=ACMR", ref])
    if r.returncode != 0:
        raise SystemExit(f"git diff failed: {r.stderr.strip()}")
    return [f for f in r.stdout.split() if (root / f).is_file()]


# --- scanners ----------------------------------------------------------------------------------

def semgrep(root: Path, out: Path, files: list[str] | None, project_only: bool, log: list,
            offline: bool = False) -> list[dict]:
    if not tool("semgrep"):
        log.append("semgrep: not installed (pip install semgrep)")
        return []
    configs = []
    if not project_only:
        stack = detect(root)
        if not offline:
            configs += SEMGREP_PACKS + [p for p in stack["semgrep_packs"] if p not in SEMGREP_PACKS]
        configs += [str(ROOT / r) for r in stack["rules"]]
        log.append(f"stacks: {', '.join(stack['stacks']) or 'none detected'}")
    rules_dir = out.parent / "rules"
    for rule in sorted(rules_dir.glob("*.y*ml")) if rules_dir.is_dir() else []:
        v = run([tool("semgrep"), "--validate", "--config", str(rule), "--metrics", "off", "--quiet"])
        if v.returncode == 0:
            configs.append(str(rule))
        else:
            log.append(f"semgrep: project rule {rule.name} is invalid, skipped: {v.stderr.strip()[-300:]}")
    if not configs:
        return []
    cmd = [tool("semgrep"), "scan", "--json", "--quiet", "--metrics", "off", "--timeout", "30"]
    for c in configs:
        cmd += ["--config", c]
    cmd += [str(root / f) for f in files] if files else [str(root)]
    r = run(cmd, timeout=1800)
    name = "semgrep-project.json" if project_only else "semgrep.json"
    (out / name).write_text(r.stdout or "{}")
    try:
        results = json.loads(r.stdout).get("results", [])
    except json.JSONDecodeError:
        log.append(f"semgrep failed (exit {r.returncode}): {r.stderr.strip()[-400:]}")
        return []
    leads = semgrep_leads(results, root)
    log.append(f"semgrep: {len(results)} results ({len(leads)} medium+) from {len(configs)} config(s)")
    return leads


def semgrep_leads(results: list[dict], root: Path) -> list[dict]:
    """Semgrep JSON results -> leads (medium severity and up, on either of Semgrep's severity scales)."""
    leads = []
    for x in results:
        sev = SEMGREP_SEVERITY.get(str(x["extra"].get("severity", "")).upper())
        if not sev:
            continue
        cwe = x["extra"].get("metadata", {}).get("cwe")
        cwe = cwe[0] if isinstance(cwe, list) and cwe else cwe
        leads.append({"tool": "semgrep", "title": x["check_id"].split(".")[-1].replace("-", " "),
                      "rule": x["check_id"], "severity": sev, "cwe": infer_cwe(x["check_id"], cwe),
                      "file": rel(x["path"], root), "line": x["start"]["line"],
                      "description": x["extra"].get("message", "")[:1000]})
    return leads


def bandit(root: Path, out: Path, files: list[str] | None, log: list) -> list[dict]:
    if not tool("bandit"):
        log.append("bandit: not installed (pip install bandit)")
        return []
    py = [f for f in files if f.endswith(".py")] if files else None
    if files is not None and not py:
        return []
    excludes = ",".join(str(root / d) for d in (".git", ".venv", "venv", "node_modules", "vendor", "third_party"))
    cmd = [tool("bandit"), "-f", "json", "-q", "-x", excludes]
    cmd += [str(root / f) for f in py] if py else ["-r", str(root)]
    r = run(cmd)
    (out / "bandit.json").write_text(r.stdout or "{}")
    try:
        results = json.loads(r.stdout).get("results", [])
    except json.JSONDecodeError:
        log.append(f"bandit failed: {r.stderr.strip()[-400:]}")
        return []
    leads = []
    for x in results:
        if x["issue_severity"] not in ("MEDIUM", "HIGH") or x["issue_confidence"] == "LOW":
            continue
        leads.append({"tool": "bandit", "title": f"{x['test_id']} {x['test_name'].replace('_', ' ')}",
                      "rule": x["test_id"], "severity": x["issue_severity"].lower(),
                      "cwe": normalize_cwe((x.get("issue_cwe") or {}).get("id")),
                      "file": rel(x["filename"], root), "line": x["line_number"],
                      "description": x["issue_text"]})
    log.append(f"bandit: {len(results)} results ({len(leads)} medium+)")
    return leads


def gitleaks(root: Path, out: Path, log: list) -> list[dict]:
    if not tool("gitleaks"):
        log.append("gitleaks: not installed (optional)")
        return []
    report = out / "gitleaks.json"
    run([tool("gitleaks"), "detect", "--no-git", "--redact", "--source", str(root),
         "--report-format", "json", "--report-path", str(report)])
    try:
        results = json.loads(report.read_text() or "[]")
    except (OSError, json.JSONDecodeError):
        log.append("gitleaks: no parseable report")
        return []
    leads = [{"tool": "gitleaks", "title": f"hardcoded secret ({x['RuleID']})", "rule": x["RuleID"],
              "severity": "high", "cwe": "CWE-798", "file": rel(x["File"], root), "line": x["StartLine"],
              "description": x.get("Description", "")} for x in results]
    log.append(f"gitleaks: {len(leads)} secrets")
    return leads


# --- import ------------------------------------------------------------------------------------

def prioritize(leads: list[dict]) -> list[dict]:
    """Order leads for the budget: round-robin across CWE families, most severe first within each.

    A purely severity-sorted cap lets one flooded class (hundreds of XSS or SQLi hits) crowd every
    other class out; round-robin keeps each class represented until the budget runs out.
    """
    families: dict[str, list[dict]] = {}
    for lead in sorted(leads, key=lambda x: (SEV_RANK.get(x["severity"], 9), x["file"], x["line"])):
        families.setdefault(min(cwe_group(canonical_cwe(lead["cwe"]))), []).append(lead)
    queues = sorted(families.values(), key=lambda q: SEV_RANK.get(q[0]["severity"], 9))
    out = []
    while queues:
        out += [q.pop(0) for q in queues]
        queues = [q for q in queues if q]
    return out


def import_leads(conn, target: str, root: Path, leads: list[dict], max_leads: int, log: list) -> None:
    """Import up to max_leads *new* candidates; duplicates of already-imported bugs don't use the budget."""
    added = dup = skipped = 0
    for lead in prioritize(leads):
        if added >= max_leads:
            skipped += 1
            continue
        text = line_text(root, lead["file"], lead["line"])
        if lead["tool"] == "gitleaks":
            text = re.sub(r"(['\"])[^'\"]{6,}\1", r"\1***REDACTED***\1", text)
        cand = {**lead, "evidence": text or "(line unavailable)",
                "sink": lead["rule"], "description": f"[{lead['tool']} {lead['rule']}] {lead['description']}"}
        msg, _ = add_candidate(conn, target, cand, origin=f"sast:{lead['tool']}", verify=False)
        added += msg.startswith("ADDED")
        dup += msg.startswith("DUPLICATE")
    if skipped:
        log.append(f"lead cap: {max_leads} new leads imported, {skipped} lower-priority hits skipped "
                   "(round-robin across classes; raise --max-leads)")
    log.append(f"imported {added} new leads, {dup} duplicates merged")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="vulnscan.sast")
    ap.add_argument("target")
    ap.add_argument("--changed-since", metavar="REF", help="only scan files changed since this git ref")
    ap.add_argument("--project-rules-only", action="store_true",
                    help="only run recon-generated rules in reports/<target>/rules/")
    ap.add_argument("--offline", action="store_true",
                    help="skip Semgrep registry packs")
    ap.add_argument("--max-leads", type=int, default=150)
    args = ap.parse_args(argv)

    root = target_dir(args.target)
    out = report_dir(args.target) / "sast"
    out.mkdir(exist_ok=True)
    conn = connect(args.target)
    files = changed_files(root, args.changed_since) if args.changed_since else None
    if files is not None:
        print(f"diff mode: {len(files)} changed file(s) since {args.changed_since}")
        if not files:
            return 0

    log: list[str] = []
    leads = semgrep(root, out, files, args.project_rules_only, log,
                    args.offline)
    if not args.project_rules_only:
        leads += bandit(root, out, files, log) + gitleaks(root, out, log)
    import_leads(conn, args.target, root, leads, args.max_leads, log)
    print("\n".join(log))
    return 0


if __name__ == "__main__":
    sys.exit(main())
