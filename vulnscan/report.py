"""Render audit results as Markdown (and JSON for the standalone API agent).

The Claude Code pipeline renders through `python3 -m vulnscan.db <target> export`.
"""
import json
from datetime import datetime, timezone
from pathlib import Path

from .common import SEVERITIES


def sort_findings(findings: list[dict]) -> list[dict]:
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    return sorted(findings, key=lambda f: rank.get(f.get("severity", "info"), 9))


def _finding_md(i: int, f: dict) -> list[str]:
    md = [f"### {i}. [{f['severity'].upper()}] {f['title']} ({f['cwe']})", "",
          f"**Location:** `{f['file']}:{f['line']}`"]
    if f.get("origin"):
        by = f["origin"] + (f", {f['also_reported_by']}" if f.get("also_reported_by") else "")
        md[-1] += f"  ·  **Reported by:** {by}"
    md.append("")
    if f.get("source") and f.get("sink"):
        md += [f"**Source → sink:** {f['source']} → {f['sink']}", ""]
    elif f.get("origin", "").startswith("sast"):
        md += [f"**Scanner rule:** `{f.get('sink')}`", ""]
    if f.get("attack_path"):
        md += [f"**Attack path:** {f['attack_path']}", ""]
    if f.get("description"):
        md += [f["description"], ""]
    md += ["```", str(f["evidence"]).rstrip(), "```", ""]
    if f.get("verdict_reason"):
        conf = f" (confidence {f['verdict_confidence']:.2f})" if f.get("verdict_confidence") is not None else ""
        md += [f"**Validator{conf}:** {f['verdict_reason']}", ""]
    if f.get("fix"):
        md += [f"**Fix:** {f['fix']}", ""]
    if f.get("patch_path"):
        md += [f"**Patch:** `{f['patch_path']}` (apply check: {f.get('patch_check') or 'n/a'})", ""]
    return md


def _cell(text) -> str:
    return " ".join(str(text or "-").split()).replace("|", "\\|")


def _dependencies_md(deps: list[dict]) -> list[str]:
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    deps = sorted(deps, key=lambda d: (rank.get(d.get("severity"), 9), d["package"], d["vuln_id"]))
    reachable = [d for d in deps if d.get("reach_status") == "reachable"]
    others = [d for d in deps if d.get("reach_status") != "reachable"]
    md = ["## Vulnerable dependencies", ""]
    if reachable:
        md += ["Reported only where first-party code reaches the vulnerable code (`python3 -m vulnscan.deps`).", "",
               "| Package | Version | Advisory | Severity | Fixed in | Reached at | Why |", "|---|---|---|---|---|---|---|"]
        for d in reachable:
            ids = d["vuln_id"] + (f" ({_cell(d.get('aliases'))})" if d.get("aliases") else "")
            md.append(f"| {_cell(d['package'])} | {_cell(d['version'])} | {ids} | {_cell(d.get('severity'))} | "
                      f"{_cell(d.get('fixed'))} | `{d.get('reach_file')}:{d.get('reach_line')}` | "
                      f"{_cell(d.get('reach_reason'))} |")
    else:
        md.append("No vulnerable dependency is reached by first-party code.")
    md.append("")
    if others:
        counts: dict[str, int] = {}
        for d in others:
            counts[d.get("reach_status") or "not analysed"] = counts.get(d.get("reach_status") or "not analysed", 0) + 1
        summary = ", ".join(f"{n} {s}" for s, n in sorted(counts.items()))
        md += [f"<details><summary>Dependency advisories not reported ({len(others)}: {summary})</summary>", "",
               "| Package | Version | Advisory | Severity | Status | Reason |", "|---|---|---|---|---|---|"]
        md += [f"| {_cell(d['package'])} | {_cell(d['version'])} | {d['vuln_id']} | {_cell(d.get('severity'))} | "
               f"{_cell(d.get('reach_status') or 'not analysed')} | {_cell(d.get('reach_reason'))} |" for d in others]
        md += ["", "`pending` means an agent has not reviewed it yet; `unknown` means the reviewer couldn't "
                   "settle reachability from the code.", "", "</details>", ""]
    return md


def _advisories_md(advisories: list[dict]) -> list[str]:
    md = ["## Disclosure drafts", "",
          "Drafted for maintainers; nothing has been sent. Each finding was re-checked against the latest "
          "upstream release before drafting (`python3 -m vulnscan.advisory`).", "",
          "| Finding | Status | CVSS | Latest release | Default branch | Affected | Draft |", "|---|---|---|---|---|---|---|"]
    for a in advisories:
        score = f"{a['cvss_score']} {a.get('cvss_severity') or ''}".strip() if a.get("cvss_score") is not None else "-"
        latest = f"{a.get('latest_release') or '-'}: {a.get('latest_status') or 'unchecked'}"
        head = f"{a.get('head_ref') or '-'}: {a.get('head_status') or 'unchecked'}"
        draft = f"`{a['path']}`" if a.get("path") else "-"
        md.append(f"| #{a['candidate_id']} {_cell(a.get('title'))} | **{a['status']}** | {score} | {_cell(latest)} | "
                  f"{_cell(head)} | {_cell(a.get('affected'))} | {draft} |")
    md.append("")
    return md


def render_markdown(data: dict) -> str:
    findings = sort_findings(data.get("findings", []))
    counts = {s: sum(f["severity"] == s for f in findings) for s in SEVERITIES}
    meta = [("Generated (UTC)", data.get("generated_utc")), ("Model", data.get("model")),
            ("Mode", data.get("mode")), ("Focus", data.get("focus") or data.get("task"))]
    md = [f"# Security audit: {data['target']}", ""]
    md += [f"- **{k}:** {v}" for k, v in meta if v]
    md.append("- **Confirmed findings:** " + (", ".join(f"{n} {s}" for s, n in counts.items() if n) or "none"))
    if st := data.get("stats"):
        total = st["candidates_total"] or 1
        md.append(f"- **Pipeline:** {st['work_units']} hunt work units → {st['candidates_total']} candidates → "
                  f"{st['confirmed']} confirmed, {st['refuted']} refuted by the validator "
                  f"({100 * st['refuted'] / total:.0f}% kill rate), {st['unvalidated']} not yet validated")
    md += ["", "## Summary", "", (data.get("summary") or "(no summary)").strip(), ""]

    if findings:
        md += ["## Findings", "", "| # | Severity | CWE | Location | Title |", "|---|---|---|---|---|"]
        md += [f"| {i} | {f['severity']} | {f['cwe']} | `{f['file']}:{f['line']}` | {f['title']} |"
               for i, f in enumerate(findings, 1)]
        md.append("")
        for i, f in enumerate(findings, 1):
            md += _finding_md(i, f)

    if deps := data.get("dependencies"):
        md += _dependencies_md(deps)
    if advisories := data.get("advisories"):
        md += _advisories_md(advisories)
    if notes := [n for n in data.get("notes", []) if n["kind"] == "suspicious-content"]:
        md += ["## Suspicious content in the target", "",
               "Comments that address AI reviewers or make unverifiable safety claims. They were stripped "
               "before analysis. Review them manually: they can indicate an attempt to evade automated review.", ""]
        md += [f"- `{n['file']}:{n['line']}`: {n['text']}" for n in notes]
        md.append("")
    if unval := data.get("unvalidated"):
        md += ["## Not yet validated", ""]
        md += [f"- #{u['id']} [{u['severity']}] {u['title']} `{u['file']}:{u['line']}` ({u['origin']})" for u in unval]
        md.append("")
    if refuted := data.get("refuted"):
        md += ["<details><summary>Refuted candidates ({})</summary>".format(len(refuted)), ""]
        md += [f"- #{r['id']} {r['title']} `{r['file']}:{r['line']}` ({r['origin']}): {r['verdict_reason']}"
               for r in refuted]
        md += ["", "</details>", ""]
    return "\n".join(md)


def write_reports(result: dict, out_dir: Path) -> tuple[Path, Path]:
    """Used by the standalone API agent (python -m vulnscan)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    target = Path(result["repo"]).name
    data = {**result, "target": target, "generated_utc": now.isoformat(timespec="seconds"),
            "findings": sort_findings(result["findings"])}
    stem = f"{target}_{now:%Y%m%dT%H%M%SZ}"
    json_path, md_path = out_dir / f"{stem}.json", out_dir / f"{stem}.md"
    json_path.write_text(json.dumps(data, indent=2))
    md_path.write_text(render_markdown(data))
    return json_path, md_path
