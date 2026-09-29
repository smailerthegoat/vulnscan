"""Score a finished audit against labeled ground truth.

Compares views of the same run so you can see what each stage contributes:
  - semgrep (plain):  a stand-alone Semgrep run, if `reports/<t>/baseline/semgrep.json` exists
                      (written by `python3 -m vulnscan.bench baseline`)
  - sast-only:        every scanner lead the pipeline imported
  - raw candidates:   every candidate before validation (scanners + hunters)
  - pipeline:         validator-confirmed findings (what the report shows)

Matching rules live in vulnscan/scoring.py. Ground truth can be the native format or a RealVuln
ground-truth.json (then scoring follows RealVuln's matcher and its numbers are comparable).

    python3 -m vulnscan.evaluate <target> [--truth eval/ground_truth/<target>.json]
"""
import argparse
import sys
from pathlib import Path

from . import scoring
from .common import ROOT, SEVERITIES, report_dir, target_dir
from .db import connect, rows

SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def score(findings: list[dict], truth: list[dict]) -> dict:
    """Score findings against a list of native-format vulnerabilities (kept for API compatibility)."""
    gt = scoring._load_native({"vulnerabilities": truth}, "adhoc")
    s = scoring.score(findings, gt)
    s["fp_items"] = [r["finding"] for r in s["results"] if r["cls"] == "FP"]
    s["missed"] = [r["entry"] for r in s["results"] if r["cls"] == "FN"]
    return s


def ordered(cands: list[dict]) -> list[dict]:
    """Deterministic order for greedy matching: most severe first, then location."""
    return sorted(cands, key=lambda c: (SEV_RANK.get(c.get("verdict_severity") or c["severity"], 9),
                                        c["file"], c["line"], c["id"]))


def views_for(target: str) -> dict[str, list[dict] | None]:
    """Findings per view. A view is None when its data doesn't exist for this target."""
    out: dict[str, list[dict] | None] = {}
    base = report_dir(target) / "baseline" / "semgrep.json"
    out["semgrep (plain)"] = (scoring.semgrep_findings(base, target_dir(target), f"repos/{target}/")
                              if base.exists() else None)
    if not (report_dir(target) / "state.db").exists():
        out.update({"sast-only": None, "raw candidates": None, "pipeline (confirmed)": None})
        return out
    allc = ordered(rows(connect(target), "SELECT * FROM candidates"))
    for c in allc:
        c["severity"] = c.get("verdict_severity") or c["severity"]
    out["sast-only"] = [c for c in allc if c["origin"].startswith("sast")
                        or any(o.startswith("sast") for o in c["also_reported_by"].split(","))]
    out["raw candidates"] = allc
    out["pipeline (confirmed)"] = [c for c in allc if c["status"] == "confirmed"]
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="vulnscan.evaluate")
    ap.add_argument("target")
    ap.add_argument("--truth", type=Path)
    args = ap.parse_args(argv)
    truth_path = args.truth or ROOT / "eval" / "ground_truth" / f"{args.target}.json"
    gt = scoring.load(truth_path, args.target)

    views = {k: v for k, v in views_for(args.target).items() if v is not None}
    results = {k: scoring.score(v, gt) for k, v in views.items()}
    rel = truth_path.relative_to(ROOT) if ROOT in truth_path.resolve().parents else truth_path

    md = [f"# Evaluation: {args.target}", "",
          f"Ground truth: `{rel}` ({gt.fmt} format, {len(gt.vulns)} vulnerabilities, {len(gt.traps)} traps)", "",
          "| View | TP | FP | FN | TN | Precision | Recall | F1 | F3 |", "|---|---|---|---|---|---|---|---|---|"]
    for k, s in results.items():
        md.append(f"| {k} | {s['tp']} | {s['fp']} | {s['fn']} | {s['tn']} | {s['precision']:.2f} | "
                  f"{s['recall']:.2f} | {s['f1']:.2f} | {s['f3']:.2f} |")
    table_end = len(md)
    if "pipeline (confirmed)" in results:
        pipe = results["pipeline (confirmed)"]
        missed = [r["entry"] for r in pipe["results"] if r["cls"] == "FN"]
        fps = [r for r in pipe["results"] if r["cls"] == "FP"]
        md += ["", "## Missed by the pipeline", ""]
        md += [f"- `{e.file}:{e.start}` {'/'.join(sorted(e.cwes or []))[:40]} {e.title}" for e in missed] or ["- none"]
        md += ["", "## False positives in the report", ""]
        md += [f"- #{r['finding']['id']} `{r['finding']['file']}:{r['finding']['line']}` {r['finding']['cwe']} "
               f"{r['finding']['title']}" + (" (on a labeled trap)" if r["entry"] else "") for r in fps] or ["- none"]
        refuted = [c for c in views["raw candidates"] if c["status"] == "refuted"
                   and any(scoring.matches({**c, "file": scoring.norm_path(c["file"])}, e) for e in gt.vulns)]
        md += ["", "## Real vulnerabilities the validator refuted", ""]
        md += [f"- #{c['id']} `{c['file']}:{c['line']}` {c['title']}: {c['verdict_reason']}" for c in refuted] or ["- none"]
        unvalidated = sum(c["status"] == "candidate" for c in views["raw candidates"])
        if unvalidated:
            md += ["", f"> {unvalidated} candidate(s) were never validated; the pipeline view excludes them."]

    out = report_dir(args.target) / "eval.md"
    out.write_text("\n".join(md) + "\n")
    print("\n".join(md[4:table_end]))
    print(f"\nwrote {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
