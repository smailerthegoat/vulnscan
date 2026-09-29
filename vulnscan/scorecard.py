"""Reproducible scorecard: the vulnscan pipeline vs plain Semgrep across many labeled repositories.

    python3 -m vulnscan.scorecard <suite> [--strict] [--bootstrap 2000] [--seed 1] [--out DIR]
    python3 -m vulnscan.scorecard --targets demo_target other_target

Views scored per repository (a view is skipped for a repo when its results don't exist):
  semgrep          plain Semgrep (reports/<t>/baseline/semgrep.json from `vulnscan.bench baseline`)
  vulnscan-leads   the pipeline's deterministic scanner leads (Semgrep packs + curated rules + Bandit)
  vulnscan-raw     every candidate before validation (scanners + hunters)
  vulnscan         validator-confirmed findings of a finished audit (reports/<t>/findings.json exists)

Matching is RealVuln's (vulnscan/scoring.py): file + CWE in the entry's acceptable set + line within
±10, each entry consumed once. Aggregates are micro-averaged (counts summed over repos); F3 weights
recall 9x (RealVuln's headline metric). 95% confidence intervals come from a percentile bootstrap
over repositories with a fixed seed, so the same inputs always give the same scorecard. --strict
counts every vulnerability in a repo without results as a miss (RealVuln's strict mode); the default
scores each view on the repos it covers and reports coverage.

Outputs: eval/scorecards/<suite>/scorecard.md, scorecard.json, per_repo.csv
"""
import argparse
import csv
import hashlib
import json
import math
import platform
import random
import re
import sqlite3
import sys
from pathlib import Path

from . import __version__, common, scoring
from .common import ROOT, SEVERITIES, utcnow

VIEWS = {
    "semgrep": "Plain Semgrep",
    "vulnscan-leads": "vulnscan scanner leads (no LLM)",
    "vulnscan-raw": "vulnscan candidates (before validation)",
    "vulnscan": "vulnscan pipeline (validated)",
}
PAIRS = [("vulnscan", "semgrep"), ("vulnscan-leads", "semgrep"), ("vulnscan", "vulnscan-leads")]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


# --- per-repo inputs -----------------------------------------------------------------------------

def _candidates(target: str) -> list[dict] | None:
    db = common.REPORTS / target / "state.db"
    if not db.exists():
        return None
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    rows = [dict(r) for r in conn.execute("SELECT * FROM candidates")]
    conn.close()
    for c in rows:
        c["severity"] = c.get("verdict_severity") or c["severity"]
    return sorted(rows, key=lambda c: (SEV_RANK.get(c["severity"], 9), c["file"], c["line"], c["id"]))


def view_findings(target: str, as_published: bool = False) -> dict[str, list[dict] | None]:
    rep = common.REPORTS / target
    base = rep / "baseline" / "semgrep.json"
    root = common.TARGETS / target
    strip = None if as_published else f"repos/{target}/"
    out: dict[str, list[dict] | None] = {
        "semgrep": scoring.semgrep_findings(base, root if root.is_dir() else None, strip) if base.exists() else None}
    cands = _candidates(target)
    is_lead = lambda c: c["origin"].startswith("sast") or any(o.startswith("sast") for o in c["also_reported_by"].split(","))
    out["vulnscan-leads"] = [c for c in cands if is_lead(c)] if cands is not None and (rep / "sast").is_dir() else None
    finished = (rep / "findings.json").exists() and cands is not None
    out["vulnscan-raw"] = cands if finished else None
    out["vulnscan"] = [c for c in cands if c["status"] == "confirmed"] if finished else None
    return out


def run_meta(target: str) -> dict:
    rep = common.REPORTS / target
    meta = {}
    try:
        run = json.loads((rep / "run.json").read_text())
        meta.update(cost_usd=run.get("total_cost_usd"), turns=run.get("num_turns"),
                    seconds=round((run.get("duration_ms") or 0) / 1000) or None)
    except (OSError, json.JSONDecodeError):
        pass
    try:
        meta["baseline"] = json.loads((rep / "baseline" / "meta.json").read_text())
    except (OSError, json.JSONDecodeError):
        pass
    return meta


# --- statistics ----------------------------------------------------------------------------------

def aggregate(items: list[dict]) -> dict:
    """Micro-averaged metrics over per-repo score dicts."""
    c = {k: sum(i[k] for i in items) for k in ("tp", "fp", "fn", "tn")}
    m = scoring.metrics(c)
    weighted = [i for i in items if i.get("w_tp") is not None]
    if weighted:
        w = {k: sum(i[k] for i in weighted) for k in ("w_tp", "w_fp", "w_fn")}
        p, r = scoring.div(w["w_tp"], w["w_tp"] + w["w_fp"]), scoring.div(w["w_tp"], w["w_tp"] + w["w_fn"])
        m["wf3"] = scoring.fbeta(p, r, 3)
    else:
        m["wf3"] = None
    return {**c, **m}


def bootstrap(items: list[dict], stat, b: int, seed: int) -> tuple[float, float] | None:
    if len(items) < 2 or b <= 0:
        return None
    rng = random.Random(seed)
    vals = sorted(stat([items[rng.randrange(len(items))] for _ in items]) for _ in range(b))
    return vals[int(0.025 * (b - 1))], vals[int(math.ceil(0.975 * (b - 1)))]


def sign_test(wins: int, losses: int) -> float:
    n = wins + losses
    if n == 0:
        return 1.0
    k = min(wins, losses)
    return min(1.0, 2 * sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n)


def miss_all(gt: scoring.GroundTruth) -> dict:
    """Score of a repo with no results (strict mode)."""
    return {k: v for k, v in scoring.score([], gt).items() if k != "results"}


# --- scorecard -----------------------------------------------------------------------------------

def build(targets: list[str], strict: bool, b: int, seed: int, suite: dict | None = None,
          as_published: bool = False) -> dict:
    per_repo, classes = [], {v: {} for v in VIEWS}
    for t in targets:
        gt_path = ROOT / "eval" / "ground_truth" / f"{t}.json"
        gt = scoring.load(gt_path, t)
        row = {"target": t, "format": gt.fmt, "vulns": len(gt.vulns), "traps": len(gt.traps),
               "gt_sha256": hashlib.sha256(gt_path.read_bytes()).hexdigest(), "views": {}, **run_meta(t)}
        if (common.TARGETS / t).is_dir():
            from .bench import source_note
            row["note"] = source_note(common.TARGETS / t)
        for view, findings in view_findings(t, as_published).items():
            if findings is None:
                row["views"][view] = None
                continue
            s = scoring.score(findings, gt)
            for r in s["results"]:
                if r["cls"] in ("TP", "FN") and r["entry"].is_vulnerable:
                    k = r["entry"].vclass or "other"
                    tp, total = classes[view].get(k, (0, 0))
                    classes[view][k] = (tp + (r["cls"] == "TP"), total + 1)
            row["views"][view] = {k: v for k, v in s.items() if k != "results"} | {"findings": len(findings)}
        per_repo.append(row)

    views = {}
    for view, label in VIEWS.items():
        items = [r["views"][view] for r in per_repo if r["views"][view] is not None]
        if not items:
            continue  # no results for this view anywhere: omit rather than score as all misses
        if strict:
            items += [miss_all(scoring.load(ROOT / "eval" / "ground_truth" / f"{r['target']}.json", r["target"]))
                      for r in per_repo if r["views"][view] is None]
        if not items:
            continue
        agg = aggregate(items)
        views[view] = {
            "label": label, "repos_scored": sum(r["views"][view] is not None for r in per_repo),
            "repos_total": len(per_repo), **agg,
            "macro_f3": sum(i["f3"] for i in items) / len(items),
            "ci95": {m: bootstrap(items, lambda s, m=m: aggregate(s)[m], b, seed)
                     for m in ("precision", "recall", "f3")},
            "per_class_recall": {k: {"tp": tp, "total": n, "recall": tp / n}
                                 for k, (tp, n) in sorted(classes[view].items())},
        }
    pairs = []
    for a, bview in PAIRS:
        both = [r for r in per_repo if r["views"].get(a) is not None and r["views"].get(bview) is not None]
        if not both:
            continue
        deltas = [r["views"][a]["f3"] - r["views"][bview]["f3"] for r in both]
        wins, losses = sum(d > 1e-9 for d in deltas), sum(d < -1e-9 for d in deltas)
        pairs.append({"a": a, "b": bview, "repos": len(both), "mean_delta_f3": sum(deltas) / len(deltas),
                      "ci95": bootstrap(deltas, lambda s: sum(s) / len(s), b, seed),
                      "wins": wins, "ties": len(deltas) - wins - losses, "losses": losses,
                      "sign_test_p": sign_test(wins, losses)})
    return {"generated_utc": utcnow(), "strict": strict, "as_published": as_published, "bootstrap": b, "seed": seed,
            "views": views, "pairs": pairs,
            "per_repo": per_repo, "provenance": provenance(per_repo, suite)}


def provenance(per_repo: list[dict], suite: dict | None) -> dict:
    models = {}
    for p in sorted((ROOT / ".claude" / "agents").glob("*.md")):
        m = re.search(r"(?m)^model:\s*(\S+)", p.read_text())
        models[p.stem] = m.group(1) if m else "inherit"
    rules = hashlib.sha256(b"".join(p.read_bytes() for p in sorted((ROOT / "rules").glob("*.yml")))).hexdigest()
    gt = hashlib.sha256("".join(r["target"] + r["gt_sha256"] for r in per_repo).encode()).hexdigest()
    semgrep = sorted({f"{(r.get('baseline') or {}).get('source', '-')} {(r.get('baseline') or {}).get('version', '')} "
                      f"{' '.join((r.get('baseline') or {}).get('configs', []))}".strip() for r in per_repo})
    return {"vulnscan_version": __version__, "python": platform.python_version(), "agent_models": models,
            "curated_rules_sha256": rules, "ground_truth_sha256": gt, "baselines": semgrep,
            "suite": (suite or {}).get("source"), "command": " ".join(["python3 -m vulnscan.scorecard", *sys.argv[1:]])}


# --- rendering -----------------------------------------------------------------------------------

def _pct(x) -> str:
    return "-" if x is None else f"{100 * x:.1f}"


def _ci(ci) -> str:
    return "" if not ci else f" [{100 * ci[0]:.1f}–{100 * ci[1]:.1f}]"


def render(card: dict, title: str) -> str:
    prov = card["provenance"]
    src = prov.get("suite") or {}
    md = [f"# Scorecard: {title}", "",
          f"Generated {card['generated_utc']} · {'strict' if card['strict'] else 'standard'} scoring · "
          f"{card['bootstrap']} bootstrap resamples (seed {card['seed']})"]
    if src:
        md.append(f"Ground truth: {src.get('benchmark')} {src.get('benchmark_version')} @ `{str(src.get('commit'))[:12]}` "
                  f"({len(card['per_repo'])} repositories, "
                  f"{sum(r['vulns'] for r in card['per_repo'])} labeled vulnerabilities, "
                  f"{sum(r['traps'] for r in card['per_repo'])} false-positive traps)")
    md += ["", "## Headline", "",
           "Micro-averaged over repositories. Brackets: 95% bootstrap confidence interval. F3 weights recall 9× "
           "over precision (RealVuln's primary metric); wF3 weights each vulnerability by its CVSS score.", "",
           "| View | Repos | TP | FP | FN | Precision | Recall | F1 | F3 | wF3 | FP rate on traps |",
           "|---|---|---|---|---|---|---|---|---|---|---|"]
    for v in card["views"].values():
        md.append(f"| {v['label']} | {v['repos_scored']}/{v['repos_total']} | {v['tp']} | {v['fp']} | {v['fn']} | "
                  f"{_pct(v['precision'])}{_ci(v['ci95']['precision'])} | {_pct(v['recall'])}{_ci(v['ci95']['recall'])} | "
                  f"{_pct(v['f1'])} | **{_pct(v['f3'])}**{_ci(v['ci95']['f3'])} | {_pct(v['wf3'])} | {_pct(v['fpr'])} |")
    if card["pairs"]:
        md += ["", "## Head to head (paired by repository)", "",
               "Per-repo F3 difference on repositories both views cover; the sign test asks whether wins and "
               "losses could be a coin flip.", "",
               "| Comparison | Repos | Mean ΔF3 | Wins / ties / losses | Sign test p |", "|---|---|---|---|---|"]
        for p in card["pairs"]:
            md.append(f"| {VIEWS[p['a']]} vs {VIEWS[p['b']]} | {p['repos']} | {100 * p['mean_delta_f3']:+.1f}"
                      f"{_ci(p['ci95'])} | {p['wins']} / {p['ties']} / {p['losses']} | {p['sign_test_p']:.3g} |")
    classes = sorted({k for v in card["views"].values() for k in v["per_class_recall"]})
    if classes:
        md += ["", "## Recall by vulnerability class", "",
               "| Class | " + " | ".join(v["label"] for v in card["views"].values()) + " |",
               "|---|" + "---|" * len(card["views"])]
        for k in classes:
            cells = []
            for v in card["views"].values():
                c = v["per_class_recall"].get(k)
                cells.append(f"{c['tp']}/{c['total']} ({100 * c['recall']:.0f}%)" if c else "-")
            md.append(f"| {k} | " + " | ".join(cells) + " |")
    md += ["", "## Per repository (F3)", "",
           "| Repo | Vulns | Traps | " + " | ".join(VIEWS) + " | Pipeline cost (USD eq.) | Note |",
           "|---|---|---|" + "---|" * len(VIEWS) + "---|---|"]
    for r in card["per_repo"]:
        cells = [_pct(r["views"][v]["f3"]) if r["views"].get(v) else "-" for v in VIEWS]
        cost = f"{r['cost_usd']:.2f}" if r.get("cost_usd") is not None else "-"
        md.append(f"| {r['target']} | {r['vulns']} | {r['traps']} | " + " | ".join(cells) + f" | {cost} | "
                  f"{r.get('note') or ''} |")
    md += ["", "## Reproduce", "", "```"]
    if src:
        md.append(f"python3 -m vulnscan.bench fetch realvuln --ref {src.get('commit')}")
        md.append("python3 -m vulnscan.bench clone <suite> && python3 -m vulnscan.bench baseline <suite>")
        md.append("python3 -m vulnscan.bench sast <suite> && python3 -m vulnscan.bench run <suite>")
    md += [prov["command"], "```", "",
           f"vulnscan {prov['vulnscan_version']} · Python {prov['python']} · curated rules "
           f"`{prov['curated_rules_sha256'][:12]}` · ground truth `{prov['ground_truth_sha256'][:12]}` · "
           f"baselines: {'; '.join(prov['baselines'])} · agent models: "
           + ", ".join(f"{k}={v}" for k, v in prov["agent_models"].items()), ""]
    return "\n".join(md)


def write_csv(card: dict, path: Path) -> None:
    with path.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["repo", "view", "tp", "fp", "fn", "tn", "precision", "recall", "f1", "f3", "wf3", "findings"])
        for r in card["per_repo"]:
            for v in VIEWS:
                s = r["views"].get(v)
                if s:
                    w.writerow([r["target"], v, s["tp"], s["fp"], s["fn"], s["tn"], f"{s['precision']:.4f}",
                                f"{s['recall']:.4f}", f"{s['f1']:.4f}", f"{s['f3']:.4f}",
                                "" if s["wf3"] is None else f"{s['wf3']:.4f}", s["findings"]])


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="vulnscan.scorecard", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("suite", nargs="?")
    ap.add_argument("--targets", nargs="+", help="score these targets (ground truth in eval/ground_truth/) instead")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--bootstrap", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--as-published", action="store_true",
                    help="score baseline paths exactly as published (reproduces RealVuln's leaderboard, including "
                         "its runs whose paths carry a repos/<name>/ prefix and therefore never match)")
    args = ap.parse_args(argv)
    if bool(args.suite) == bool(args.targets):
        ap.error("give a suite name or --targets")
    if args.suite:
        from .bench import load_suite
        suite = load_suite(args.suite)
        targets, title = [r["target"] for r in suite["repos"]], args.suite
    else:
        suite, targets, title = None, args.targets, "adhoc"
    card = build(targets, args.strict, args.bootstrap, args.seed, suite, args.as_published)
    out = args.out or ROOT / "eval" / "scorecards" / (title + ("-strict" if args.strict else "")
                                                      + ("-as-published" if args.as_published else ""))
    out.mkdir(parents=True, exist_ok=True)
    (out / "scorecard.json").write_text(json.dumps(card, indent=2, default=str))
    (out / "scorecard.md").write_text(render(card, title))
    write_csv(card, out / "per_repo.csv")
    for v in card["views"].values():
        print(f"{v['label']:<42} repos {v['repos_scored']:>3}/{v['repos_total']:<3} P {_pct(v['precision']):>5} "
              f"R {_pct(v['recall']):>5} F3 {_pct(v['f3']):>5}{_ci(v['ci95']['f3'])}")
    print(f"wrote {out.relative_to(ROOT) if ROOT in out.resolve().parents else out}/scorecard.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
