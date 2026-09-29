"""Audit many repositories unattended by driving headless Claude Code (`claude -p`).

Uses your Claude Code login (subscription), not an API key. Each target runs the /vuln-audit skill
in its own session; a small worker pool bounds concurrency so you stay within rate limits.
Finished targets are skipped on re-runs (resume), unless --force.

    python3 -m vulnscan.batch                                   # every dir in targets/
    python3 -m vulnscan.batch demo_target flask-app             # named targets
    python3 -m vulnscan.batch https://github.com/org/repo.git   # shallow-clone into targets/ first
    python3 -m vulnscan.batch --list repos.txt --parallel 3 --diff origin/main
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .common import REPORTS, ROOT, TARGETS, report_dir, utcnow


def resolve_item(item: str) -> str:
    """Return a target name, cloning git URLs into targets/ when needed."""
    if re.match(r"^(https?://|git@|ssh://)", item):
        from .targets import add
        print(f"[clone] {item}")
        return add(item)
    return item


def audit(name: str, args) -> dict:
    out = report_dir(name)
    if (out / "findings.json").exists() and not args.force:
        return {"target": name, "status": "skipped (already audited)"}
    if args.force:
        from .db import main as db_main
        db_main([name, "reset"])
    prompt = f"/vuln-audit {name}"
    if args.diff:
        prompt += f" --diff {args.diff}"
    if args.quick:
        prompt += " --quick"
    if args.focus:
        prompt += f" {args.focus}"
    cmd = ["claude", "-p", prompt, "--output-format", "json"]
    if args.model:
        cmd += ["--model", args.model]
    env = {**os.environ, "PATH": f"{ROOT / '.venv' / 'bin'}{os.pathsep}{os.environ.get('PATH', '')}"}
    start = time.monotonic()
    try:
        r = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True, timeout=args.timeout)
    except subprocess.TimeoutExpired:
        return {"target": name, "status": f"timeout after {args.timeout}s"}
    (out / "run.log").write_text(r.stderr)
    (out / "run.json").write_text(r.stdout)
    res = {"target": name, "seconds": round(time.monotonic() - start)}
    try:
        meta = json.loads(r.stdout)
        res.update(status="error" if meta.get("is_error") else "ok", turns=meta.get("num_turns"),
                   cost_usd_equiv=meta.get("total_cost_usd"))
    except json.JSONDecodeError:
        res["status"] = f"failed (exit {r.returncode})"
    try:
        stats = json.loads((out / "findings.json").read_text())["stats"]
        res.update(confirmed=stats["confirmed"], refuted=stats["refuted"])
    except (OSError, json.JSONDecodeError, KeyError):
        pass
    return res


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="vulnscan.batch", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("items", nargs="*", help="target names under targets/ or git URLs")
    ap.add_argument("--list", type=Path, help="file with one target name or git URL per line")
    ap.add_argument("--parallel", type=int, default=2)
    ap.add_argument("--timeout", type=int, default=3600, help="seconds per target")
    ap.add_argument("--diff", metavar="REF", help="incremental mode: only audit changes since REF")
    ap.add_argument("--quick", action="store_true", help="cheap pass: few work units, validate high+ only")
    ap.add_argument("--focus", default="", help="extra focus passed to the skill")
    ap.add_argument("--model", help="model for the orchestrating session (subagents set their own)")
    ap.add_argument("--force", action="store_true", help="re-audit targets that already have a report")
    args = ap.parse_args(argv)

    items = list(args.items)
    if args.list:
        items += [l.strip() for l in args.list.read_text().splitlines() if l.strip() and not l.startswith("#")]
    if not items:
        items = sorted(p.name for p in TARGETS.iterdir() if p.is_dir())
    names = [resolve_item(i) for i in items]
    print(f"[batch] {len(names)} target(s), parallel={args.parallel}")

    results = []
    with ThreadPoolExecutor(max_workers=args.parallel) as pool:
        futs = {pool.submit(audit, n, args): n for n in names}
        for fut in as_completed(futs):
            res = fut.result()
            results.append(res)
            print(f"[done] {res['target']}: {res['status']}")

    lines = [f"# Batch audit {utcnow()}", "", "| Target | Status | Confirmed | Refuted | Turns | Time (s) |",
             "|---|---|---|---|---|---|"]
    for r in sorted(results, key=lambda r: r["target"]):
        lines.append(f"| {r['target']} | {r['status']} | {r.get('confirmed', '-')} | {r.get('refuted', '-')} | "
                     f"{r.get('turns', '-')} | {r.get('seconds', '-')} |")
    (REPORTS / "batch_summary.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0 if all(r["status"].startswith(("ok", "skipped")) for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
