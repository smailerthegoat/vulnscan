"""Benchmark suites of labeled real repositories (RealVuln), pinned for reproducibility.

    python3 -m vulnscan.bench fetch realvuln [--ref main] [--language python,typescript] [--framework flask]
                                             [--repos a,b] [--limit N] [--human-only] [--with-reference] [--suite NAME]
    python3 -m vulnscan.bench clone <suite> [--repos a,b] [--parallel 4]
    python3 -m vulnscan.bench baseline <suite> [--config p/default ...] [--reference]
    python3 -m vulnscan.bench sast <suite> [--offline]
    python3 -m vulnscan.bench run <suite> [--parallel 2] [--quick] [--force] [--timeout 3600]
    python3 -m vulnscan.bench status <suite>
    then: python3 -m vulnscan.scorecard <suite>

`fetch` resolves the benchmark ref to a commit and downloads each repository's ground-truth.json unchanged
into eval/ground_truth/<repo>.json, plus a suite manifest (eval/suites/<suite>.json) with the pinned
commit of every repository and a hash of every ground-truth file. `clone` checks out exactly those
commits (git hooks disabled; nothing from the repos is executed). `baseline` runs plain Semgrep, or with
--reference uses the Semgrep results RealVuln published for the same commits, which lets you score
without cloning and check this scorer against RealVuln's leaderboard. `sast` runs the pipeline's
deterministic stages only (no LLM); `run` runs the full /vuln-audit pipeline through vulnscan.batch.

RealVuln (https://github.com/kolega-ai/Real-Vuln-Benchmark, Apache-2.0) by Kolega.ai.
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import common
from .common import ROOT, utcnow

REALVULN = "kolega-ai/Real-Vuln-Benchmark"
SUITES = ROOT / "eval" / "suites"
GROUND_TRUTH = ROOT / "eval" / "ground_truth"
CACHE = ROOT / "eval" / "cache"
SEARCH_PATH = os.pathsep.join([str(ROOT / ".venv" / "bin"), os.environ.get("PATH", "")])


def _get(url: str, raw: bool = False):
    req = urllib.request.Request(url, headers={"User-Agent": "vulnscan-bench", "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read()
    return data if raw else json.loads(data)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_suite(name: str) -> dict:
    p = SUITES / f"{common.check_target_name(name)}.json"
    if not p.exists():
        raise SystemExit(f"no suite {p.relative_to(ROOT)}; run `python3 -m vulnscan.bench fetch realvuln` first")
    return json.loads(p.read_text())


def selected(suite: dict, repos: str | None) -> list[dict]:
    if not repos:
        return suite["repos"]
    want = set(repos.split(","))
    out = [r for r in suite["repos"] if r["target"] in want]
    if missing := want - {r["target"] for r in out}:
        raise SystemExit(f"not in suite: {', '.join(sorted(missing))}")
    return out


# --- fetch ---------------------------------------------------------------------------------------

def fetch_realvuln(args) -> dict:
    commit = _get(f"https://api.github.com/repos/{REALVULN}/commits/{args.ref}")["sha"]
    raw = f"https://raw.githubusercontent.com/{REALVULN}/{commit}/"
    manifest = _get(raw + "benchmark-manifest.json")
    langs = set(args.language.split(",")) if args.language else None
    fws = set(args.framework.split(",")) if args.framework else None
    names = set(args.repos.split(",")) if args.repos else None
    picked = [(slug, m) for slug, m in sorted(manifest["repos"].items())
              if (not langs or m.get("language") in langs) and (not fws or (m.get("framework") or "none") in fws)
              and (not names or slug in names) and (not args.human_only or m.get("authorship") == "human_authored")]
    if args.limit:
        picked = picked[:args.limit]
    if not picked:
        raise SystemExit("no repositories match the filters")
    GROUND_TRUTH.mkdir(parents=True, exist_ok=True)
    ref_dir = CACHE / "realvuln" / commit[:12]

    def one(item):
        slug, m = item
        common.check_target_name(slug)
        gt = _get(raw + f"ground-truth/{slug}/ground-truth.json", raw=True)
        (GROUND_TRUTH / f"{slug}.json").write_bytes(gt)
        entry = {"target": slug, "repo_url": m["repo_url"], "commit_sha": m["commit_sha"],
                 "language": m.get("language"), "framework": m.get("framework"), "authorship": m.get("authorship"),
                 "vulns": m.get("vulnerable_findings"), "traps": m.get("false_positive_traps"),
                 "non_scoring": m.get("non_scoring"), "ground_truth": f"eval/ground_truth/{slug}.json",
                 "gt_sha256": sha256(gt)}
        if args.with_reference:
            try:
                res = _get(raw + f"scan-results/{slug}/semgrep/results.json", raw=True)
                (ref_dir / slug).mkdir(parents=True, exist_ok=True)
                (ref_dir / slug / "semgrep.json").write_bytes(res)
                entry["reference_semgrep"] = str((ref_dir / slug / "semgrep.json").relative_to(ROOT))
            except OSError:
                entry["reference_semgrep"] = None
        return entry

    with ThreadPoolExecutor(max_workers=8) as pool:
        repos = list(pool.map(one, picked))
    suite = {
        "name": args.suite,
        "source": {"benchmark": "RealVuln", "repo": f"https://github.com/{REALVULN}", "ref": args.ref,
                   "commit": commit, "benchmark_version": manifest.get("benchmark_version"),
                   "ground_truth_version": manifest.get("ground_truth_version"),
                   "release_date": manifest.get("release_date"), "license": "Apache-2.0", "fetched_utc": utcnow()},
        "filters": {k: getattr(args, k) for k in ("language", "framework", "repos", "limit", "human_only")},
        "repos": repos,
    }
    SUITES.mkdir(parents=True, exist_ok=True)
    (SUITES / f"{args.suite}.json").write_text(json.dumps(suite, indent=2) + "\n")
    return suite


# --- clone / baseline / sast / run ---------------------------------------------------------------

def clone(suite: dict, repos: str | None, parallel: int) -> list[str]:
    from .advisory import read_git_head
    from .targets import add

    def one(r):
        dest = common.TARGETS / r["target"]
        if dest.exists():
            head = read_git_head(dest)
            return f"{r['target']}: present" + ("" if head == r["commit_sha"] else f" (HEAD {head} != pinned!)")
        try:
            add(r["repo_url"], name=r["target"], ref=r["commit_sha"])
        except (subprocess.CalledProcessError, OSError) as e:
            return f"{r['target']}: FAILED ({e})"
        note = source_note(dest)
        return f"{r['target']}: cloned at {r['commit_sha'][:12]}" + (f" (WARNING: {note})" if note else "")

    with ThreadPoolExecutor(max_workers=parallel) as pool:
        return list(pool.map(one, selected(suite, repos)))


def source_note(root: Path) -> str | None:
    """Flag pinned trees with no scannable source (e.g. the code ships only inside a .zip)."""
    from .stacks import detect
    if detect(root)["languages"]:
        return None
    archives = sorted(p.name for p in root.iterdir() if p.suffix in (".zip", ".tgz", ".gz", ".tar", ".7z", ".rar"))
    return "no source files at the pinned commit" + (f"; code is inside {', '.join(archives)}" if archives else "")


def semgrep_version() -> str:
    exe = shutil.which("semgrep", path=SEARCH_PATH)
    if not exe:
        return ""
    return subprocess.run([exe, "--version"], capture_output=True, text=True).stdout.strip()


def baseline(suite: dict, repos: str | None, configs: list[str], reference: bool) -> list[str]:
    out = []
    version = "" if reference else semgrep_version()
    if not reference and not version:
        raise SystemExit("semgrep is not installed (pip install semgrep)")
    for r in selected(suite, repos):
        dest = common.REPORTS / r["target"] / "baseline"
        dest.mkdir(parents=True, exist_ok=True)
        if reference:
            src = r.get("reference_semgrep")
            if not src or not (ROOT / src).exists():
                out.append(f"{r['target']}: no reference results (fetch with --with-reference)")
                continue
            shutil.copyfile(ROOT / src, dest / "semgrep.json")
            meta = {"source": "RealVuln published Semgrep results", "file": src, "suite_commit": suite["source"]["commit"]}
        else:
            root = common.TARGETS / r["target"]
            if not root.is_dir():
                out.append(f"{r['target']}: not cloned")
                continue
            cmd = [shutil.which("semgrep", path=SEARCH_PATH), "scan", "--json", "--quiet", "--metrics", "off"]
            for c in configs:
                cmd += ["--config", c]
            start = time.monotonic()
            res = subprocess.run(cmd + ["."], cwd=root, capture_output=True, text=True, timeout=3600,
                                 env={**os.environ, "SEMGREP_SEND_METRICS": "off"})
            (dest / "semgrep.json").write_text(res.stdout or "{}")
            meta = {"source": "semgrep", "version": version, "configs": configs, "exit": res.returncode,
                    "seconds": round(time.monotonic() - start, 1), "commit": r["commit_sha"]}
        meta["created_utc"] = utcnow()
        (dest / "meta.json").write_text(json.dumps(meta, indent=2))
        try:
            n = len(json.loads((dest / "semgrep.json").read_text() or "{}").get("results", []))
        except json.JSONDecodeError:
            n = "unparseable"
        out.append(f"{r['target']}: {n} results ({meta['source']})")
    return out


def sast(suite: dict, repos: str | None, offline: bool) -> list[str]:
    from .sast import main as sast_main
    out = []
    for r in selected(suite, repos):
        if not (common.TARGETS / r["target"]).is_dir():
            out.append(f"{r['target']}: not cloned")
            continue
        sast_main([r["target"]] + (["--offline"] if offline else []))
        out.append(f"{r['target']}: leads imported")
    return out


def run(suite: dict, args) -> int:
    from .batch import main as batch_main
    names = [r["target"] for r in selected(suite, args.repos) if (common.TARGETS / r["target"]).is_dir()]
    if not names:
        raise SystemExit("nothing cloned; run `bench clone` first")
    argv = names + ["--parallel", str(args.parallel), "--timeout", str(args.timeout)]
    if args.force:
        argv.append("--force")
    if args.quick:
        argv.append("--quick")
    return batch_main(argv)


def status(suite: dict) -> list[str]:
    from .advisory import read_git_head
    lines = ["| Repo | Lang | Cloned | Baseline | Leads | Audited | Note |", "|---|---|---|---|---|---|---|"]
    for r in suite["repos"]:
        t, rep = common.TARGETS / r["target"], common.REPORTS / r["target"]
        head = read_git_head(t) if t.is_dir() else None
        cloned = "no" if not t.is_dir() else ("yes" if head == r["commit_sha"] else f"wrong commit {str(head)[:8]}")
        base = json.loads((rep / "baseline" / "meta.json").read_text())["source"] if (rep / "baseline" / "meta.json").exists() else "-"
        lines.append(f"| {r['target']} | {r['language']} | {cloned} | {base} | {'yes' if (rep / 'sast').is_dir() else '-'} | "
                     f"{'yes' if (rep / 'findings.json').exists() else '-'} | {(source_note(t) or '') if t.is_dir() else ''} |")
    return lines


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="vulnscan.bench", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("fetch"); p.add_argument("benchmark", choices=["realvuln"])
    p.add_argument("--ref", default="main"); p.add_argument("--language"); p.add_argument("--framework")
    p.add_argument("--repos"); p.add_argument("--limit", type=int); p.add_argument("--human-only", action="store_true")
    p.add_argument("--with-reference", action="store_true", help="also download RealVuln's published Semgrep results")
    p.add_argument("--suite", default="realvuln")
    for name in ("clone", "baseline", "sast", "run", "status"):
        p = sub.add_parser(name); p.add_argument("suite")
        if name != "status":
            p.add_argument("--repos", help="comma-separated subset")
        if name in ("clone", "run"):
            p.add_argument("--parallel", type=int, default=4 if name == "clone" else 2)
        if name == "baseline":
            p.add_argument("--config", action="append", help="Semgrep config (default p/default)")
            p.add_argument("--reference", action="store_true")
        if name == "sast":
            p.add_argument("--offline", action="store_true")
        if name == "run":
            p.add_argument("--quick", action="store_true"); p.add_argument("--force", action="store_true")
            p.add_argument("--timeout", type=int, default=3600)
    args = ap.parse_args(argv)

    if args.cmd == "fetch":
        s = fetch_realvuln(args)
        vulns = sum(r["vulns"] or 0 for r in s["repos"])
        print(f"suite {args.suite}: {len(s['repos'])} repos, {vulns} labeled vulnerabilities, "
              f"RealVuln {s['source']['benchmark_version']} @ {s['source']['commit'][:12]}")
        print(f"wrote eval/suites/{args.suite}.json and {len(s['repos'])} ground-truth files")
        return 0
    suite = load_suite(args.suite)
    if args.cmd == "clone":
        print("\n".join(clone(suite, args.repos, args.parallel)))
    elif args.cmd == "baseline":
        print("\n".join(baseline(suite, args.repos, args.config or ["p/default"], args.reference)))
    elif args.cmd == "sast":
        print("\n".join(sast(suite, args.repos, args.offline)))
    elif args.cmd == "run":
        return run(suite, args)
    elif args.cmd == "status":
        print("\n".join(status(suite)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
