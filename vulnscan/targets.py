"""Manage audit targets (operator action; deliberately not pre-approved for agents).

    python3 -m vulnscan.targets add <git-url | local-path> [--name NAME] [--ref BRANCH|TAG|COMMIT-SHA]
    python3 -m vulnscan.targets remove <name>
    python3 -m vulnscan.targets list

Clones are shallow, skip submodules, and run with git hooks disabled, so adding a target never
executes code from it.
"""
import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

from . import common
from .common import SKIP_DIRS, check_target_name


def add(source: str, name: str | None = None, ref: str | None = None) -> str:
    is_url = bool(re.match(r"^(https?://|git@|ssh://)", source))
    name = check_target_name(name or re.sub(r"\.git$", "", source.rstrip("/").split("/")[-1].split(":")[-1]))
    dest = common.TARGETS / name
    if dest.exists():
        return name
    common.TARGETS.mkdir(exist_ok=True)
    if is_url and ref and re.fullmatch(r"[0-9a-f]{40}", ref):
        clone_commit(source, ref, dest)
    elif is_url:
        cmd = ["git", "-c", "core.hooksPath=/dev/null", "clone", "--quiet", "--no-recurse-submodules"]
        cmd += ["--depth", "1"] + (["--branch", ref] if ref else []) + [source, str(dest)]
        subprocess.run(cmd, check=True)
    else:
        src = Path(source).resolve()
        if not src.is_dir():
            raise SystemExit(f"not a directory: {source}")
        shutil.copytree(src, dest, symlinks=True, ignore=shutil.ignore_patterns(*(SKIP_DIRS - {".git"})))
    return name


def clone_commit(url: str, sha: str, dest: Path) -> None:
    """Shallow checkout of one exact commit (benchmarks pin commits so ground truth can't drift)."""
    git = ["git", "-c", "core.hooksPath=/dev/null", "-c", "advice.detachedHead=false", "-C", str(dest)]
    dest.mkdir(parents=True)
    try:
        subprocess.run(["git", "init", "--quiet", str(dest)], check=True)
        subprocess.run(git + ["remote", "add", "origin", url], check=True)
        if subprocess.run(git + ["fetch", "--quiet", "--depth", "1", "origin", sha]).returncode != 0:
            subprocess.run(git + ["fetch", "--quiet", "origin"], check=True)  # server refuses fetch-by-sha
        subprocess.run(git + ["checkout", "--quiet", "--detach", sha], check=True)
    except subprocess.CalledProcessError:
        shutil.rmtree(dest, ignore_errors=True)
        raise


def remove(name: str) -> None:
    dest = (common.TARGETS / check_target_name(name)).resolve()
    if dest.parent != common.TARGETS.resolve() or not dest.is_dir():
        raise SystemExit(f"no such target: {name}")
    shutil.rmtree(dest)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="vulnscan.targets")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("add"); p.add_argument("source"); p.add_argument("--name"); p.add_argument("--ref")
    p = sub.add_parser("remove"); p.add_argument("name")
    sub.add_parser("list")
    args = ap.parse_args(argv)
    if args.cmd == "add":
        print(f"target ready: targets/{add(args.source, args.name, args.ref)}")
    elif args.cmd == "remove":
        remove(args.name)
        print(f"removed targets/{args.name}")
    else:
        for d in sorted(p for p in common.TARGETS.iterdir() if p.is_dir()):
            print(d.name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
