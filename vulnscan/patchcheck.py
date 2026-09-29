"""Build and check fix patches without ever modifying the target.

    python3 -m vulnscan.patchcheck <target> prepare <id> <file> [<file> ...]
        copy target files to reports/<target>/patches/work/<id>/ for editing
    python3 -m vulnscan.patchcheck <target> diff <id>
        diff the edited copies against the target -> reports/<target>/patches/<id>.diff,
        check it, and record the result in the state store
    python3 -m vulnscan.patchcheck <target> check <diff-file>
        check an existing diff

A check copies the target to a throwaway directory, applies the diff there with `git apply`, and
syntax-checks changed files (Python: py_compile; JS: node --check; Ruby: ruby -c; Go: gofmt -e;
PHP: php -l; each only if installed). These parse without running anything.
"""
import argparse
import difflib
import py_compile
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from .common import ROOT, SKIP_DIRS, report_dir, resolve_in, target_dir


def workdir(target: str, cid: int) -> Path:
    return report_dir(target) / "patches" / "work" / str(cid)


def prepare(target: str, cid: int, files: list[str]) -> str:
    root, work = target_dir(target), workdir(target, cid)
    for f in files:
        src = resolve_in(root, f)
        if not src.is_file():
            raise SystemExit(f"no such file in target: {f}")
        dst = resolve_in(work, f)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    return f"edit these copies: " + ", ".join(str((work / f).relative_to(ROOT)) for f in files)


def make_diff(target: str, cid: int) -> Path:
    root, work = target_dir(target), workdir(target, cid)
    if not work.is_dir():
        raise SystemExit(f"nothing prepared for #{cid}; run prepare first")
    chunks = []
    for copy in sorted(p for p in work.rglob("*") if p.is_file()):
        rel = copy.relative_to(work).as_posix()
        a = resolve_in(root, rel).read_text().splitlines(keepends=True)
        b = copy.read_text().splitlines(keepends=True)
        chunks += difflib.unified_diff(a, b, f"a/{rel}", f"b/{rel}")
    if not chunks:
        raise SystemExit(f"copies for #{cid} are identical to the target; edit them first")
    text = "".join(c if c.endswith("\n") else c + "\n\\ No newline at end of file\n" for c in chunks)
    out = report_dir(target) / "patches" / f"{cid}.diff"
    out.write_text(text)
    return out


# Parse-only checkers (none of them runs the code). Skipped when the tool isn't installed.
SYNTAX_CHECKERS = {
    (".js", ".mjs", ".cjs"): ("node", ["--check"]),
    (".rb",): ("ruby", ["-c"]),
    (".go",): ("gofmt", ["-e", "-l"]),
    (".php",): ("php", ["-l"]),
}


def syntax_command(path: Path) -> list[str] | None:
    for suffixes, (exe, flags) in SYNTAX_CHECKERS.items():
        if path.suffix in suffixes and shutil.which(exe):
            return [exe, *flags, str(path)]
    return None


def check(target: str, diff: Path) -> tuple[bool, str]:
    diff = diff.resolve()
    if ROOT / "reports" not in diff.parents:
        return False, "patch must live under reports/"
    changed = sorted(set(re.findall(r"^\+\+\+ b/(.+)$", diff.read_text(), re.M)))
    if not changed:
        return False, "no '+++ b/<file>' headers found; use a unified diff with a/ b/ prefixes"
    with tempfile.TemporaryDirectory(prefix="vulnscan-patch-") as tmp:
        work = Path(tmp) / "src"
        shutil.copytree(target_dir(target), work, symlinks=True, ignore=shutil.ignore_patterns(*SKIP_DIRS))
        r = subprocess.run(["git", "apply", "--check", "-p1", str(diff)], cwd=work, capture_output=True, text=True)
        if r.returncode != 0:
            return False, f"does not apply: {r.stderr.strip()[-500:]}"
        subprocess.run(["git", "apply", "-p1", str(diff)], cwd=work, check=True, capture_output=True)
        for f in changed:
            p = work / f
            if p.suffix == ".py":
                try:
                    py_compile.compile(str(p), cfile=str(Path(tmp) / "x.pyc"), doraise=True)
                except py_compile.PyCompileError as e:
                    return False, f"{f}: syntax error after patch: {e.msg.strip()[-300:]}"
            elif cmd := syntax_command(p):
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                if r.returncode != 0:
                    return False, f"{f}: syntax error after patch: {(r.stderr or r.stdout).strip()[-300:]}"
    return True, f"applies cleanly; syntax OK for {', '.join(changed)}"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="vulnscan.patchcheck", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("prepare"); p.add_argument("id", type=int); p.add_argument("files", nargs="+")
    p = sub.add_parser("diff"); p.add_argument("id", type=int)
    p = sub.add_parser("check"); p.add_argument("diff", type=Path)
    args = ap.parse_args(argv)

    if args.cmd == "prepare":
        print(prepare(args.target, args.id, args.files))
        return 0
    if args.cmd == "check":
        ok, msg = check(args.target, args.diff)
    else:
        from .db import connect
        path = make_diff(args.target, args.id)
        ok, msg = check(args.target, path)
        conn = connect(args.target)
        conn.execute("UPDATE candidates SET patch_path=?, patch_check=? WHERE id=?",
                     (str(path.relative_to(ROOT)), "ok" if ok else "failed", args.id))
        conn.commit()
        print(f"wrote {path.relative_to(ROOT)}")
    print(("OK: " if ok else "FAILED: ") + msg)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
