"""Shared paths, constants and helpers for the audit pipeline."""
import re
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS = ROOT / "targets"
REPORTS = ROOT / "reports"

SEVERITIES = ["critical", "high", "medium", "low", "info"]
# Always skipped: VCS metadata, installed dependencies and caches.
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", ".tox", "vendor", "third_party",
             ".mypy_cache", ".pytest_cache", ".next", "coverage"}
# Build output, skipped only next to the build file that produces it: a source folder that happens to be
# called target/ or build/ is kept (RealVuln's python-app keeps its whole application in target/).
BUILD_DIRS = {"target": ("pom.xml", "build.gradle", "build.gradle.kts", "Cargo.toml", "build.sbt"),
              "build": ("build.gradle", "build.gradle.kts", "setup.py", "pyproject.toml", "package.json",
                        "CMakeLists.txt"),
              "dist": ("package.json", "setup.py", "pyproject.toml")}
MAX_FILE_BYTES = 1_000_000
EVIDENCE_WINDOW = 5  # lines of slack around a reported line

# CWEs that describe the same bug class; used for dedup and evaluation matching.
CWE_GROUPS = [
    {"CWE-77", "CWE-78", "CWE-88"},                       # OS command injection
    {"CWE-89", "CWE-564", "CWE-943"},                     # SQL / query injection
    {"CWE-94", "CWE-95", "CWE-96", "CWE-1336"},           # code / template injection
    {"CWE-22", "CWE-23", "CWE-35", "CWE-36", "CWE-73"},   # path traversal
    {"CWE-502", "CWE-915"},                               # unsafe deserialization
    {"CWE-798", "CWE-259", "CWE-321", "CWE-547"},         # hardcoded credentials
    {"CWE-918"},                                          # SSRF
    {"CWE-79", "CWE-80", "CWE-116"},                      # XSS / output encoding
    {"CWE-611", "CWE-776"},                               # XXE
    {"CWE-601"},                                          # open redirect
    {"CWE-284", "CWE-285", "CWE-639", "CWE-862", "CWE-863", "CWE-566"},  # access control / IDOR
    {"CWE-287", "CWE-345", "CWE-347", "CWE-306", "CWE-1390"},            # authentication
    {"CWE-326", "CWE-327", "CWE-328", "CWE-916", "CWE-759"},             # weak crypto / hashing
    {"CWE-295", "CWE-297"},                               # TLS verification
    {"CWE-330", "CWE-338"},                               # weak randomness
    {"CWE-489", "CWE-215", "CWE-1188", "CWE-16"},         # debug / insecure defaults
    {"CWE-352"},                                          # CSRF
    {"CWE-605", "CWE-668", "CWE-1327"},                   # bound to all interfaces / exposure
]


# Variant CWEs stored as their widely used parent (e.g. eval injection CWE-95 -> code injection CWE-94),
# so scanners, hunters and ground truth that label the same bug differently agree. On the RealVuln
# corpus no entry accepts a variant without also accepting its parent.
CANONICAL_CWE = {"CWE-95": "CWE-94", "CWE-96": "CWE-94", "CWE-80": "CWE-79", "CWE-23": "CWE-22",
                 "CWE-35": "CWE-22", "CWE-36": "CWE-22", "CWE-564": "CWE-89"}


def canonical_cwe(cwe: str) -> str:
    c = normalize_cwe(cwe)
    return CANONICAL_CWE.get(c, c)


def normalize_cwe(cwe: str) -> str:
    m = re.search(r"(\d+)", str(cwe or ""))
    return f"CWE-{m.group(1)}" if m else "CWE-UNKNOWN"


def cwe_group(cwe: str) -> frozenset:
    c = normalize_cwe(cwe)
    for g in CWE_GROUPS:
        if c in g:
            return frozenset(g)
    return frozenset({c})


def same_cwe_family(a: str, b: str) -> bool:
    return normalize_cwe(b) in cwe_group(a)


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def norm_ws(s: str) -> str:
    return " ".join(str(s).split())


def check_target_name(name: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9._-]+", name or "") or name in {".", ".."}:
        raise SystemExit(f"invalid target name: {name!r} (use the directory name under targets/)")
    return name


def target_dir(name: str) -> Path:
    d = TARGETS / check_target_name(name)
    if not d.is_dir():
        raise SystemExit(f"no such target: {d}")
    return d


def report_dir(name: str) -> Path:
    d = REPORTS / check_target_name(name)
    d.mkdir(parents=True, exist_ok=True)
    return d


def resolve_in(root: Path, rel: str) -> Path:
    """Resolve rel inside root, refusing anything that escapes it."""
    root = root.resolve()
    p = (root / rel).resolve()
    if p != root and root not in p.parents:
        raise ValueError(f"path escapes target: {rel}")
    return p


def skipped_dir(root: Path, parts) -> bool:
    """True if a path under root (given as directory parts) is dependency, cache or build output."""
    cur = root
    for part in parts:
        if part in SKIP_DIRS or (part in BUILD_DIRS and any((cur / m).is_file() for m in BUILD_DIRS[part])):
            return True
        cur = cur / part
    return False


def iter_source_files(root: Path):
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.is_symlink():
            continue
        rel = p.relative_to(root)
        if skipped_dir(root, rel.parts[:-1]):
            continue
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                continue
            with p.open("rb") as fh:
                if b"\0" in fh.read(4096):
                    continue
        except OSError:
            continue
        yield p


TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "testdata", "fixtures", "e2e", "cypress", "testing"}
TEST_FILE = re.compile(r"(^test_.*\.py$|_test\.(py|go)$|\.(test|spec)\.[cm]?[jt]sx?$|Tests?\.(java|kt|php)$|_spec\.rb$|_test\.rb$)")


def is_test_path(rel: str) -> bool:
    """Test code, fixtures and specs: not shipped, so not part of the attack surface."""
    parts = Path(rel).parts
    return any(p.lower() in TEST_DIRS for p in parts[:-1]) or bool(TEST_FILE.search(parts[-1] if parts else ""))


def read_lines(path: Path) -> list[str]:
    return path.read_text(errors="replace").splitlines()


def evidence_problem(root: Path, file: str, line: int, evidence: str) -> str | None:
    """Return why the evidence doesn't match the source, or None if it does.

    At least one substantive evidence line (>= 8 chars) must appear within EVIDENCE_WINDOW
    lines of the reported line. Comment-stripped evidence still matches the raw source.
    """
    try:
        path = resolve_in(root, file)
    except ValueError as e:
        return str(e)
    if not path.is_file():
        return f"file not found in target: {file}"
    lines = read_lines(path)
    if not isinstance(line, int) or not 1 <= line <= len(lines):
        return f"line {line} out of range ({file} has {len(lines)} lines)"
    lo, hi = max(0, line - 1 - EVIDENCE_WINDOW), line + EVIDENCE_WINDOW
    window = norm_ws("\n".join(lines[lo:hi]))
    ev = [norm_ws(l) for l in str(evidence).splitlines() if len(norm_ws(l)) >= 8]
    if not ev:
        return "evidence must contain at least one code line of 8+ characters copied from the file"
    if not any(l in window for l in ev):
        return f"evidence not found within {EVIDENCE_WINDOW} lines of {file}:{line}"
    return None
