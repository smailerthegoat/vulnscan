"""Ground-truth loading and matching shared by `evaluate` (one target) and `scorecard` (many).

Two ground-truth formats are accepted:
  - native (eval/ground_truth/demo_target.json): {"vulnerabilities": [...], "traps": [...]}
    CWEs match by family (common.CWE_GROUPS) plus `accept_cwes`; tolerance is `window` (default 3).
  - RealVuln (https://github.com/kolega-ai/Real-Vuln-Benchmark): {"repo_id", "findings": [...]}
    with is_vulnerable, acceptable_cwes, location.start_line/end_line, acceptable_locations and
    scoring=non_scoring. CWEs must be in acceptable_cwes; tolerance is +/-10 lines around the range.

Matching follows RealVuln's published scorer (scorer/matcher.py) so numbers are comparable with its
leaderboard: findings are processed in order, each entry is consumed at most once, a vulnerable
entry is preferred over a co-located trap, and a finding that lands on a non-scoring entry is
withheld rather than counted. A finding that would only match an entry already consumed is a
duplicate; RealVuln counts it as a false positive, the native format reports it separately.
"""
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .common import cwe_group, normalize_cwe

REALVULN_TOLERANCE = 10
NATIVE_TOLERANCE = 3
# RealVuln weights unmatched findings by the scanner's severity (CVSS band midpoints).
SEVERITY_WEIGHT = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 2.0, "info": 0.5}


@dataclass
class Entry:
    id: str
    file: str
    start: int | None
    end: int | None
    tol: int
    cwes: frozenset | None          # None = any CWE (native traps carry no CWE)
    is_vulnerable: bool = True
    scoring: str = "scored"         # scored | non_scoring
    alt: list = field(default_factory=list)   # [(file, start, end)]
    cvss: float | None = None
    vclass: str = ""
    title: str = ""


@dataclass
class GroundTruth:
    target: str
    fmt: str                        # native | realvuln
    entries: list
    meta: dict = field(default_factory=dict)

    @property
    def vulns(self):
        return [e for e in self.entries if e.is_vulnerable and e.scoring == "scored"]

    @property
    def traps(self):
        return [e for e in self.entries if not e.is_vulnerable and e.scoring == "scored"]


def norm_path(p: str) -> str:
    p = str(p or "").replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/")


def load(path: Path, target: str | None = None) -> GroundTruth:
    data = json.loads(Path(path).read_text())
    name = target or Path(path).stem
    if "findings" in data:
        return _load_realvuln(data, name)
    if "vulnerabilities" in data:
        return _load_native(data, name)
    raise ValueError(f"{path}: unknown ground-truth format (expected 'findings' or 'vulnerabilities')")


def _load_native(data: dict, name: str) -> GroundTruth:
    entries = []
    for i, v in enumerate(data["vulnerabilities"]):
        cwes = set(cwe_group(v["cwe"])) | {normalize_cwe(c) for c in v.get("accept_cwes", [])}
        entries.append(Entry(id=v.get("id", f"V{i + 1}"), file=norm_path(v["file"]), start=v["line"], end=v["line"],
                             tol=v.get("window", NATIVE_TOLERANCE), cwes=frozenset(cwes), title=v.get("title", ""),
                             vclass=min(cwe_group(v["cwe"]))))
    for i, t in enumerate(data.get("traps", [])):
        cwes = frozenset(cwe_group(t["cwe"])) if t.get("cwe") else None
        entries.append(Entry(id=t.get("id", f"T{i + 1}"), file=norm_path(t["file"]), start=t["line"], end=t["line"],
                             tol=t.get("window", NATIVE_TOLERANCE), cwes=cwes, is_vulnerable=False,
                             title=t.get("reason", "")))
    return GroundTruth(name, "native", entries, {k: v for k, v in data.items() if k not in ("vulnerabilities", "traps")})


def _load_realvuln(data: dict, name: str) -> GroundTruth:
    entries = []
    for f in data["findings"]:
        scoring = f.get("scoring", "scored")
        if scoring not in ("scored", "non_scoring"):
            raise ValueError(f"entry {f.get('id')!r} has invalid scoring {scoring!r}")
        loc = f.get("location") or {}
        cwes = {normalize_cwe(c) for c in f.get("acceptable_cwes") or []}
        if not cwes and f.get("primary_cwe"):
            cwes = {normalize_cwe(f["primary_cwe"])}
        cvss = (f.get("cvss") or {}).get("base_score") if isinstance(f.get("cvss"), dict) else None
        try:
            cvss = float(cvss) if cvss is not None and not isinstance(cvss, bool) else None
        except (TypeError, ValueError):
            cvss = None
        alt = [(norm_path(a.get("file")), a.get("start_line"), a.get("end_line"))
               for a in f.get("acceptable_locations", []) if a.get("file")]
        entries.append(Entry(id=f["id"], file=norm_path(f["file"]), start=loc.get("start_line"),
                             end=loc.get("end_line"), tol=REALVULN_TOLERANCE, cwes=frozenset(cwes),
                             is_vulnerable=bool(f.get("is_vulnerable")), scoring=scoring, alt=alt, cvss=cvss,
                             vclass=f.get("vulnerability_class") or "",
                             title=((f.get("evidence") or {}).get("description") or "")[:160]))
    meta = {k: v for k, v in data.items() if k != "findings"}
    return GroundTruth(name, "realvuln", entries, meta)


# --- matching ------------------------------------------------------------------------------------

def _line_ok(line, start, end, tol) -> bool:
    if line is None or start is None:
        return True  # RealVuln: can't compare, don't penalise
    return start - tol <= line <= (end if end is not None else start) + tol


def _at_location(f: dict, e: Entry) -> bool:
    if f["file"] == e.file and _line_ok(f.get("line"), e.start, e.end, e.tol):
        return True
    return any(f["file"] == file and _line_ok(f.get("line"), s, en, e.tol) for file, s, en in e.alt)


def _cwe_ok(f: dict, e: Entry) -> bool:
    return e.cwes is None or normalize_cwe(f.get("cwe")) in e.cwes


def matches(f: dict, e: Entry) -> bool:
    return _cwe_ok(f, e) and _at_location(f, e)


def match(findings: list[dict], gt: GroundTruth) -> list[dict]:
    """Classify every finding and every scored entry: TP, FP, DUP, NS, FN, TN."""
    scored = [e for e in gt.entries if e.scoring == "scored"]
    non_scoring = [e for e in gt.entries if e.scoring == "non_scoring"]
    used, out = set(), []
    for f in findings:
        f = {**f, "file": norm_path(f["file"])}
        cands = [e for e in scored if e.id not in used and matches(f, e)]
        if cands:
            best = sorted(cands, key=lambda e: not e.is_vulnerable)[0]
            used.add(best.id)
            out.append({"cls": "TP" if best.is_vulnerable else "FP", "finding": f, "entry": best})
            continue
        if f.get("line") is not None:
            ns = sorted((e for e in non_scoring if _at_location(f, e)), key=lambda e: e.id)
            if ns:
                out.append({"cls": "NS", "finding": f, "entry": ns[0]})
                continue
        dup = next((e for e in scored if e.id in used and e.is_vulnerable and matches(f, e)), None)
        out.append({"cls": "DUP" if dup else "FP", "finding": f, "entry": dup})
    for e in scored:
        if e.id not in used:
            out.append({"cls": "FN" if e.is_vulnerable else "TN", "finding": None, "entry": e})
    return out


def fbeta(p: float, r: float, beta: float) -> float:
    b2 = beta * beta
    return (1 + b2) * p * r / (b2 * p + r) if p + r else 0.0


def div(a: float, b: float) -> float:
    return a / b if b else 0.0


def metrics(counts: dict) -> dict:
    tp, fp, fn, tn = (counts.get(k, 0) for k in ("tp", "fp", "fn", "tn"))
    p, r = div(tp, tp + fp), div(tp, tp + fn)
    return {"precision": p, "recall": r, "f1": fbeta(p, r, 1), "f2": fbeta(p, r, 2), "f3": fbeta(p, r, 3),
            "fpr": div(fp, fp + tn)}


def score(findings: list[dict], gt: GroundTruth, dups_as_fp: bool | None = None) -> dict:
    """Counts, metrics and itemised results for one view of one target."""
    if dups_as_fp is None:
        dups_as_fp = gt.fmt == "realvuln"
    res = match(findings, gt)
    n = {c: sum(r["cls"] == c for r in res) for c in ("TP", "FP", "DUP", "NS", "FN", "TN")}
    counts = {"tp": n["TP"], "fp": n["FP"] + (n["DUP"] if dups_as_fp else 0), "fn": n["FN"], "tn": n["TN"],
              "dups": n["DUP"], "ns": n["NS"]}
    out = {**counts, **metrics(counts)}
    out.update(_weighted(res, dups_as_fp))
    out["results"] = res
    return out


def _weighted(res: list[dict], dups_as_fp: bool) -> dict:
    """CVSS-weighted precision/recall/F3 (RealVuln's wF3); equals the unweighted numbers without CVSS data."""
    gt_backed = [r for r in res if r["entry"] is not None and r["cls"] in ("TP", "FN", "TN", "FP")]
    known = [r["entry"].cvss for r in gt_backed if r["entry"].cvss is not None]
    if not known:
        return {"w_tp": None, "w_fp": None, "w_fn": None, "wf3": None}
    mean = sum(known) / len(known)
    w = {"TP": 0.0, "FP": 0.0, "FN": 0.0}
    for r in res:
        cls = "FP" if r["cls"] == "DUP" and dups_as_fp else r["cls"]
        if cls in ("TP", "FN"):
            w[cls] += mean if r["entry"].cvss is None else r["entry"].cvss
        elif cls == "FP":
            w["FP"] += SEVERITY_WEIGHT.get(str(r["finding"].get("severity") or "").lower(), mean)
    p, rc = div(w["TP"], w["TP"] + w["FP"]), div(w["TP"], w["TP"] + w["FN"])
    return {"w_tp": w["TP"], "w_fp": w["FP"], "w_fn": w["FN"], "wf3": fbeta(p, rc, 3)}


# --- scanner output ----------------------------------------------------------------------------

def semgrep_findings(path: Path, root: Path | None = None, strip_prefix: str | None = None) -> list[dict]:
    """Plain Semgrep JSON -> findings, one per CWE in the rule metadata (RealVuln's parser semantics).

    strip_prefix removes a leading path segment such as "repos/<repo>/": some of RealVuln's published
    Semgrep runs were made from the parent directory, so their paths never match the ground truth.
    """
    data = json.loads(Path(path).read_text() or "{}")
    out = []
    for r in data.get("results", []):
        p = r.get("path", "")
        if strip_prefix and norm_path(p).startswith(strip_prefix):
            p = norm_path(p)[len(strip_prefix):]
        if root is not None and Path(p).is_absolute():
            try:
                p = str(Path(p).resolve().relative_to(root.resolve()))
            except ValueError:
                pass
        p = norm_path(p)
        if not p:
            continue
        extra = r.get("extra", {})
        raw = extra.get("metadata", {}).get("cwe", [])
        for c in [raw] if isinstance(raw, str) else raw or []:
            m = re.match(r"(CWE-\d+)", str(c))
            if m:
                out.append({"file": p, "line": r.get("start", {}).get("line"), "cwe": m.group(1),
                            "severity": (extra.get("severity") or "").lower() or None, "rule": r.get("check_id")})
    return out
