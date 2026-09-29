"""CVSS calculator, RealVuln-compatible matching, and scorecard statistics."""
import json
from pathlib import Path

import pytest

from vulnscan import cvss, scorecard, scoring

FIX = Path(__file__).resolve().parent / "fixtures" / "realvuln"


# --- CVSS ----------------------------------------------------------------------------------------

@pytest.mark.parametrize("vector,expected", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),   # classic reflected XSS
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
    ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9),
])
def test_cvss_base_scores(vector, expected):
    assert cvss.base_score(vector) == expected


def test_cvss_every_vector_in_the_realvuln_fixture():
    """RealVuln stores a vector and a score per entry; the fixture's pairs are consistent with the spec."""
    for f in json.loads((FIX / "vulpy.ground-truth.json").read_text())["findings"]:
        assert cvss.base_score(f["cvss"]["vector"]) == f["cvss"]["base_score"]


@pytest.mark.parametrize("bad", ["", "AV:N/AC:L", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
                                 "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS:4.0/AV:N/AC:L/AT:N"])
def test_cvss_rejects_invalid_vectors(bad):
    with pytest.raises(cvss.CVSSError):
        cvss.base_score(bad)


def test_cvss_severity_bands():
    assert [cvss.severity(x) for x in (0, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0)] == \
        ["none", "low", "medium", "medium", "high", "high", "critical"]


# --- matching ------------------------------------------------------------------------------------

def test_scorer_reproduces_realvuln_official_numbers():
    gt = scoring.load(FIX / "vulpy.ground-truth.json", "realvuln-vulpy")
    s = scoring.score(scoring.semgrep_findings(FIX / "vulpy.semgrep.json"), gt)
    assert (s["tp"], s["fp"], s["fn"], s["tn"]) == (16, 29, 41, 6)
    assert round(s["f3"], 4) == 0.2867 and round(s["wf3"], 4) == 0.3028


def _rv(*entries):
    return scoring._load_realvuln({"repo_id": "x", "findings": list(entries)}, "x")


def _entry(id, line, vuln=True, cwes=("CWE-89",), file="a.py", **extra):
    return {"id": id, "is_vulnerable": vuln, "primary_cwe": cwes[0], "acceptable_cwes": list(cwes), "file": file,
            "location": {"start_line": line, "end_line": line}, **extra}


def test_realvuln_matching_rules():
    gt = _rv(_entry("V1", 20), _entry("T1", 22, vuln=False), _entry("V2", 100, cwes=("CWE-79",)),
             _entry("NS", 200, scoring="non_scoring"),
             _entry("V3", 300, cwes=("CWE-22",), acceptable_locations=[{"file": "b.py", "start_line": 5, "end_line": 5}]))
    findings = [
        {"file": "a.py", "line": 21, "cwe": "CWE-89"},    # vuln preferred over the co-located trap -> TP
        {"file": "a.py", "line": 21, "cwe": "CWE-89"},    # V1 consumed; the trap matches -> FP
        {"file": "a.py", "line": 25, "cwe": "CWE-89"},    # only consumed entries left -> duplicate (FP in RealVuln)
        {"file": "a.py", "line": 100, "cwe": "CWE-89"},   # wrong CWE for V2 -> FP
        {"file": "a.py", "line": 205, "cwe": "CWE-1"},    # lands on a non-scoring entry -> withheld
        {"file": "./b.py", "line": 14, "cwe": "CWE-22"},  # acceptable location, within +/-10 -> TP
    ]
    s = scoring.score(findings, gt)
    assert [r["cls"] for r in s["results"][:6]] == ["TP", "FP", "DUP", "FP", "NS", "TP"]
    assert (s["tp"], s["fp"], s["fn"], s["tn"], s["ns"]) == (2, 3, 1, 0, 1)


def test_native_format_keeps_duplicates_separate_and_uses_cwe_families():
    gt = scoring._load_native({"vulnerabilities": [{"file": "a.py", "line": 10, "cwe": "CWE-78"}],
                               "traps": [{"file": "a.py", "line": 30, "reason": "safe"}]}, "n")
    s = scoring.score([{"file": "a.py", "line": 12, "cwe": "CWE-77"}, {"file": "a.py", "line": 10, "cwe": "CWE-78"},
                       {"file": "a.py", "line": 30, "cwe": "CWE-89"}], gt)
    assert (s["tp"], s["fp"], s["dups"], s["tn"]) == (1, 1, 1, 0)


def test_semgrep_findings_one_per_cwe(tmp_path):
    p = tmp_path / "s.json"
    p.write_text(json.dumps({"results": [{"path": "./app.py", "start": {"line": 3}, "check_id": "r",
                                          "extra": {"severity": "ERROR", "metadata": {"cwe": [
                                              "CWE-89: SQL Injection", "CWE-943: NoSQL"]}}}]}))
    assert [(f["file"], f["cwe"]) for f in scoring.semgrep_findings(p)] == [("app.py", "CWE-89"), ("app.py", "CWE-943")]


# --- scorecard statistics ------------------------------------------------------------------------

def test_sign_test_exact_values():
    assert scorecard.sign_test(0, 0) == 1.0
    assert scorecard.sign_test(6, 1) == pytest.approx(0.125)
    assert scorecard.sign_test(10, 0) == pytest.approx(2 / 1024)


def test_bootstrap_is_deterministic_and_brackets_the_mean():
    items = [0.1, 0.2, 0.3, 0.4, 0.9]
    mean = lambda s: sum(s) / len(s)  # noqa: E731
    a = scorecard.bootstrap(items, mean, 500, seed=7)
    assert a == scorecard.bootstrap(items, mean, 500, seed=7)
    assert a[0] <= mean(items) <= a[1]
    assert scorecard.bootstrap([0.5], mean, 500, seed=7) is None


def test_aggregate_is_micro_averaged():
    agg = scorecard.aggregate([{"tp": 1, "fp": 0, "fn": 9, "tn": 0, "w_tp": None},
                               {"tp": 9, "fp": 10, "fn": 1, "tn": 5, "w_tp": None}])
    assert (agg["tp"], agg["fp"], agg["fn"]) == (10, 10, 10)
    assert agg["precision"] == agg["recall"] == 0.5 and agg["fpr"] == pytest.approx(10 / 15)


def test_semgrep_paths_from_parent_directory_runs_can_be_corrected(tmp_path):
    p = tmp_path / "s.json"
    p.write_text(json.dumps({"results": [{"path": "repos/app/views.py", "start": {"line": 3}, "check_id": "r",
                                          "extra": {"metadata": {"cwe": ["CWE-89"]}}}]}))
    assert scoring.semgrep_findings(p)[0]["file"] == "repos/app/views.py"          # as published
    assert scoring.semgrep_findings(p, strip_prefix="repos/app/")[0]["file"] == "views.py"
