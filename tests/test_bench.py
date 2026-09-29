"""Benchmark plumbing (no network): pinned clones, suites, reference baselines, scorecard build."""
import json
import shutil
import sqlite3
import subprocess
from pathlib import Path

import pytest

from vulnscan import bench, common, db, evaluate, scorecard, targets

FIX = Path(__file__).resolve().parent / "fixtures" / "realvuln"


def git(*args, cwd):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args], cwd=cwd, check=True,
                   capture_output=True)


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_clone_commit_checks_out_the_pinned_commit(tmp_path):
    up = tmp_path / "up"
    up.mkdir()
    git("init", "-q", cwd=up)
    (up / "a.txt").write_text("one\n")
    git("add", ".", cwd=up)
    git("commit", "-q", "-m", "1", cwd=up)
    first = subprocess.run(["git", "rev-parse", "HEAD"], cwd=up, capture_output=True, text=True).stdout.strip()
    (up / "a.txt").write_text("two\n")
    git("commit", "-qam", "2", cwd=up)
    dest = tmp_path / "t"
    targets.clone_commit(str(up), first, dest)
    assert (dest / "a.txt").read_text() == "one\n"
    from vulnscan.advisory import read_git_head
    assert read_git_head(dest) == first


@pytest.fixture
def ws(tmp_path, monkeypatch):
    monkeypatch.setattr(common, "TARGETS", tmp_path / "targets")
    monkeypatch.setattr(common, "REPORTS", tmp_path / "reports")
    for mod in (bench, scorecard, evaluate):
        monkeypatch.setattr(mod, "ROOT", tmp_path)
    monkeypatch.setattr(bench, "SUITES", tmp_path / "eval" / "suites")
    gt_dir = tmp_path / "eval" / "ground_truth"
    gt_dir.mkdir(parents=True)
    shutil.copy(FIX / "vulpy.ground-truth.json", gt_dir / "realvuln-vulpy.json")
    ref = tmp_path / "eval" / "cache" / "realvuln-vulpy.json"
    ref.parent.mkdir(parents=True)
    shutil.copy(FIX / "vulpy.semgrep.json", ref)
    (tmp_path / "rules").mkdir()
    (tmp_path / ".claude" / "agents").mkdir(parents=True)
    suite = {"name": "s", "source": {"benchmark": "RealVuln", "benchmark_version": "3.1.0", "commit": "abc"},
             "repos": [{"target": "realvuln-vulpy", "repo_url": "https://example.com/v.git", "commit_sha": "0" * 40,
                        "language": "python", "vulns": 57, "traps": 6, "reference_semgrep": "eval/cache/realvuln-vulpy.json"}]}
    bench.SUITES.mkdir(parents=True)
    (bench.SUITES / "s.json").write_text(json.dumps(suite))
    return tmp_path


def test_suite_selection_and_reference_baseline(ws):
    suite = bench.load_suite("s")
    assert bench.selected(suite, None)[0]["target"] == "realvuln-vulpy"
    with pytest.raises(SystemExit):
        bench.selected(suite, "nope")
    out = bench.baseline(suite, None, ["p/default"], reference=True)
    assert "45 results" in out[0]
    assert json.loads((ws / "reports" / "realvuln-vulpy" / "baseline" / "meta.json").read_text())["source"].startswith("RealVuln")


def test_scorecard_matches_realvuln_and_handles_missing_views(ws):
    bench.baseline(bench.load_suite("s"), None, [], reference=True)
    card = scorecard.build(["realvuln-vulpy"], strict=False, b=200, seed=1, suite=bench.load_suite("s"))
    v = card["views"]["semgrep"]
    assert (v["tp"], v["fp"], v["fn"]) == (16, 29, 41) and round(v["f3"], 4) == 0.2867
    assert set(card["views"]) == {"semgrep"}  # no pipeline results -> views omitted, not scored as zero
    md = scorecard.render(card, "s")
    assert "Plain Semgrep" in md and "Reproduce" in md
    strict = scorecard.build(["realvuln-vulpy"], strict=True, b=0, seed=1)
    assert set(strict["views"]) == {"semgrep"}


def test_scorecard_reads_pipeline_state_read_only(ws):
    """A finished audit's state.db feeds the leads/raw/confirmed views."""
    rep = ws / "reports" / "realvuln-vulpy"
    (rep / "sast").mkdir(parents=True)
    (rep / "findings.json").write_text("{}")
    conn = sqlite3.connect(rep / "state.db")
    conn.executescript(db.SCHEMA)
    rows = [("a", "confirmed", "hunter:injection", "", "SQLi", "high", "CWE-89", "bad/libuser.py", 12),
            ("b", "refuted", "sast:semgrep", "", "x", "medium", "CWE-79", "bad/templates/x.html", 1),
            ("c", "confirmed", "sast:bandit", "hunter:injection", "SQLi 2", "high", "CWE-89", "bad/libuser.py", 25)]
    conn.executemany("INSERT INTO candidates (fingerprint, status, origin, also_reported_by, title, severity, cwe, "
                     "file, line, evidence) VALUES (?,?,?,?,?,?,?,?,?, 'e')", rows)
    conn.commit()
    conn.close()
    bench.baseline(bench.load_suite("s"), None, [], reference=True)
    card = scorecard.build(["realvuln-vulpy"], strict=False, b=0, seed=1)
    assert card["views"]["vulnscan"]["tp"] == 2 and card["views"]["vulnscan-leads"]["fp"] == 1
    pair = next(p for p in card["pairs"] if (p["a"], p["b"]) == ("vulnscan", "semgrep"))
    assert pair["repos"] == 1 and pair["losses"] == 1  # 2 TPs don't beat Semgrep's 16 on F3


def test_evaluate_accepts_realvuln_ground_truth(ws, capsys):
    shutil.copytree(FIX, ws / "targets" / "realvuln-vulpy")  # evaluate needs the target dir to exist
    bench.baseline(bench.load_suite("s"), None, [], reference=True)
    evaluate.main(["realvuln-vulpy"])
    out = capsys.readouterr().out
    assert "semgrep (plain) | 16 | 29 | 41 | 6 |" in out
