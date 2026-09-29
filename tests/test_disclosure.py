"""Disclosure stage against a real (local) git upstream with release tags."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from vulnscan import advisory, common, db, targets

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")

VULN = 'rows = db.execute(f"SELECT * FROM users WHERE name = \'{name}\'").fetchall()\n'
SAFE = 'rows = db.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchall()\n'


def app(sink: str) -> str:
    return ("import sqlite3\n\n\ndef search(db, request):\n    name = request.args.get('name', '')\n"
            f"    {sink}    return rows\n")


def sh(*args, cwd):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "core.hooksPath=/dev/null",
                    *args], cwd=cwd, check=True, capture_output=True)


def release(repo: Path, text: str, tag: str):
    (repo / "app.py").write_text(text)
    sh("add", "app.py", cwd=repo)
    sh("commit", "-q", "-m", tag, cwd=repo)
    sh("tag", tag, cwd=repo)


@pytest.fixture
def upstream_ws(tmp_path, monkeypatch):
    monkeypatch.setattr(common, "TARGETS", tmp_path / "targets")
    monkeypatch.setattr(common, "REPORTS", tmp_path / "reports")
    monkeypatch.setattr(advisory, "ROOT", tmp_path)
    up = tmp_path / "upstream"
    up.mkdir()
    sh("init", "-q", "-b", "main", cwd=up)
    (up / "pyproject.toml").write_text('[project]\nname = "tinyapp"\nversion = "1.0.0"\n')
    sh("add", "pyproject.toml", cwd=up)
    release(up, app(SAFE), "v1.0.0")
    release(up, app(VULN), "v1.1.0")
    (up / "README.md").write_text("docs\n")
    sh("add", "README.md", cwd=up)
    sh("commit", "-q", "-m", "docs", cwd=up)
    sh("tag", "v1.2.0", cwd=up)
    sh("tag", "v2.0.0rc1", cwd=up)  # pre-release: must not count as the latest release
    clone = tmp_path / "clone"
    sh("clone", "-q", str(up), str(clone), cwd=tmp_path)
    name = targets.add(str(clone), name="tinyapp")
    conn = db.connect(name)
    finding = {"title": "SQL injection in search", "severity": "high", "cwe": "CWE-89", "file": "app.py", "line": 6,
               "source": "GET ?name=", "sink": "sqlite execute", "attack_path": "app.py:5 -> app.py:6",
               "description": "d", "fix": "bind", "evidence": VULN.strip()}
    msg, cid = db.add_candidate(conn, name, finding, "hunter:injection")
    assert msg.startswith("ADDED"), msg
    db.main([name, "verdict", str(cid), "--status", "confirmed", "--reason", "app.py:6 interpolates name into SQL"])
    return tmp_path, up, name, cid


def draft(tmp_path: Path, **over) -> Path:
    d = {"title": "SQL injection in tinyapp search", "summary": "s", "details": "d", "poc": "GET /?name=' OR '1'='1",
         "impact": "read all users", "remediation": "use placeholders", "cvss_vector":
         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "upstream_verified": True,
         "upstream_notes": "app.py:6 unchanged at v1.2.0", **over}
    p = tmp_path / "draft.json"
    p.write_text(json.dumps(d))
    return p


def test_releases_ignore_prereleases_and_group_prefixes():
    tags = [{"name": n, "commit": n, "date": ""} for n in
            ["v1.0.0", "v1.10.0", "v1.9.2", "v2.0.0rc1", "docs-2024", "pkg-a@3.0.0", "v1.2.0-beta.1"]]
    assert [t["name"] for t in advisory.releases(tags)] == ["v1.0.0", "v1.9.2", "v1.10.0"]


def test_upstream_refuses_untrusted_remote_without_explicit_url(upstream_ws):
    _, _, name, _ = upstream_ws
    info = advisory.upstream(name)  # origin is a local path copied from the target's .git/config
    assert info["status"].startswith("refusing")


def test_still_vulnerable_in_latest_release(upstream_ws):
    tmp_path, up, name, cid = upstream_ws
    info = advisory.upstream(name, url=str(up))
    assert info["status"] == "ok" and info["latest_release"] == "v1.2.0" and info["audited_in_mirror"]
    assert info["package"] == {"ecosystem": "PyPI", "name": "tinyapp"}
    [row] = advisory.check(name)
    assert row["latest_status"] == "present" and row["head_status"] == "present"
    assert row["introduced_in"] == "v1.1.0" and row["affected"] == ">= v1.1.0, <= v1.2.0 (latest release)"
    ok, msg = advisory.render(name, cid, draft(tmp_path))
    assert ok and "ready" in msg and "7.5" in msg, msg
    md = (tmp_path / "reports" / name / "advisories" / f"{cid}.md").read_text()
    assert "Draft advisory, not submitted" in md and ">= v1.1.0" in md
    osv = json.loads((tmp_path / "reports" / name / "advisories" / f"{cid}.osv.json").read_text())
    assert osv["affected"][0]["package"]["name"] == "tinyapp" and osv["severity"][0]["type"] == "CVSS_V3"


def test_fixed_upstream_is_not_reported_as_ready(upstream_ws):
    tmp_path, up, name, cid = upstream_ws
    release(up, app(SAFE), "v1.3.0")
    advisory.upstream(name, url=str(up))
    [row] = advisory.check(name)
    assert row["latest_status"] == "absent" and row["fixed_in"] == "v1.3.0"
    ok, msg = advisory.render(name, cid, draft(tmp_path))
    assert ok and "fixed-upstream" in msg


def test_render_rejects_bad_drafts(upstream_ws):
    tmp_path, up, name, cid = upstream_ws
    advisory.upstream(name, url=str(up))
    advisory.check(name)
    ok, msg = advisory.render(name, cid, draft(tmp_path, cvss_vector="CVSS:3.1/AV:N"))
    assert not ok and "cvss" in msg
    ok, msg = advisory.render(name, cid, draft(tmp_path, poc=""))
    assert not ok and "poc" in msg
    ok, msg = advisory.render(name, cid, draft(tmp_path, upstream_verified=False))
    assert ok and "needs-review" in msg


def test_cat_rejects_option_injection(upstream_ws):
    _, up, name, _ = upstream_ws
    advisory.upstream(name, url=str(up))
    assert advisory.cat(name, "--output=/tmp/x", "app.py", None) == "invalid ref or path"
    assert "SELECT * FROM users" in advisory.cat(name, "v1.2.0", "app.py", "6:6")
