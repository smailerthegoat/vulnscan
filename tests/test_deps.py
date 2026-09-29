"""Dependency advisories: lockfile parsing, OSV merging, reachability pre-pass, verdicts, report output."""
import json
import shutil
from pathlib import Path

import pytest

from vulnscan import common, db, deps, report, sarif

DEMO = Path(__file__).resolve().parents[1] / "examples" / "demo_target"


# --- parsers -------------------------------------------------------------------------------------

def test_requirements_only_pinned_and_dev_files_marked():
    pk = deps.parse_requirements("flask==2.2.2\nrequests>=2\npyyaml[x] == 5.3.1 ; python_version<'4'\n# c\n", "requirements.txt")
    assert [(p["name"], p["version"]) for p in pk] == [("flask", "2.2.2"), ("pyyaml", "5.3.1")]
    assert deps.parse_requirements("pytest==8.0\n", "requirements-dev.txt")[0]["scope"] == "dev"


def test_package_lock_v3_direct_dev_and_nested():
    lock = {"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"express": "^4"}, "devDependencies": {"jest": "^29"}},
        "node_modules/express": {"version": "4.17.1"},
        "node_modules/qs": {"version": "6.7.0"},
        "node_modules/jest": {"version": "29.0.0", "dev": True},
        "node_modules/express/node_modules/qs": {"version": "6.5.0"},
        "node_modules/local": {"link": True}}}
    got = {(p["name"], p["version"]): (p["scope"], p["direct"]) for p in deps.parse_package_lock(json.dumps(lock), "l")}
    assert got == {("express", "4.17.1"): ("runtime", True), ("qs", "6.7.0"): ("runtime", False),
                   ("jest", "29.0.0"): ("dev", True), ("qs", "6.5.0"): ("runtime", False)}


def test_yarn_and_pnpm_locks():
    yarn = '# yarn\n"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.2.0"\n\nlodash@^4.17.0:\n  version "4.17.15"\n'
    assert [(p["name"], p["version"]) for p in deps.parse_yarn_lock(yarn, "y")] == \
        [("@babel/core", "7.2.0"), ("lodash", "4.17.15")]
    berry = '"lodash@npm:^4.17.0":\n  version: 4.17.21\n'
    assert deps.parse_yarn_lock(berry, "y")[0]["name"] == "lodash"
    pnpm = "lockfileVersion: '9.0'\npackages:\n  /lodash@4.17.15:\n    resolution: {}\n  '@types/node@20.1.0':\n    x: y\nsnapshots:\n  /ignored@1.0.0:\n"
    assert [(p["name"], p["version"]) for p in deps.parse_pnpm_lock(pnpm, "p")] == \
        [("lodash", "4.17.15"), ("@types/node", "20.1.0")]


def test_go_mod_gemfile_composer_pom_gradle():
    gomod = "module x\n\ngo 1.21\n\nrequire (\n\tgolang.org/x/net v0.7.0\n\tgithub.com/a/b v1.2.3 // indirect\n)\nrequire github.com/c/d v0.1.0\n"
    got = [(p["name"], p["version"], p["direct"]) for p in deps.parse_go_mod(gomod, "go.mod")]
    assert got == [("golang.org/x/net", "0.7.0", True), ("github.com/a/b", "1.2.3", False), ("github.com/c/d", "0.1.0", True)]
    gem = "GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.13.3-x86_64-linux)\n      racc (~> 1.4)\n    rails (7.0.1)\n\nDEPENDENCIES\n  rails\n"
    assert [(p["name"], p["version"], p["direct"]) for p in deps.parse_gemfile_lock(gem, "g")] == \
        [("nokogiri", "1.13.3", False), ("rails", "7.0.1", True)]
    comp = {"packages": [{"name": "guzzlehttp/guzzle", "version": "v7.0.0", "autoload": {"psr-4": {"GuzzleHttp\\": "src/"}}}],
            "packages-dev": [{"name": "phpunit/phpunit", "version": "9.0.0"}]}
    c = deps.parse_composer_lock(json.dumps(comp), "c")
    assert c[0]["version"] == "7.0.0" and c[0]["namespaces"] == ["GuzzleHttp"] and c[1]["scope"] == "dev"
    pom = ('<project xmlns="http://maven.apache.org/POM/4.0.0"><version>1.0</version><properties><log4j.version>2.14.1'
           '</log4j.version></properties><dependencies><dependency><groupId>org.apache.logging.log4j</groupId>'
           '<artifactId>log4j-core</artifactId><version>${log4j.version}</version></dependency><dependency>'
           '<groupId>junit</groupId><artifactId>junit</artifactId><version>4.12</version><scope>test</scope>'
           '</dependency></dependencies></project>')
    assert [(p["name"], p["version"], p["scope"]) for p in deps.parse_pom(pom, "pom.xml")] == \
        [("org.apache.logging.log4j:log4j-core", "2.14.1", "runtime"), ("junit:junit", "4.12", "dev")]
    gradle = "dependencies {\n  implementation 'com.fasterxml.jackson.core:jackson-databind:2.9.8'\n  testImplementation(\"junit:junit:4.12\")\n}"
    assert [(p["name"], p["scope"]) for p in deps.parse_gradle(gradle, "b")] == \
        [("com.fasterxml.jackson.core:jackson-databind", "runtime"), ("junit:junit", "dev")]


# --- OSV merging ---------------------------------------------------------------------------------

GHSA = {"id": "GHSA-aaaa", "aliases": ["CVE-2020-1"], "summary": "Unsafe load", "details": "yaml.load is unsafe",
        "database_specific": {"severity": "CRITICAL", "cwe_ids": ["CWE-502"]},
        "affected": [{"package": {"name": "PyYAML", "ecosystem": "PyPI"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.4"}]}]}]}
PYSEC = {"id": "PYSEC-1", "aliases": ["CVE-2020-1", "GHSA-aaaa"], "details": "dup",
         "affected": [{"package": {"name": "pyyaml", "ecosystem": "PyPI"},
                       "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.4"}]}]}]}
PKG = {"ecosystem": "PyPI", "name": "PyYAML", "version": "5.3.1", "manifest": "requirements.txt", "scope": "runtime",
       "direct": None}


def test_merge_collapses_aliases_and_prefers_ghsa():
    [v] = deps.merge_vulns(PKG, [PYSEC, GHSA])
    assert v["vuln_id"] == "GHSA-aaaa" and set(v["aliases"]) == {"PYSEC-1", "CVE-2020-1"}
    assert v["severity"] == "critical" and v["fixed"] == ["5.4"] and v["cwe"] == ["CWE-502"]


def test_merge_severity_from_cvss_vector_when_no_label():
    v = {**GHSA, "database_specific": {}, "severity": [{"type": "CVSS_V3",
                                                        "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"}]}
    assert deps.merge_vulns(PKG, [v])[0]["severity"] == "medium"


# --- reachability pre-pass -----------------------------------------------------------------------

class Idx(deps.CodeIndex):
    def __init__(self, files: dict, bundler=False):
        self.files = {k: v.splitlines() for k, v in files.items()}
        self.bundler_require = bundler


def _vuln(symbols=()):
    return {"vuln_id": "X", "symbols": list(symbols)}


def test_prepass_statuses():
    idx = Idx({"app.py": "import yaml\nfrom flask import Flask\n", "cli.go": 'import (\n  h "net/http"\n)\nfunc main() { h.ListenAndServe(":8080", nil) }\n'})
    p = lambda **k: {**PKG, **k}  # noqa: E731
    assert deps.prepass(p(scope="dev"), _vuln(), idx, set())["reach_status"] == "dev-only"
    r = deps.prepass(p(), _vuln(), idx, set())
    assert r["reach_status"] == "pending" and r["import_sites"][0]["file"] == "app.py"
    assert deps.prepass(p(name="lxml"), _vuln(), idx, set())["reach_status"] == "not-imported"
    r = deps.prepass(p(name="Werkzeug"), _vuln(), idx, {"flask", "werkzeug"})
    assert r["reach_status"] == "pending" and "flask" in r["reach_reason"]
    go = {"ecosystem": "Go", "name": "stdlib", "version": "1.19", "manifest": "go.mod", "scope": "runtime", "direct": True}
    r = deps.prepass(go, _vuln([{"path": "net/http", "symbols": ["ListenAndServe", "Server.Serve"]}]), idx, set())
    assert r["reach_status"] == "reachable" and r["reach_file"] == "cli.go" and "ListenAndServe" in r["reach_reason"]
    r = deps.prepass(go, _vuln([{"path": "net/http", "symbols": ["ServeTLS"]}]), idx, set())
    assert r["reach_status"] == "unreachable"
    r = deps.prepass(go, _vuln([{"path": "golang.org/x/net/http2", "symbols": ["Server.ServeConn"]}]), idx, set())
    assert r["reach_status"] == "not-imported"


def test_test_code_is_not_first_party_usage(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_a.py").write_text("import yaml\n")
    (tmp_path / "app.py").write_text("print(1)\n")
    assert list(deps.CodeIndex(tmp_path).files) == ["app.py"]


# --- end to end with a fake OSV API --------------------------------------------------------------

@pytest.fixture
def ws(tmp_path, monkeypatch):
    shutil.copytree(DEMO, tmp_path / "targets" / "demo")
    monkeypatch.setattr(common, "TARGETS", tmp_path / "targets")
    monkeypatch.setattr(common, "REPORTS", tmp_path / "reports")
    return tmp_path


def fake_osv(url, payload=None):
    if url.endswith("/querybatch"):
        return {"results": [{"vulns": [{"id": "GHSA-aaaa"}, {"id": "PYSEC-1"}]} if q["package"]["name"] == "PyYAML"
                            else {} for q in payload["queries"]]}
    return {"GHSA-aaaa": GHSA, "PYSEC-1": PYSEC}[url.rsplit("/", 1)[1]]


def test_scan_verdict_rescan_and_report(ws):
    log = deps.scan("demo", http=fake_osv)
    assert any("1 advisories" in l for l in log), log
    conn = db.connect("demo")
    d = dict(conn.execute("SELECT * FROM dependencies").fetchone())
    assert d["reach_status"] == "pending" and "storage.py" in d["import_sites"]
    assert deps.main(["demo", "verdict", str(d["id"]), "--status", "reachable", "--reason",
                      "yaml.load on request data", "--file", "storage.py", "--line", "8",
                      "--evidence", "made up line that is not in the file"]) == 1
    assert deps.main(["demo", "verdict", str(d["id"]), "--status", "unreachable", "--reason",
                      "only yaml.safe_load is used (storage.py:13); yaml.load/full_load never called"]) == 0
    deps.scan("demo", http=fake_osv)  # a re-scan must not overwrite the agent's verdict
    assert conn.execute("SELECT reach_status FROM dependencies").fetchone()[0] == "unreachable"
    data = db.collect(conn, "demo")
    md = report.render_markdown(data)
    assert "No vulnerable dependency is reached" in md and "GHSA-aaaa" in md
    assert not sarif.to_sarif(data)["runs"][0]["results"]
    conn.execute("UPDATE dependencies SET reach_status='reachable', reach_file='storage.py', reach_line=13")
    data = db.collect(conn, "demo")
    res = sarif.to_sarif(data)["runs"][0]["results"]
    assert res[0]["ruleId"] == "GHSA-aaaa" and res[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "storage.py"
    assert "Reached at" in report.render_markdown(data)


def test_offline_scan_parses_without_network(ws):
    log = deps.scan("demo", offline=True, http=lambda *a: pytest.fail("network used"))
    assert log[0].startswith("4 pinned") and "offline" in log[-1]
