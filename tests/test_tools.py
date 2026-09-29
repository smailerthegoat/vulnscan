from pathlib import Path

import pytest

from vulnscan.tools import RepoTools

DEMO = Path(__file__).resolve().parents[1] / "examples" / "demo_target"


@pytest.fixture
def tools():
    return RepoTools(DEMO)


def test_list_files(tools):
    assert "app.py" in tools.list_files()


def test_read_file_numbers_lines(tools):
    out = tools.read_file("app.py", 1, 2)
    assert out.splitlines()[1].strip().startswith("1")


def test_path_escape_blocked(tools):
    assert "escapes repository" in tools.dispatch("read_file", {"path": "../../README.md"})


def test_search_code(tools):
    assert "app.py" in tools.search_code(r"shell=True")


def test_report_finding_validates_file(tools):
    base = dict(title="t", severity="high", cwe="CWE-78", line=1, description="d", evidence="e", fix="f")
    assert "Tool error" in tools.dispatch("report_finding", {**base, "file": "nope.py"})
    assert "Recorded" in tools.dispatch("report_finding", {**base, "file": "app.py"})
    assert len(tools.findings) == 1
