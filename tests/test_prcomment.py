"""Pull-request comment: validated findings only, refuted ones counted but never listed."""
from vulnscan import prcomment


def _f(id, status, sev, title, line=10):
    return {"id": id, "status": status, "severity": sev, "verdict_severity": sev, "title": title, "cwe": "CWE-89",
            "file": "app.py", "line": line, "source": "q", "sink": "execute", "verdict_reason": "app.py:9 reads q",
            "fix": "bind it"}


def test_lists_only_confirmed_findings_at_or_above_the_threshold():
    data = {"findings": [_f(1, "confirmed", "high", "SQL injection | search", 42), _f(2, "refuted", "critical", "trap"),
                         _f(3, "confirmed", "low", "minor"), _f(4, "candidate", "high", "unvalidated")]}
    md = prcomment.render(data, "o/r", "abc", "medium")
    assert md.startswith(prcomment.MARKER) and "1 confirmed issue(s)" in md
    assert "[`app.py:42`](https://github.com/o/r/blob/abc/app.py#L42)" in md
    assert "SQL injection / search" in md and "trap" not in md and "minor" not in md and "unvalidated" not in md
    assert "1 other candidate(s) were refuted" in md


def test_quiet_comment_when_nothing_is_confirmed():
    md = prcomment.render({"findings": [_f(1, "refuted", "high", "trap")]}, min_severity="medium")
    assert "no confirmed medium+ issues" in md and "1 refuted" in md and "|" not in md
