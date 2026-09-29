"""Read-only tools the agent can call. All paths are confined to the target repo."""
import json
import re
import shutil
import subprocess
from pathlib import Path

from .common import skipped_dir

MAX_READ_LINES = 400
MAX_OUTPUT_CHARS = 20_000


class RepoTools:
    def __init__(self, repo: Path):
        self.repo = repo.resolve()
        self.findings: list[dict] = []

    # --- helpers -----------------------------------------------------------
    def _safe_path(self, rel: str) -> Path:
        p = (self.repo / rel).resolve()
        if p != self.repo and self.repo not in p.parents:
            raise ValueError(f"path escapes repository: {rel}")
        return p

    def _iter_files(self):
        for p in self.repo.rglob("*"):
            if p.is_file() and not skipped_dir(self.repo, p.relative_to(self.repo).parts[:-1]):
                yield p

    @staticmethod
    def _clip(text: str) -> str:
        return text if len(text) <= MAX_OUTPUT_CHARS else text[:MAX_OUTPUT_CHARS] + "\n...[truncated]"

    def _rel(self, path: str) -> str:
        p = Path(path)
        return str(p.relative_to(self.repo)) if p.is_absolute() else path

    # --- tools -------------------------------------------------------------
    def list_files(self, subdir: str = ".") -> str:
        base = self._safe_path(subdir)
        files = [str(p.relative_to(self.repo)) for p in self._iter_files() if base == self.repo or base in p.parents]
        return self._clip("\n".join(sorted(files)) or "(no files)")

    def read_file(self, path: str, start_line: int = 1, end_line: int | None = None) -> str:
        lines = self._safe_path(path).read_text(errors="replace").splitlines()
        start = max(start_line, 1)
        end = min(end_line or start + MAX_READ_LINES - 1, start + MAX_READ_LINES - 1, len(lines))
        body = "\n".join(f"{i:>5}  {lines[i - 1]}" for i in range(start, end + 1))
        more = f"\n...[{len(lines) - end} more lines; call again with start_line={end + 1}]" if end < len(lines) else ""
        return self._clip(f"{path} (lines {start}-{end} of {len(lines)})\n{body}{more}")

    def search_code(self, pattern: str, glob: str = "*") -> str:
        rx = re.compile(pattern)
        hits = []
        for p in self._iter_files():
            if not p.match(glob):
                continue
            try:
                for n, line in enumerate(p.read_text(errors="ignore").splitlines(), 1):
                    if rx.search(line):
                        hits.append(f"{p.relative_to(self.repo)}:{n}: {line.strip()[:200]}")
            except OSError:
                continue
            if len(hits) >= 200:
                break
        return self._clip("\n".join(hits) or "(no matches)")

    def run_static_scanners(self) -> str:
        out = []
        if shutil.which("semgrep"):
            r = subprocess.run(["semgrep", "scan", "--config", "auto", "--json", "--quiet", str(self.repo)],
                               capture_output=True, text=True, timeout=600)
            try:
                out.append("## semgrep")
                out += [f"{self._rel(x['path'])}:{x['start']['line']} [{x['extra'].get('severity')}] {x['check_id']}"
                        for x in json.loads(r.stdout).get("results", [])]
            except (json.JSONDecodeError, ValueError):
                out.append(f"semgrep failed: {r.stderr[-500:]}")
        if shutil.which("bandit"):
            r = subprocess.run(["bandit", "-r", str(self.repo), "-f", "json", "-q"],
                               capture_output=True, text=True, timeout=600)
            try:
                out.append("## bandit")
                out += [f"{self._rel(x['filename'])}:{x['line_number']} [{x['issue_severity']}] "
                        f"{x['test_id']} {x['issue_text']}" for x in json.loads(r.stdout).get("results", [])]
            except (json.JSONDecodeError, ValueError):
                out.append(f"bandit failed: {r.stderr[-500:]}")
        if not out:
            return "No static scanners installed (pip install semgrep bandit). Continue with manual review."
        return self._clip("\n".join(out))

    def report_finding(self, **finding) -> str:
        if not self._safe_path(finding["file"]).is_file():
            raise ValueError(f"file not found in repo: {finding['file']}")
        self.findings.append(finding)
        return f"Recorded finding #{len(self.findings)}: {finding['title']}"

    def dispatch(self, name: str, args: dict) -> str:
        fn = {
            "list_files": self.list_files,
            "read_file": self.read_file,
            "search_code": self.search_code,
            "run_static_scanners": self.run_static_scanners,
            "report_finding": self.report_finding,
        }.get(name)
        if fn is None:
            return f"Unknown tool: {name}"
        try:
            return fn(**args)
        except Exception as e:  # surface errors to the model so it can recover
            return f"Tool error: {type(e).__name__}: {e}"


TOOL_SCHEMAS = [
    {
        "name": "list_files",
        "description": "List files in the target repository (optionally under a subdirectory).",
        "input_schema": {"type": "object", "properties": {"subdir": {"type": "string"}}},
    },
    {
        "name": "read_file",
        "description": f"Read a file with line numbers. Returns at most {MAX_READ_LINES} lines per call.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "start_line": {"type": "integer"},
                "end_line": {"type": "integer"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "search_code",
        "description": "Regex search across the repo. Use to find sources/sinks (e.g. 'execute\\(|subprocess|eval\\(').",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string"},
                "glob": {"type": "string", "description": "e.g. '*.py'"},
            },
            "required": ["pattern"],
        },
    },
    {
        "name": "run_static_scanners",
        "description": "Run installed SAST tools (semgrep, bandit) and return their raw findings as leads to verify.",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "report_finding",
        "description": "Record a confirmed vulnerability. Only call after reading the relevant code.",
        "input_schema": {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                "cwe": {"type": "string", "description": "e.g. CWE-89"},
                "file": {"type": "string"},
                "line": {"type": "integer"},
                "description": {"type": "string", "description": "What is wrong and how untrusted data reaches the sink."},
                "evidence": {"type": "string", "description": "The vulnerable code snippet."},
                "fix": {"type": "string", "description": "Concrete remediation, ideally a code patch."},
            },
            "required": ["title", "severity", "cwe", "file", "line", "description", "evidence", "fix"],
        },
    },
]
