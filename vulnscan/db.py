"""Per-target SQLite state store shared by all pipeline stages.

Every stage (SAST import, hunters, validator, patcher) reads and writes through this CLI, so
parallel subagents never race on a JSON file, runs are resumable, and every candidate is checked
against the real source before it is stored.

    python3 -m vulnscan.db <target> init
    python3 -m vulnscan.db <target> plan add --class injection --scope "app/**" --rationale "..."
    python3 -m vulnscan.db <target> plan list [--status pending]
    python3 -m vulnscan.db <target> plan start|done <id> [--result "..."]
    python3 -m vulnscan.db <target> add --file reports/<target>/inbox/x.json   (or JSON on stdin)
    python3 -m vulnscan.db <target> list [--status candidate] [--format table|ids|json]
    python3 -m vulnscan.db <target> show <id> [--blind]
    python3 -m vulnscan.db <target> verdict <id> --status confirmed|refuted --reason "..." [--severity high] [--confidence 0.9]
    python3 -m vulnscan.db <target> patch <id> --path reports/<target>/patches/<id>.diff --check ok|failed
    python3 -m vulnscan.db <target> note --kind suspicious-content --file f --line 3 --text "..."
    python3 -m vulnscan.db <target> stats
    python3 -m vulnscan.db <target> export
"""
import argparse
import hashlib
import json
import shutil
import sqlite3
import sys
from pathlib import Path

from .common import (ROOT, SEVERITIES, canonical_cwe, cwe_group, evidence_problem, normalize_cwe, norm_ws,
                     read_lines, report_dir, resolve_in, target_dir, utcnow)

SCHEMA = """
CREATE TABLE IF NOT EXISTS candidates (
  id INTEGER PRIMARY KEY,
  fingerprint TEXT UNIQUE NOT NULL,
  status TEXT NOT NULL DEFAULT 'candidate',       -- candidate | confirmed | refuted
  origin TEXT NOT NULL,                           -- hunter:<class> | sast:<tool>
  also_reported_by TEXT NOT NULL DEFAULT '',
  title TEXT NOT NULL, severity TEXT NOT NULL, cwe TEXT NOT NULL,
  file TEXT NOT NULL, line INTEGER NOT NULL,
  source TEXT, sink TEXT, attack_path TEXT, description TEXT,
  evidence TEXT NOT NULL, fix TEXT, confidence REAL,
  verdict_reason TEXT, verdict_severity TEXT, verdict_confidence REAL,
  patch_path TEXT, patch_check TEXT,
  created TEXT, updated TEXT
);
CREATE TABLE IF NOT EXISTS work_units (
  id INTEGER PRIMARY KEY, vuln_class TEXT NOT NULL, scope TEXT NOT NULL, rationale TEXT,
  status TEXT NOT NULL DEFAULT 'pending', result TEXT, created TEXT, updated TEXT
);
CREATE TABLE IF NOT EXISTS notes (
  id INTEGER PRIMARY KEY, kind TEXT, file TEXT, line INTEGER, text TEXT, created TEXT,
  UNIQUE(kind, file, line, text)
);
CREATE TABLE IF NOT EXISTS dependencies (
  id INTEGER PRIMARY KEY, ecosystem TEXT, package TEXT, version TEXT, vuln_id TEXT,
  summary TEXT, severity TEXT, fixed TEXT, manifest TEXT,
  UNIQUE(package, version, vuln_id)
);
CREATE TABLE IF NOT EXISTS advisories (
  candidate_id INTEGER PRIMARY KEY,
  status TEXT NOT NULL DEFAULT 'pending',   -- pending | ready | needs-review | fixed-upstream | fixed-unreleased | duplicate
  upstream_url TEXT, audited_commit TEXT,
  latest_release TEXT, latest_commit TEXT, latest_status TEXT, latest_location TEXT,
  head_ref TEXT, head_commit TEXT, head_status TEXT, head_location TEXT,
  introduced_in TEXT, fixed_in TEXT, affected TEXT,
  cvss_vector TEXT, cvss_score REAL, cvss_severity TEXT,
  known_advisories TEXT, path TEXT, osv_path TEXT, checked TEXT, updated TEXT
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""

# Columns added after the first release; connect() adds them to existing state stores.
MIGRATIONS = {
    "dependencies": {
        "aliases": "TEXT", "cwe": "TEXT", "cvss": "TEXT", "details": "TEXT", "symbols": "TEXT",
        "scope": "TEXT", "direct": "INTEGER", "manifest_line": "INTEGER",
        "import_sites": "TEXT", "symbol_hits": "TEXT",
        "reach_status": "TEXT", "reach_method": "TEXT", "reach_reason": "TEXT",
        "reach_file": "TEXT", "reach_line": "INTEGER", "reach_evidence": "TEXT", "updated": "TEXT",
    },
}


def migrate(conn: sqlite3.Connection) -> None:
    for table, cols in MIGRATIONS.items():
        have = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
        for col, typ in cols.items():
            if col not in have:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typ}")
    conn.commit()

HUNTER_REQUIRED = ["title", "severity", "cwe", "file", "line", "evidence",
                   "source", "sink", "attack_path", "description", "fix"]
DUP_LINE_SLACK = 3


def connect(target: str) -> sqlite3.Connection:
    target_dir(target)
    conn = sqlite3.connect(report_dir(target) / "state.db", timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.executescript(SCHEMA)
    migrate(conn)
    return conn


def fingerprint(target: str, cwe: str, file: str, line: int) -> str:
    """Stable across line shifts: keyed on the CWE family, the normalized sink line, and which occurrence
    of that exact line in the file it is (so repeated lines such as `@csrf_exempt` or
    `cursor.execute(query)` stay separate findings)."""
    try:
        lines = [norm_ws(l) for l in read_lines(resolve_in(target_dir(target), file))]
        text = lines[line - 1]
        text += f"#{lines[:line - 1].count(text)}"
    except (IndexError, OSError, ValueError):
        text = f"L{line}"
    family = min(cwe_group(cwe))
    return hashlib.sha256(f"{family}|{file}|{text}".encode()).hexdigest()[:16]


def find_duplicate(conn, target: str, c: dict, origin: str = "") -> sqlite3.Row | None:
    fp = fingerprint(target, c["cwe"], c["file"], c["line"])
    row = conn.execute("SELECT * FROM candidates WHERE fingerprint=?", (fp,)).fetchone()
    if row:
        return row
    family = cwe_group(c["cwe"])
    for r in conn.execute("SELECT * FROM candidates WHERE file=? AND ABS(line-?)<=?",
                          (c["file"], c["line"], DUP_LINE_SLACK)):
        if normalize_cwe(r["cwe"]) not in family:
            continue
        if r["line"] != c["line"] and origin.startswith("sast") and r["origin"].startswith("sast"):
            continue  # scanners report exact sink lines: hits on different lines are different sinks
        return r
    return None


def add_candidate(conn, target: str, c: dict, origin: str, verify: bool = True) -> tuple[str, int | None]:
    """Insert a candidate. Returns (message, id). Rejects hallucinated or malformed findings."""
    if origin.startswith("hunter"):
        missing = [k for k in HUNTER_REQUIRED if not str(c.get(k, "")).strip()]
        if missing:
            return f"REJECTED: missing fields {missing}", None
    c = {**c, "cwe": canonical_cwe(c.get("cwe")), "severity": str(c.get("severity", "")).lower()}
    try:
        c["line"] = int(c["line"])
    except (KeyError, TypeError, ValueError):
        return "REJECTED: line must be an integer", None
    if c["severity"] not in SEVERITIES:
        return f"REJECTED: severity must be one of {SEVERITIES}", None
    if verify and (problem := evidence_problem(target_dir(target), c["file"], c["line"], c["evidence"])):
        return f"REJECTED: {problem}", None

    now = utcnow()
    if dup := find_duplicate(conn, target, c, origin):
        others = {o for o in dup["also_reported_by"].split(",") if o} | {origin}
        others.discard(dup["origin"])
        fill = {k: c[k] for k in ("source", "sink", "attack_path", "description", "fix")
                if c.get(k) and not dup[k]}
        if dup["origin"].startswith("sast") and origin.startswith("hunter"):
            # a hunter's traced explanation beats a scanner's rule text
            fill.update({k: c[k] for k in ("title", "sink", "description") if c.get(k)})
        sets = ", ".join(f"{k}=?" for k in fill)
        conn.execute(f"UPDATE candidates SET also_reported_by=?, updated=?{', ' + sets if sets else ''} WHERE id=?",
                     (",".join(sorted(others)), now, *fill.values(), dup["id"]))
        conn.commit()
        return f"DUPLICATE of #{dup['id']} ({dup['title']}); merged", dup["id"]

    cur = conn.execute(
        """INSERT INTO candidates (fingerprint, origin, title, severity, cwe, file, line, source, sink,
           attack_path, description, evidence, fix, confidence, created, updated)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (fingerprint(target, c["cwe"], c["file"], c["line"]), origin, c["title"], c["severity"],
         c["cwe"], c["file"], c["line"], c.get("source"), c.get("sink"), c.get("attack_path"),
         c.get("description"), c["evidence"], c.get("fix"), c.get("confidence"), now, now))
    conn.commit()
    return f"ADDED #{cur.lastrowid}: {c['title']}", cur.lastrowid


def add_note(conn, kind: str, file: str, line: int | None, text: str) -> None:
    conn.execute("INSERT OR IGNORE INTO notes (kind, file, line, text, created) VALUES (?,?,?,?,?)",
                 (kind, file, line, text[:500], utcnow()))
    conn.commit()


def rows(conn, sql: str, *args) -> list[dict]:
    return [dict(r) for r in conn.execute(sql, args)]


# --- export ------------------------------------------------------------------------------------

def collect(conn, target: str) -> dict:
    sev_rank = {s: i for i, s in enumerate(SEVERITIES)}
    confirmed = rows(conn, "SELECT * FROM candidates WHERE status='confirmed'")
    for f in confirmed:
        f["severity"] = f["verdict_severity"] or f["severity"]
    confirmed.sort(key=lambda f: (sev_rank.get(f["severity"], 9), f["file"], f["line"]))
    by_status = {r["status"]: r["n"] for r in conn.execute(
        "SELECT status, COUNT(*) n FROM candidates GROUP BY status")}
    meta = {r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM meta")}
    return {
        "target": target,
        "generated_utc": utcnow(),
        "focus": meta.get("focus", ""),
        "mode": meta.get("mode", "full"),
        "summary": meta.get("summary", ""),
        "stats": {
            "candidates_total": sum(by_status.values()),
            "confirmed": by_status.get("confirmed", 0),
            "refuted": by_status.get("refuted", 0),
            "unvalidated": by_status.get("candidate", 0),
            "work_units": conn.execute("SELECT COUNT(*) FROM work_units").fetchone()[0],
        },
        "findings": confirmed,
        "refuted": rows(conn, "SELECT id, origin, title, cwe, file, line, verdict_reason FROM candidates "
                              "WHERE status='refuted' ORDER BY file, line"),
        "unvalidated": rows(conn, "SELECT id, origin, title, severity, cwe, file, line FROM candidates "
                                  "WHERE status='candidate' ORDER BY file, line"),
        "dependencies": rows(conn, "SELECT * FROM dependencies ORDER BY package"),
        "advisories": rows(conn, "SELECT a.*, c.title, c.cwe, c.file, c.line FROM advisories a "
                                 "JOIN candidates c ON c.id = a.candidate_id ORDER BY a.candidate_id"),
        "notes": rows(conn, "SELECT kind, file, line, text FROM notes ORDER BY kind, file, line"),
        "work_units": rows(conn, "SELECT id, vuln_class, scope, status, result FROM work_units"),
    }


def export(conn, target: str) -> list[Path]:
    from .report import render_markdown
    from .sarif import to_sarif

    data = collect(conn, target)
    out = report_dir(target)
    paths = [out / "findings.json", out / "report.md", out / "results.sarif"]
    paths[0].write_text(json.dumps(data, indent=2))
    paths[1].write_text(render_markdown(data))
    paths[2].write_text(json.dumps(to_sarif(data), indent=2))
    return paths


# --- CLI ---------------------------------------------------------------------------------------

def _print_table(items: list[dict]) -> None:
    if not items:
        print("(none)")
        return
    for r in items:
        who = r["origin"] + (f" +{r['also_reported_by']}" if r.get("also_reported_by") else "")
        print(f"#{r['id']:<4} {r['status']:<10} {r['severity']:<8} {r['cwe']:<9} "
              f"{r['file']}:{r['line']}  {r['title']}  [{who}]")


def _load_candidates(args) -> list[dict]:
    raw = Path(args.file).read_text() if args.file else sys.stdin.read()
    data = json.loads(raw)
    return data if isinstance(data, list) else [data]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="vulnscan.db", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init")
    p = sub.add_parser("meta"); p.add_argument("key"); p.add_argument("value")

    p = sub.add_parser("plan")
    psub = p.add_subparsers(dest="plan_cmd", required=True)
    q = psub.add_parser("add")
    q.add_argument("--class", dest="vuln_class", required=True)
    q.add_argument("--scope", required=True, help="comma-separated paths/globs relative to the target")
    q.add_argument("--rationale", default="")
    q = psub.add_parser("list"); q.add_argument("--status")
    for name in ("start", "done"):
        q = psub.add_parser(name); q.add_argument("id", type=int); q.add_argument("--result", default="")

    p = sub.add_parser("add")
    p.add_argument("--file", help="JSON file with one candidate object or a list (default: stdin)")
    p.add_argument("--origin", default="hunter", help="e.g. hunter:injection")

    p = sub.add_parser("list")
    p.add_argument("--status"); p.add_argument("--origin")
    p.add_argument("--format", choices=["table", "ids", "json"], default="table")

    p = sub.add_parser("show"); p.add_argument("id", type=int)
    p.add_argument("--blind", action="store_true",
                   help="validator view: the claim only, without the reporter's reasoning or confidence")

    p = sub.add_parser("verdict"); p.add_argument("id", type=int)
    p.add_argument("--status", choices=["confirmed", "refuted"], required=True)
    p.add_argument("--reason", required=True)
    p.add_argument("--severity", choices=SEVERITIES)
    p.add_argument("--confidence", type=float)
    p.add_argument("--title", help="clearer title (e.g. for scanner leads named after a rule)")

    p = sub.add_parser("patch"); p.add_argument("id", type=int)
    p.add_argument("--path", required=True); p.add_argument("--check", choices=["ok", "failed"], required=True)

    p = sub.add_parser("note")
    p.add_argument("--kind", required=True); p.add_argument("--file", default="")
    p.add_argument("--line", type=int); p.add_argument("--text", required=True)

    sub.add_parser("stats")
    sub.add_parser("export")
    sub.add_parser("reset", help="clear all pipeline state for this target (fresh audit)")

    args = ap.parse_args(argv)
    conn = connect(args.target)
    t = args.target

    if args.cmd == "init":
        print(f"state store ready: {report_dir(t) / 'state.db'}")
    elif args.cmd == "meta":
        conn.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (args.key, args.value)); conn.commit()
        print(f"set {args.key}")
    elif args.cmd == "plan":
        now = utcnow()
        if args.plan_cmd == "add":
            cur = conn.execute("INSERT INTO work_units (vuln_class, scope, rationale, created, updated) "
                               "VALUES (?,?,?,?,?)", (args.vuln_class, args.scope, args.rationale, now, now))
            conn.commit()
            print(f"work unit #{cur.lastrowid}: {args.vuln_class} over {args.scope}")
        elif args.plan_cmd == "list":
            sql, params = "SELECT * FROM work_units", ()
            if args.status:
                sql, params = sql + " WHERE status=?", (args.status,)
            for r in conn.execute(sql, params):
                print(f"#{r['id']:<3} {r['status']:<8} {r['vuln_class']:<16} scope={r['scope']}  {r['rationale'] or ''}")
        else:
            status = "running" if args.plan_cmd == "start" else "done"
            conn.execute("UPDATE work_units SET status=?, result=COALESCE(NULLIF(?, ''), result), updated=? "
                         "WHERE id=?", (status, args.result, now, args.id))
            conn.commit()
            print(f"work unit #{args.id} -> {status}")
    elif args.cmd == "add":
        rc = 0
        for c in _load_candidates(args):
            msg, _ = add_candidate(conn, t, c, args.origin)
            print(msg)
            rc |= msg.startswith("REJECTED")
        return rc
    elif args.cmd == "list":
        sql, params = "SELECT * FROM candidates WHERE 1=1", []
        if args.status:
            sql += " AND status=?"; params.append(args.status)
        if args.origin:
            sql += " AND origin LIKE ?"; params.append(args.origin + "%")
        items = rows(conn, sql + " ORDER BY file, line", *params)
        if args.format == "ids":
            print(" ".join(str(r["id"]) for r in items))
        elif args.format == "json":
            print(json.dumps(items, indent=2))
        else:
            _print_table(items)
    elif args.cmd == "show":
        r = conn.execute("SELECT * FROM candidates WHERE id=?", (args.id,)).fetchone()
        if not r:
            print(f"no candidate #{args.id}"); return 1
        keys = (["id", "title", "cwe", "file", "line", "source", "sink", "attack_path"] if args.blind
                else list(r.keys()))
        print(json.dumps({k: r[k] for k in keys}, indent=2))
    elif args.cmd == "verdict":
        if len(args.reason.strip()) < 20:
            print("REJECTED: give a concrete reason (20+ chars) citing the code you checked"); return 1
        conn.execute("UPDATE candidates SET status=?, verdict_reason=?, verdict_severity=?, "
                     "verdict_confidence=?, title=COALESCE(?, title), updated=? WHERE id=?",
                     (args.status, args.reason, args.severity, args.confidence, args.title, utcnow(), args.id))
        conn.commit()
        print(f"#{args.id} -> {args.status}")
    elif args.cmd == "patch":
        conn.execute("UPDATE candidates SET patch_path=?, patch_check=?, updated=? WHERE id=?",
                     (args.path, args.check, utcnow(), args.id))
        conn.commit()
        print(f"#{args.id} patch recorded ({args.check})")
    elif args.cmd == "note":
        add_note(conn, args.kind, args.file, args.line, args.text)
        print("note recorded")
    elif args.cmd == "stats":
        print(json.dumps(collect(conn, t)["stats"], indent=2))
    elif args.cmd == "export":
        for p in export(conn, t):
            print(f"wrote {p.relative_to(ROOT)}")
    elif args.cmd == "reset":
        for table in ("candidates", "work_units", "notes", "dependencies", "advisories", "meta"):
            conn.execute(f"DELETE FROM {table}")
        conn.commit()
        out = report_dir(t)
        for name in ("findings.json", "report.md", "results.sarif", "eval.md", "architecture.md"):
            (out / name).unlink(missing_ok=True)
        for name in ("inbox", "patches", "rules", "sanitized", "sast", "deps", "advisories"):
            shutil.rmtree(out / name, ignore_errors=True)
        print(f"reset pipeline state for {t}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
