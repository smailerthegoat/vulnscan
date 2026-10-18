"""Render a pull-request comment from a finished audit: validated findings only.

The CI workflow posts this with `gh pr comment`. Only validator-confirmed findings at or above
--min-severity appear; candidates the validator refuted are counted, never listed, so the bot stays
quiet unless it can back a claim.

    python3 -m vulnscan.prcomment <target> [--repo owner/name --sha <head sha>] [--min-severity medium]
"""
import argparse
import json
import sys

from .common import SEVERITIES, report_dir

MARKER = "<!-- vulnscan -->"


def render(data: dict, repo: str | None = None, sha: str | None = None, min_severity: str = "medium") -> str:
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    keep = [f for f in data["findings"] if f["status"] == "confirmed"
            and rank.get(f.get("verdict_severity") or f["severity"], 9) <= rank[min_severity]]
    keep.sort(key=lambda f: (rank.get(f.get("verdict_severity") or f["severity"], 9), f["file"], f["line"]))
    refuted = sum(f["status"] == "refuted" for f in data["findings"])

    def where(f: dict) -> str:
        loc = f"{f['file']}:{f['line']}"
        if repo and sha:
            return f"[`{loc}`](https://github.com/{repo}/blob/{sha}/{f['file']}#L{f['line']})"
        return f"`{loc}`"

    if not keep:
        head = f"### vulnscan: no confirmed {min_severity}+ issues in this change"
        return "\n".join([MARKER, head, "", f"{len(data['findings'])} candidate(s) checked; "
                          f"{refuted} refuted by the independent validator.", ""])
    out = [MARKER, f"### vulnscan: {len(keep)} confirmed issue(s) in this change", "",
           "| Severity | Issue | Location | CWE |", "|---|---|---|---|"]
    out += [f"| {f.get('verdict_severity') or f['severity']} | {f['title'].replace('|', '/')} | {where(f)} | {f['cwe']} |"
            for f in keep]
    for f in keep:
        out += ["", f"<details><summary><b>{f['title']}</b> ({where(f)})</summary>", ""]
        if f.get("source") and f.get("sink"):  # scanner leads carry a rule id instead of a flow
            out.append(f"- **Source → sink:** {f['source']} → {f['sink']}")
        out.append(f"- **Why it is real:** {f.get('verdict_reason') or f.get('attack_path') or ''}")
        if f.get("fix"):
            out.append(f"- **Fix:** {f['fix']}")
        out += ["", "</details>"]
    out += ["", f"<sub>Each issue was confirmed by a second, independent model that tried to refute it "
                f"({refuted} other candidate(s) were refuted and are not shown). Full report and SARIF: "
                f"workflow artifacts and the Security tab.</sub>", ""]
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="vulnscan.prcomment")
    ap.add_argument("target")
    ap.add_argument("--repo", help="owner/name, for links")
    ap.add_argument("--sha", help="head commit of the pull request, for links")
    ap.add_argument("--min-severity", default="medium", choices=SEVERITIES)
    args = ap.parse_args(argv)
    data = json.loads((report_dir(args.target) / "findings.json").read_text())
    print(render(data, args.repo, args.sha, args.min_severity))
    return 0


if __name__ == "__main__":
    sys.exit(main())
