#!/usr/bin/env python3
"""PreToolUse guard: repositories under targets/ are read-only evidence.

Defense in depth on top of settings.json permissions, and it also covers subagents:
- Write/Edit/NotebookEdit into targets/ is blocked.
- A Bash command that touches targets/ is allowed only if every sub-command is on a read-only
  allowlist, so code from a target is never executed, installed, built or modified.
Exit code 2 blocks the call and sends the reason back to the agent.
"""
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(os.environ.get("CLAUDE_PROJECT_DIR") or Path(__file__).resolve().parents[2]).resolve()
TARGETS = ROOT / "targets"

READ_ONLY = [
    r"python3? -m vulnscan\.(db|sast|sanitize|patchcheck|evaluate|report|targets|batch|stacks|deps|advisory|bench|scorecard|cvss)\b",
    r"git -C \S+ (log|diff|show|ls-files|rev-parse|blame|status|grep)\b",
    r"(ls|cat|head|tail|wc|grep|rg|file|stat|tree|sort|uniq|cut|nl|diff|basename|dirname|realpath|echo|true)\b",
    r"sed -n\b",
    r"find\b(?!.*\s-(exec|execdir|delete|ok|okdir|fprint\w*|fls)\b)",
]
REDIRECT_INTO_TARGETS = re.compile(r"(>|>>|\btee\b)\s*\S*targets/")


def block(reason: str) -> None:
    print(f"Blocked by vulnscan guard: {reason}", file=sys.stderr)
    sys.exit(2)


def inside_targets(path: str) -> bool:
    p = Path(path)
    p = (p if p.is_absolute() else ROOT / p).resolve()
    return p == TARGETS or TARGETS in p.parents


def mentions_targets(cmd: str) -> bool:
    return bool(re.search(r"(^|[\s'\"=:(])(\./)?targets(/|\s|$)", cmd)) or str(TARGETS) in cmd


def segments(cmd: str) -> list[str] | None:
    """Split on shell control operators outside quotes (so `grep -E "a|b"` stays one command).

    Returns None when the command uses command or process substitution anywhere outside single
    quotes: `ls $(rm -rf targets/x)` would otherwise pass as an allowlisted `ls`.
    """
    # Drop heredoc bodies (data, not commands) before splitting on shell operators.
    cmd = re.sub(r"<<-?\s*(['\"]?)(\w+)\1.*?^\s*\2\s*$", "<<HEREDOC", cmd, flags=re.S | re.M)
    out, cur, quote, i = [], [], None, 0
    while i < len(cmd):
        ch = cmd[i]
        if quote == "'":
            quote = None if ch == "'" else quote
            cur.append(ch)
            i += 1
            continue
        if ch == "\\" and i + 1 < len(cmd):
            cur.append(cmd[i:i + 2])
            i += 2
            continue
        if ch == "`" or cmd.startswith(("$(", "<(", ">("), i):
            return None
        if quote == '"' or ch in "'\"":
            quote = None if ch == quote else (ch if quote is None and ch in "'\"" else quote)
            cur.append(ch)
            i += 1
            continue
        if cmd.startswith(("&&", "||"), i):
            out.append("".join(cur)); cur = []; i += 2
            continue
        redirect = ch == "&" and ((cur and cur[-1] in "<>") or cmd.startswith("&>", i))  # 2>&1, &>file
        if ch in ";|\n" or (ch == "&" and not redirect):
            out.append("".join(cur)); cur = []; i += 1
            continue
        cur.append(ch)
        i += 1
    out.append("".join(cur))
    return [s.strip() for s in out if s.strip()]


def main() -> None:
    data = json.load(sys.stdin)
    tool, inp = data.get("tool_name", ""), data.get("tool_input", {}) or {}

    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        path = inp.get("file_path") or inp.get("notebook_path") or ""
        if path and inside_targets(path):
            block("targets/ is read-only. Write audit output under reports/<target>/ instead.")
        sys.exit(0)

    if tool == "Bash":
        cmd = inp.get("command", "")
        if not mentions_targets(cmd):
            sys.exit(0)
        if REDIRECT_INTO_TARGETS.search(cmd):
            block("redirecting output into targets/ is not allowed.")
        segs = segments(cmd)
        if segs is None:
            block("command substitution ($(...), backticks, <(...)) is not allowed in commands that touch targets/.")
        for seg in segs:
            seg = re.sub(r"^(\w+=\S*\s+)+", "", seg)  # ignore leading VAR=value assignments
            if not any(re.match(p, seg) for p in READ_ONLY):
                block(f"'{seg[:80]}' is not on the read-only allowlist for commands that touch targets/. "
                      "Target code must never be executed, installed, built or modified. Use Read/Grep/Glob, "
                      "the vulnscan modules, or read-only git (log/diff/show/blame).")
    sys.exit(0)


if __name__ == "__main__":
    main()
