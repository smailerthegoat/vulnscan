"""CLI: python -m vulnscan <repo> "<prompt>" """
import argparse
import os
import sys
from pathlib import Path

from .agent import run_scan
from .report import write_reports

DEFAULT_TASK = "Audit this repository for exploitable security vulnerabilities and propose fixes."


def main() -> int:
    ap = argparse.ArgumentParser(prog="vulnscan", description="Agentic LLM security code auditor")
    ap.add_argument("repo", type=Path, help="path to the cloned target repository")
    ap.add_argument("prompt", nargs="?", default=DEFAULT_TASK, help="what you want the agent to do")
    ap.add_argument("--model", default=os.getenv("VULNSCAN_MODEL", "claude-sonnet-5"))
    ap.add_argument("--max-turns", type=int, default=40)
    ap.add_argument("--out", type=Path, default=Path("reports"))
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()

    if not args.repo.is_dir():
        print(f"error: {args.repo} is not a directory", file=sys.stderr)
        return 2
    if not os.getenv("ANTHROPIC_API_KEY"):
        print("error: set ANTHROPIC_API_KEY", file=sys.stderr)
        return 2

    result = run_scan(args.repo, args.prompt, args.model, args.max_turns, verbose=not args.quiet)
    json_path, md_path = write_reports(result, args.out)
    print(f"\n{len(result['findings'])} finding(s). Reports: {md_path}  {json_path}")
    print(f"Tokens: {result['usage']['input_tokens']} in / {result['usage']['output_tokens']} out")
    return 0


if __name__ == "__main__":
    sys.exit(main())
