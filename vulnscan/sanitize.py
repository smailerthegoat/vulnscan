"""Build a comment-stripped, line-preserving mirror of a target for the hunter and validator agents.

Why: natural-language comments can steer LLM detectors without changing program behaviour
(ALIBI, arXiv:2607.24964). Pre-detector comment sanitization plus architectural isolation is the
defense that held up there, so agents that judge code read this mirror instead of the raw tree.
Line and column positions are preserved, so findings map 1:1 back to the original files.

Comments that address AI reviewers or make unverifiable claims ("already audited", "scanner
passed") are recorded as `suspicious-content` notes in the state store.

    python3 -m vulnscan.sanitize <target>
"""
import io
import re
import shutil
import sys
import tokenize

from .common import iter_source_files, report_dir, target_dir

C_LIKE = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".cs", ".java", ".js", ".jsx", ".mjs",
          ".cjs", ".ts", ".tsx", ".go", ".kt", ".kts", ".scala", ".swift", ".rs", ".dart", ".php",
          ".groovy", ".css", ".scss", ".sol", ".m", ".mm"}
HASH = {".sh", ".bash", ".zsh", ".rb", ".pl", ".pm", ".yaml", ".yml", ".toml", ".r", ".ps1",
        ".tf", ".hcl", ".conf", ".cfg", ".ini", ".properties", ".env.example", ".mk"}
MARKUP = {".html", ".htm", ".xml", ".vue", ".svelte", ".jinja", ".jinja2", ".j2", ".tmpl", ".ejs",
          ".hbs", ".erb", ".twig", ".jsp", ".xhtml"}
SQL = {".sql"}
DOCS = {".md", ".rst", ".txt", ".adoc"}  # prose is left out of the mirror entirely
HASH_NAMES = {"Dockerfile", "Makefile", "Gemfile", "Rakefile", "Procfile", ".gitignore", ".dockerignore"}

STEERING = [re.compile(p, re.I) for p in [
    r"\b(ignore|disregard|forget|override)\b.{0,40}\b(instruction|prompt|rule|previous|above|guideline)",
    r"\b(ai|llm|gpt|claude|copilot|gemini|assistant|language model|agent|(security|code) "
    r"(scanner|tool|reviewer|auditor|bot))\b.{0,80}\b(report|flag|mark|treat|consider|skip|ignore|"
    r"approve|safe|secure|false positive|no (issues|vulnerabilit))",
    r"\b(already|previously|has been|have been|was|were)\s+(fully\s+)?(audited|reviewed|verified|"
    r"approved|pentested|pen-tested|signed off)\b",
    r"\b(do not|don't|dont|never)\s+(report|flag|mention|analy[sz]e|scan)\b",
    r"\b(no|zero)\s+(security\s+)?(vulnerabilit\w*|issues?|findings?)\s+(here|in this|exist|present)",
    r"<\s*/?\s*(system|instructions?|tool_result|function_results?|assistant|user)\s*>",
    r"\b(semgrep|bandit|codeql|snyk|sonar\w*|scanner|fuzzer)\b.{0,50}\b(pass(ed)?|clean|no findings|"
    r"0 findings|verified|confirmed safe)",
]]


def _blank(s: str) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in s)


def strip_python(src: str, comments: list) -> str:
    try:
        toks = list(tokenize.generate_tokens(io.StringIO(src).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return strip_hash(src, comments)
    lines = src.splitlines(keepends=True)
    offsets = [0]
    for ln in lines:
        offsets.append(offsets[-1] + len(ln))
    pos = lambda r, c: offsets[r - 1] + c  # noqa: E731
    out = list(src)
    prev = tokenize.NEWLINE
    for i, tok in enumerate(toks):
        is_docstring = (tok.type == tokenize.STRING and prev in (tokenize.NEWLINE, tokenize.INDENT,
                        tokenize.DEDENT, tokenize.NL, tokenize.ENCODING)
                        and i + 1 < len(toks) and toks[i + 1].type in (tokenize.NEWLINE, tokenize.ENDMARKER))
        if tok.type == tokenize.COMMENT or is_docstring:
            a, b = pos(*tok.start), pos(*tok.end)
            comments.append((tok.start[0], tok.string))
            if is_docstring:  # keep the quotes so the mirror stays valid Python
                q = re.match(r"[rRbBuUfF]*('''|\"\"\"|'|\")", tok.string)
                a += len(q.group(0))  # prefix + opening quote
                b -= len(q.group(1))  # closing quote
            out[a:b] = _blank(src[a:b])
        if tok.type not in (tokenize.COMMENT, tokenize.NL):
            prev = tok.type
    return "".join(out)


def _scan(src: str, comments: list, line_markers: tuple, block: tuple | None, quotes: str,
          hash_attributes: bool = False) -> str:
    """Small lexer: blanks comments while respecting string literals.

    hash_attributes keeps PHP 8 attributes (`#[Route(...)]`), which look like `#` comments.
    """
    out, i, n, line = list(src), 0, len(src), 1
    while i < n:
        ch = src[i]
        if ch == "\n":
            line += 1; i += 1; continue
        if ch in quotes:
            j = i + 1
            while j < n and src[j] != ch:
                if src[j] == "\\" and j + 1 < n:
                    line += src[j + 1] == "\n"
                    j += 2; continue
                if src[j] == "\n":
                    if ch != "`":
                        break  # unterminated single-line string: resume at the newline
                    line += 1
                j += 1
            i = j + 1 if j < n and src[j] == ch else j; continue
        if block and src.startswith(block[0], i):
            j = src.find(block[1], i + len(block[0]))
            j = n if j == -1 else j + len(block[1])
            comments.append((line, src[i:j]))
            out[i:j] = _blank(src[i:j]); line += src.count("\n", i, j); i = j; continue
        marker = next((m for m in line_markers if src.startswith(m, i)), None)
        if marker == "#" and hash_attributes and src.startswith("#[", i):
            marker = None
        if marker and not (marker == "#" and i > 0 and src[i - 1] == "$"):  # keep shell "$#"
            j = src.find("\n", i)
            j = n if j == -1 else j
            comments.append((line, src[i:j]))
            out[i:j] = _blank(src[i:j]); i = j; continue
        i += 1
    return "".join(out)


def strip_c_like(src, comments, php=False):
    return _scan(src, comments, ("//", "#") if php else ("//",), ("/*", "*/"), "\"'`", hash_attributes=php)


def strip_hash(src, comments):
    return _scan(src, comments, ("#",), None, "\"'")


def strip_ruby(src, comments):
    """`=begin ... =end` block comments (at line start), then `#` comments."""
    def blank(m):
        comments.append((src.count("\n", 0, m.start()) + 1, m.group(0)))
        return _blank(m.group(0))
    return strip_hash(re.sub(r"(?ms)^=begin\b.*?^=end\b[^\n]*", blank, src), comments)


def strip_markup(src, comments):
    for block in (("<!--", "-->"), ("{#", "#}"), ("<%#", "%>"), ("{{--", "--}}")):  # HTML, Jinja/Twig, ERB/EJS, Blade
        src = _scan(src, comments, (), block, "")
    return src


def strip_sql(src, comments):
    return _scan(src, comments, ("--",), ("/*", "*/"), "'")


def sanitize_text(name: str, suffix: str, src: str) -> tuple[str | None, list]:
    comments: list = []
    if suffix in DOCS:
        return None, comments
    if suffix in (".py", ".pyi", ".pyw"):
        out = strip_python(src, comments)
    elif suffix in C_LIKE:
        out = strip_c_like(src, comments, php=suffix == ".php")
    elif suffix in HASH or name in HASH_NAMES:
        out = strip_ruby(src, comments) if suffix == ".rb" else strip_hash(src, comments)
    elif suffix in MARKUP:
        out = strip_markup(src, comments)
    elif suffix in SQL:
        out = strip_sql(src, comments)
    else:
        out = src  # data/config formats without a comment syntax we trust to strip
    out = "\n".join(l.rstrip() for l in out.split("\n"))
    return out, comments


def steering_hits(comments: list) -> list[tuple[int, str]]:
    return [(ln, " ".join(text.split())[:300]) for ln, text in comments
            if any(p.search(text) for p in STEERING)]


def build_mirror(target: str) -> dict:
    from .db import add_note, connect

    src_root = target_dir(target)
    dst_root = report_dir(target) / "sanitized"
    if dst_root.exists():
        shutil.rmtree(dst_root)
    conn = connect(target)
    stats = {"files": 0, "stripped_comments": 0, "suspicious": 0, "skipped_docs": 0}
    for path in iter_source_files(src_root):
        rel = path.relative_to(src_root)
        out, comments = sanitize_text(path.name, path.suffix.lower(), path.read_text(errors="replace"))
        if out is None:
            stats["skipped_docs"] += 1
            continue
        dst = dst_root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(out)
        stats["files"] += 1
        stats["stripped_comments"] += len(comments)
        for ln, text in steering_hits(comments):
            add_note(conn, "suspicious-content", str(rel), ln, text)
            stats["suspicious"] += 1
    return stats


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) != 1:
        print("usage: python3 -m vulnscan.sanitize <target>", file=sys.stderr)
        return 2
    s = build_mirror(argv[0])
    print(f"sanitized mirror: reports/{argv[0]}/sanitized/ ({s['files']} files, "
          f"{s['stripped_comments']} comments stripped, {s['skipped_docs']} prose files excluded, "
          f"{s['suspicious']} suspicious comments noted)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
