"""Detect a target's languages and frameworks, and pick the matching scanner rules and playbooks.

Deterministic (file extensions and manifest contents only; nothing from the target is executed).
The result drives three things:
  - which Semgrep registry packs and curated rules (rules/*.yml) `vulnscan.sast` runs,
  - which stack playbooks (playbooks/stacks/*.md) hunters and validators read,
  - the `stacks` meta entry in the state store (shown in the report).

    python3 -m vulnscan.stacks <target> [--json]
"""
import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

from .common import ROOT, iter_source_files, skipped_dir, target_dir

LANG_EXT = {
    ".py": "python", ".go": "go", ".java": "java", ".kt": "kotlin", ".kts": "kotlin", ".scala": "scala",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".vue": "javascript", ".svelte": "javascript",
    ".rb": "ruby", ".erb": "ruby", ".php": "php", ".rs": "rust", ".cs": "csharp",
    ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp",
}
MANIFESTS = {"package.json", "go.mod", "pom.xml", "build.gradle", "build.gradle.kts", "Gemfile", "composer.json",
             "requirements.txt", "pyproject.toml", "Pipfile", "setup.py", "setup.cfg", "Cargo.toml"}

# stack id -> (Semgrep registry packs, curated rule file under rules/, playbook under playbooks/stacks/)
STACKS = {
    "python": (["p/python"], None, None),
    "django": (["p/django"], None, None),
    "flask": (["p/flask"], None, None),
    "fastapi": ([], None, None),
    "go": (["p/golang", "p/gosec"], "go.yml", "go.md"),
    "java": (["p/java", "p/findsecbugs"], "java-spring.yml", "java-spring.md"),
    "kotlin": (["p/kotlin"], None, "java-spring.md"),
    "spring": ([], "java-spring.yml", "java-spring.md"),
    "node": (["p/javascript", "p/nodejsscan", "p/nodejs"], "node-express.yml", "node-express.md"),
    "typescript": (["p/typescript"], "node-express.yml", "node-express.md"),
    "express": (["p/expressjs"], "node-express.yml", "node-express.md"),
    "koa": ([], "node-express.yml", "node-express.md"),
    "fastify": ([], "node-express.yml", "node-express.md"),
    "nestjs": ([], "node-express.yml", "node-express.md"),
    "nextjs": ([], "node-express.yml", "node-express.md"),
    "frontend-js": (["p/javascript"], "node-express.yml", "node-express.md"),
    "ruby": (["p/ruby"], "ruby-rails.yml", "ruby-rails.md"),
    "rails": (["p/brakeman"], "ruby-rails.yml", "ruby-rails.md"),
    "sinatra": ([], "ruby-rails.yml", "ruby-rails.md"),
    "php": (["p/php", "p/phpcs-security-audit"], "php.yml", "php.md"),
    "laravel": ([], "php.yml", "php.md"),
    "symfony": ([], "php.yml", "php.md"),
    "wordpress": ([], "php.yml", "php.md"),
    "rust": (["p/rust"], None, None),
    "c": (["p/c"], None, None),
    "cpp": (["p/c"], None, None),
    "csharp": (["p/csharp"], None, None),
}

# framework id -> (manifest file names, regex over their text)
FRAMEWORKS = {
    "django": (("requirements.txt", "pyproject.toml", "Pipfile", "setup.py", "setup.cfg"), r"(?im)^\W*django\b|[\"']django[\"'<>=~ ]"),
    "flask": (("requirements.txt", "pyproject.toml", "Pipfile", "setup.py", "setup.cfg"), r"(?im)^\W*flask\b|[\"']flask[\"'<>=~ ]"),
    "fastapi": (("requirements.txt", "pyproject.toml", "Pipfile", "setup.py", "setup.cfg"), r"(?im)^\W*fastapi\b|[\"']fastapi[\"'<>=~ ]"),
    "spring": (("pom.xml", "build.gradle", "build.gradle.kts"), r"org\.springframework|spring-boot"),
    "express": (("package.json",), r"\"express\"\s*:"),
    "koa": (("package.json",), r"\"koa\"\s*:"),
    "fastify": (("package.json",), r"\"fastify\"\s*:"),
    "nestjs": (("package.json",), r"\"@nestjs/core\"\s*:"),
    "nextjs": (("package.json",), r"\"next\"\s*:"),
    "rails": (("Gemfile",), r"(?m)^\s*gem\s+['\"]rails['\"]"),
    "sinatra": (("Gemfile",), r"(?m)^\s*gem\s+['\"]sinatra['\"]"),
    "laravel": (("composer.json",), r"\"laravel/framework\"\s*:"),
    "symfony": (("composer.json",), r"\"symfony/(framework-bundle|http-kernel)\"\s*:"),
}
MIN_FILES, MIN_SHARE = 3, 0.10
# Front-end libraries bundled into asset folders ship their own composer.json/package.json;
# those manifests say nothing about the server stack.
ASSET_DIRS = {"static", "assets", "bower_components", "wwwroot"}


def _manifests(root: Path) -> dict[str, list[Path]]:
    found: dict[str, list[Path]] = {}
    for p in root.rglob("*"):
        if p.name in MANIFESTS and p.is_file() and not p.is_symlink():
            rel = p.relative_to(root)
            if not skipped_dir(root, rel.parts[:-1]) and not ASSET_DIRS & set(rel.parts[:-1]):
                found.setdefault(p.name, []).append(p)
    for p in root.glob("requirements*.txt"):
        if p.name != "requirements.txt":
            found.setdefault("requirements.txt", []).append(p)
    return found


def detect(root: Path) -> dict:
    counts = Counter(LANG_EXT[p.suffix.lower()] for p in iter_source_files(root) if p.suffix.lower() in LANG_EXT)
    total = sum(counts.values()) or 1
    manifests = _manifests(root)
    langs = {l for l, n in counts.items() if n >= MIN_FILES or n / total >= MIN_SHARE}

    stacks: list[str] = []
    if "python" in langs or {"requirements.txt", "pyproject.toml", "Pipfile", "setup.py"} & manifests.keys():
        stacks.append("python")
    if "go" in langs or "go.mod" in manifests:
        stacks.append("go")
    if "java" in langs or {"pom.xml", "build.gradle"} & manifests.keys():
        stacks.append("java")
    if "kotlin" in langs or "build.gradle.kts" in manifests:
        stacks.append("kotlin")
    if "package.json" in manifests:
        stacks.append("node")
    elif "javascript" in langs:
        stacks.append("frontend-js")
    if "typescript" in langs:
        stacks.append("typescript")
    if "ruby" in langs or "Gemfile" in manifests:
        stacks.append("ruby")
    if "php" in langs or "composer.json" in manifests:
        stacks.append("php")
    stacks += [l for l in ("rust", "c", "cpp", "csharp") if l in langs]

    frameworks = []
    for fw, (names, rx) in FRAMEWORKS.items():
        for name in names:
            if any(re.search(rx, p.read_text(errors="replace")) for p in manifests.get(name, [])):
                frameworks.append(fw)
                break
    if "php" in stacks and ((root / "wp-config.php").exists() or (root / "wp-includes").is_dir()
                            or any(root.glob("*/wp-content"))):
        frameworks.append("wordpress")
    if "ruby" in stacks and "rails" not in frameworks and (root / "config" / "application.rb").exists():
        frameworks.append("rails")
    stacks += [f for f in frameworks if f not in stacks]

    packs, rules, playbooks = [], [], []
    for s in stacks:
        p, r, b = STACKS[s]
        packs += [x for x in p if x not in packs]
        if r and (ROOT / "rules" / r).exists() and f"rules/{r}" not in rules:
            rules.append(f"rules/{r}")
        if b and (ROOT / "playbooks" / "stacks" / b).exists() and f"playbooks/stacks/{b}" not in playbooks:
            playbooks.append(f"playbooks/stacks/{b}")
    return {"languages": dict(counts.most_common()), "stacks": stacks, "frameworks": frameworks,
            "semgrep_packs": packs, "rules": rules, "playbooks": playbooks,
            "manifests": sorted(str(p.relative_to(root)) for ps in manifests.values() for p in ps)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="vulnscan.stacks")
    ap.add_argument("target")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    info = detect(target_dir(args.target))
    from .db import connect
    conn = connect(args.target)
    conn.execute("INSERT OR REPLACE INTO meta VALUES ('stacks', ?)", (json.dumps(info),))
    conn.commit()
    if args.json:
        print(json.dumps(info, indent=2))
        return 0
    print(f"languages:  {', '.join(f'{k} ({v})' for k, v in info['languages'].items()) or 'none'}")
    print(f"stacks:     {', '.join(info['stacks']) or 'none'}")
    print(f"rules:      {', '.join(info['rules']) or 'none'} (+ project rules from recon)")
    print(f"packs:      {', '.join(info['semgrep_packs']) or 'none'}")
    print(f"playbooks:  {', '.join(info['playbooks']) or 'none (class playbooks only)'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
