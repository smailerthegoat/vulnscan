"""CVSS v3.x base score calculator (FIRST specification, v3.0 and v3.1).

The disclosure agent chooses the vector; this module computes the score, so the number in an
advisory always matches its vector.

    python3 -m vulnscan.cvss "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
"""
import math
import re
import sys

WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": None, "C": None},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
BASE_METRICS = list(WEIGHTS)


class CVSSError(ValueError):
    pass


def parse(vector: str) -> tuple[str, dict]:
    m = re.fullmatch(r"CVSS:(3\.[01])/(.+)", (vector or "").strip())
    if not m:
        raise CVSSError("vector must start with CVSS:3.1/ (or CVSS:3.0/)")
    metrics = {}
    for part in m.group(2).split("/"):
        key, _, val = part.partition(":")
        if key in metrics:
            raise CVSSError(f"metric {key} given twice")
        metrics[key] = val
    for key in BASE_METRICS:
        if key not in metrics:
            raise CVSSError(f"missing base metric {key}")
        if metrics[key] not in WEIGHTS[key]:
            raise CVSSError(f"invalid value {key}:{metrics[key]}")
    return m.group(1), metrics


def _roundup(x: float, version: str) -> float:
    if version == "3.0":
        return math.ceil(x * 10) / 10
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def severity(score: float) -> str:
    if score == 0:
        return "none"
    return "low" if score < 4 else "medium" if score < 7 else "high" if score < 9 else "critical"


def base_score(vector: str) -> float:
    version, m = parse(vector)
    changed = m["S"] == "C"
    iss = 1 - (1 - WEIGHTS["C"][m["C"]]) * (1 - WEIGHTS["I"][m["I"]]) * (1 - WEIGHTS["A"][m["A"]])
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    pr = (PR_CHANGED if changed else WEIGHTS["PR"])[m["PR"]]
    exploitability = 8.22 * WEIGHTS["AV"][m["AV"]] * WEIGHTS["AC"][m["AC"]] * pr * WEIGHTS["UI"][m["UI"]]
    if impact <= 0:
        return 0.0
    raw = 1.08 * (impact + exploitability) if changed else impact + exploitability
    return _roundup(min(raw, 10), version)


def score(vector: str) -> dict:
    s = base_score(vector)
    return {"vector": vector.strip(), "base_score": s, "severity": severity(s)}


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) != 1:
        print("usage: python3 -m vulnscan.cvss <CVSS:3.1/... vector>", file=sys.stderr)
        return 2
    try:
        r = score(argv[0])
    except CVSSError as e:
        print(f"invalid vector: {e}", file=sys.stderr)
        return 1
    print(f"{r['base_score']} {r['severity']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
