"""SARIF 2.1.0 export so confirmed findings (and reachable vulnerable dependencies) show up in GitHub code scanning."""
import hashlib

from . import __version__

LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note", "unknown": "warning"}
SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0", "unknown": "5.5"}


def _raise_score(rule: dict, severity: str) -> None:
    props = rule["properties"]
    props["security-severity"] = max(props.get("security-severity", "0"), SCORE.get(severity, "5.5"), key=float)


def to_sarif(data: dict) -> dict:
    rules, results = {}, []
    for f in data["findings"]:
        rule_id = f["cwe"]
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": rule_id.replace("-", ""),
            "shortDescription": {"text": f["title"]},
            "helpUri": f"https://cwe.mitre.org/data/definitions/{rule_id.split('-')[-1]}.html",
            "properties": {"tags": ["security", rule_id]},
        })
        _raise_score(rules[rule_id], f["severity"])
        msg = f"{f['title']}. {f.get('description') or ''}".strip()
        if f.get("fix"):
            msg += f"\n\nFix: {f['fix']}"
        results.append({
            "ruleId": rule_id,
            "level": LEVEL[f["severity"]],
            "message": {"text": msg},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f["file"]},
                "region": {"startLine": f["line"]},
            }}],
            "partialFingerprints": {"vulnscanFingerprint/v1": f["fingerprint"]},
            "properties": {"severity": f["severity"], "origin": f["origin"],
                           "validatorConfidence": f.get("verdict_confidence")},
        })
    for d in data.get("dependencies") or []:
        if d.get("reach_status") != "reachable":
            continue
        sev = d.get("severity") or "unknown"
        rule_id = d["vuln_id"]
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": rule_id.replace("-", ""),
            "shortDescription": {"text": d.get("summary") or rule_id},
            "helpUri": f"https://osv.dev/vulnerability/{rule_id}",
            "properties": {"tags": ["security", "dependency", *filter(None, (d.get("cwe") or "").split(", "))]},
        })
        _raise_score(rules[rule_id], sev)
        fixed = f" Upgrade to {d['fixed']}." if d.get("fixed") else " No fixed version published."
        uri, line = (d["reach_file"], d["reach_line"]) if d.get("reach_file") else (d["manifest"], 1)
        results.append({
            "ruleId": rule_id,
            "level": LEVEL.get(sev, "warning"),
            "message": {"text": f"{d['package']} {d['version']} is vulnerable ({rule_id}: {d.get('summary') or ''}) "
                                f"and reached here: {d.get('reach_reason') or ''}.{fixed}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri},
                                                "region": {"startLine": line or 1}}}],
            "partialFingerprints": {"vulnscanFingerprint/v1": hashlib.sha256(
                f"dep|{d['ecosystem']}|{d['package']}|{d['version']}|{rule_id}".encode()).hexdigest()[:16]},
            "properties": {"severity": sev, "origin": "deps", "package": d["package"], "version": d["version"]},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "vulnscan", "version": __version__, "rules": list(rules.values())}},
            "results": results,
        }],
    }
