from __future__ import annotations
import json
from collections import Counter
from .models import Severity


def summary(findings):
    c = Counter(f.severity.name for f in findings)
    return ", ".join(f"{c[s.name]} {s.name}" for s in sorted(Severity, reverse=True) if c[s.name]) or "no findings"


def to_text(findings):
    lines = []
    for f in findings:
        loc = f"{f.location}:{f.line}" if f.line else f.location
        lines.append(f"[{f.severity.name:<8}] {f.rule_id}  {f.title}\n    {loc}"
                     + (f"\n    evidence: {f.evidence}" if f.evidence else "")
                     + (f"\n    triage: {f.triage_verdict} - {f.triage_note}" if f.triage_verdict else "")
                     + (f"\n    fix: {f.remediation}" if f.remediation else ""))
    lines.append(f"\nSummary: {summary(findings)}")
    return "\n".join(lines)


def to_json(findings):
    return json.dumps({"summary": summary(findings), "findings": [f.to_dict() for f in findings]}, indent=2)


def to_markdown(findings):
    out = ["# Vulnerability Scan Report", "", f"**Summary:** {summary(findings)}", "",
           "| Severity | Rule | Title | Location | CWE | OWASP |", "|---|---|---|---|---|---|"]
    for f in findings:
        loc = f"{f.location}:{f.line}" if f.line else f.location
        out.append(f"| {f.severity.name} | {f.rule_id} | {f.title} | `{loc}` | {f.cwe} | {f.owasp} |")
    out += ["", "## Details"]
    for f in findings:
        loc = f"{f.location}:{f.line}" if f.line else f.location
        out += [f"### {f.rule_id} — {f.title}", f"- **Severity:** {f.severity.name}",
                f"- **Location:** `{loc}`"]
        if f.evidence: out.append(f"- **Evidence:** `{f.evidence}`")
        if f.triage_verdict: out.append(f"- **AI triage (advisory):** {f.triage_verdict} - {f.triage_note}")
        if f.description: out.append(f"- **Description:** {f.description}")
        if f.remediation: out.append(f"- **Remediation:** {f.remediation}")
        out.append("")
    return "\n".join(out)


def to_sarif(findings):
    lvl = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
    rules = {f.rule_id: {"id": f.rule_id, "name": f.title, "shortDescription": {"text": f.title},
                         "help": {"text": f.remediation or f.title},
                         "properties": {"tags": [t for t in (f.cwe, f.owasp) if t]}} for f in findings}
    results = []
    for f in findings:
        loc = {"artifactLocation": {"uri": f.location}}
        if f.line:
            loc["region"] = {"startLine": f.line}
        results.append({"ruleId": f.rule_id, "level": lvl[f.severity.name],
                        "message": {"text": f"{f.title}. {f.description}".strip()},
                        "locations": [{"physicalLocation": loc}]})
    return json.dumps({"version": "2.1.0",
                       "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                       "runs": [{"tool": {"driver": {"name": "vulnscan", "version": "0.1.0",
                                                     "rules": list(rules.values())}},
                                 "results": results}]}, indent=2)


FORMATS = {"text": to_text, "json": to_json, "md": to_markdown, "sarif": to_sarif}
