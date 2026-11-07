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


def _findings_table_and_details(findings):
    """Shared body used by both the plain Markdown report and the client report: a summary
    table followed by one expanded section per finding. Kept as one function so the two report
    styles can never drift apart on what a finding actually shows."""
    out = ["| Severity | Rule | Title | Location | CWE | OWASP |", "|---|---|---|---|---|---|"]
    for f in findings:
        loc = f"{f.location}:{f.line}" if f.line else f.location
        out.append(f"| {f.severity.name} | {f.rule_id} | {f.title} | `{loc}` | {f.cwe} | {f.owasp} |")
    out += ["", "## Findings — Details"]
    for f in findings:
        loc = f"{f.location}:{f.line}" if f.line else f.location
        out += [f"### {f.rule_id} — {f.title}", f"- **Severity:** {f.severity.name}",
                f"- **Location:** `{loc}`"]
        if f.evidence: out.append(f"- **Evidence:** `{f.evidence}`")
        if f.triage_verdict: out.append(f"- **AI triage (advisory):** {f.triage_verdict} - {f.triage_note}")
        if f.description: out.append(f"- **Description:** {f.description}")
        if f.remediation: out.append(f"- **Remediation:** {f.remediation}")
        out.append("")
    return out


def to_markdown(findings):
    out = ["# Vulnerability Scan Report", "", f"**Summary:** {summary(findings)}", ""]
    out += _findings_table_and_details(findings)
    return "\n".join(out)


def _executive_summary(findings):
    """Plain-language paragraph for a non-technical reader -- no rule IDs, no jargon."""
    c = Counter(f.severity.name for f in findings)
    total = len(findings)
    if total == 0:
        return ("No issues were identified within the tested scope during this assessment. "
                "This reflects the state of the target at the time of testing and does not "
                "guarantee the absence of other vulnerabilities (see Limitations below).")
    bits = [f"{c[s.name]} {s.name.lower()}" for s in sorted(Severity, reverse=True) if c[s.name]]
    headline = ("critical" if c["CRITICAL"] else
               "high" if c["HIGH"] else
               "moderate" if c["MEDIUM"] else "low")
    plain = {
        "critical": "could allow an attacker to directly compromise the system or its data",
        "high": "could allow significant unauthorized access or data exposure",
        "moderate": "could weaken security but typically needs another issue to be exploited",
        "low": "represent hardening opportunities rather than immediate exposure",
    }[headline]
    return (f"This assessment identified {total} issue(s) ({', '.join(bits)}). "
           f"Overall, the findings represent {headline}-risk exposure: the most serious issues "
           f"found {plain}. Each finding below states what it is, where it was found, and the "
           "recommended fix. Items marked HIGH or CRITICAL should be prioritized first.")


def _methodology(meta):
    if meta.get("scan_type") == "code":
        n = meta.get("units_scanned", "the provided")
        return (f"Static analysis (SAST) of {n} source file(s). Python files were analysed with "
               "an AST-based, taint-aware engine covering command injection, SQL injection, "
               "insecure deserialisation, weak cryptography, disabled TLS verification, and "
               "hard-coded credentials; other languages were checked against a curated set of "
               "known-risky patterns. Findings are traced, where possible, to whether the risky "
               "input came from this function's own parameters or was confirmed to originate "
               "from an external-input source (see each finding's Description).")
    n = meta.get("units_scanned", "the")
    active = meta.get("active", False)
    bits = ["automated crawling of the target, followed by passive checks of every response "
           "(security headers, cookie flags, TLS/version disclosure, verbose error messages)"]
    if active:
        bits.append("active, behavioral tests against every discovered form and parameter: "
                    "reflected cross-site scripting (XSS), SQL injection (error-based"
                    + (" and time-based/blind" if meta.get("blind_sqli") else "")
                    + "), cross-site request forgery (CSRF, tested by actually resubmitting "
                    "forms rather than guessing from field names), and open redirects")
    else:
        bits.append("no active/intrusive testing was performed in this assessment (passive only)")
    return f"{n} page(s) were in scope. Testing consisted of: " + "; ".join(bits) + "."


def to_client_report(findings, meta):
    """meta keys (all optional except 'client'):
    client, target, date, tester, scan_type ('web'|'code'), units_scanned, active, blind_sqli,
    scope_summary, authorized_by, date_authorized
    """
    client = meta.get("client", "Client")
    lines = [f"# Security Assessment Report — {client}", ""]
    meta_rows = [
        ("Target", meta.get("target", "")),
        ("Assessment date", meta.get("date", "")),
        ("Performed by", meta.get("tester", "Automated scan (vulnscan)")),
        ("Authorized by", meta.get("authorized_by", "")),
        ("Authorization date", meta.get("authorized_date_note", "")),
        ("Scope", meta.get("scope_summary", meta.get("target", ""))),
    ]
    for label, val in meta_rows:
        if val:
            lines.append(f"- **{label}:** {val}")
    lines += ["", "## Executive Summary", "", _executive_summary(findings), "",
             "## Scope & Methodology", "", _methodology(meta), "",
             f"**Overall finding count:** {summary(findings)}", ""]
    lines += _findings_table_and_details(findings)
    lines += ["## Limitations & Disclaimer", "",
             f"This assessment reflects the state of the target as observed on "
             f"{meta.get('date', 'the assessment date')} and was performed primarily using "
             "automated tooling (vulnscan). Automated findings should be manually verified "
             "before remediation planning or sign-off; absence of findings in a given category "
             "does not guarantee that category is free of issues, only that this tool's current "
             "checks did not detect one. This report does not constitute a legal, regulatory, "
             "or compliance certification."]
    return "\n".join(lines)


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
