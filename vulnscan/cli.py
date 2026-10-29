from __future__ import annotations
import argparse
import sys
from .models import Severity
from . import engine, report


def main(argv=None):
    ap = argparse.ArgumentParser(prog="vulnscan", description="Web (DAST) + code (SAST) scanner")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--format", choices=report.FORMATS, default="text")
        p.add_argument("-o", "--output", help="write report to file")
        p.add_argument("--fail-on", choices=[s.name.lower() for s in Severity],
                       help="exit 1 if any finding >= this severity (CI gate)")
        p.add_argument("--triage", action="store_true", help="annotate findings with a local Ollama model")
        p.add_argument("--triage-model", default="qwen2.5-coder:7b")
        p.add_argument("--ollama-host", default="http://localhost:11434")
        p.add_argument("--hide-false-positives", action="store_true",
                       help="drop findings the model marked false_positive (after triage)")

    w = sub.add_parser("web", help="crawl and scan a web application")
    w.add_argument("url")
    w.add_argument("--active", action="store_true", help="send test payloads (XSS/SQLi/redirect)")
    w.add_argument("--authorized", action="store_true",
                   help="confirm you have written permission to test this target (required for --active)")
    w.add_argument("--max-pages", type=int, default=30)
    w.add_argument("--delay", type=float, default=0.2, help="seconds between requests")
    w.add_argument("--insecure", action="store_true", help="skip TLS verification")
    w.add_argument("-H", "--header", action="append", default=[], help="extra header 'Name: value'")
    common(w)

    c = sub.add_parser("code", help="static analysis of a file or directory")
    c.add_argument("path")
    common(c)

    a = ap.parse_args(argv)
    if a.cmd == "web":
        if a.active and not a.authorized:
            ap.error("--active requires --authorized (only test systems you have permission to test)")
        hdrs = dict(h.split(":", 1) for h in a.header)
        hdrs = {k.strip(): v.strip() for k, v in hdrs.items()}
        findings, n = engine.scan_web(a.url, active=a.active, max_pages=a.max_pages, delay=a.delay,
                                      verify=not a.insecure, headers=hdrs)
        print(f"Scanned {n} pages", file=sys.stderr)
    else:
        findings, n = engine.scan_code(a.path)
        print(f"Scanned {n} files", file=sys.stderr)

    if a.triage:
        from . import triage
        findings = triage.run(findings, a.triage_model, a.ollama_host)
        if a.hide_false_positives:
            findings = [f for f in findings if f.triage_verdict != "false_positive"]

    text = report.FORMATS[a.format](findings)
    if a.output:
        with open(a.output, "w") as fh:
            fh.write(text)
        print(f"Report written to {a.output}  ({report.summary(findings)})", file=sys.stderr)
    else:
        print(text)
    if a.fail_on and any(f.severity >= Severity.parse(a.fail_on) for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
