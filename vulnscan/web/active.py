"""Active checks: detection only. Payloads are harmless markers/single quotes, no exploitation."""
from __future__ import annotations
import re
import secrets
from urllib.parse import urlparse, parse_qsl
from ..models import Finding, Severity as S
from ..registry import web_active

SKIP_TYPES = {"submit", "button", "image", "file", "checkbox", "radio", "reset", "password"}
REDIRECT_NAMES = {"next", "url", "redirect", "redirect_url", "return", "returnurl", "return_to",
                  "goto", "dest", "destination", "continue", "target"}
SQL_ERR = re.compile(r"SQL syntax.*MySQL|SQLSTATE\[|ORA-\d{5}|PG::SyntaxError|"
                     r"unclosed quotation mark|sqlite3?\.OperationalError|psycopg2\.errors|"
                     r"System\.Data\.SqlClient|near \".*\": syntax error", re.I)


def _points(pages):
    seen = set()
    for pg in pages:
        u = urlparse(pg.url)
        q = dict(parse_qsl(u.query, keep_blank_values=True))
        base = u._replace(query="", fragment="").geturl()
        cands = []
        if q:
            cands.append(("get", base, q, list(q)))
        for f in pg.forms:
            fu = urlparse(f.action)
            fb = fu._replace(query="", fragment="").geturl()
            params = {n: v for n, (t, v) in f.inputs.items()}
            names = [n for n, (t, _) in f.inputs.items() if t not in SKIP_TYPES]
            cands.append((f.method if f.method in ("get", "post") else "get", fb, params, names))
        for m, b, p, names in cands:
            k = (m, b, tuple(sorted(p)))
            if k not in seen and names:
                seen.add(k)
                for n in names:
                    yield m, b, p, n


def _f(rule, title, sev, loc, desc, fix, cwe, ev):
    return Finding(rule, title, sev, "web", loc, desc, fix, cwe, "A03:2021", None, ev)


@web_active
def reflected_xss(pages, ctx):
    for m, base, params, name in _points(pages):
        tag = secrets.token_hex(4)
        p = dict(params)
        p[name] = f'vs{tag}"\'<vs{tag}x>'
        r = ctx.request(m, base, p)
        if r is not None and "html" in r.headers.get("content-type", "") and f"<vs{tag}x>" in r.text:
            yield _f("WEB-XSS-001", "Reflected XSS (unencoded HTML reflection)", S.HIGH, base,
                     f"Parameter '{name}' is reflected without output encoding.",
                     "Context-aware output encoding; add CSP.", "CWE-79", f"{m.upper()} param={name}")


@web_active
def sqli_error_based(pages, ctx):
    for m, base, params, name in _points(pages):
        b = ctx.request(m, base, params)
        if b is None or SQL_ERR.search(b.text):
            continue
        p = dict(params)
        p[name] = (params.get(name) or "1") + "'"
        r = ctx.request(m, base, p)
        if r is not None and SQL_ERR.search(r.text):
            yield _f("WEB-SQLI-001", "Possible SQL injection (database error on quote)", S.HIGH,
                     base, f"A single quote in '{name}' triggers a database error.",
                     "Use parameterised queries / ORM bindings.", "CWE-89",
                     f"{m.upper()} param={name}")


@web_active
def open_redirect(pages, ctx):
    for m, base, params, name in _points(pages):
        if name.lower() not in REDIRECT_NAMES:
            continue
        p = dict(params)
        p[name] = "https://example.invalid/vs"
        r = ctx.request(m, base, p, allow_redirects=False)
        if r is not None and r.headers.get("Location", "").startswith("https://example.invalid"):
            yield _f("WEB-RDR-001", "Open redirect", S.MEDIUM, base,
                     f"Parameter '{name}' redirects to arbitrary external URLs.",
                     "Allow-list redirect targets or use relative paths only.", "CWE-601",
                     f"{m.upper()} param={name}")
