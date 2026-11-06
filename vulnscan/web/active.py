"""Active checks: detection only. Payloads are harmless markers/single quotes, no exploitation."""
from __future__ import annotations
import re
import secrets
import time
from urllib.parse import urlparse, parse_qsl
from ..models import Finding, Severity as S
from ..registry import web_active, web_time

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


TOKEN_FIELD = re.compile(r"csrf|xsrf|_token|authenticity", re.I)


def _similar(a, b, tolerance=0.15):
    """True if two responses look like the 'same outcome' (lengths within tolerance, same status)."""
    if a is None or b is None or a.status_code != b.status_code:
        return False
    la, lb = len(a.text), len(b.text)
    if la == 0 and lb == 0:
        return True
    return abs(la - lb) <= tolerance * max(la, lb, 1)


@web_active
def csrf_forgery(pages, ctx):
    """For each state-changing form, submit it once as-is, then again with any token field
    stripped and a cross-origin Origin/Referer header. If the server accepts both the same
    way, it isn't actually validating a token or checking the request's origin."""
    seen = set()
    for pg in pages:
        for f in pg.forms:
            if f.method != "post":
                continue
            key = (f.action, tuple(sorted(f.inputs)))
            if key in seen:
                continue
            seen.add(key)

            baseline_params = {n: (v or "x") for n, (t, v) in f.inputs.items()
                               if t not in SKIP_TYPES or t == "hidden"}
            token_fields = [n for n in f.inputs if TOKEN_FIELD.search(n)]

            baseline = ctx.request("post", f.action, baseline_params)
            if baseline is None or baseline.status_code >= 400:
                continue  # can't establish what a normal submission looks like

            # Attempt 1: drop any token-like field entirely.
            if token_fields:
                stripped = {k: v for k, v in baseline_params.items() if k not in token_fields}
                r1 = ctx.request("post", f.action, stripped)
                if _similar(baseline, r1):
                    yield Finding("WEB-CSRF-001", "CSRF: request accepted without token field",
                                 S.HIGH, "web", f.action,
                                 f"Submitting without {', '.join(token_fields)} produced the same "
                                 "outcome as a normal submission.",
                                 "Validate the anti-CSRF token server-side and reject requests "
                                 "where it is missing or wrong.", "CWE-352", "A01:2021", None,
                                 f"POST {f.action} (field(s) removed: {', '.join(token_fields)})")
                    continue  # one CSRF finding per form is enough

            # Attempt 2: keep all fields, but send from a cross-origin Origin/Referer.
            orig_headers = dict(ctx.session.headers)
            ctx.session.headers["Origin"] = "https://vulnscan-csrf-test.invalid"
            ctx.session.headers["Referer"] = "https://vulnscan-csrf-test.invalid/"
            try:
                r2 = ctx.request("post", f.action, baseline_params)
            finally:
                ctx.session.headers.clear()
                ctx.session.headers.update(orig_headers)
            if _similar(baseline, r2):
                yield Finding("WEB-CSRF-001", "CSRF: request accepted from a different origin",
                             S.MEDIUM, "web", f.action,
                             "The server accepted the submission with a cross-origin Origin/Referer, "
                             "with no token-based protection to compensate.",
                             "Check Origin/Referer server-side, or add a validated anti-CSRF token.",
                             "CWE-352", "A01:2021", None, f"POST {f.action} (cross-origin headers)")


TIME_PAYLOAD_TEMPLATES = [
    "' OR SLEEP({d})-- -",            # MySQL / MariaDB, string context
    ") OR SLEEP({d})-- -",            # MySQL, value inside parentheses
    "'||pg_sleep({d})--",             # PostgreSQL, string context
    "'; WAITFOR DELAY '0:0:{d}'--",   # SQL Server
]
TIME_DELAY = 2  # seconds requested from the DB; kept short to limit scan time, still distinct
                # from normal network jitter when the response is measured twice


@web_time
def sqli_time_based(pages, ctx):
    """Blind/time-based SQLi: error-based detection (sqli_error_based, above) only catches
    injection points that leak a DB error message. Many real apps swallow that error and show
    a generic page instead -- this check catches those by asking the database to pause and
    timing the response, which works even when nothing in the page content changes at all.

    Each candidate is timed twice with the same payload before being reported, to avoid a
    single slow network blip being mistaken for a vulnerability."""
    for m, base, params, name in _points(pages):
        t0 = time.perf_counter()
        baseline = ctx.request(m, base, params)
        baseline_elapsed = time.perf_counter() - t0
        if baseline is None:
            continue
        for tmpl in TIME_PAYLOAD_TEMPLATES:
            p = dict(params)
            p[name] = (params.get(name) or "1") + tmpl.format(d=TIME_DELAY)

            t0 = time.perf_counter()
            r1 = ctx.request(m, base, p)
            e1 = time.perf_counter() - t0
            if r1 is None or e1 - baseline_elapsed < TIME_DELAY * 0.8:
                continue

            t0 = time.perf_counter()
            r2 = ctx.request(m, base, p)
            e2 = time.perf_counter() - t0
            if r2 is None or e2 - baseline_elapsed < TIME_DELAY * 0.8:
                continue  # didn't reproduce -- likely jitter, not a real finding

            yield _f("WEB-SQLI-002", "Possible blind/time-based SQL injection", S.HIGH, base,
                     f"Parameter '{name}' consistently delays the response by roughly "
                     f"{TIME_DELAY}s when a time-based payload is sent, reproduced twice.",
                     "Use parameterised queries / ORM bindings; never build SQL from input.",
                     "CWE-89", f"{m.upper()} param={name} delay1={e1-baseline_elapsed:.1f}s "
                     f"delay2={e2-baseline_elapsed:.1f}s")
            break  # one confirmed finding per parameter is enough


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
