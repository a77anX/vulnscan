from __future__ import annotations
import re
from urllib.parse import urlparse
from ..models import Finding, Severity as S
from ..registry import web_passive


def _origin(u):
    p = urlparse(u)
    return f"{p.scheme}://{p.netloc}"


def _w(rule, title, sev, loc, desc, fix, cwe="", owasp="", evidence=""):
    return Finding(rule, title, sev, "web", loc, desc, fix, cwe, owasp, None, evidence)


@web_passive
def security_headers(page, ctx):
    if not page.is_html:
        return
    h, o = page.headers, _origin(page.url)
    csp = h.get("content-security-policy", "")
    if not csp:
        yield _w("WEB-HDR-001", "Missing Content-Security-Policy", S.LOW, o,
                 "No CSP reduces defence-in-depth against XSS.",
                 "Add a restrictive Content-Security-Policy header.", "CWE-693", "A05:2021")
    if "x-frame-options" not in h and "frame-ancestors" not in csp:
        yield _w("WEB-HDR-002", "Clickjacking protection missing", S.LOW, o,
                 "Page can be framed by other origins.",
                 "Set X-Frame-Options: DENY or CSP frame-ancestors.", "CWE-1021", "A05:2021")
    if h.get("x-content-type-options", "").lower() != "nosniff":
        yield _w("WEB-HDR-003", "Missing X-Content-Type-Options: nosniff", S.LOW, o,
                 "Browsers may MIME-sniff responses.", "Add X-Content-Type-Options: nosniff.",
                 "CWE-693", "A05:2021")
    if page.url.startswith("https") and "strict-transport-security" not in h:
        yield _w("WEB-HDR-004", "Missing HSTS", S.MEDIUM, o,
                 "Clients are not forced onto HTTPS.", "Add Strict-Transport-Security.",
                 "CWE-319", "A02:2021")
    if "referrer-policy" not in h:
        yield _w("WEB-HDR-005", "Missing Referrer-Policy", S.INFO, o,
                 "URLs may leak via the Referer header.", "Add Referrer-Policy.", "CWE-200", "A05:2021")


@web_passive
def cookie_flags(page, ctx):
    o = _origin(page.url)
    for raw in page.set_cookies:
        name = raw.split("=", 1)[0].strip()
        attrs = [x.strip().lower() for x in raw.split(";")[1:]]
        if page.url.startswith("https") and "secure" not in attrs:
            yield _w("WEB-CKE-001", "Cookie without Secure flag", S.MEDIUM, o,
                     "Cookie may be sent over plain HTTP.", "Set the Secure attribute.",
                     "CWE-614", "A05:2021", name)
        if "httponly" not in attrs:
            yield _w("WEB-CKE-002", "Cookie without HttpOnly flag", S.MEDIUM, o,
                     "Cookie readable by JavaScript (XSS impact).", "Set HttpOnly.",
                     "CWE-1004", "A05:2021", name)
        if not any(a.startswith("samesite") for a in attrs):
            yield _w("WEB-CKE-003", "Cookie without SameSite", S.LOW, o,
                     "Weaker CSRF protection.", "Set SameSite=Lax or Strict.", "CWE-1275",
                     "A01:2021", name)


@web_passive
def banner_disclosure(page, ctx):
    for hn in ("server", "x-powered-by", "x-aspnet-version"):
        v = page.headers.get(hn)
        if v and re.search(r"\d+\.\d+", v):
            yield _w("WEB-INF-001", "Software version disclosed", S.LOW, _origin(page.url),
                     "Version banners help attackers pick known exploits.",
                     "Suppress or genericise version headers.", "CWE-200", "A05:2021", f"{hn}: {v}")


ERR_SIGS = [
    (re.compile(r"Traceback \(most recent call last\)"), "Python stack trace"),
    (re.compile(r"\bat [\w.$]+\([\w]+\.java:\d+\)"), "Java stack trace"),
    (re.compile(r"(Warning|Fatal error): .{0,120} on line \d+"), "PHP error"),
    (re.compile(r"<title>Index of /"), "Directory listing"),
    (re.compile(r"SQL syntax.*MySQL|ORA-\d{5}|PG::SyntaxError|SQLSTATE\[", re.I), "Database error"),
]


@web_passive
def verbose_errors(page, ctx):
    for rx, label in ERR_SIGS:
        if rx.search(page.body):
            yield _w("WEB-INF-002", f"Verbose error / info leak: {label}", S.MEDIUM, page.url,
                     "Error output reveals internals.", "Disable debug output; use generic errors.",
                     "CWE-209", "A05:2021", label)


@web_passive
def form_checks(page, ctx):
    for f in page.forms:
        has_pw = any(t == "password" for t, _ in f.inputs.values())
        if has_pw and f.action.startswith("http://"):
            yield _w("WEB-FRM-001", "Password form submits over HTTP", S.HIGH, f.action,
                     "Credentials sent in cleartext.", "Serve and submit over HTTPS.",
                     "CWE-319", "A02:2021", f.action)
        if f.method == "post" and not any(re.search(r"csrf|xsrf|token|authenticity", n, re.I)
                                          for n in f.inputs):
            yield _w("WEB-FRM-002", "POST form without apparent CSRF token (heuristic)", S.MEDIUM,
                     f.action, "State-changing form may be CSRF-able.",
                     "Add anti-CSRF tokens / SameSite cookies.", "CWE-352", "A01:2021", f.action)
