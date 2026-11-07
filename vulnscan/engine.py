from __future__ import annotations
import os
from . import registry
from .models import Finding
from .web.crawler import Crawler
from .web import passive, active          # noqa: F401  (registers checks)
from .sast import python_rules, patterns  # noqa: F401  (registers checks)

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".tox"}
MAX_BYTES = 1_000_000


def _finish(findings):
    uniq = {f.key(): f for f in findings}
    return sorted(uniq.values(), key=lambda f: (-int(f.severity), f.rule_id, f.location, f.line or 0))


def scan_web(url, *, active=False, blind_sqli=False, render_js=False, max_pages=30, delay=0.2,
            verify=True, headers=None, scope=None):
    if render_js:
        from .web.jscrawler import JSCrawler
        from .web.crawler import WebContext
        import requests
        jc = JSCrawler(url, max_pages, delay, headers=headers, scope=scope)
        pages = jc.crawl()
        # Active/blind-SQLi probes still use the fast requests-based context, not the browser.
        ctx = WebContext(requests.Session(), 10, verify, delay, scope=scope)
        ctx.session.headers["User-Agent"] = "vulnscan/0.1 (authorized-testing)"
        if headers:
            ctx.session.headers.update(headers)
    else:
        crawler = Crawler(url, max_pages, delay, verify=verify, headers=headers, scope=scope)
        pages = crawler.crawl()
        ctx = crawler.ctx

    out = []
    for pg in pages:
        for chk in registry.WEB_PASSIVE:
            out.extend(chk(pg, ctx))
    if active:
        for chk in registry.WEB_ACTIVE:
            out.extend(chk(pages, ctx))
        if blind_sqli:
            for chk in registry.WEB_TIME:
                out.extend(chk(pages, ctx))
    return _finish(out), len(pages)


def scan_code(root):
    out, n = [], 0
    files = [root] if os.path.isfile(root) else (
        os.path.join(d, f) for d, ds, fs in os.walk(root)
        if not ds.__setitem__(slice(None), [x for x in ds if x not in SKIP_DIRS]) for f in fs)
    for path in files:
        try:
            if os.path.getsize(path) > MAX_BYTES:
                continue
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
        except OSError:
            continue
        n += 1
        for chk in registry.CODE_CHECKS:
            out.extend(chk(path, text))
    return _finish(out), n
