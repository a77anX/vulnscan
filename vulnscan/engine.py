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


def scan_web(url, *, active=False, max_pages=30, delay=0.2, verify=True, headers=None):
    crawler = Crawler(url, max_pages, delay, verify=verify, headers=headers)
    pages = crawler.crawl()
    out = []
    for pg in pages:
        for chk in registry.WEB_PASSIVE:
            out.extend(chk(pg, crawler.ctx))
    if active:
        for chk in registry.WEB_ACTIVE:
            out.extend(chk(pages, crawler.ctx))
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
