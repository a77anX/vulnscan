"""Optional JavaScript-rendering crawler, for single-page apps (React/Vue/Angular) whose raw
HTML is just an empty shell (`<div id="app"></div>`) until client-side JS runs. The default
Crawler (crawler.py) never executes JS, so it finds nothing to follow on pages like that; this
module renders each page in a real headless browser via Playwright and reads the DOM afterwards.

One-time setup, on your own machine (this needs a real browser binary, which this tool's
sandboxed build/test environment cannot download, so this file is written against Playwright's
documented sync API but has not been exercised against a live browser in that environment --
only its data-shaping logic has been unit-tested with a mocked browser):

    pip install playwright
    playwright install chromium

Then pass --render-js to `vulnscan web`.

Known limitations:
- Finds only <a href> links and <form> elements present in the rendered DOM. It does not click
  buttons, simulate SPA client-side routing that isn't backed by a real href, or fill in and
  submit multi-step flows.
- Slower than the plain crawler (full browser navigation per page vs. a bare HTTP request) and
  heavier (needs a Chromium install, several hundred MB).
- --active/--blind-sqli probes still go through the plain, fast requests-based WebContext --
  only the crawl (discovery) step uses the browser.
"""
from __future__ import annotations
from urllib.parse import urljoin, urldefrag, urlparse
from .crawler import Page, Form, SKIP_EXT

EXTRACT_JS = """
() => {
  const links = Array.from(document.querySelectorAll('a[href]')).map(a => a.href);
  const forms = Array.from(document.querySelectorAll('form')).map(f => ({
    action: f.action || location.href,
    method: (f.method || 'get').toLowerCase(),
    inputs: Array.from(f.querySelectorAll('input,textarea,select')).map(i => ({
      name: i.name, type: (i.type || 'text').toLowerCase(), value: i.value || ''
    })).filter(i => i.name)
  }));
  return {links: links, forms: forms, html: document.documentElement.outerHTML};
}
"""


class PlaywrightUnavailable(RuntimeError):
    pass


def _require_playwright():
    try:
        import playwright.sync_api  # noqa: F401
    except ImportError as e:
        raise PlaywrightUnavailable(
            "--render-js needs Playwright, which isn't installed here. Run:\n"
            "    pip install playwright\n"
            "    playwright install chromium\n"
            "then retry. (Base vulnscan has no browser dependency -- this is opt-in.)"
        ) from e


def _page_from_eval(url, status, data):
    p = Page(url, status, {"content-type": "text/html"}, [], data["html"])
    p.links = [urljoin(url, h) for h in data.get("links", [])]
    p.forms = [Form(urljoin(url, f["action"]), f.get("method", "get"),
                    {i["name"]: (i.get("type", "text"), i.get("value", ""))
                     for i in f.get("inputs", [])})
              for f in data.get("forms", [])]
    return p


class JSCrawler:
    """Same role as Crawler (crawler.py): .crawl() -> list[Page]. Renders JS first."""

    def __init__(self, start, max_pages=30, delay=0.2, timeout_ms=15000, headers=None,
                scope=None):
        _require_playwright()
        self.start, self.max_pages, self.delay = start, max_pages, delay
        self.timeout_ms, self.headers, self.scope = timeout_ms, headers or {}, scope
        self.host = urlparse(start).netloc

    def _in_scope(self, url):
        p = urlparse(url)
        if p.scheme not in ("http", "https") or p.path.lower().endswith(SKIP_EXT):
            return False
        if self.scope is not None:
            return any(urlparse(t).netloc == p.netloc for t in self.scope.targets)
        return p.netloc == self.host

    def crawl(self):
        import sys
        import time as _time
        from playwright.sync_api import sync_playwright

        pages, queue, seen = [], [self.start], set()
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            try:
                bctx = browser.new_context(
                    extra_http_headers=self.headers,
                    user_agent="vulnscan/0.1 (authorized-testing, JS-render)")
                page = bctx.new_page()
                while queue and len(pages) < self.max_pages:
                    url = urldefrag(queue.pop(0))[0]
                    if url in seen or not self._in_scope(url):
                        continue
                    seen.add(url)
                    if self.scope is not None:
                        try:
                            self.scope.check(url)
                        except Exception as e:
                            print(f"[scope] {e}", file=sys.stderr)
                            continue
                    _time.sleep(self.delay)
                    try:
                        resp = page.goto(url, timeout=self.timeout_ms, wait_until="networkidle")
                    except Exception as e:
                        print(f"[render] could not load {url}: {e}", file=sys.stderr)
                        continue
                    status = resp.status if resp else 0
                    data = page.evaluate(EXTRACT_JS)
                    pg = _page_from_eval(url, status, data)
                    queue.extend(pg.links)
                    pages.append(pg)
            finally:
                browser.close()
        return pages
