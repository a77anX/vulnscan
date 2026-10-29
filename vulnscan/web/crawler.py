from __future__ import annotations
import time
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, urldefrag
import requests

SKIP_EXT = (".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".css", ".js", ".woff",
            ".woff2", ".ttf", ".pdf", ".zip", ".mp4", ".mp3")


@dataclass
class Form:
    action: str
    method: str
    inputs: dict            # name -> (type, default value)


@dataclass
class Page:
    url: str
    status: int
    headers: dict           # lower-cased names
    set_cookies: list
    body: str
    links: list = field(default_factory=list)
    forms: list = field(default_factory=list)

    @property
    def is_html(self) -> bool:
        return "html" in self.headers.get("content-type", "").lower()


@dataclass
class WebContext:
    session: requests.Session
    timeout: float = 10
    verify: bool = True
    delay: float = 0.2

    def request(self, method, url, params, allow_redirects=True):
        time.sleep(self.delay)
        try:
            if method == "post":
                return self.session.post(url, data=params, timeout=self.timeout,
                                         verify=self.verify, allow_redirects=allow_redirects)
            return self.session.get(url, params=params, timeout=self.timeout,
                                    verify=self.verify, allow_redirects=allow_redirects)
        except requests.RequestException:
            return None


class _Extractor(HTMLParser):
    def __init__(self, base):
        super().__init__(convert_charrefs=True)
        self.base, self.links, self.forms, self._form = base, [], [], None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(urljoin(self.base, a["href"]))
        elif tag == "form":
            self._form = Form(urljoin(self.base, a.get("action") or self.base),
                              (a.get("method") or "get").lower(), {})
            self.forms.append(self._form)
        elif tag in ("input", "textarea", "select") and self._form is not None and a.get("name"):
            self._form.inputs[a["name"]] = ((a.get("type") or "text").lower(), a.get("value") or "")

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None


class Crawler:
    """Same-origin breadth-first crawler with a hard page cap and request delay."""

    def __init__(self, start, max_pages=30, delay=0.2, timeout=10, verify=True, headers=None):
        self.start, self.max_pages = start, max_pages
        self.host = urlparse(start).netloc
        self.ctx = WebContext(requests.Session(), timeout, verify, delay)
        self.ctx.session.headers["User-Agent"] = "vulnscan/0.1 (authorized-testing)"
        if headers:
            self.ctx.session.headers.update(headers)

    def _in_scope(self, url):
        p = urlparse(url)
        return p.scheme in ("http", "https") and p.netloc == self.host \
            and not p.path.lower().endswith(SKIP_EXT)

    def crawl(self):
        queue, seen, pages = [self.start], set(), []
        while queue and len(pages) < self.max_pages:
            url = urldefrag(queue.pop(0))[0]
            if url in seen or not self._in_scope(url):
                continue
            seen.add(url)
            try:
                time.sleep(self.ctx.delay)
                r = self.ctx.session.get(url, timeout=self.ctx.timeout, verify=self.ctx.verify)
            except requests.RequestException:
                continue
            try:
                cookies = r.raw.headers.getlist("Set-Cookie")
            except Exception:
                cookies = [r.headers["Set-Cookie"]] if "Set-Cookie" in r.headers else []
            page = Page(url, r.status_code, {k.lower(): v for k, v in r.headers.items()},
                        cookies, r.text)
            if page.is_html:
                ex = _Extractor(r.url)
                ex.feed(r.text)
                page.links, page.forms = ex.links, ex.forms
                queue.extend(ex.links)
            pages.append(page)
        return pages
