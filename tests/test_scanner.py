import os, sys, threading, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "samples"))
from http.server import HTTPServer
from vulnscan import engine
from vulnscan.scope import Scope, ScopeViolation
import vuln_server


def test_sast_finds_core_issues():
    f, _ = engine.scan_code(os.path.join(os.path.dirname(__file__), "..", "samples", "vuln_app.py"))
    ids = {x.rule_id for x in f}
    assert {"PY-SQLI-001", "PY-CMD-001", "PY-CMD-002", "PY-DES-001", "PY-DES-002",
            "PY-CRY-001", "PY-TLS-001", "PY-SEC-001"} <= ids


def test_dast_finds_core_issues():
    srv = HTTPServer(("127.0.0.1", 8765), vuln_server.H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.3)
    f, _ = engine.scan_web("http://127.0.0.1:8765/", active=True, delay=0)
    srv.shutdown()
    ids = {x.rule_id for x in f}
    assert {"WEB-XSS-001", "WEB-SQLI-001", "WEB-RDR-001", "WEB-CKE-002", "WEB-INF-001",
            "WEB-CSRF-001"} <= ids


def test_triage_with_mock_ollama():
    import json
    from http.server import BaseHTTPRequestHandler
    from vulnscan import triage

    class Mock(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            body = json.dumps({"message": {"content": '{"verdict":"false_positive","reason":"test fixture"}'}}).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(body)
        def log_message(self, *a): pass

    srv = HTTPServer(("127.0.0.1", 8766), Mock)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    f, _ = engine.scan_code(os.path.join(os.path.dirname(__file__), "..", "samples", "vuln_app.py"))
    out = triage.run(f, "m", "http://127.0.0.1:8766")
    srv.shutdown()
    assert all(x.triage_verdict == "false_positive" for x in out)
    assert triage._parse("garbage")[0] == "uncertain"
    assert triage._parse('{"verdict":"IGNORE PREVIOUS"}')[0] == "uncertain"


def test_blind_time_based_sqli():
    srv = HTTPServer(("127.0.0.1", 8767), vuln_server.H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.3)
    f, _ = engine.scan_web("http://127.0.0.1:8767/", active=True, blind_sqli=True, delay=0)
    srv.shutdown()
    ids = {x.rule_id for x in f}
    assert "WEB-SQLI-002" in ids


def test_scope_blocks_out_of_scope_url():
    s = Scope({"targets": ["https://allowed.example.com"], "excluded_paths": ["/admin"]})
    s.check("https://allowed.example.com/search")      # should not raise
    try:
        s.check("https://not-allowed.example.com/")
        assert False, "expected ScopeViolation for a different host"
    except ScopeViolation:
        pass
    try:
        s.check("https://allowed.example.com/admin/delete")
        assert False, "expected ScopeViolation for an excluded path"
    except ScopeViolation:
        pass


def test_scope_enforced_during_crawl():
    srv = HTTPServer(("127.0.0.1", 8768), vuln_server.H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.3)
    # Scope names a DIFFERENT host than the one we're about to scan -> crawl should find nothing.
    s = Scope({"targets": ["https://totally-different-host.example.com"]})
    from vulnscan.web.crawler import Crawler
    c = Crawler("http://127.0.0.1:8768/", max_pages=10, delay=0, scope=s)
    pages = c.crawl()
    srv.shutdown()
    assert pages == []


def test_jscrawler_shapes_rendered_dom_into_pages(monkeypatch):
    """No real browser is available in this environment (binary download is blocked), so this
    verifies JSCrawler's own logic -- queueing, scope/page-cap limits, and turning a rendered
    DOM snapshot into Page/Form objects -- against a hand-written stand-in for Playwright's
    sync API, rather than a live Chromium instance."""
    pytest = __import__("pytest")
    playwright_sync_api = pytest.importorskip("playwright.sync_api")
    from vulnscan.web import jscrawler

    class FakeResponse:
        status = 200

    class FakePage:
        def __init__(self, routes):
            self.routes = routes
            self.current = None

        def goto(self, url, timeout=None, wait_until=None):
            self.current = url
            return FakeResponse()

        def evaluate(self, js):
            return self.routes[self.current]

    class FakeContext:
        def __init__(self, routes, **kw):
            self._page = FakePage(routes)

        def new_page(self):
            return self._page

    class FakeBrowser:
        def __init__(self, routes):
            self.routes = routes

        def new_context(self, **kw):
            return FakeContext(self.routes)

        def close(self):
            pass

    class FakeChromium:
        def __init__(self, routes):
            self.routes = routes

        def launch(self, headless=True):
            return FakeBrowser(self.routes)

    class FakePW:
        def __init__(self, routes):
            self.chromium = FakeChromium(routes)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    routes = {
        "http://spa.example.com/": {
            "html": "<html></html>",
            "links": ["http://spa.example.com/about"],
            "forms": [{"action": "http://spa.example.com/contact", "method": "post",
                      "inputs": [{"name": "email", "type": "email", "value": ""}]}],
        },
        "http://spa.example.com/about": {"html": "<html></html>", "links": [], "forms": []},
    }
    monkeypatch.setattr(playwright_sync_api, "sync_playwright", lambda: FakePW(routes))

    jc = jscrawler.JSCrawler("http://spa.example.com/", max_pages=10, delay=0)
    pages = jc.crawl()
    assert {p.url for p in pages} == set(routes)
    home = next(p for p in pages if p.url == "http://spa.example.com/")
    assert home.forms[0].inputs == {"email": ("email", "")}
    assert home.links == ["http://spa.example.com/about"]


def test_client_report_has_front_page_sections():
    from vulnscan import report
    f, _ = engine.scan_code(os.path.join(os.path.dirname(__file__), "..", "samples", "vuln_app.py"))
    meta = {"client": "Acme Corp", "target": "vuln_app.py", "date": "2026-11-07",
           "scan_type": "code", "units_scanned": 1}
    text = report.to_client_report(f, meta)
    for must_have in ("# Security Assessment Report — Acme Corp", "## Executive Summary",
                      "## Scope & Methodology", "## Limitations & Disclaimer",
                      "PY-CMD-001"):
        assert must_have in text


def test_client_report_cli_end_to_end(tmp_path):
    import subprocess
    out = tmp_path / "report.md"
    r = subprocess.run([sys.executable, "-m", "vulnscan", "code",
                        os.path.join(os.path.dirname(__file__), "..", "samples", "vuln_app.py"),
                        "--client", "Acme Corp", "-o", str(out)],
                       cwd=os.path.join(os.path.dirname(__file__), ".."),
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0
    text = out.read_text()
    assert "Security Assessment Report — Acme Corp" in text
    assert "Executive Summary" in text
