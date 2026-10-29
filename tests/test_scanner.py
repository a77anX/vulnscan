import os, sys, threading, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "samples"))
from http.server import HTTPServer
from vulnscan import engine
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
    assert {"WEB-XSS-001", "WEB-SQLI-001", "WEB-RDR-001", "WEB-CKE-002", "WEB-INF-001"} <= ids


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
