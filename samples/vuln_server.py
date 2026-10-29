"""Deliberately vulnerable local lab target (127.0.0.1 only). DO NOT expose."""
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

HOME = b"""<html><body><h1>Lab</h1>
<a href="/search?q=test">search</a> <a href="/item?id=1">item</a> <a href="/go?next=/">go</a>
<form method="post" action="/login"><input name="user"><input type="password" name="pw"></form>
</body></html>"""


class H(BaseHTTPRequestHandler):
    server_version = "VulnLab/1.0"

    def _send(self, body, code=200, headers=None):
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", "sid=abc123; Path=/")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body if isinstance(body, bytes) else body.encode())

    def do_GET(self):
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if u.path == "/search":
            self._send(f"<html>Results for {q.get('q','')}</html>")
        elif u.path == "/item":
            v = q.get("id", "")
            if "'" in v:
                self._send("You have an error in your SQL syntax near ''' at line 1 MySQL")
            else:
                self._send(f"<html>Item {v}</html>")
        elif u.path == "/go":
            self._send(b"", 302, {"Location": q.get("next", "/")})
        else:
            self._send(HOME)

    def do_POST(self):
        self._send("<html>nope</html>")

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print("Lab on http://127.0.0.1:8000")
    HTTPServer(("127.0.0.1", 8000), H).serve_forever()
