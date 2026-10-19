"""Loopback-only, exact-route, ephemeral HTTP UI. No arbitrary file serving."""
import hmac
import json
import secrets
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer

from .core import InputError, MAX_BYTES, analyze
from .report import ui_asset


class WorkbenchServer(HTTPServer):
    allow_reuse_address = True

    def __init__(self, address=("127.0.0.1", 8765)):
        if address[0] != "127.0.0.1":
            raise ValueError("The UI must bind to 127.0.0.1")
        self.csrf = secrets.token_urlsafe(32)
        super().__init__(address, Handler)
        self.authority = f"127.0.0.1:{self.server_port}"
        self.origin = "http://" + self.authority

    def get_request(self):
        sock, address = super().get_request()
        sock.settimeout(5)
        return sock, address


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "IncidentWorkbench"
    sys_version = ""

    def log_message(self, *_):
        # Do not persist submitted events or HTTP metadata.
        pass

    def send_error(self, code, message=None, explain=None):
        self.reply(code, {"error": "HTTP request rejected"})

    def reply(self, status, value, content_type="application/json"):
        body = json.dumps(value, ensure_ascii=True).encode() if content_type == "application/json" else value.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass
        self.close_connection = True

    def boundary(self):
        if len(self.path) > 256:
            self.reply(414, {"error": "Path too long"})
            return False
        hosts = self.headers.get_all("Host", [])
        if hosts != [self.server.authority]:
            self.reply(403, {"error": "Host is not the exact loopback authority"})
            return False
        origins = self.headers.get_all("Origin", [])
        if origins and origins != [self.server.origin]:
            self.reply(403, {"error": "Origin rejected"})
            return False
        if self.headers.get("Sec-Fetch-Site") not in {None, "same-origin", "none"}:
            self.reply(403, {"error": "Cross-site request rejected"})
            return False
        return True

    def do_GET(self):
        if not self.boundary():
            return
        routes = {"/": ("index.html", "text/html"), "/app.js": ("app.js", "text/javascript"),
                  "/style.css": ("style.css", "text/css")}
        if self.path in routes:
            name, content_type = routes[self.path]
            self.reply(200, ui_asset(name), content_type)
        elif self.path == "/api/session":
            self.reply(200, {"csrf": self.server.csrf, "engine": "deterministic-rules", "max_bytes": MAX_BYTES})
        elif self.path == "/api/example":
            self.reply(200, {"jsonl": ui_asset("sample.jsonl")})
        else:
            self.reply(404, {"error": "Route not found"})

    def do_POST(self):
        if not self.boundary():
            return
        if self.path != "/api/analyze":
            self.reply(404, {"error": "Route not found"})
            return
        tokens = self.headers.get_all("X-CSRF-Token", [])
        if (self.headers.get_all("Origin", []) != [self.server.origin] or len(tokens) != 1
                or not tokens[0].isascii() or not hmac.compare_digest(tokens[0], self.server.csrf)):
            self.reply(403, {"error": "Same-origin and session CSRF token required"})
            return
        if self.headers.get("Transfer-Encoding") is not None:
            self.reply(400, {"error": "Transfer encoding is unsupported"})
            return
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit():
            self.reply(411, {"error": "One Content-Length required"})
            return
        if len(lengths[0]) > 10 or not 0 < int(lengths[0]) <= MAX_BYTES:
            self.reply(413, {"error": "Body exceeds allowed size or is empty"})
            return
        content_types = self.headers.get_all("Content-Type", [])
        if len(content_types) != 1 or content_types[0].lower() not in {"application/x-ndjson", "application/x-ndjson; charset=utf-8"}:
            self.reply(415, {"error": "Use application/x-ndjson UTF-8"})
            return
        try:
            body = self.rfile.read(int(lengths[0]))
            if len(body) != int(lengths[0]):
                raise InputError("Incomplete body")
            result = analyze(body.decode("utf-8"))
            self.reply(200, result)
        except (InputError, UnicodeError) as exc:
            self.reply(400, {"error": str(exc) if isinstance(exc, InputError) else "Invalid UTF-8"})
        except (socket.timeout, TimeoutError):
            self.reply(408, {"error": "Request body timeout"})
