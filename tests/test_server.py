import http.client
import json
import socket
import threading
import unittest

from incident_workbench.report import ui_asset
from incident_workbench.server import WorkbenchServer


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = WorkbenchServer(("127.0.0.1", 0))
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(2)

    def request(self, method="GET", path="/", body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        conn.request(method, path, body=body, headers=headers or {})
        r = conn.getresponse()
        value = r.read()
        result = r.status, dict(r.getheaders()), value
        conn.close()
        return result

    def post(self, body=None, **headers):
        defaults = {"Origin": self.server.origin, "X-CSRF-Token": self.server.csrf,
                    "Content-Type": "application/x-ndjson"}
        defaults.update(headers)
        return self.request("POST", "/api/analyze", body=body or ui_asset("sample.jsonl"), headers=defaults)

    def test_live_page_has_csp_and_no_store(self):
        status, headers, body = self.request()
        self.assertEqual(status, 200)
        self.assertIn(b"Investigate the sequence", body)
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertNotIn("Access-Control-Allow-Origin", headers)

    def test_valid_post_returns_computed_cases(self):
        status, _, body = self.post()
        self.assertEqual(status, 200)
        result = json.loads(body)
        self.assertEqual(result["summary"]["incidents"], 3)
        self.assertEqual(result["summary"]["findings"], 5)
        self.assertEqual(result["model"]["status"], "disabled")

    def test_exact_host_required(self):
        for host in ["evil.example", "localhost:" + str(self.server.server_port), "127.0.0.1", self.server.authority + ".evil.example"]:
            with self.subTest(host=host):
                self.assertEqual(self.request(headers={"Host": host})[0], 403)

    def test_cross_origin_get_and_post_rejected(self):
        self.assertEqual(self.request(headers={"Origin": "https://evil.example"})[0], 403)
        self.assertEqual(self.post(Origin="null")[0], 403)
        self.assertEqual(self.post(Origin="http://localhost:" + str(self.server.server_port))[0], 403)

    def test_missing_origin_rejected(self):
        self.assertEqual(self.request("POST", "/api/analyze", body="{}", headers={"X-CSRF-Token": self.server.csrf})[0], 403)

    def test_csrf_missing_or_incorrect(self):
        self.assertEqual(self.post(**{"X-CSRF-Token": "wrong"})[0], 403)
        self.assertEqual(self.request("POST", "/api/analyze", body="{}", headers={"Origin": self.server.origin})[0], 403)

    def test_nonascii_csrf_is_rejected_without_handler_error(self):
        self.assertEqual(self.post(**{"X-CSRF-Token": "é"})[0], 403)

    def test_fetch_site_rejected(self):
        self.assertEqual(self.request(headers={"Sec-Fetch-Site": "cross-site"})[0], 403)
        self.assertEqual(self.post(**{"Sec-Fetch-Site": "same-site"})[0], 403)

    def test_routes_cannot_read_files(self):
        for path in ["/../../etc/passwd", "/%2e%2e/etc/passwd", "/README.md", "/?file=x", "/api/example?file=x"]:
            with self.subTest(path=path):
                self.assertEqual(self.request(path=path)[0], 404)

    def test_path_length_bound(self):
        self.assertEqual(self.request(path="/" + "a" * 256)[0], 414)

    def test_unsupported_content_type(self):
        self.assertEqual(self.post(**{"Content-Type": "text/plain"})[0], 415)

    def test_oversized_body_rejected_before_reading(self):
        self.assertEqual(self.post(body="x", **{"Content-Length": "262145"})[0], 413)

    def test_transfer_encoding_rejected(self):
        self.assertEqual(self.post(**{"Transfer-Encoding": "chunked"})[0], 400)

    def test_invalid_utf8_and_event_rejected(self):
        self.assertEqual(self.post(body=b"\xff")[0], 400)
        status, _, body = self.post(body='{"type":"shell_execution"}')
        self.assertEqual(status, 400)
        self.assertIn("Unsupported event type", json.loads(body)["error"])

    def test_duplicate_host_header_rejected(self):
        with socket.create_connection(("127.0.0.1", self.server.server_port), timeout=3) as s:
            s.sendall((f"GET / HTTP/1.1\r\nHost: {self.server.authority}\r\nHost: {self.server.authority}\r\n\r\n").encode())
            self.assertIn(b" 403 ", s.recv(4096))

    def test_loopback_only(self):
        with self.assertRaises(ValueError):
            WorkbenchServer(("0.0.0.0", 0))

    def test_session_and_example_are_bundled(self):
        value = json.loads(self.request(path="/api/session")[2])
        self.assertEqual(value["csrf"], self.server.csrf)
        self.assertEqual(json.loads(self.request(path="/api/example")[2])["jsonl"], ui_asset("sample.jsonl"))


if __name__ == "__main__":
    unittest.main()
