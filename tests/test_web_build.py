import hashlib
import importlib.util
import json
from pathlib import Path
import re
import runpy
import tempfile
import unittest

from incident_workbench import analyze

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("web_build", ROOT / "web" / "build.py")
web_build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(web_build)


class WebBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        artifacts = ROOT / "artifacts"
        artifacts.mkdir(exist_ok=True)
        cls.temp = tempfile.TemporaryDirectory(prefix="web-build-tests-", dir=artifacts)
        cls.output = Path(cls.temp.name) / "one"
        cls.manifest = web_build.build(cls.output)
        cls.html = (cls.output / "index.html").read_text()

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_core_is_exact_original_bytes_and_hash(self):
        original = (ROOT / "src/incident_workbench/core.py").read_bytes()
        self.assertEqual((self.output / "core.py").read_bytes(), original)
        self.assertEqual(self.manifest["core_sha256"], hashlib.sha256(original).hexdigest())
        self.assertIn(self.manifest["core_sha256"], (self.output / "runtime-config.mjs").read_text())

    def test_all_manifest_assets_match(self):
        self.assertEqual({p.name for p in self.output.iterdir()}, web_build.FILES)
        for name, record in self.manifest["assets"].items():
            data = (self.output / name).read_bytes()
            self.assertEqual(record["sha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual(record["bytes"], len(data))

    def test_build_is_reproducible(self):
        second = Path(self.temp.name) / "two"
        web_build.build(second)
        for item in self.output.iterdir():
            self.assertEqual(item.read_bytes(), (second / item.name).read_bytes())

    def test_default_result_is_computed_by_current_engine(self):
        source = (self.output / "sample.jsonl").read_text()
        self.assertEqual(json.loads((self.output / "results.json").read_text()), analyze(source))
        self.assertEqual(json.loads((ROOT / "docs/results.json").read_text()), analyze(source))

    def test_bootstrap_embeds_example_without_runtime_fetch(self):
        match = re.search(r'<script id="browser-example" type="application/json">(.*?)</script>', self.html, re.S)
        payload = json.loads(match.group(1))
        self.assertEqual(payload["result"], analyze(payload["jsonl"]))
        scripts = re.findall(r'<script[^>]+src="([^"]+)"', self.html)
        self.assertEqual(scripts, ["./browser-backend.js", "./app.js"])
        self.assertNotIn("pyodide.mjs", self.html)

    def test_assets_resolve_below_repository_subpath(self):
        from urllib.parse import urljoin
        for path in re.findall(r'(?:src|href)="([^"#][^"]*)"', self.html):
            if path == "../":
                self.assertEqual(urljoin("https://example.test/incident-evidence-workbench/", path), "https://example.test/")
                continue
            self.assertFalse(path.startswith("/"), path)
            self.assertTrue(urljoin("https://example.test/incident-evidence-workbench/", path).startswith("https://example.test/incident-evidence-workbench/"))

    def test_ui_assets_reuse_existing_renderer(self):
        self.assertEqual((self.output / "app.js").read_bytes(), (ROOT / "src/incident_workbench/ui/app.js").read_bytes())
        self.assertIn('id="cancel-analysis"', self.html)
        self.assertIn('id="runtime-progress"', self.html)
        self.assertIn("Event text is not submitted to a server", self.html)

    def test_pinned_official_runtime_and_restricted_csp(self):
        self.assertEqual(self.manifest["pyodide_version"], "314.0.7")
        self.assertEqual(self.manifest["pyodide_base"], "https://cdn.jsdelivr.net/pyodide/v314.0.7/full/")
        self.assertIn("worker-src 'self'", self.html)
        self.assertIn("'wasm-unsafe-eval'", self.html)
        self.assertNotIn("'unsafe-inline'", self.html)
        self.assertNotIn("'unsafe-eval'", self.html)

    def test_copied_core_native_parity_on_custom_events(self):
        copied = runpy.run_path(str(self.output / "core.py"))["analyze"]
        events = [json.loads(line) for line in (self.output / "sample.jsonl").read_text().splitlines()]
        for event in events:
            event["tenant"] = "custom-review"
            event["actor"] = "custom-" + event["actor"]
        source = "\n".join(map(json.dumps, reversed(events)))
        self.assertEqual(copied(source), analyze(source))

    def test_no_server_or_model_adapter_shipped(self):
        self.assertNotIn("server.py", self.manifest["assets"])
        self.assertNotIn("ollama.py", self.manifest["assets"])
        self.assertNotIn("report.py", self.manifest["assets"])

    def test_unknown_output_files_are_not_removed(self):
        target = Path(self.temp.name) / "occupied"
        target.mkdir()
        marker = target / "keep-me.txt"
        marker.write_text("preserve")
        with self.assertRaises(ValueError):
            web_build.build(target)
        self.assertEqual(marker.read_text(), "preserve")

    def test_shared_template_drift_fails_explicitly(self):
        with self.assertRaises(ValueError):
            web_build.replace_one("changed template", "missing marker", "replacement")


if __name__ == "__main__":
    unittest.main()
