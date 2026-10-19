import json
import unittest

from incident_workbench import analyze
from incident_workbench.report import standalone, text_report, ui_asset


class ReportTests(unittest.TestCase):
    def test_script_breakout_is_encoded(self):
        events = [json.loads(line) for line in ui_asset("sample.jsonl").splitlines()]
        for event in events:
            if event["actor"] == "avery.demo":
                event["actor"] = '</script><img src=x onerror=alert(1)>'
        result = analyze("\n".join(map(json.dumps, events)))
        page = standalone(result)
        self.assertNotIn('</script><img src=x', page)
        self.assertIn('\\u003c/script\\u003e', page)
        self.assertIn('type="application/json"', page)
        self.assertIn(".textContent", page)
        self.assertNotIn(".innerHTML", page)

    def test_standalone_has_no_external_assets(self):
        page = standalone(analyze(ui_asset("sample.jsonl")))
        self.assertNotIn('<link rel="stylesheet"', page)
        self.assertNotIn('<script src=', page)
        self.assertIn('"incidents":', page)
        self.assertGreater(page.index('<script id="snapshot"'), page.index('id="search"'))

    def test_snapshot_uses_neutral_provenance_labels(self):
        page = standalone(analyze(ui_asset("sample.jsonl")))
        self.assertIn("Computed evidence snapshot", page)
        self.assertNotIn("Computed synthetic snapshot", page)
        self.assertNotIn("SYNTHETIC LAB", page)
        self.assertNotIn("Original synthetic lab", page)
        self.assertIn("Bundled synthetic example", page)

    def test_text_report_contains_complete_source_evidence(self):
        result = analyze(ui_asset("sample.jsonl"))
        report = text_report(result)
        for e in result["events"]:
            self.assertIn(e["evidence_id"], report)
        self.assertIn(result["input_sha256"], report)
        self.assertIn("human review required", report)

    def test_asset_allowlist(self):
        with self.assertRaises(ValueError):
            ui_asset("../../README.md")

    def test_example_copies_are_identical(self):
        from pathlib import Path
        self.assertEqual(ui_asset("sample.jsonl"), Path("examples/synthetic-events.jsonl").read_text())


if __name__ == "__main__":
    unittest.main()
