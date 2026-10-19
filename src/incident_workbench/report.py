"""Portable report generation with inert text and no external resources."""
import json
from importlib.resources import files


def ui_asset(name):
    if name not in {"index.html", "app.js", "style.css", "sample.jsonl"}:
        raise ValueError("Unknown bundled asset")
    return files("incident_workbench").joinpath("ui", name).read_text(encoding="utf-8")


def standalone(result):
    # JSON lives in a non-executable data element; escape the HTML tokenizer's
    # closing-script delimiters, not just JSON quotes.
    payload = json.dumps(result, ensure_ascii=True).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    page = ui_asset("index.html").replace('<link rel="stylesheet" href="/style.css">', "<style>" + ui_asset("style.css") + "</style>")
    page = page.replace('<script src="/app.js" defer></script>', '')
    # Inline classic scripts ignore defer. Execute after the body DOM exists.
    return page.replace('</body>', '<script id="snapshot" type="application/json">' + payload
                        + '</script><script>' + ui_asset("app.js") + '</script></body>')


def text_report(result):
    lines = ["INCIDENT EVIDENCE WORKBENCH", "Deterministic rule findings; human review required.",
             "Input SHA-256: " + result["input_sha256"],
             f"Unique events: {result['summary']['events']} | Cases: {result['summary']['incidents']}", ""]
    for case in result["incidents"]:
        # JSON encoding keeps embedded markup/control-ish characters inert in a
        # plain text export and makes field boundaries unambiguous.
        lines += [case["case_id"] + " | " + case["severity"].upper(),
                  "Actor: " + json.dumps(case["actor"], ensure_ascii=True),
                  "Tenant: " + json.dumps(case["tenant"], ensure_ascii=True),
                  case["start"] + " to " + case["end"]]
        for finding in case["findings"]:
            lines += [finding["rule_id"] + ": " + finding["title"], finding["reason"],
                      "Investigate: " + finding["investigation"], "Limits: " + finding["limitations"],
                      "Evidence: " + ", ".join(finding["evidence_ids"])]
        lines.append("")
    lines += ["SOURCE EVIDENCE (NORMALIZED)"]
    for event in result["events"]:
        lines += [event["evidence_id"] + " | lines " + ",".join(map(str, event["source_lines"])), json.dumps(event["normalized"], sort_keys=True, ensure_ascii=True)]
    if result.get("model", {}).get("status") != "disabled":
        lines += ["UNTRUSTED MODEL ADAPTER RESULT", json.dumps(result["model"], ensure_ascii=True, sort_keys=True)]
    return "\n".join(lines) + "\n"
