#!/usr/bin/env python3
"""Build a deterministic, static browser demo from the actual Python/UI sources."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from incident_workbench.core import analyze  # noqa: E402

PYODIDE_VERSION = "314.0.7"
PYODIDE_BASE = f"https://cdn.jsdelivr.net/pyodide/v{PYODIDE_VERSION}/full/"
FILES = {"index.html", "style.css", "app.js", "browser-backend.js", "worker.mjs", "runtime-config.mjs",
         "core.py", "sample.jsonl", "results.json", "manifest.json", ".nojekyll"}


def sha256(value):
    return hashlib.sha256(value).hexdigest()


def replace_one(text, before, after):
    if text.count(before) != 1:
        raise ValueError(f"Shared UI changed: expected one occurrence of {before!r}")
    return text.replace(before, after, 1)


def build(output: Path):
    output = Path(output)
    if output.exists() and any(path.name not in FILES or not path.is_file() for path in output.iterdir()):
        raise ValueError("Output contains unrecognized files; choose a dedicated empty build directory")
    ui = ROOT / "src" / "incident_workbench" / "ui"
    core = (ROOT / "src" / "incident_workbench" / "core.py").read_bytes()
    example = (ui / "sample.jsonl").read_text(encoding="utf-8")
    result = analyze(example)
    bootstrap = json.dumps({"jsonl": example, "result": result}, ensure_ascii=True, separators=(",", ":"))
    bootstrap = bootstrap.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    index = (ui / "index.html").read_text(encoding="utf-8")
    index = replace_one(index, 'href="/style.css"', 'href="./style.css"')
    index = replace_one(index, '<script src="/app.js" defer></script>',
                        '<script id="browser-example" type="application/json">' + bootstrap + '</script>\n'
                        '<script src="./browser-backend.js" defer></script>\n<script src="./app.js" defer></script>')
    index = replace_one(index, '<title>Incident Evidence Workbench</title>',
                        '<title>Incident Evidence Workbench · Live browser demo</title>\n'
                        '<meta name="referrer" content="no-referrer">\n'
                        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
                        'script-src \'self\' https://cdn.jsdelivr.net \'wasm-unsafe-eval\'; '
                        'style-src \'self\'; connect-src \'self\' https://cdn.jsdelivr.net; '
                        'worker-src \'self\'; img-src \'self\' data:; base-uri \'none\'; '
                        'object-src \'none\'; form-action \'none\'">')
    index = replace_one(index, 'OFFLINE BY DEFAULT', 'ANALYSIS IN YOUR BROWSER')
    index = replace_one(index, 'WORKSPACE <span>/</span> LOCAL INVESTIGATION', '<a href="../" class="all-demos">← All demos</a><span>/</span> BROWSER INVESTIGATION')
    index = replace_one(index, 'Starting local session', 'Browser demo · computed example')
    index = replace_one(index, 'LOCAL ANALYSIS', 'BROWSER ANALYSIS')
    index = replace_one(index, 'Paste normalized JSONL. Up to 256 KiB, 1,000 event lines, 4 KiB per line. Analysis is ephemeral; export explicitly to keep a copy.',
                        'Paste normalized JSONL or choose a file. Analysis runs in this browser using the original Python engine. First use downloads a Python runtime from the pinned CDN; no installation or account is needed. Event text is not submitted to a server. Limits: 256 KiB, 1,000 event lines, 4 KiB per line.')
    index = replace_one(index, '<span id="input-size"></span>',
                        '<span id="input-size"></span><button id="cancel-analysis" class="button secondary" hidden>Cancel</button>')
    index = replace_one(index, '<p id="input-error"',
                        '<p id="runtime-progress" role="status" aria-live="polite" class="runtime-progress"></p><p id="input-error"')
    style = (ui / "style.css").read_text(encoding="utf-8") + '\n.runtime-progress{font-size:11px;color:#536e49;min-height:0;line-height:1.7}.runtime-progress:empty{display:none}button[hidden]{display:none}.signal{letter-spacing:.3px}.all-demos{text-decoration:none;color:inherit}.all-demos:hover{text-decoration:underline}\n'
    assets = {
        "index.html": index.encode("utf-8"), "style.css": style.encode("utf-8"),
        "app.js": (ui / "app.js").read_bytes(), "browser-backend.js": (ROOT / "web/browser-backend.js").read_bytes(),
        "worker.mjs": (ROOT / "web/worker.mjs").read_bytes(), "core.py": core,
        "sample.jsonl": example.encode("utf-8"),
        "results.json": (json.dumps(result, indent=2) + "\n").encode("utf-8"),
        "runtime-config.mjs": (f"// Generated from the original Python source; do not edit.\n"
                               f"export const PYODIDE_VERSION = {json.dumps(PYODIDE_VERSION)};\n"
                               f"export const PYODIDE_BASE = {json.dumps(PYODIDE_BASE)};\n"
                               f"export const CORE_SHA256 = {json.dumps(sha256(core))};\n").encode(),
        ".nojekyll": b"",
    }
    manifest = {"schema_version": 1, "engine": "original-python-core", "pyodide_version": PYODIDE_VERSION,
                "pyodide_base": PYODIDE_BASE, "core_sha256": sha256(core),
                "core_source": "src/incident_workbench/core.py",
                "fixture_sha256": sha256(example.encode("utf-8")),
                "assets": {name: {"sha256": sha256(content), "bytes": len(content)} for name, content in sorted(assets.items())}}
    assets["manifest.json"] = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    output.mkdir(parents=True, exist_ok=True)
    for name, content in assets.items():
        (output / name).write_bytes(content)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "web" / "dist")
    args = parser.parse_args()
    try:
        manifest = build(args.output_dir)
    except (OSError, ValueError) as exc:
        parser.exit(2, f"Build failed: {exc}\n")
    print(json.dumps({"output": str(args.output_dir), "core_sha256": manifest["core_sha256"],
                      "pyodide_version": manifest["pyodide_version"], "files": len(FILES)}))


if __name__ == "__main__":
    main()
