"""python -m incident_workbench: local server, bounded analysis, reproducible demo."""
import argparse
import json
from pathlib import Path

from .core import InputError, MAX_BYTES, analyze
from .ollama import ModelError, summarize
from .report import standalone, text_report, ui_asset
from .server import WorkbenchServer


def read_input(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise InputError("Input exceeds byte limit")
    try:
        return raw.decode("utf-8")
    except UnicodeError as exc:
        raise InputError("Input is not UTF-8") from exc


def main():
    parser = argparse.ArgumentParser(description="Offline defensive incident evidence workbench")
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="Start the loopback browser UI (no model)")
    serve.add_argument("--port", type=int, default=8765)
    demo = commands.add_parser("demo", help="Analyze the bundled synthetic fixture and write portable artifacts")
    demo.add_argument("--output-dir", type=Path, default=Path("artifacts/demo"))
    run = commands.add_parser("analyze", help="Analyze a bounded, explicitly provided JSONL file")
    run.add_argument("input", type=Path)
    run.add_argument("--output-dir", type=Path, default=Path("artifacts/analysis"))
    run.add_argument("--ollama-model", help="Opt-in installed local model name")
    run.add_argument("--ollama-endpoint", help="Explicit loopback IP /api/chat URL; requires --ollama-model")
    args = parser.parse_args()
    try:
        if args.command == "serve":
            if not 0 <= args.port <= 65535:
                parser.error("port must be from 0 through 65535")
            with WorkbenchServer(("127.0.0.1", args.port)) as server:
                print(f"Incident Evidence Workbench: {server.origin}", flush=True)
                print("Offline rules. No logs persisted. Stop with Ctrl+C.", flush=True)
                server.serve_forever()
            return
        if args.command == "analyze" and bool(args.ollama_model) != bool(args.ollama_endpoint):
            parser.error("--ollama-model and --ollama-endpoint must be supplied together")
        result = analyze(ui_asset("sample.jsonl") if args.command == "demo" else read_input(args.input))
        if args.command == "analyze" and args.ollama_model:
            try:
                result["model"] = summarize(result, endpoint=args.ollama_endpoint, model=args.ollama_model)
            except ModelError as exc:
                result["model"] = {"status": "rejected", "reason": str(exc), "notice": "Offline rule findings remain unchanged."}
        args.output_dir.mkdir(parents=True, exist_ok=True)
        (args.output_dir / "results.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        (args.output_dir / "demo.html").write_text(standalone(result), encoding="utf-8")
        (args.output_dir / "report.txt").write_text(text_report(result), encoding="utf-8")
        print(json.dumps({"summary": result["summary"], "model": result["model"]["status"], "output": str(args.output_dir)}))
    except (InputError, OSError) as exc:
        parser.exit(2, f"Error: {exc}\n")
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
