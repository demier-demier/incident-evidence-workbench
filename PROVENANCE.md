# Provenance and verification scope

This is an original defensive investigation workbench. Its code, UI, fixtures, tests and explanatory material were created for this public project. No internal source repository, employer/client dataset, production incident, private log or proprietary workflow is included.

## Synthetic fixtures

`examples/synthetic-events.jsonl` and packaged `ui/sample.jsonl` are identical original synthetic records, written specifically to exercise the four implemented correlations and benign counterexamples. The two tenants, identities, sessions, token references, resources, timestamps, counts and policy annotations are fictional. Documentation-range IPv4 addresses are used for all examples. Token identifiers are labels and contain no credential material.

`docs/results.json`, `docs/demo.html` and `docs/report.txt` are computed by the actual rules from that fixture. They are not a hand-authored success report. Regenerate with:

```sh
python -m incident_workbench demo --output-dir docs
```

The generated report contains 22 unique events, 3 cases, 5 findings and no model narrative. The live UI screenshot is captured separately from the running local application; it is a visual record, not proof of untested functionality.

## Primary references checked on 2026-10-19

| Source | Purpose and limits |
|---|---|
| [MITRE ATT&CK T1110: Brute Force](https://attack.mitre.org/techniques/T1110/) | Conceptual detection context for repeated failures followed by success. No adversary procedures or operational attack code were copied. |
| [MITRE ATT&CK T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078/) | Context for identity and privileged-access investigation. A rule match does not establish this technique. |
| [Ollama chat API](https://docs.ollama.com/api/chat) | Request/response structure, `stream`, `format` and completion fields for the optional adapter. |
| [Ollama structured outputs](https://docs.ollama.com/capabilities/structured-outputs) | JSON-schema request format and independent response validation. Structured output does not establish factual accuracy. |

ATT&CK names and identifiers belong to their respective maintainers. They are external references, not endorsements or a claimed certified detection mapping.

## What has been verified

The Python standard-library tests exercise strict ingestion, evidence IDs, duplicates, window/order boundaries, tenant/identity isolation, fixed case spans, server routes and origin controls, report escaping, and success/failure paths of a local model protocol stub. The computed fixture outputs are reproducible. GitHub Actions is configured to run the same suite and demo on Python 3.11–3.13.

Actual Ollama inference and model quality have not been tested. There is no live SIEM/identity-provider/cloud integration, production log validation, red-team exercise or precision/recall benchmark. Stub success must not be described as actual model integration success. No external network actions are performed by the default demo or analysis mode.
