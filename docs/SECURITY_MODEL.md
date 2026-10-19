# Security and model boundaries

## Browser service

The standard-library HTTP server binds only to `127.0.0.1`. Every route requires the exact `Host` authority including the actual port. If supplied, `Origin` must be the same exact HTTP origin. Cross-site Fetch Metadata is rejected. Analysis POSTs additionally require that exact Origin and a per-process random CSRF token obtained from the same-origin session endpoint. No CORS is enabled. Responses set a restrictive CSP, `nosniff`, `no-store`, frame denial and no-referrer.

Only five exact GET paths and one POST path are served. Assets come from a package allowlist, never a user-provided file path. Query strings, traversal paths and unrecognized routes fail. POST bodies require one bounded Content-Length, the JSONL content type, and no transfer encoding. Socket reads have a five-second idle timeout. Path and normalized ingestion sizes are bounded. This small single-process server is intended for an interactive desktop session, not hostile shared hosting; it does not offer production availability or a hard total request deadline for a peer that slowly drips headers/body within the idle timeout. Stop and restart if a local peer monopolizes the server.

The CSRF and Host controls target browser-origin attacks and DNS rebinding; they do not isolate hostile local processes. Any process with access to the loopback port can request a session token and submit its own data. There is no identity authentication, per-user authorization, persistence or multiuser state. Do not expose the port through a reverse proxy or tunnel.

The browser renders event and model fields using text DOM APIs. The standalone report escapes HTML tokenizer delimiters inside embedded JSON; input text is not executable HTML. JSON and plain-text exports include evidence fields and may contain sensitive data when the user supplies it. The bundled fixture is synthetic.

## Optional loopback Ollama adapter

Only the `analyze` CLI accepts model flags. The live UI never connects to a model. Both the model name and explicit endpoint must be provided. URLs require HTTP, a loopback IP literal, an explicit port and exact `/api/chat` path. DNS hostnames, credentials, query strings, fragments, HTTPS and redirects are rejected. Model names containing `cloud` are rejected as a defense-in-depth check, not proof of on-device computation.

A local daemon or alias can still proxy requests remotely. Operators must independently ensure local inference and disable cloud routing. The workbench cannot attest the daemon's behavior. No model or server is installed, started or downloaded by this project.

The adapter sends correlated evidence and deterministic findings as untrusted data, uses `stream=false`, requests a JSON schema and does not advertise tools. It asks for summaries and uncertainty only. Limits are 20 cases, 100 evidence references per case, 65,536 request bytes, 32,768 response bytes, a ten-second response deadline with a socket-shutdown timer, and a bounded generation-token option. The installed runtime remains responsible for actual inference resource limits.

Only a completed assistant message with no tool calls is accepted. Parsed output must have exact schema fields, one entry per known case, bounded prose, and nonduplicate evidence references belonging to that case. Schema, transport, context or reference failure rejects the narrative while preserving the offline findings. All accepted prose is marked untrusted and is inert text in reports.

Evidence-reference validation verifies **membership**, not whether prose is entailed by cited events. Prompt instructions, schema validation, temperature settings and token bounds cannot guarantee truthful narration or immunity to prompt injection. A malicious model can generate plausible but false statements using valid references. A human must compare the prose with normalized source evidence. The model has no action interface and cannot modify findings, call tools, run commands or remediate a system through this adapter.

## Validation limits

Automated tests use an ephemeral loopback HTTP stub to exercise success, schema failures, invalid references, tool-call rejection, redirection, response size and deadlines. These are protocol and boundary tests, not an evaluation of any actual model. Real Ollama compatibility, installed-model behavior, performance and narrative accuracy are **untested** unless separately recorded in a future verification report.

The correlation rules have synthetic examples and boundary tests; they have no production precision/recall benchmark. Evidence hashes provide stable identifiers and exact-input comparison, not trusted timestamping, signed source provenance or immutable chain of custody.
