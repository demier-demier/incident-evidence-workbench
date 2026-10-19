# Browser edition

The public demo runs the same Python correlation function as the CLI, inside a WebAssembly Python runtime in the visitor's browser. There is no duplicate JavaScript rule implementation, analysis API, authentication requirement, model connector or server-side evidence storage.

## Build and publish

```sh
python web/build.py
```

Publish the **contents** of `web/dist/` at `/incident-evidence-workbench/`. Relative stylesheet/script/worker/core paths keep it functional beneath that prefix. The All demos link goes to the parent directory. The generated directory is ignored; the build sources, tests and pinned runtime configuration are versioned.

The build is deterministic: it copies `src/incident_workbench/core.py` byte-for-byte, copies the shared application renderer, computes the bundled example with the current Python core, and records byte sizes and SHA-256 hashes in `manifest.json`. The worker compares the fetched core bytes against the generated expected hash before importing them. This checks build consistency; it is not an independent signature or a defense against a compromised publisher changing both source and expected hash.

A build directory containing unrecognized files is rejected rather than cleaned destructively. Run the builder from the repository; its default output path does not depend on the shell's working directory. Hosting must serve `.mjs` as JavaScript and provide HTTPS. `file://` is unsupported. Browser and hosting compatibility are verified separately from build and unit tests.

## Runtime behavior

1. The initial HTML contains the synthetic fixture and its computed result in an inert JSON element. Filters, source evidence, and exports are available immediately. Loading the page does **not** start Pyodide or download its runtime.
2. Selecting Analyze JSONL opens the input panel. Clicking Analyze evidence starts one module worker, downloads fixed runtime assets, and verifies the copied Python engine.
3. The worker loads Pyodide **314.0.7** from `https://cdn.jsdelivr.net/pyodide/v314.0.7/full/`. It writes the verified core into the in-memory Python filesystem and installs a fixed wrapper function. The submitted string is passed to that function as data. User text is never interpolated into Python code, executed, imported or used as a URL.
4. The original core parses and analyzes the text. Its JSON result is returned to the existing renderer. Rules, evidence IDs, timestamps, tenant/session boundaries and input errors retain their Python semantics.
5. The UI prevents parallel runs. Cancellation terminates the worker. Runtime startup has a 90-second UI deadline; correlation execution has a 15-second deadline. A timeout or worker failure terminates the worker and permits a clean retry. A normal input-validation failure preserves the loaded runtime and the prior visible result.

Initial loading may take a minute on slower connections; download size and warm-cache behavior depend on the pinned runtime and browser. Warm analyses reuse the worker until cancelled or the page closes. Reloading the synthetic example restores the embedded result without starting the runtime.

## Data and network boundaries

The site and CDN receive ordinary static-asset requests, including normal connection metadata. The application has no evidence POST, analytics, telemetry, external enrichment, local storage or remote inference path. The worker's fetch wrapper allows only GETs for the fixed core URL and the pinned runtime directory, omits credentials, rejects redirects and request bodies, then closes that fetch path after startup. Module imports use fixed runtime URLs. Neither request URLs nor methods come from event data.

This is not a sandbox for executing arbitrary user Python, and it does not offer that feature. It is also not an attestation of the browser, CDN or hosting provider. The pinned third-party runtime is trusted code; version pinning and a first-party core hash cannot guarantee safety if the publisher, browser or runtime distribution is compromised. Use synthetic material for public demos and retain normal handling requirements for sensitive logs.

Pasted text is bounded to 256 KiB before it reaches the worker and again by the Python core. File input checks file byte size before reading, uses strict UTF-8 decoding, and preserves a UTF-8 BOM so the Python parser can reject it consistently. Browser textarea newline normalization can change uploaded file line endings; `input_sha256` identifies the exact UTF-8 text submitted for analysis, not a claim to preserve an uploaded file's original bytes. Python continues enforcing 1,000 event lines and 4 KiB per line. There is no browser Ollama option.

The page uses text DOM rendering, a restrictive metadata CSP, and no inline executable script. Model narratives are not produced by this browser edition. Exports contain the currently displayed result and are created as local browser downloads when requested.

## Verification

```sh
python -m unittest discover -s tests -v
python web/build.py
node --test web/test_worker_contract.mjs
```

Python tests check deterministic builds, core-byte/hash equality, result parity with the current engine, manifest consistency, repository-prefix paths, and explicit failure on template drift or unknown output files. Node's built-in unit tests exercise the data-only worker request envelope and browser transport lifecycle using a stub Worker. They test on-demand startup, strict byte/Unicode bounds, parallel-run rejection, cancellation, validation-error retry and runtime-error recovery. These tests are not headless browser tests and do not download or run Pyodide.

A real browser run of the served build verified the initial runtime download and a custom four-event sequence producing one R01 case with four linked evidence items and the current input fingerprint. This is browser-execution evidence; it does not by itself verify the deployed public host.

The published browser flow must additionally be checked with a real browser: initial example, first runtime load, custom JSONL, malformed JSONL, filtering, evidence selection and exports. A build success or worker stub pass alone is not a claim that those browser interactions have been verified.

## Official runtime references

Checked on 2026-10-19:

- [Pyodide getting started](https://pyodide.org/en/stable/usage/quickstart.html) documents the versioned runtime URL and Python execution API.
- [Pyodide Web Workers](https://pyodide.org/en/stable/usage/webworker.html) specifies module workers for this release and describes keeping Python execution off the UI thread.

The documentation identified version 314.0.7; the exact pinned `pyodide.mjs` CDN asset returned HTTP 200 during implementation. That asset check is transport evidence, not successful browser runtime execution.
