/** Fixed-code worker: request text is data passed to a Python function, never code. */
import {PYODIDE_VERSION, PYODIDE_BASE, CORE_SHA256} from './runtime-config.mjs';

export const MAX_BYTES = 262144;
export function validateRequest(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join(',') !== 'id,text,type'
      || value.type !== 'analyze' || !Number.isSafeInteger(value.id) || value.id < 1
      || typeof value.text !== 'string') throw new Error('Unsupported analysis request.');
  if (/[\uD800-\uDFFF]/u.test(value.text)) throw new Error('Input contains invalid Unicode.');
  if (new TextEncoder().encode(value.text).length > MAX_BYTES) throw new Error('Input exceeds 262,144 bytes.');
  return value;
}

export const FIXED_BOOTSTRAP = `
import json
from incident_core import analyze, InputError

def _workbench_analyze(text):
    try:
        return json.dumps({"ok": True, "result": analyze(text)}, ensure_ascii=True)
    except InputError as exc:
        return json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=True)
`;

let ready = null, callAnalyze = null, busy = false, allowAssetFetch = true;
const isWorker = typeof self !== 'undefined' && typeof self.postMessage === 'function';
const coreURL = new URL('./core.py', import.meta.url).href;

if (isWorker) {
  const nativeFetch = self.fetch.bind(self);
  // No request URL, method, headers or body comes from an event or UI input.
  // The interpreter needs only static assets. Close this path after startup.
  self.fetch = (input, init = {}) => {
    const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url, self.location.href);
    const method = String(init.method || (input instanceof Request ? input.method : 'GET')).toUpperCase();
    if (!allowAssetFetch || method !== 'GET' || init.body != null
        || (input instanceof Request && input.body !== null)
        || !(url.href === coreURL || (url.href.startsWith(PYODIDE_BASE) && !url.search && !url.hash))) {
      return Promise.reject(new Error('Only fixed runtime assets may be fetched.'));
    }
    return nativeFetch(url.href, {...init, method: 'GET', credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer'});
  };
}

async function loadRuntime(id) {
  self.postMessage({id, type: 'progress', phase: 'loading', message: `Downloading Python runtime ${PYODIDE_VERSION} from the pinned CDN. First load may take a minute…`});
  const response = await fetch(coreURL, {signal: AbortSignal.timeout(20000)});
  if (!response.ok) throw new Error('The published Python engine could not be loaded.');
  if (Number(response.headers.get('Content-Length')) > 131072) throw new Error('Python engine asset is oversized.');
  const reader = response.body.getReader(), chunks = [];
  let size = 0;
  while (true) {
    const {done, value} = await reader.read();
    if (done) break;
    size += value.length;
    if (size > 131072) { await reader.cancel(); throw new Error('Python engine asset is oversized.'); }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), b => b.toString(16).padStart(2, '0')).join('');
  if (digest !== CORE_SHA256) throw new Error('Engine integrity check failed. Reload the page before retrying.');
  new TextDecoder('utf-8', {fatal: true}).decode(bytes);
  const {loadPyodide} = await import(PYODIDE_BASE + 'pyodide.mjs');
  const pyodide = await loadPyodide({indexURL: PYODIDE_BASE, stdout: () => {}, stderr: () => {}});
  self.postMessage({id, type: 'progress', phase: 'loading', message: 'Verifying the original Python engine in this browser…'});
  pyodide.FS.writeFile('/home/pyodide/incident_core.py', bytes);
  pyodide.runPython(FIXED_BOOTSTRAP);
  callAnalyze = pyodide.globals.get('_workbench_analyze');
  allowAssetFetch = false;
}

if (isWorker) self.onmessage = async event => {
  let request;
  try { request = validateRequest(event.data); }
  catch (error) { self.postMessage({id: Number.isSafeInteger(event.data?.id) ? event.data.id : null, type: 'error', error: error.message}); return; }
  const {id, text} = request;
  if (busy) { self.postMessage({id, type: 'error', error: 'Another analysis is still running.'}); return; }
  busy = true;
  try {
    if (!ready) ready = loadRuntime(id);
    await ready;
    self.postMessage({id, type: 'progress', phase: 'analyzing', message: 'Running the original Python correlation engine in this browser…'});
    const result = JSON.parse(callAnalyze(text));
    if (result.ok) self.postMessage({id, type: 'result', result: result.result});
    else self.postMessage({id, type: 'error', error: result.error});
  } catch (_) {
    // Runtime internals and event content are never echoed into crash reports.
    self.postMessage({id, type: 'error', fatal: true, error: 'Browser Python could not complete analysis. Check the connection, reload and retry. The existing result is unchanged.'});
  } finally { busy = false; }
};
