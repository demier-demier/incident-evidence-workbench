/* Static-browser transport. Never submits evidence to an HTTP API. */
(() => {
'use strict';
const base = new URL('.', document.currentScript.src);
const bootstrap = JSON.parse(document.getElementById('browser-example').textContent);
let worker = null, pending = null, nextId = 0;

function clearPending() {
  const current = pending;
  if (current) clearTimeout(current.timer);
  pending = null;
  return current;
}
function stop(message) {
  if (worker) worker.terminate();
  worker = null;
  const current = clearPending();
  if (current) current.reject(new Error(message));
}
function armTimeout(ms) {
  if (!pending) return;
  clearTimeout(pending.timer);
  pending.timer = setTimeout(() => stop('Browser analysis timed out. The worker was stopped; retry to start a fresh runtime.'), ms);
}
function startWorker() {
  if (worker) return;
  if (!window.isSecureContext || !window.Worker || !window.WebAssembly || !window.crypto?.subtle) {
    throw new Error('This demo needs a modern browser on HTTPS or localhost with WebAssembly and Web Workers enabled.');
  }
  worker = new Worker(new URL('worker.mjs', base), {type: 'module', name: 'incident-evidence-python'});
  worker.onmessage = event => {
    const message = event.data;
    if (!pending || message?.id !== pending.id) return;
    if (message.type === 'progress') {
      if (message.phase === 'analyzing') armTimeout(15000);
      pending.progress(String(message.message));
    } else if (message.type === 'result') {
      const current = clearPending();
      current.resolve(message.result);
    } else if (message.type === 'error') {
      if (message.fatal) stop(String(message.error));
      else { const current = clearPending(); current.reject(new Error(String(message.error))); }
    }
  };
  worker.onerror = event => { event.preventDefault(); stop('The browser Python worker could not load. Check the network or browser restrictions and retry.'); };
  worker.onmessageerror = () => stop('The browser could not read the analysis response. Retry to start a fresh runtime.');
}

window.incidentBrowserBackend = Object.freeze({
  example: () => bootstrap,
  analyze(text, progress) {
    if (pending) return Promise.reject(new Error('An analysis is already running.'));
    if (typeof text !== 'string' || /[\uD800-\uDFFF]/u.test(text)) return Promise.reject(new Error('Input contains invalid Unicode.'));
    if (new TextEncoder().encode(text).length > 262144) return Promise.reject(new Error('Input exceeds 262,144 bytes.'));
    return new Promise((resolve, reject) => {
      try {
        startWorker();
        pending = {id: ++nextId, resolve, reject, progress, timer: null};
        armTimeout(90000);
        progress('Preparing browser Python. Only the fixed runtime assets are downloaded; event text is processed here.');
        worker.postMessage({id: pending.id, type: 'analyze', text});
      } catch (error) { stop(error.message); reject(error); }
    });
  },
  cancel: () => stop('Analysis cancelled. The Python worker was stopped; the previous result is unchanged.')
});
})();
