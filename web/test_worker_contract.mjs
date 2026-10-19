/** Node unit tests only: no browser automation or downloaded runtime. */
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';
import {validateRequest, FIXED_BOOTSTRAP} from './dist/worker.mjs';

const valid = () => ({id: 1, type: 'analyze', text: '{"actor":"demo"}'});
test('worker accepts data-only analysis envelope', () => {
  assert.deepEqual(validateRequest(valid()), valid());
});
test('worker rejects arbitrary code, URLs, command types and unknown keys', () => {
  for (const input of [null, [], {...valid(), python:'print(1)'}, {...valid(), endpoint:'https://example.test'}, {...valid(), type:'execute'}, {...valid(), id:NaN}, {...valid(), text:123}]) {
    assert.throws(() => validateRequest(input));
  }
});
test('worker enforces bytes and rejects lone surrogates', () => {
  assert.doesNotThrow(() => validateRequest({...valid(), text:'a'.repeat(262144)}));
  assert.throws(() => validateRequest({...valid(), text:'a'.repeat(262145)}));
  assert.throws(() => validateRequest({...valid(), text:'é'.repeat(131073)}));
  assert.throws(() => validateRequest({...valid(), text:'\uD800'}));
  assert.doesNotThrow(() => validateRequest({...valid(), text:'😀'}));
});
test('Python wrapper calls fixed core function with text as an argument', () => {
  assert.match(FIXED_BOOTSTRAP, /from incident_core import analyze, InputError/);
  assert.match(FIXED_BOOTSTRAP, /"result": analyze\(text\)/);
  assert.doesNotMatch(FIXED_BOOTSTRAP, /\beval\(|\bexec\(/);
});

const backendSource = await readFile(new URL('./browser-backend.js', import.meta.url), 'utf8');
function harness() {
  const workers=[];
  class FakeWorker {
    constructor(url, options) { this.url=String(url);this.options=options;this.messages=[];this.terminated=false;workers.push(this); }
    postMessage(message) { this.messages.push(message); }
    terminate() { this.terminated=true; }
    reply(value) { this.onmessage({data:value}); }
  }
  const example={jsonl:'synthetic-fixture',result:{summary:{events:22}}};
  const context={URL,TextEncoder,setTimeout,clearTimeout,Worker:FakeWorker,
    window:{isSecureContext:true,Worker:FakeWorker,WebAssembly:{},crypto:{subtle:{}}},
    document:{currentScript:{src:'https://example.test/incident-evidence-workbench/browser-backend.js'},getElementById:()=>({textContent:JSON.stringify(example)})}};
  vm.runInNewContext(backendSource,context,{filename:'browser-backend.js'});
  return {backend:context.window.incidentBrowserBackend, workers, context};
}
test('computed example creates no worker and uses no network', () => {
  const h=harness();
  assert.equal(h.backend.example().result.summary.events,22);
  assert.equal(h.workers.length,0);
});
test('analysis starts a module worker under repository path and passes only text', async () => {
  const h=harness(), progress=[];
  const pending=h.backend.analyze('custom event data',message=>progress.push(message));
  assert.equal(h.workers.length,1);
  const worker=h.workers[0];
  assert.equal(worker.url,'https://example.test/incident-evidence-workbench/worker.mjs');
  assert.equal(worker.options.type,'module');
  assert.equal(worker.messages[0].text,'custom event data');
  assert.deepEqual(Object.keys(worker.messages[0]).sort(),['id','text','type']);
  worker.reply({id:1,type:'result',result:{engine:'deterministic-rules'}});
  assert.equal((await pending).engine,'deterministic-rules');
  assert.equal(progress.length,1);
});
test('parallel analyses are refused and cancellation terminates worker', async () => {
  const h=harness(), first=h.backend.analyze('one',()=>{});
  const stopped=assert.rejects(first,/cancelled/);
  await assert.rejects(h.backend.analyze('two',()=>{}),/already running/);
  assert.equal(h.workers[0].messages.length,1);
  h.backend.cancel();await stopped;
  assert.equal(h.workers[0].terminated,true);
});
test('validation error retains runtime and allows a subsequent analysis', async () => {
  const h=harness(), first=h.backend.analyze('invalid',()=>{});
  const rejected=assert.rejects(first,/Invalid JSON/);
  h.workers[0].reply({id:1,type:'error',error:'Invalid JSON'});await rejected;
  const second=h.backend.analyze('valid',()=>{});
  assert.equal(h.workers.length,1);
  h.workers[0].reply({id:2,type:'result',result:{ok:true}});
  assert.equal((await second).ok,true);
});
test('fatal runtime failure creates a fresh worker on retry', async () => {
  const h=harness(), first=h.backend.analyze('data',()=>{});
  const rejected=assert.rejects(first,/Runtime failed/);
  h.workers[0].reply({id:1,type:'error',fatal:true,error:'Runtime failed'});await rejected;
  assert.equal(h.workers[0].terminated,true);
  const second=h.backend.analyze('retry',()=>{});
  assert.equal(h.workers.length,2);
  h.workers[1].reply({id:2,type:'result',result:{ok:true}});await second;
});
test('oversized input rejected before worker construction', async () => {
  const h=harness();
  await assert.rejects(h.backend.analyze('x'.repeat(262145),()=>{}),/262,144/);
  assert.equal(h.workers.length,0);
});
