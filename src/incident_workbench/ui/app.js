/* Every event/model field is rendered as text, never HTML or executable code. */
(() => {
'use strict';
const $ = id => document.getElementById(id);
const make = (tag, className, text) => { const n = document.createElement(tag); if(className) n.className = className; if(text !== undefined) n.textContent = text; return n; };
const snapshot = $('snapshot');
const browserBackend = globalThis.incidentBrowserBackend || null;
let analysisBusy = false;
let data = null, selectedCase = null, csrf = '', source = 'Bundled synthetic example';
const labels = {auth_failure:'Authentication failed',auth_success:'Authentication succeeded',role_change:'Privileged role changed',token_use:'API token used',data_access:'Data accessed'};
const time = iso => iso.slice(11,19) + ' UTC';
const short = id => id.slice(0,18) + '…';
function status(message, error=false) { $('status').textContent=message; $('status').classList.toggle('error',error); }
function download(name, body, type) { const url = URL.createObjectURL(new Blob([body], {type})); const a=make('a'); a.href=url; a.download=name; a.click(); setTimeout(()=>URL.revokeObjectURL(url),1000); }
function updateSize(){ $('input-size').textContent=new TextEncoder().encode($('jsonl').value).length.toLocaleString()+' / 262,144 bytes'; }
function setData(result){
 data=result; selectedCase=data.incidents[0]?.case_id || null;
 $('stat-events').textContent=data.summary.events; $('stat-cases').textContent=data.summary.incidents;
 $('stat-high').textContent=data.summary.high; $('stat-coverage').textContent=data.summary.findings ? '100%' : '—';
 $('nav-count').textContent=data.summary.incidents; $('fingerprint').textContent='INPUT SHA-256 '+data.input_sha256.slice(0,20)+'…'; $('fingerprint').title=data.input_sha256;
 $('source-label').textContent=source; $('export-json').disabled=false; $('export-report').disabled=false;
 status(data.summary.events+(data.summary.events===1?' unique event · ':' unique events · ')+data.summary.findings+(data.summary.findings===1?' finding · ':' findings · ')+data.duplicates+(data.duplicates===1?' duplicate line collapsed · ':' duplicate lines collapsed · ')+'timestamps normalized to UTC');
 renderQueue();
}
function renderQueue(){
 if(!data)return;
 const needle=$('search').value.toLowerCase(), severity=$('severity').value;
 const cases=data.incidents.filter(c => (severity==='all'||c.severity===severity) && [c.actor,c.tenant,...c.findings.map(f=>f.title)].join(' ').toLowerCase().includes(needle));
 if(!cases.some(c=>c.case_id===selectedCase))selectedCase=cases[0]?.case_id || null;
 $('queue-count').textContent=cases.length+' '+(cases.length===1?'case':'cases'); $('case-list').replaceChildren();
 for(const c of cases){
  const card=make('button','case-card'+(c.case_id===selectedCase?' selected':'')); card.type='button'; card.setAttribute('aria-pressed',c.case_id===selectedCase?'true':'false');
  const head=make('div','case-card-head'); head.append(make('span','badge '+c.severity,c.severity.toUpperCase()),make('span','time',time(c.start))); card.append(head,make('h3',null,c.actor),make('p',null,c.tenant),make('p','case-desc',c.findings[0].title));
  const meta=make('div','case-meta'); meta.append(make('span',null,c.findings.length+(c.findings.length===1?' signal':' signals')),make('span',null,c.evidence_ids.length+(c.evidence_ids.length===1?' evidence item →':' evidence items →'))); card.append(meta);
  card.addEventListener('click',()=>{selectedCase=c.case_id;renderQueue();}); $('case-list').append(card);
 }
 if(!cases.length){const empty=make('div','empty');empty.append(make('h2',null,'No matching cases'),make('p',null,data.incidents.length?'Adjust the search or priority filter.':'These events did not meet a correlation rule. This does not establish that activity is safe.'));$('case-list').append(empty);}
 renderDetail();
}
function renderDetail(){
 const c=data.incidents.find(c=>c.case_id===selectedCase); $('detail').replaceChildren();
 if(!c){const empty=make('div','empty');empty.append(make('span',null,'◎'),make('h2',null,'No case selected'),make('p',null,'Choose a case or analyze another event sequence.'));$('detail').append(empty);return;}
 const head=make('div','detail-head'),top=make('div','detail-topline'); top.append(make('span','badge '+c.severity,c.severity.toUpperCase()+' PRIORITY'),make('span','case-ref',short(c.case_id)));head.append(top,make('h2',null,c.actor));
 const sub=make('div','detail-subtitle');sub.append(make('span',null,'TENANT '+c.tenant),make('span',null,c.start.slice(0,10)),make('span',null,time(c.start)+' → '+time(c.end)));head.append(sub);
 const body=make('div','detail-body');body.append(make('h3','section-title','WHY THIS CASE EXISTS'));
 for(const f of c.findings){const box=make('div','finding'), title=make('div','finding-title');title.append(make('span','rule-id',f.rule_id),make('span',null,f.title));box.append(title,make('p',null,f.reason));const details=make('details');details.append(make('summary',null,'Investigation guidance & detection limits'));details.append(make('p','investigate',f.investigation),make('p',null,f.limitations));if(f.attack.length){details.append(make('p','attack','ATT&CK reference: '+f.attack.join(', ')+' · hypothesis mapping only'));}box.append(details);body.append(box);}
 const timelineHead=make('div','timeline-head');timelineHead.append(make('h3','section-title','EVIDENCE TIMELINE'),make('span','muted',c.evidence_ids.length+' linked events · click to inspect'));body.append(timelineHead);
 const timeline=make('div','timeline'),evidence=make('div','evidence');body.append(timeline,evidence);
 const events=c.evidence_ids.map(ref=>data.events.find(e=>e.evidence_id===ref));
 function inspect(event,row){for(const child of timeline.children){child.classList.remove('selected');child.setAttribute('aria-pressed','false');}row.classList.add('selected');row.setAttribute('aria-pressed','true');evidence.replaceChildren(make('h3',null,'Source evidence · '+labels[event.normalized.type]),make('div','evidence-meta','Evidence ID: '+event.evidence_id),make('div','evidence-meta','Source line'+(event.source_lines.length>1?'s':'')+': '+event.source_lines.join(', ')+' · SHA-256: '+event.sha256),make('pre',null,JSON.stringify(event.normalized,null,2)));}
 for(const e of events){const row=make('button','timeline-row');row.type='button';row.append(make('span','timeline-time',e.normalized.timestamp.slice(11,19)),make('span','timeline-dot'));const label=make('span','timeline-label');label.append(make('span',null,labels[e.normalized.type]),make('span','timeline-ip',e.normalized.source_ip));row.append(label);row.addEventListener('click',()=>inspect(e,row));timeline.append(row);}
 if(events.length)inspect(events[events.length-1],timeline.lastChild);
 if(data.model?.status==='untrusted-narrative'){const narrative=data.model.cases.find(v=>v.case_id===c.case_id);if(narrative){const warning=make('div','model-warning');warning.append(make('strong',null,'UNTRUSTED MODEL NARRATIVE'),make('p',null,narrative.summary),make('p',null,'Uncertainty: '+narrative.uncertainty),make('p',null,data.model.notice));body.append(warning);}}
 if(data.model?.status==='rejected'){const warning=make('div','model-warning','Model narrative rejected: '+data.model.reason);body.append(warning);}
 $('detail').append(head,body);
}
function setBusy(value){
 analysisBusy=value;
 for(const id of ['analyze','load-example','file-input'])$(id).disabled=value;
 const cancel=$('cancel-analysis');if(cancel)cancel.hidden=!value;
 $('analyze').textContent=value?'Analyzing…':'Analyze evidence →';
 $('input-dialog').setAttribute('aria-busy',String(value));
}
async function analyzeInput(text, nextSource){
 if(analysisBusy)return;
 setBusy(true);$('input-error').textContent='';status('Analyzing bounded event sequence…');
 const progress=message=>{status(message);const node=$('runtime-progress');if(node)node.textContent=message;};
 try {
  if(new TextEncoder().encode(text).length>262144)throw Error('Input exceeds 262,144 bytes.');
  let result;
  if(browserBackend){result=await browserBackend.analyze(text,progress);}
  else {const response=await fetch('/api/analyze',{method:'POST',headers:{'Content-Type':'application/x-ndjson; charset=utf-8','X-CSRF-Token':csrf},body:text,credentials:'same-origin'});result=await response.json();if(!response.ok)throw Error(result.error||'Analysis failed');}
  source=nextSource;setData(result);$('input-dialog').close();
 } catch(error){$('input-error').textContent=error.message;status('Analysis rejected: '+error.message,true);}
 finally{setBusy(false);const node=$('runtime-progress');if(node)node.textContent='';}
}
async function loadExample(){
 if(analysisBusy)return;
 if(browserBackend){const example=browserBackend.example();$('jsonl').value=example.jsonl;updateSize();source='Bundled synthetic example · computed preview';setData(example.result);return;}
 try{const r=await fetch('/api/example');if(!r.ok)throw Error('Example unavailable');const value=await r.json();$('jsonl').value=value.jsonl;updateSize();await analyzeInput(value.jsonl,'Bundled synthetic example');}catch(e){status(e.message,true);}
}
$('search').addEventListener('input',renderQueue);$('severity').addEventListener('change',renderQueue);
$('open-input').addEventListener('click',()=>{$('input-dialog').showModal();$('jsonl').focus();});$('close-input').addEventListener('click',()=>$('input-dialog').close());$('jsonl').addEventListener('input',updateSize);
$('analyze').addEventListener('click',()=>analyzeInput($('jsonl').value,'Pasted or uploaded events · user supplied'));
$('load-example').addEventListener('click',loadExample);
if(browserBackend&&$('cancel-analysis'))$('cancel-analysis').addEventListener('click',()=>browserBackend.cancel());
$('file-input').addEventListener('change',async(event)=>{const file=event.target.files[0];if(!file)return;try{if(file.size>262144)throw Error('File exceeds 262,144 bytes.');const buffer=await file.arrayBuffer();$('jsonl').value=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(buffer);updateSize();$('input-error').textContent='';}catch(e){$('input-error').textContent=e.message;}event.target.value='';});
$('export-json').addEventListener('click',()=>download('incident-evidence.json',JSON.stringify(data,null,2)+'\n','application/json'));
$('export-report').addEventListener('click',()=>{const lines=['INCIDENT EVIDENCE WORKBENCH','Deterministic findings; human review required.','Input SHA-256: '+data.input_sha256,''];for(const c of data.incidents){lines.push(c.case_id+' | '+c.severity.toUpperCase(),'Actor: '+JSON.stringify(c.actor)+' | Tenant: '+JSON.stringify(c.tenant),c.start+' → '+c.end);for(const f of c.findings){lines.push(f.rule_id+': '+f.title,f.reason,'Investigate: '+f.investigation,'Limits: '+f.limitations,'Evidence: '+f.evidence_ids.join(', '));}lines.push('');}lines.push('SOURCE EVIDENCE (NORMALIZED)',JSON.stringify(data.events,null,2));if(data.model?.status!=='disabled')lines.push('UNTRUSTED MODEL ADAPTER RESULT',JSON.stringify(data.model,null,2));download('incident-evidence-report.txt',lines.join('\n')+'\n','text/plain');});
if(browserBackend){$('mode').replaceChildren(make('i'),document.createTextNode('Browser demo · Python on demand'));$('source-note').textContent='Analyze runs the original Python engine in this browser. First use downloads the runtime; no account or installation.';loadExample();}
else if(snapshot){source='Computed evidence snapshot';$('mode').textContent='Portable preview · no server';$('open-input').disabled=true;$('open-input').title='Start the local server to analyze input';$('load-example').disabled=true;$('source-note').textContent='Computed by the offline rules. Start the local server to analyze your own JSONL.';setData(JSON.parse(snapshot.textContent));}
else {(async()=>{try{const response=await fetch('/api/session');if(!response.ok)throw Error('Local session unavailable');const session=await response.json();csrf=session.csrf;$('mode').replaceChildren(make('i'),document.createTextNode('Live loopback · offline rules'));await loadExample();}catch(e){status(e.message,true);}})();}
})();
