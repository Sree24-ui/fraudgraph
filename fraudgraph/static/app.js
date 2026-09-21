'use strict';
const $ = (id) => document.getElementById(id);
const state = {user:null,csrf:null,source:'synthetic',offset:0,total:0,selected:null,detail:null,view:'cases',polling:false,environment:null,epoch:0,selectionEpoch:0};
const number = new Intl.NumberFormat('en-IN');
const money = (value) => state.source === 'external_synthetic' ? `${number.format(value/100)} source units` : new Intl.NumberFormat('en-IN',{style:'currency',currency:'INR',maximumFractionDigits:2}).format(value/100);
const time = (value) => value ? new Intl.DateTimeFormat('en-IN',{timeZone:'Asia/Kolkata',month:'short',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false}).format(new Date(value)) : '—';
function el(tag,cls,text){const e=document.createElement(tag);if(cls)e.className=cls;if(text!==undefined)e.textContent=text;return e;}
function message(text,error=false){$('global-message').textContent=text;$('global-message').className=error?'error':'';$('global-message').hidden=false;}
function clearMessage(){$('global-message').hidden=true;}
async function api(path,options={}){
  const epoch=state.epoch;
  const method=options.method||'GET';
  const headers={...options.headers};
  if(method!=='GET'){headers['Content-Type']='application/json';if(state.csrf)headers['X-CSRF-Token']=state.csrf;}
  const response=await fetch(path,{...options,method,headers,credentials:'same-origin',cache:'no-store'});
  const data=await response.json().catch(()=>({detail:'Unexpected server response'}));
  if(epoch!==state.epoch)throw new Error('Session changed; previous response discarded');
  if(!response.ok){
    if(response.status===401&&state.user){showLogin();$('login-error').textContent='Your session ended. Sign in again.';}
    const detail=Array.isArray(data.detail)?data.detail.map(x=>`${x.loc.slice(1).join('.')}: ${x.msg}`).join('; '):data.detail;
    const error=new Error(detail||`Request failed (${response.status})`);error.status=response.status;throw error;
  }
  return data;
}
function showLogin(){
  state.epoch++;state.selectionEpoch++;state.user=null;state.csrf=null;state.selected=null;state.detail=null;state.offset=0;state.total=0;
  $('workspace').hidden=true;$('login-view').hidden=false;$('detail-content').hidden=true;$('detail-empty').hidden=false;
  for(const id of ['identity','case-list','user-list','audit-rows','transaction-rows','review-history','flow','detail-account','detail-reason','detail-score','detail-in','detail-out','detail-ratio','detail-window','case-label','detail-status','queue-count','page-range','watermark','metric-transactions','metric-accounts','metric-open','metric-escalated','replay-result'])$(id).replaceChildren();
  document.querySelectorAll('input,textarea').forEach(input=>input.value='');clearMessage();
}
async function enter(data){
  state.epoch++;
  state.user=data.user;state.csrf=data.csrf;
  $('login-view').hidden=true;$('workspace').hidden=false;$('identity').replaceChildren(el('span','',state.user.username),el('small','',state.user.role));
  document.querySelectorAll('.admin-only').forEach(x=>x.hidden=state.user.role!=='admin');
  $('review-form').hidden=!['admin','analyst'].includes(state.user.role);
  $('review-readonly').hidden=['admin','analyst'].includes(state.user.role);
  if(state.user.role==='ingestor'){
    document.querySelectorAll('.nav-item').forEach(x=>x.hidden=x.dataset.view!=='profile');
    switchView('profile');message('Your ingestion account can submit transactions through the API. Case data requires an analyst or viewer role.');return;
  }
  document.querySelectorAll('.nav-item:not(.admin-only)').forEach(x=>x.hidden=false);
  const config=await api('/api/config');state.environment=config.environment;
  $('config-values').textContent=`Active detector: ${config.detector.version} · Dashboard refresh: every 2 seconds · Environment: ${config.environment}`;
  if(state.user.role==='admin'){
    const data=await api('/api/demo/scenarios');$('scenario').replaceChildren();
    for(const [name,description] of Object.entries(data.items)){$('scenario').append(el('option','',description.replace(/^SYNTHETIC[^:]*:\s*/,'')));$('scenario').lastChild.value=name;}
    $('replay-controls').hidden=!data.enabled;
  }
  switchView('cases');await refresh();
}
$('login-form').addEventListener('submit',async(e)=>{e.preventDefault();const b=e.submitter;b.disabled=true;$('login-error').textContent='';try{const data=await api('/api/login',{method:'POST',body:JSON.stringify({username:$('username').value,password:$('password').value})});$('password').value='';await enter(data);}catch(error){$('login-error').textContent=error.message;}finally{b.disabled=false;}});
$('logout').addEventListener('click',async()=>{try{await api('/api/logout',{method:'POST'});showLogin();}catch(error){message(error.message,true);}});
const titles={cases:['CASE QUEUE','Follow the money.'],method:['DETECTION & LIMITS','Understand the signal.'],users:['USER ACCESS','The right access.'],audit:['AUDIT LOG','A traceable record.'],profile:['ACCOUNT SECURITY','Protect your access.']};
function switchView(view){state.view=view;document.querySelectorAll('.view').forEach(x=>x.hidden=x.id!==`${view}-view`);document.querySelectorAll('.nav-item').forEach(x=>x.classList.toggle('active',x.dataset.view===view));$('page-name').textContent=titles[view][0];$('page-title').textContent=titles[view][1];clearMessage();if(view==='users')loadUsers().catch(e=>message(e.message,true));if(view==='audit')loadAudit().catch(e=>message(e.message,true));}
document.querySelectorAll('[data-view]').forEach(button=>button.addEventListener('click',()=>switchView(button.dataset.view)));
function setConnection(ok){$('connection').textContent=ok?'Connected · 2s refresh':'Connection interrupted';$('connection-dot').classList.toggle('offline',!ok);}
async function refresh(){
  if(!state.user||state.user.role==='ingestor'||state.polling)return;
  state.polling=true;
  const source=state.source;
  try{
    const params=new URLSearchParams({provenance:state.source,status:$('status').value,q:$('search').value,offset:String(state.offset),limit:'20'});
    const [metrics,cases]=await Promise.all([api(`/api/metrics?provenance=${state.source}`),api(`/api/alerts?${params}`)]);
    if(source!==state.source)return;
    $('metric-transactions').textContent=number.format(metrics.transactions);$('metric-accounts').textContent=number.format(metrics.accounts);$('metric-open').textContent=number.format((metrics.alerts.open||0)+(metrics.alerts.investigating||0));$('metric-escalated').textContent=number.format(metrics.alerts.escalated||0);$('watermark').textContent=metrics.watermark?`Latest event ${time(metrics.watermark)}`:'No transactions in this data source';
    state.total=cases.total;$('queue-count').textContent=cases.total;$('case-list').replaceChildren();
    if(!cases.items.length){const empty=el('div','empty');empty.append(el('h2','','No matching cases'),el('p','','No alerts does not establish that these payments are safe.'));$('case-list').append(empty);}
    for(const item of cases.items){
      const button=el('button',`case-row${state.selected===item.id?' selected':''}`);button.type='button';button.setAttribute('aria-pressed',String(state.selected===item.id));
      const top=el('div','case-top');top.append(el('span','case-name',item.account_id),el('span','risk-score',`${item.score} / 100`));
      const bottom=el('div','case-bottom');bottom.append(el('span',`status ${item.status}`,item.status),el('span','',time(item.updated_at)));
      button.append(top,el('div','case-meta',`Case #${String(item.id).padStart(4,'0')} · Collection / redistribution`),bottom);
      button.addEventListener('click',()=>selectCase(item.id));$('case-list').append(button);
      if(state.selected===item.id&&state.detail&&state.detail.version!==item.version){$('case-label').textContent=`CASE #${item.id} · UPDATED — RELOAD TO REVIEW`;}
    }
    $('page-range').textContent=cases.total?`${state.offset+1}–${Math.min(state.offset+20,cases.total)} of ${cases.total}`:'0 cases';$('previous').disabled=state.offset===0;$('next').disabled=state.offset+20>=cases.total;setConnection(true);
  }catch(error){setConnection(false);if(error.status!==401)message(error.message,true);}finally{state.polling=false;}
}
$('refresh').addEventListener('click',async()=>{clearMessage();await refresh();if(state.selected&&state.view==='cases')await selectCase(state.selected);});
for(const id of ['status','source'])$(id).addEventListener('change',()=>{state.offset=0;if(id==='source'){state.selectionEpoch++;state.source=$('source').value;state.selected=null;state.detail=null;$('detail-content').hidden=true;$('detail-empty').hidden=false;const labels={synthetic:['SYNTHETIC DATA','Local generator · no real payments or customer accounts'],external_synthetic:['EXTERNAL SYNTHETIC DATA','Independent source · synthetic payments; amounts retain source units'],real:['SUPPLIED TRANSACTION DATA','Origin declared by the submitting account; provenance is not independently attested']};$('source-badge').textContent=labels[state.source][0];$('source-description').textContent=labels[state.source][1];}refresh();});
let searchTimer;$('search').addEventListener('input',()=>{clearTimeout(searchTimer);searchTimer=setTimeout(()=>{state.offset=0;refresh();},250);});
$('previous').addEventListener('click',()=>{state.offset=Math.max(0,state.offset-20);refresh();});$('next').addEventListener('click',()=>{state.offset+=20;refresh();});
async function selectCase(id){
  const selectionEpoch=++state.selectionEpoch;
  const draft=state.selected===id?$('review-note').value:'';
  try{const data=await api(`/api/alerts/${id}`);if(selectionEpoch!==state.selectionEpoch)return;state.selected=id;state.detail=data;renderDetail(data);$('review-note').value=draft;await refresh();}catch(error){message(error.message,true);}
}
function renderDetail(data){
  $('detail-empty').hidden=true;$('detail-content').hidden=false;$('detail-account').textContent=data.account_id;$('case-label').textContent=`CASE #${String(data.id).padStart(4,'0')} · ${data.provenance.replace('_',' ').toUpperCase()}`;$('detail-status').className=`status ${data.status}`;$('detail-status').textContent=data.status;$('detail-score').textContent=data.score;$('detail-reason').textContent=data.evidence.reason;$('detail-window').textContent=`${data.window_seconds/60} min window · ${data.evidence.duration_seconds}s observed`;
  $('detail-in').textContent=money(data.evidence.incoming_paise);$('detail-out').textContent=money(data.evidence.outgoing_paise);$('detail-ratio').textContent=`${(data.evidence.passthrough_ratio*100).toFixed(1)}%`;$('transaction-count').textContent=`${data.transactions.length} payments`;
  drawFlow(data);$('transaction-rows').replaceChildren();
  for(const tx of data.transactions){const row=el('tr');const accounts=el('td','tx-account',`${tx.sender} → ${tx.receiver}`);accounts.append(el('span','tx-id',tx.id));row.append(el('td','',time(tx.occurred_at)),accounts,el('td','money',money(tx.amount_paise)));$('transaction-rows').append(row);}
  $('review-status').value=data.status==='open'?'investigating':data.status;$('review-note').value='';$('review-history').replaceChildren();
  if(!data.reviews.length)$('review-history').append(el('p','subtle','No analyst assessment recorded.'));
  for(const review of data.reviews){const entry=el('div','history-item');entry.append(el('span',`status ${review.status}`,review.status),el('p','',review.note),el('small','',`${review.username} · ${time(review.created_at)}`));if(review.evidence){const snapshot=el('details');snapshot.append(el('summary','',`Evidence at decision · version ${review.alert_version}`),el('p','',review.evidence.reason),el('p','subtle',`Payment IDs: ${review.evidence.transaction_ids.join(', ')}`));entry.append(snapshot);}$('review-history').append(entry);}
}
function drawFlow(data){
  const NS='http://www.w3.org/2000/svg';const svg=document.createElementNS(NS,'svg');svg.setAttribute('viewBox','0 0 600 255');svg.setAttribute('role','img');svg.setAttribute('aria-label',`${data.evidence.unique_sources} sources paid the flagged account; it paid ${data.evidence.unique_recipients} recipients.`);
  const node=(tag,attrs,text)=>{const e=document.createElementNS(NS,tag);for(const[k,v]of Object.entries(attrs))e.setAttribute(k,v);if(text!==undefined)e.textContent=text;svg.append(e);return e;};
  const left=data.evidence.source_accounts.slice(0,6),right=data.evidence.recipient_accounts.slice(0,6);
  function side(accounts,inbound){const x=inbound?135:465,color=inbound?'#84aecb':'#d7b271';accounts.forEach((account,i)=>{const y=35+i*35;node('path',{d:inbound?`M ${x} ${y} C 215 ${y},215 122,274 122`:`M 326 122 C 385 122,385 ${y},${x} ${y}`,stroke:color,'stroke-width':1.4,fill:'none',opacity:.55});node('circle',{cx:x,cy:y,r:5,fill:color});const label=account.length>16?`${account.slice(0,6)}…${account.slice(-9)}`:account;const text=node('text',{x:inbound?x-12:x+12,y:y+4,'text-anchor':inbound?'end':'start'},label);const title=document.createElementNS(NS,'title');title.textContent=account;text.append(title);});}
  side(left,true);side(right,false);node('circle',{cx:300,cy:122,r:30,fill:'#e0f3ee',stroke:'#81c5b7','stroke-width':1});node('circle',{cx:300,cy:122,r:19,fill:'#087c75'});const text=node('text',{x:300,y:127,'text-anchor':'middle'},'H');text.setAttribute('fill','white');text.style.fill='white';node('text',{x:300,y:174,'text-anchor':'middle'},'Flagged account');node('text',{x:105,y:244,'text-anchor':'middle'},`${data.evidence.unique_sources} sources${data.evidence.unique_sources>6?' · 6 shown':''}`);node('text',{x:495,y:244,'text-anchor':'middle'},`${data.evidence.unique_recipients} recipients${data.evidence.unique_recipients>6?' · 6 shown':''}`);$('flow').replaceChildren(svg);
}
$('review-form').addEventListener('submit',async e=>{e.preventDefault();if(!state.detail)return;e.submitter.disabled=true;try{await api(`/api/alerts/${state.selected}/review`,{method:'POST',body:JSON.stringify({status:$('review-status').value,note:$('review-note').value,version:state.detail.version})});$('review-note').value='';await selectCase(state.selected);message('Assessment saved to the case and audit log.');}catch(error){message(error.message,true);}finally{e.submitter.disabled=false;}});
$('replay').addEventListener('click',async()=>{$('replay').disabled=true;try{const data=await api(`/api/demo/${$('scenario').value}`,{method:'POST'});$('replay-result').textContent=`Synthetic replay: ${data.accepted} payments accepted; ${data.alert_ids.length} cases updated. ${data.description}`;$('source').value='synthetic';$('source').dispatchEvent(new Event('change'));await refresh();if(data.alert_ids.length)await selectCase(data.alert_ids[0]);}catch(error){message(error.message,true);}finally{$('replay').disabled=false;}});
async function loadUsers(){const data=await api('/api/users');$('user-list').replaceChildren();for(const user of data.items){const row=el('div','user-row');const identity=el('div','',user.username);identity.append(el('small','',`${user.role} · ${user.active?'Active':'Disabled'}`));const button=el('button','secondary',user.active?'Disable':'Enable');button.disabled=user.id===state.user.id;button.addEventListener('click',async()=>{try{await api(`/api/users/${user.id}`,{method:'PATCH',body:JSON.stringify({active:!user.active})});await loadUsers();message('Access updated. Existing sessions were revoked.');}catch(error){message(error.message,true);}});row.append(identity,button);$('user-list').append(row);}}
$('user-form').addEventListener('submit',async e=>{e.preventDefault();e.submitter.disabled=true;try{await api('/api/users',{method:'POST',body:JSON.stringify({username:$('new-username').value,password:$('new-password').value,role:$('new-role').value})});$('user-form').reset();await loadUsers();message('Account created.');}catch(error){message(error.message,true);}finally{e.submitter.disabled=false;}});
async function loadAudit(){const data=await api('/api/audit');$('audit-rows').replaceChildren();for(const item of data.items){const row=el('tr');for(const value of[time(item.created_at),item.actor,item.action,item.object_id||'—',item.detail])row.append(el('td','',value));$('audit-rows').append(row);}}
$('password-form').addEventListener('submit',async e=>{e.preventDefault();e.submitter.disabled=true;try{await api('/api/password',{method:'POST',body:JSON.stringify({current_password:$('current-password').value,new_password:$('change-password').value})});$('password-form').reset();showLogin();$('login-error').textContent='Password changed. Sign in with your new password.';}catch(error){message(error.message,true);}finally{e.submitter.disabled=false;}});
setInterval(()=>{if(state.user&&state.view==='cases'&&!document.hidden)refresh();},2000);
api('/api/me').then(enter).catch(()=>showLogin());
