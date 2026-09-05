/* No external dependencies, network services, telemetry, or persisted bearer tokens. */
"use strict";
const $ = s => document.querySelector(s);
const esc = v => String(v ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const preview = window.OPENWAIVER_PREVIEW || null;
const state = {token:"", actor:null, runs:[], run:null, assessment:null, waivers:[], snapshots:[], view:"overview", offset:0, total:0, rows:[], drawer:null};
const titles = {overview:["Waiver overview","One place to understand every exception. Nothing waived silently."],violations:["Violation explorer","Trace every finding to its evidence, scope and review decision."],waivers:["Waiver register","Bounded exceptions. Named owners. Independent reviewers."],compare:["Tapeout comparison","Compare frozen evidence, not a moving view of today's approvals."],audit:["Audit trail","Every lifecycle change, linked to its content and predecessor."],policy:["Workspace policy","Guardrails shared by the API, command line and CI gate."]};
const label = s => String(s).replaceAll("_"," ");
const pill = s => `<span class="status-pill ${esc(s)}">${esc(label(s))}</span>`;
const datefmt = s => s ? new Date(s).toLocaleDateString(undefined,{day:"2-digit",month:"short",year:"numeric",...(/^\d{4}-\d{2}-\d{2}$/.test(s)?{timeZone:"UTC"}:{})}) : "Revision bound";
const disabled = () => preview ? "disabled title='Read-only synthetic preview'" : "";
let toastTimer, searchTimer, requestGeneration=0;
function toast(message, failure=false){clearTimeout(toastTimer);$("#toast").textContent=message;$("#toast").className="toast"+(failure?" failure":"");toastTimer=setTimeout(()=>$("#toast").classList.add("hidden"),5500);}
async function guard(fn){try{return await fn();}catch(e){toast(e.message,true);return null;}}
async function api(path, options={}){
  if(preview)return previewAPI(path,options);
  const response=await fetch(path,{...options,headers:{"Authorization":`Bearer ${state.token}`,"Content-Type":"application/json",...(options.headers||{})}});
  if(!response.ok){let data;try{data=await response.json();}catch{data={detail:response.statusText};}throw new Error(typeof data.detail==="string"?data.detail:JSON.stringify(data.detail));}
  return response.json();
}
function post(path,body){return api(path,{method:"POST",body:JSON.stringify(body)});}
function previewAPI(path, options){
  if(options.method && options.method!=="GET")throw new Error("Read-only preview. Start the local application for lifecycle changes.");
  const u=new URL(path,"http://preview.local"), p=u.pathname;
  if(p==="/api/me")return {name:"Reference workspace",role:"viewer"};
  if(p==="/api/runs")return {items:preview.runs,total:preview.runs.length};
  if(p==="/api/waivers")return {items:preview.waivers,total:preview.waivers.length};
  if(p==="/api/snapshots")return preview.snapshots;
  if(p==="/api/audit")return preview.audit;
  if(p==="/api/policy")return preview.policy;
  if(p.startsWith("/api/compare/"))return preview.comparisons[p.split("/").slice(-2).join("/")];
  if(p.startsWith("/api/waivers/")){
    if(p.endsWith("/history"))return preview.history[p.split("/")[3]]||[];
    return preview.waivers.find(w=>w.id===p.split("/")[3]);
  }
  if(p.endsWith("/assessment")){
    const result=structuredClone(preview.assessments[p.split("/")[3]]);
    let rows=result.violations;
    const q=(u.searchParams.get("q")||"").toLowerCase(), status=u.searchParams.get("status"), category=u.searchParams.get("category");
    if(q)rows=rows.filter(r=>JSON.stringify(r.violation).toLowerCase().includes(q));
    if(status)rows=rows.filter(r=>r.status===status);
    if(category)rows=rows.filter(r=>r.violation.category===category);
    result.total=rows.length;result.offset=Number(u.searchParams.get("offset")||0);result.violations=rows.slice(result.offset,result.offset+100);return result;
  }
  throw new Error("This operation is available in the running application.");
}
async function download(path,name){
  let blob;
  if(preview){
    const parts=path.split("/"), id=parts[3], format=parts.at(-1);
    const value=preview.exports?.[id]?.[format];
    if(value===undefined)throw new Error("Run the local application to retrieve this file.");
    blob=new Blob([value],{type:"application/octet-stream"});
  } else {
    const r=await fetch(path,{headers:{Authorization:`Bearer ${state.token}`}});
    if(!r.ok)throw new Error((await r.json()).detail||"Download failed");
    blob=await r.blob();
  }
  const url=URL.createObjectURL(blob),a=document.createElement("a");a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
function navigate(view){state.view=view;document.querySelectorAll(".nav").forEach(b=>b.classList.toggle("active",b.dataset.view===view));document.querySelectorAll(".view").forEach(v=>v.classList.add("hidden"));$(`#${view}-view`).classList.remove("hidden");$("#page-title").textContent=titles[view][0];$("#page-description").textContent=titles[view][1];if(view==="waivers")renderWaivers();if(view==="compare")guard(renderCompare);if(view==="audit")guard(renderAudit);if(view==="policy")guard(renderPolicy);}
async function boot(){
  state.actor=await api("/api/me");$("#identity").textContent=state.actor.name;$("#role").textContent=state.actor.role;$("#avatar").textContent=state.actor.name.slice(0,2).toUpperCase();
  if(preview){$("#preview-banner").classList.remove("hidden");$("#mode-label").textContent="Synthetic preview";$("#import-open").disabled=true;$("#logout").disabled=true;}
  await refresh();
}
async function refresh(){
  const [runs,waivers,snapshots]=await Promise.all([api("/api/runs"),api("/api/waivers?limit=1000"),api("/api/snapshots")]);
  state.runs=runs.items;state.waivers=waivers.items;state.snapshots=snapshots;
  const old=state.run?.id;state.run=state.runs.find(r=>r.id===old)||state.runs[0]||null;
  $("#run-select").innerHTML=state.runs.map(r=>`<option value="${esc(r.id)}">${esc(r.revision)} · ${esc(r.scope.tool)}</option>`).join("");
  if(state.run){$("#run-select").value=state.run.id;await loadRun();}else{$("#overview-view").innerHTML='<div class="panel empty"><h3>Your workspace is ready</h3><p>Import an unfiltered run to begin. Use the CLI demo for synthetic examples.</p></div>';$("#export").disabled=true;}
  navigate(state.view);
}
async function loadRun(){
  $("#export").disabled=false;
  $("#project").textContent=state.run.scope.project;$("#run-meta").textContent=`${state.run.complete?"Complete":"Partial"} · ${datefmt(state.run.created_at)}`;
  state.assessment=await api(`/api/runs/${state.run.id}/assessment?limit=100`);
  $("#nav-count").textContent=state.run.violation_count;renderOverview();state.offset=0;await loadFindings();
}
function counts(){return state.assessment?.counts||{};}
function metric(title,value,note,style="",icon="◇"){return `<div class="metric"><div class="metric-label">${esc(title)}<span class="metric-icon">${icon}</span></div><div class="metric-value">${value}</div><div class="metric-note ${style}">${esc(note)}</div></div>`;}
function renderOverview(){
  if(!state.assessment)return;
  const a=state.assessment,c=a.counts,total=Object.values(c).reduce((x,y)=>x+y,0),review=(c.needs_review||0)+(c.stale||0)+(c.ambiguous||0),unused=a.waivers.filter(w=>w.status==="unused").length;
  const queue=a.violations.filter(r=>["needs_review","stale","ambiguous"].includes(r.status)).slice(0,4);
  const bars=Object.entries(c).map(([k,v])=>`<div class="bar-row"><span class="bar-label">${esc(label(k))}</span><progress class="bar-track ${esc(k)}" value="${v}" max="${total||1}" aria-label="${esc(label(k))}: ${v}"></progress><span class="bar-number">${v}</span></div>`).join("");
  $("#overview-view").innerHTML=`<div class="metrics">${metric("Total findings",total,"Across "+state.run.checked_categories.length+" declared check categories","","◫")}${metric("Active waivers",c.waived||0,"Exact identity + valid approval","positive","✓")}${metric("Needs re-review",review,"Changes never inherit approval","warning","↻")}${metric("Unused waivers",unused,a.complete?"Not observed in this complete run":"Partial run cannot establish unused","","▤")}</div>
  <div class="grid-two"><div class="panel"><div class="panel-head"><div><h2>Tapeout readiness</h2><p>Current run against your workspace policy</p></div>${pill(a.gate_pass?"approved":"open")}</div><div class="panel-content"><div class="readiness ${a.gate_pass?"pass":""}"><span class="symbol">${a.gate_pass?"✓":"!"}</span><div><strong>${a.gate_pass?"Waiver gate passed":"Review required before proceeding"}</strong><p>${a.blockers.length} gate blocker${a.blockers.length===1?"":"s"} · ${a.complete?"Complete unfiltered run declared":"Incomplete check coverage"}</p></div></div>${bars}</div></div><div class="panel"><div class="panel-head"><div><h2>Change review queue</h2><p>Review suggestions, never automatic waivers</p></div><button class="button small" data-navigate="violations">View all →</button></div><div class="panel-content"><ul class="rule-list">${queue.map(r=>`<li><div class="rule-info"><strong>${esc(r.violation.rule)}</strong><small>${esc(r.violation.hierarchy||r.violation.path)}</small></div>${pill(r.status)}<button class="rule-arrow" data-finding="${esc(r.violation_id)}" aria-label="Review ${esc(r.violation.rule)}">↗</button></li>`).join("")||'<li>No changed findings in the displayed batch.</li>'}</ul><div class="note">Movement or reshaping breaks exact identity. Rebind the target, then obtain fresh independent approval.</div></div></div></div>
  <div class="panel"><div class="panel-head"><div><h2>Findings at a glance</h2><p>${esc(state.run.scope.stream)} · ${esc(state.run.revision)}</p></div><button class="button small" data-navigate="violations">Explore findings →</button></div><div class="table-wrap"><table><thead><tr><th>Rule / finding</th><th>Check</th><th>Location</th><th>Severity</th><th>Status</th><th></th></tr></thead><tbody>${a.violations.slice(0,5).map(findingRow).join("")}</tbody></table></div></div>`;
}
function findingRow(r){const v=r.violation;return `<tr><td class="rule-cell"><strong>${esc(v.rule)}</strong><small title="${esc(v.message)}">${esc(v.message)}</small></td><td><span class="check-chip">${esc(v.category)}</span></td><td class="location">${esc(v.hierarchy||v.path)}${v.line?`<div class="muted">line ${v.line}</div>`:""}</td><td class="severity">${esc(v.severity)}</td><td>${pill(r.status)}</td><td><button class="rule-arrow" data-finding="${esc(r.violation_id)}" aria-label="Inspect ${esc(v.rule)}">↗</button></td></tr>`;}
async function loadFindings(){
  if(!state.run)return;
  const generation=++requestGeneration;
  const params=new URLSearchParams({limit:100,offset:state.offset,q:$("#search").value,status:$("#status-filter").value,category:$("#category-filter").value});
  const result=await api(`/api/runs/${state.run.id}/assessment?${params}`);if(generation!==requestGeneration)return;
  state.rows=result.violations;state.total=result.total;
  $("#findings-body").innerHTML=result.violations.map(findingRow).join("")||'<tr><td colspan="6" class="empty">No findings match these filters.</td></tr>';
  $("#page-info").textContent=`${result.total?state.offset+1:0}–${Math.min(state.offset+100,result.total)} of ${result.total} findings`;
  $("#prev-page").disabled=state.offset===0;$("#next-page").disabled=state.offset+100>=result.total;
}
function renderWaivers(){
  const outcomes=Object.fromEntries((state.assessment?.waivers||[]).map(w=>[w.waiver_id,w.status]));
  $("#waivers-view").innerHTML=`<div class="panel"><div class="panel-head"><div><h2>Lifecycle register</h2><p>${state.waivers.length} loaded records · effective state is evaluated for the selected run</p></div></div><div class="table-wrap"><table><thead><tr><th>Target rule</th><th>Owner</th><th>Lifecycle</th><th>Effective state</th><th>Expiration</th><th>Approvals</th><th></th></tr></thead><tbody>${state.waivers.map(w=>`<tr><td class="rule-cell"><strong>${esc(w.target.rule)}</strong><small>${esc(w.id.slice(0,16))} · v${w.version}</small></td><td>${esc(w.owner)}</td><td>${pill(w.status)}</td><td>${outcomes[w.id]?pill(outcomes[w.id]):'<span class="muted">Other stream</span>'}</td><td>${esc(datefmt(w.expires_on))}</td><td>${w.approvals.filter(a=>a.decision==="approve").length} / ${w.reviewers.length}</td><td><button class="rule-arrow" data-waiver="${esc(w.id)}" aria-label="View waiver">↗</button></td></tr>`).join("")||'<tr><td colspan="7" class="empty">No waivers yet. Propose one from a finding.</td></tr>'}</tbody></table></div></div>`;
}
function openDrawer(content){$("#drawer").innerHTML=content;$("#drawer").classList.remove("hidden");$("#drawer-shade").classList.remove("hidden");$("#drawer").scrollTop=0;}
function closeDrawer(){state.drawer=null;$("#drawer").classList.add("hidden");$("#drawer-shade").classList.add("hidden");}
function drawerHead(title,status){return `<div class="drawer-header"><span class="eyebrow">${esc(title)}</span><button class="icon-button" data-close-drawer aria-label="Close detail">×</button></div><div class="drawer-actions">${pill(status)}</div>`;}
function geometry(oldGeometries,newGeometries){
  const all=[...(oldGeometries||[]),...(newGeometries||[])];if(!all.length)return "";
  if(new Set(all.map(g=>JSON.stringify([g.unit,g.frame,g.layer]))).size>1)return '<div class="note">Multiple layers or coordinate frames: inspect the original report. These markers are not overlaid on an assumed shared coordinate system.</div>';
  if(all.reduce((n,g)=>n+g.points.length,0)>20000)return '<div class="note">Large marker geometry: inspect the original report or exported coordinates. The full shape is retained for identity matching.</div>';
  const pts=all.flatMap(g=>g.points),xs=pts.map(p=>p[0]),ys=pts.map(p=>p[1]);let minx=Math.min(...xs),miny=Math.min(...ys),dx=Math.max(...xs)-minx,dy=Math.max(...ys)-miny;const scale=150/Math.max(dx,dy,1);
  const transform=p=>[50+(p[0]-minx)*scale,173-(p[1]-miny)*scale];
  const draw=(gs,color,dash)=>gs.map(g=>{let p=g.points;if(g.kind==="box"){const a=p[0],b=p[1];p=[a,[b[0],a[1]],b,[a[0],b[1]]];}const coords=p.map(transform).map(p=>p.join(",")).join(" ");if(g.kind==="point"){const p=transform(g.points[0]);return `<circle cx="${p[0]}" cy="${p[1]}" r="4" fill="${color}"/>`;}return `<${g.kind==="edge"?"polyline":"polygon"} points="${coords}" fill="${g.kind==="edge"?"none":color+"14"}" stroke="${color}" stroke-width="2" stroke-dasharray="${dash}"/>`;}).join("");
  return `<svg class="geometry" viewBox="0 0 480 205" role="img" aria-label="Local marker geometry, before and after"><defs><pattern id="grid" width="20" height="20" patternUnits="userSpaceOnUse"><path d="M 20 0 L 0 0 0 20" fill="none" stroke="#e5edf0" stroke-width=".7"/></pattern></defs><rect width="480" height="205" fill="url(#grid)"/>${draw(oldGeometries||[],"#429886","5 3")}${draw(newGeometries||[],"#c99443","")}<text x="292" y="36" fill="#879aa3" font-size="10">LOCAL MARKER VIEW</text><text x="292" y="54" fill="#879aa3" font-size="10">${esc(all[0].unit)} · ${esc(all[0].layer||"unspecified layer")}</text></svg><div class="legend"><span class="old">- - Previous waiver target</span><span class="new">— Current finding</span></div>`;
}
async function showFinding(id){
  const r=[...state.rows,...(state.assessment?.violations||[])].find(r=>r.violation_id===id);if(!r)return;
  state.drawer={kind:"finding",id};const v=r.violation;
  let baseline=null;if(r.candidates.length)baseline=state.waivers.find(w=>w.id===r.candidates[0].waiver_id)?.target;
  openDrawer(`${drawerHead("VIOLATION DETAIL",r.status)}<h2>${esc(v.rule)}</h2><p>${esc(v.message)}</p><dl class="detail-grid"><div><dt>Category</dt><dd>${esc(label(v.category))}</dd></div><div><dt>Severity</dt><dd>${esc(v.severity)}</dd></div><div><dt>Hierarchy</dt><dd>${esc(v.hierarchy||"—")}</dd></div><div><dt>Source</dt><dd>${esc(v.path||"—")}${v.line?":"+v.line:""}</dd></div><div><dt>Context</dt><dd>${v.context_hash?esc(v.context_hash.slice(0,18))+"…":"Not supplied"}</dd></div><div><dt>Multiplicity</dt><dd>${v.multiplicity}</dd></div></dl>${geometry(baseline?.geometries,v.geometries)}${r.reasons.length?`<div class="note">${r.reasons.map(esc).join("<br>")}</div>`:""}<h3>Identity fingerprint</h3><pre>${esc(r.fingerprint)}</pre>${r.waiver_ids.map(w=>`<button class="button" data-waiver="${esc(w)}">Open linked waiver →</button>`).join("")}${r.candidates.map(c=>`<div class="candidate"><strong>Possible previous waiver · ${Math.round(c.score*100)} similarity score</strong><p>${c.reasons.map(esc).join(" · ")}</p><p>This score is not a probability or authorization.</p><div class="drawer-actions"><button class="button small" data-waiver="${esc(c.waiver_id)}">Inspect waiver</button><button class="button small" data-rebind="${esc(c.waiver_id)}" data-target="${esc(id)}" ${disabled()}>Rebind for review</button></div></div>`).join("")}${!r.waiver_ids.length?`<div class="drawer-actions"><button class="button primary" data-propose="${esc(id)}" ${disabled()}>Propose a new waiver</button></div>`:""}`);
}
async function showWaiver(id){
  const w=await api(`/api/waivers/${id}`);if(!w)throw new Error("Waiver not found");state.drawer={kind:"waiver",id};
  const owner=state.actor.role==="admin"||state.actor.name===w.owner, reviewer=w.reviewers.includes(state.actor.name)&&["reviewer","admin"].includes(state.actor.role);
  openDrawer(`${drawerHead("WAIVER RECORD · VERSION "+w.version,w.status)}<h2>${esc(w.target.rule)}</h2><p class="location">${esc(w.target.hierarchy||w.target.path)}</p><h3>Engineering rationale</h3><p>${esc(w.rationale)}</p><dl class="detail-grid"><div><dt>Owner</dt><dd>${esc(w.owner)}</dd></div><div><dt>Independent reviewers</dt><dd>${w.reviewers.map(esc).join(", ")}</dd></div><div><dt>Expiration (inclusive UTC)</dt><dd>${esc(datefmt(w.expires_on))}</dd></div><div><dt>Revision bound</dt><dd>${esc(w.valid_revision||"Context-checked across revisions")}</dd></div><div><dt>Baseline revision</dt><dd>${esc(w.baseline_revision)}</dd></div><div><dt>Record ID</dt><dd>${esc(w.id)}</dd></div></dl><div class="drawer-actions">${owner&&["proposed","rejected"].includes(w.status)?`<button class="button primary" data-action="submit" ${disabled()}>Submit for review</button><button class="button" data-action="attach" ${disabled()}>Attach evidence</button>`:""}${reviewer&&w.status==="submitted"?`<button class="button primary" data-action="approve" ${disabled()}>Approve</button><button class="button danger" data-action="reject" ${disabled()}>Reject</button>`:""}${owner&&w.status!=="revoked"?`<button class="button" data-action="amend" ${disabled()}>Amend rationale</button>`:""}${(owner||reviewer)&&w.status!=="revoked"?`<button class="button danger" data-action="revoke" ${disabled()}>Revoke</button>`:""}</div><h3>Evidence · ${w.evidence.length} attachment${w.evidence.length===1?"":"s"}</h3>${w.evidence.map(e=>`<div class="evidence-row"><div>${esc(e.filename)}<br><small>SHA-256 ${esc(e.sha256.slice(0,19))}…</small></div><button class="button small" data-evidence="${esc(e.sha256)}" data-filename="${esc(e.filename)}" ${disabled()}>Save</button></div>`).join("")||'<p>No evidence attached. Policy may block submission.</p>'}<h3>Review decisions</h3>${w.approvals.map(a=>`<div class="approval-row"><strong>${esc(a.actor)} · ${esc(a.decision)}</strong><p>${esc(a.comment)}</p><small class="muted">${esc(new Date(a.at).toLocaleString())}</small></div>`).join("")||'<p>No decisions on this version of the content.</p>'}<h3>Version history</h3><div id="record-history" class="muted">Loading audit history…</div>`);
  $("#drawer").querySelectorAll("[data-action]").forEach(b=>b.addEventListener("click",()=>guard(()=>waiverAction(w,b.dataset.action))));
  const events=await api(`/api/waivers/${id}/history`);if(state.drawer?.id===id)$("#record-history").innerHTML=events.slice().reverse().map(e=>`<div class="evidence-row"><span>${esc(e.action)}</span><span>${esc(e.actor)} · #${e.seq}</span></div>`).join("");
}
function modal(title,body,onsubmit){
  $("#modal").innerHTML=`<div class="modal-header"><h2>${esc(title)}</h2><button class="icon-button" data-close-modal aria-label="Close dialog">×</button></div><form id="modal-form">${body}<div id="modal-error" class="error"></div><button type="submit" class="button primary wide">Continue →</button></form>`;
  $("#modal").showModal();$("#modal-form").addEventListener("submit",async e=>{e.preventDefault();const button=e.target.querySelector("button[type=submit]");button.disabled=true;try{await onsubmit(new FormData(e.target));$("#modal").close();}catch(err){$("#modal-error").textContent=err.message;}finally{button.disabled=false;}});
}
async function waiverAction(w,action){
  const done=async(p,b)=>{await post(p,b);await refresh();await showWaiver(w.id);toast("Waiver updated. Assessment recalculated.");};
  if(action==="submit")return done(`/api/waivers/${w.id}/submit`,{version:w.version});
  if(action==="attach")return modal("Attach engineering evidence",'<p>TXT, JSON, PDF, PNG or JPEG. Maximum 5 MiB. Evidence remains private to this workspace.</p><label>Evidence file<input type="file" name="file" required accept=".txt,.json,.pdf,.png,.jpg,.jpeg"></label>',async form=>{const file=form.get("file");if(file.size>5*1024*1024)throw new Error("Attachment exceeds 5 MiB");const content=await new Promise((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>resolve(reader.result.split(",")[1]);reader.onerror=reject;reader.readAsDataURL(file);});await done(`/api/waivers/${w.id}/evidence`,{version:w.version,filename:file.name,content_base64:content});});
  if(action==="amend")return modal("Amend waiver rationale",`<p>Changing approved content resets all approvals and returns the record to proposed.</p><label>Rationale<textarea name="rationale" required minlength="12">${esc(w.rationale)}</textarea></label>`,f=>done(`/api/waivers/${w.id}/amend`,{version:w.version,changes:{rationale:f.get("rationale")}}));
  modal(action==="revoke"?"Revoke this waiver":`${label(action)} waiver`,'<p>Your authenticated identity is recorded with this decision. Revocation is terminal.</p><label>Engineering decision / reason<textarea name="comment" required minlength="3"></textarea></label>',f=>done(`/api/waivers/${w.id}/${action==="revoke"?"revoke":"review"}`,{version:w.version,comment:f.get("comment"),...(action==="revoke"?{}:{decision:action})}));
}
function propose(id){
  const expiry=new Date(Date.now()+30*86400000).toISOString().slice(0,10);
  modal("Propose an exception",`<p>This targets one exact finding. Evidence and independent review are required before it can become effective.</p><label>Engineering rationale<textarea name="rationale" required minlength="12" placeholder="Why is this violation acceptable, under which conditions?"></textarea></label><div class="form-row"><label>Owner<input name="owner" value="${esc(state.actor.name)}" required></label><label>Reviewers (comma-separated)<input name="reviewers" required placeholder="reviewer, signoff"></label></div><div class="form-row"><label>Expiration date<input type="date" name="expires" value="${expiry}"></label><label>Exact revision bound (optional)<input name="revision" placeholder="${esc(state.run.revision)}"></label></div>`,async f=>{const w=await post("/api/waivers",{run_id:state.run.id,violation_id:id,rationale:f.get("rationale"),owner:f.get("owner"),reviewers:f.get("reviewers").split(",").map(s=>s.trim()).filter(Boolean),expires_on:f.get("expires")||null,valid_revision:f.get("revision")||null});await refresh();await showWaiver(w.id);toast("Proposal created. Attach evidence before submitting.");});
}
function importDialog(){modal("Import a verification run",'<p>Import a documented, unfiltered report. Only declare complete when the entire selected check domain ran successfully.</p><div class="form-row"><label>Format<select name="format"><option>json</option><option>csv</option><option>xml</option><option>text</option><option>sarif</option><option>klayout</option><option>verilator</option></select></label><label>Report file<input type="file" name="file" required></label></div><div class="form-row"><label>Project<input name="project" required></label><label>Check stream<input name="stream" required placeholder="nightly-lint"></label></div><div class="form-row"><label>Tool namespace<input name="tool" required placeholder="verilator"></label><label>Design revision<input name="revision" required></label></div><label>Tool version<input name="tool_version"></label><label>Rule-deck digest<input name="rule_deck_digest"></label><label>Configuration digest<input name="configuration_digest"></label><label>Checked categories (comma-separated)<input name="checked" placeholder="lint or drc,lvs,erc"></label><label><input type="checkbox" name="complete"> I declare this run complete and unfiltered for the listed categories.</label>',async f=>{const file=f.get("file");if(file.size>32*1024*1024)throw new Error("Report exceeds 32 MiB");const r=await post("/api/runs",{content:await file.text(),format:f.get("format"),scope:{project:f.get("project"),stream:f.get("stream"),tool:f.get("tool")},revision:f.get("revision"),tool_version:f.get("tool_version"),rule_deck_digest:f.get("rule_deck_digest"),configuration_digest:f.get("configuration_digest"),complete:f.get("complete")==="on",checked_categories:f.get("checked").split(",").map(s=>s.trim()).filter(Boolean)});state.run={id:r.id};await refresh();toast("Run imported and assessed.");});}
async function renderCompare(){
  const options=state.snapshots.map(s=>`<option value="${esc(s.id)}">${esc(s.name)}</option>`).join("");
  $("#compare-view").innerHTML=`<div class="panel"><div class="panel-head"><div><h2>Frozen tapeout candidates</h2><p>Immutable assessments retain the waiver set and policy used at capture.</p></div><button class="button small" id="freeze-open" ${disabled()}>＋ Freeze current run</button></div><div class="split-controls"><label>Baseline snapshot<select id="compare-before">${options}</select></label><span>→</span><label>Candidate snapshot<select id="compare-after">${options}</select></label><button id="compare-go" class="button primary">Compare</button></div><div id="compare-result" class="panel-content"></div></div><div class="panel panel-spaced"><div class="panel-head"><h2>Snapshot register</h2></div><div class="table-wrap"><table><thead><tr><th>Snapshot</th><th>Revision</th><th>Gate at freeze</th><th>Captured</th><th></th></tr></thead><tbody>${state.snapshots.map(s=>`<tr><td>${esc(s.name)}</td><td class="location">${esc(s.revision)}</td><td>${pill(s.gate_pass?"approved":"open")}</td><td>${esc(datefmt(s.created_at))}</td><td><button class="button small" data-bundle="${esc(s.id)}" ${disabled()}>Evidence bundle ↗</button></td></tr>`).join("")}</tbody></table></div></div>`;
  $("#freeze-open").onclick=()=>modal("Freeze current assessment",'<p>The immutable snapshot captures the run, waiver records, policy and decision results together.</p><label>Candidate name<input name="name" required></label><label><input type="checkbox" name="clean"> Require a passing gate</label>',async f=>{await post("/api/snapshots",{run_id:state.run.id,name:f.get("name"),require_clean:f.get("clean")==="on"});await refresh();toast("Snapshot frozen.");});
  $("#compare-go").onclick=()=>guard(compareNow);
  if(state.snapshots.length>1){$("#compare-before").value=state.snapshots[1].id;$("#compare-after").value=state.snapshots[0].id;await compareNow();}else $("#compare-result").textContent="Freeze at least two candidates to compare their waiver sets.";
}
async function compareNow(){
  const before=$("#compare-before").value,after=$("#compare-after").value;if(!before||!after)return;
  const d=await api(`/api/compare/${before}/${after}`);if(!d)throw new Error("Comparison is unavailable in this preview.");
  $("#compare-result").innerHTML=`<div class="compare-cards"><div class="compare-card"><strong>+${d.occurrences_added} / −${d.occurrences_removed}</strong><span>Exact finding identities added / removed</span></div><div class="compare-card"><strong>+${d.waivers_added.length} / −${d.waivers_removed.length}</strong><span>Waiver records added / removed</span></div><div class="compare-card"><strong>${d.waivers_changed.length}</strong><span>Waiver records with content changes</span></div></div><div class="note">Exact finding differences can include moved or reshaped markers. The explorer shows correspondence suggestions; they do not retain approval.</div><h3>Effective-state count changes</h3><pre>${esc(JSON.stringify(d.gate_count_delta,null,2))}</pre><p>Gate: <strong>${d.before_gate?"PASS":"BLOCKED"}</strong> → <strong>${d.after_gate?"PASS":"BLOCKED"}</strong></p>`;
}
async function renderAudit(){
  const a=await api("/api/audit");$("#audit-view").innerHTML=`<div class="panel"><div class="audit-banner"><span class="hash-icon">✓</span><div><strong>Content and hash chain verified · ${a.events.length} recent events shown</strong><code>HEAD ${esc(a.head)}</code></div></div><div class="panel-content"><p>Save this head outside the database to detect history replacement. Hash chaining alone is not administrator-proof storage.</p></div><div class="table-wrap"><table><thead><tr><th>Sequence</th><th>Action</th><th>Actor</th><th>Entity</th><th>Time</th></tr></thead><tbody>${a.events.map(e=>`<tr><td class="location">#${e.seq}</td><td>${esc(e.action)}</td><td>${esc(e.actor)}</td><td class="location">${esc(e.entity)}<div class="muted">${esc(e.id.slice(0,24))}</div></td><td>${esc(new Date(e.at).toLocaleString())}</td></tr>`).join("")}</tbody></table></div></div>`;
}
async function renderPolicy(){
  const policy=await api("/api/policy");const can=state.actor.role==="admin"&&!preview;
  $("#policy-view").innerHTML=`<div class="panel"><div class="panel-head"><div><h2>Risk and review controls</h2><p>Changing policy can invalidate previously effective approvals.</p></div><button id="save-policy" class="button primary" ${can?"":"disabled"}>Save policy</button></div><div class="panel-content"><textarea id="policy-json" class="policy-textarea" ${can?"":"readonly"} aria-label="Workspace policy JSON"></textarea></div><p class="policy-note">Only workspace administrators can change this policy. Dates are inclusive in UTC; revision bounds are exact matches, not commit-order comparisons.</p></div>`;
  $("#policy-json").value=JSON.stringify(policy,null,2);$("#save-policy").onclick=()=>guard(async()=>{const data=JSON.parse($("#policy-json").value);await api("/api/policy",{method:"PUT",body:JSON.stringify(data)});await refresh();toast("Policy saved. All assessments recalculated.");});
}
document.addEventListener("click",e=>{
  const button=e.target.closest("button");if(!button||button.disabled)return;
  if(button.dataset.view)navigate(button.dataset.view);
  if(button.dataset.navigate)navigate(button.dataset.navigate);
  if(button.hasAttribute("data-close-drawer"))closeDrawer();
  if(button.hasAttribute("data-close-modal"))$("#modal").close();
  if(button.dataset.finding)guard(()=>showFinding(button.dataset.finding));
  if(button.dataset.waiver)guard(()=>showWaiver(button.dataset.waiver));
  if(button.dataset.propose)propose(button.dataset.propose);
  if(button.dataset.evidence)guard(()=>download(`/api/evidence/${button.dataset.evidence}`,button.dataset.filename));
  if(button.dataset.bundle)guard(()=>download(`/api/snapshots/${button.dataset.bundle}/bundle`,"openwaiver-evidence.zip"));
  if(button.dataset.rebind)guard(async()=>{const w=await api(`/api/waivers/${button.dataset.rebind}`);modal("Rebind changed target",'<p>Rebinding clears every approval and returns the waiver to proposed. Existing evidence is retained for fresh independent review.</p>',async()=>{await post(`/api/waivers/${w.id}/rebind`,{version:w.version,run_id:state.run.id,violation_id:button.dataset.target});await refresh();await showWaiver(w.id);toast("Target rebound; fresh approval is required.");});});
});
$("#drawer-shade").onclick=closeDrawer;document.addEventListener("keydown",e=>{if(e.key==="Escape")closeDrawer();});
$("#import-open").onclick=importDialog;$("#refresh").onclick=()=>guard(refresh);
$("#run-select").onchange=()=>guard(async()=>{state.run=state.runs.find(r=>r.id===$("#run-select").value);closeDrawer();await loadRun();navigate(state.view);});
$("#export").onclick=()=>guard(()=>download(`/api/runs/${state.run.id}/export/${$("#export-format").value}`,`openwaiver-assessment.${$("#export-format").value}`));
$("#search").oninput=()=>{clearTimeout(searchTimer);searchTimer=setTimeout(()=>{state.offset=0;guard(loadFindings);},200);};
for(const id of ["status-filter","category-filter"])$("#"+id).onchange=()=>{state.offset=0;guard(loadFindings);};
$("#prev-page").onclick=()=>{state.offset=Math.max(0,state.offset-100);guard(loadFindings);};$("#next-page").onclick=()=>{state.offset+=100;guard(loadFindings);};
$("#login-form").onsubmit=async e=>{e.preventDefault();state.token=$("#login-token").value.trim();try{await boot();$("#login-dialog").close();$("#login-token").value="";}catch(err){state.token="";$("#login-error").textContent=err.message;}};
$("#logout").onclick=()=>{state.token="";state.actor=null;location.reload();};
$("#login-dialog").addEventListener("cancel",e=>e.preventDefault());
if(preview)guard(boot);else $("#login-dialog").showModal();
