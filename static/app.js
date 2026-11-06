"use strict";
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
const token=$('meta[name="lab-token"]').content;
const titles={overview:["Investigation","From packets to perspective.","A practical workspace for network evidence, DNS behavior and analyst decisions."],dns:["DNS monitor","Understand the names behind the traffic.","Explore visible DNS activity, client behavior and resolver review signals."],triage:["Alert triage","Follow the evidence.","Inspect the signal, validate the context and record your analyst decision."],automation:["Automation","From findings to a clear brief.","Local summaries first. Optional OpenAI explanations and n8n email delivery."],method:["Method & rules","Know what your tools are saying.","Transparent thresholds, reproducible inputs and honest limitations."]};
let current=null, selected=null, config={};
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const fmt=n=>Number(n).toLocaleString("en-US");
function notify(message,error=false){$("#notice").textContent=message;$("#notice").className=error?"error":"";}
async function request(path,body,headers={}){
 const response=await fetch(path,{method:body===undefined?"GET":"POST",headers:body===undefined?{}:{"X-Lab-Token":token,"Content-Type":"application/json",...headers},body:body===undefined?undefined:body});
 if(!response.ok){let message="Request failed.";try{message=(await response.json()).error||message;}catch{}throw new Error(message);}
 return response;
}
async function action(path,data){return (await request(path,JSON.stringify(data))).json();}
function page(name){
 $$(".page").forEach(x=>x.classList.toggle("active",x.id===name));
 $$(".nav").forEach(x=>x.classList.toggle("active",x.dataset.page===name));
 $("#crumb").textContent=titles[name][0];$("#page-title").textContent=titles[name][1];$("#page-description").textContent=titles[name][2];
}
function severity(a){return '<span class="severity '+a.severity.toLowerCase()+'">'+esc(a.severity)+'</span>';}
function setCase(c){
 current=c;selected=c.alerts.some(a=>a.id===selected)?selected:c.alerts[0]?.id;
 $("#case-label").textContent=c.synthetic?"Training scenario · DNS & port discovery":c.source;
 $("#case-id").textContent=c.id;$("#data-badge").textContent=c.synthetic?"SYNTHETIC DATA":"PRIVATE UPLOAD";
 const m=c.metrics;
 $("#m-events").textContent=fmt(m.events);$("#m-hosts").textContent=fmt(m.hosts);$("#m-alerts").textContent=m.alerts;$("#m-dns").textContent=fmt(m.dns_queries);
 $("#m-duration").textContent=m.duration+" second evidence window";$("#m-high").textContent=m.high+" high-priority · analyst review";
 $(".mini-bars").innerHTML=c.timeline.slice(0,13).map(n=>'<i style="height:'+Math.max(5,n/Math.max(...c.timeline)*34)+'px"></i>').join("");
 const max=Math.max(...c.timeline,1);
 $("#timeline").innerHTML=c.timeline.map((n,i)=>'<div class="bar '+(n>max*.75?"peak":"")+'" style="height:'+Math.max(2,n/max*95)+'%" title="Bucket '+(i+1)+': '+n+' events"></div>').join("");
 $("#protocols").innerHTML=c.protocols.slice(0,6).map(p=>'<span class="protocol-chip"><i></i>'+esc(p.name)+'<b>'+fmt(p.count)+'</b></span>').join("");
 $("#signal-count").textContent=c.alerts.length;
 $("#signal-table").innerHTML=c.alerts.length?'<table class="table"><thead><tr><th>SIGNAL / RULE</th><th>SEVERITY</th><th>SUBJECT</th><th>STATUS</th><th></th></tr></thead><tbody>'+c.alerts.map(a=>'<tr tabindex="0" data-alert="'+a.id+'"><td><strong>'+esc(a.name)+'</strong><small>'+a.rule+' · '+esc(a.observed)+'</small></td><td>'+severity(a)+'</td><td class="code">'+esc(a.subject)+'</td><td><span class="state">'+a.status+'</span></td><td class="row-arrow">↗</td></tr>').join("")+'</tbody></table>':'<div class="empty">No rule thresholds were met. This does not establish that the evidence is benign.</div>';
 $$("[data-alert]").forEach(row=>{const open=()=>{selected=row.dataset.alert;page("triage");renderQueue();};row.onclick=open;row.onkeydown=e=>{if(e.key==="Enter")open();};});
 $("#d-queries").textContent=fmt(m.dns_queries);$("#d-blocked").textContent=fmt(m.blocked);
 $("#d-domains").textContent=fmt(c.unique_domains??c.domains.length);$("#d-alerts").textContent=c.alerts.filter(a=>a.rule.startsWith("DNS")).length;
 rank("#domains",c.domains);rank("#clients",c.clients);
 $("#limitations").innerHTML=c.limitations.map(x=>"<li>"+esc(x)+"</li>").join("");
 const rules=new Map(c.alerts.map(a=>[a.rule,a]));
 // All four rules stay visible even if the current file triggers none.
 const defaults=[
 {rule:"TCP-SCAN",name:"TCP port sweep",severity:"High",threshold:"12 distinct destination ports on one target within 60 seconds",explanation:"SYN attempts are a discovery signal. Authorized scanners can trigger this rule."},
 {rule:"DNS-BURST",name:"DNS query burst",severity:"Medium",threshold:"40 DNS queries from one client within 60 seconds",explanation:"Retries and busy legitimate applications can produce bursts."},
 {rule:"DNS-NXDOMAIN",name:"High NXDOMAIN response ratio",severity:"Medium",threshold:"At least 20 DNS responses with 65% or more NXDOMAIN",explanation:"Responses are grouped by destination client. Failed names can be configuration errors."},
 {rule:"DNS-LONG",name:"Repeated long DNS labels",severity:"Medium",threshold:"At least 8 queried names with a label of 45 or more characters",explanation:"Long labels are not proof of tunneling. Legitimate services also use them."}];
 $("#rules").innerHTML=defaults.map(x=>{const r=rules.get(x.rule)||x;return '<article class="panel rule-card"><code>'+r.rule+'</code> '+severity(r)+'<h2>'+esc(r.name)+'</h2><p><b>'+esc(r.threshold)+'</b></p><p>'+esc(r.explanation)+'</p></article>';}).join("");
 $("#brief-output").textContent="Your brief will appear here.";renderQueue();
}
function rank(target,items){
 const max=Math.max(...items.map(x=>x.count),1);
 $(target).innerHTML=items.length?items.map(x=>'<div class="rank-row"><div class="rank-title"><span>'+esc(x.name)+'</span><span>'+fmt(x.count)+'</span></div><div class="rank-track"><div style="width:'+x.count/max*100+'%"></div></div></div>').join(""):'<div class="empty">No visible DNS names in this evidence.</div>';
}
function renderQueue(){
 if(!current)return;
 const search=$("#search").value.toLowerCase(),sev=$("#severity").value,status=$("#status-filter").value;
 const alerts=current.alerts.filter(a=>(sev==="All severities"||a.severity===sev)&&(status==="All statuses"||a.status===status)&&(a.name+" "+a.subject+" "+a.rule).toLowerCase().includes(search));
 $("#queue").innerHTML='<h2>Review queue <span class="count">'+alerts.length+'</span></h2>'+alerts.map(a=>'<button class="queue-item '+(selected===a.id?"selected":"")+'" data-id="'+a.id+'">'+severity(a)+'<strong>'+esc(a.name)+'</strong><small>'+a.id+' · '+esc(a.subject)+' · '+a.status+'</small></button>').join("")+(!alerts.length?'<div class="empty">No signals match these filters.</div>':'');
 $$(".queue-item").forEach(x=>x.onclick=()=>{selected=x.dataset.id;renderQueue();});
 const a=alerts.find(x=>x.id===selected);
 if(!a){$("#detail").innerHTML='<div class="empty">Select a visible signal to inspect its evidence.</div>';return;}
 $("#detail").innerHTML='<span class="panel-kicker">'+a.id+' / '+a.rule+'</span><h2>'+esc(a.name)+'</h2>'+severity(a)+'<p>'+esc(a.observed)+' · Subject: <b>'+esc(a.subject)+'</b></p><p>'+esc(a.explanation)+'</p><h3>Rule threshold</h3><p>'+esc(a.threshold)+'</p><h3>Evidence preview <span class="count">'+a.evidence.length+' of '+a.evidence_total+'</span></h3><div class="evidence"><ul>'+a.evidence.map(v=>'<li><small>#'+v.frame+' · '+esc(new Date(v.time*1000).toISOString().slice(11,23))+'</small><br>'+esc(v.detail)+'</li>').join("")+'</ul></div><h3>Recommended checks</h3><ol>'+a.next_steps.map(v=>'<li>'+esc(v)+'</li>').join("")+'</ol><label>Analyst decision <select id="decision">'+["New","Investigating","Benign","Escalated"].map(s=>'<option '+(s===a.status?"selected":"")+'>'+s+'</option>').join("")+'</select></label><p class="muted">Decisions are kept in this running session. Export the report to retain them.</p>';
 $("#decision").onchange=async e=>{try{const c=await action("/api/triage",{case_id:current.id,alert_id:a.id,status:e.target.value});setCase(c);notify("Analyst decision recorded. Export a report to keep a copy.");}catch(err){notify(err.message,true);}};
}
async function demo(){try{notify("Loading synthetic evidence…");setCase(await (await request("/api/demo")).json());notify("");}catch(e){notify(e.message,true);}}
async function download(format){
 if(!current)return;
 try{const response=await request("/api/report",JSON.stringify({case_id:current.id,format}));const blob=await response.blob();const url=URL.createObjectURL(blob);const a=document.createElement("a");a.href=url;a.download=current.id+"."+format;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);notify("Report downloaded. Uploaded-data reports may contain private network details.");}catch(e){notify(e.message,true);}
}
function confirmAction(title,text){
 return new Promise(resolve=>{
 const d=$("#confirm-dialog");$("#confirm-title").textContent=title;$("#confirm-text").textContent=text;
 const done=result=>{d.close();resolve(result);};
 $("#confirm-go").onclick=()=>done(true);$("#confirm-cancel").onclick=()=>done(false);
 d.oncancel=e=>{e.preventDefault();done(false);};d.showModal();
 });
}
async function brief(live){
 if(!current)return;
 if(live&&!await confirmAction("Send aggregate findings to OpenAI?","Only event counts, rule IDs, severity and observed totals will be sent. Addresses, domains, filenames and raw packets are excluded. This may use API credits."))return;
 try{$("#brief-output").textContent="Preparing brief…";const result=await action("/api/brief",{case_id:current.id,live,confirm:live});$("#brief-output").textContent=result.text;notify(live?"AI-assisted interpretation generated. Validate it against the evidence.":"Offline brief ready. Nothing was sent externally.");}catch(e){$("#brief-output").textContent="Brief unavailable.";notify(e.message,true);}
}
$$(".nav").forEach(x=>x.onclick=()=>page(x.dataset.page));$("#reset").onclick=demo;$("#see-triage").onclick=()=>page("triage");
$("#search").oninput=renderQueue;$("#severity").onchange=renderQueue;$("#status-filter").onchange=renderQueue;
$("#export").onclick=()=>download("html");$("#export-json").onclick=()=>download("json");$("#email-draft").onclick=()=>download("eml");
$("#brief-local").onclick=()=>brief(false);$("#brief-ai").onclick=()=>brief(true);
$("#file").onchange=async e=>{
 const file=e.target.files[0];if(!file)return;
 if(file.size>20*1024*1024){notify("Please choose a file smaller than 20 MB.",true);return;}
 try{document.body.classList.add("busy");notify("Analyzing evidence locally…");
 const c=await (await request("/api/analyze",file,{"Content-Type":"application/octet-stream","X-Filename":encodeURIComponent(file.name)})).json();
 setCase(c);page("overview");notify("Analysis complete. The uploaded file was not retained; reports remain private until you choose to share them.");
 }catch(err){notify(err.message,true);}finally{document.body.classList.remove("busy");e.target.value="";}
};
$("#choose-evidence").onclick=()=>$("#file").click();
const zone=$(".import");zone.ondragover=e=>e.preventDefault();zone.ondrop=e=>{e.preventDefault();if(e.dataTransfer.files.length){$("#file").files=e.dataTransfer.files;$("#file").dispatchEvent(new Event("change"));}};
$("#send-webhook").onclick=async()=>{
 if(!current)return;if(!await confirmAction("Deliver to your n8n workflow?","This sends aggregate findings to the configured webhook. If you activated the connected OpenAI/email workflow, it may generate an AI brief and send an email to your configured recipient."))return;
 try{const r=await action("/api/webhook",{case_id:current.id,confirm:true});notify(r.message);}catch(e){notify(e.message,true);}
};
async function init(){
 try{config=await(await request("/api/status")).json();$("#ai-state").textContent=config.ai?"OpenAI configured · external request requires confirmation":"OpenAI not configured · offline brief available";$("#webhook-state").textContent=config.webhook?"n8n webhook configured · manual delivery only":"n8n not configured · workflow available for import";$("#brief-ai").disabled=!config.ai;$("#send-webhook").disabled=!config.webhook;
 }catch(e){notify(e.message,true);}await demo();
}
init();

