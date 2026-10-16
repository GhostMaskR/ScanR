$ErrorActionPreference = "Stop"
if (!(Test-Path ".\app.py") -or !(Test-Path ".\templates\index.html") -or !(Test-Path ".\static\css\style.css") -or !(Test-Path ".\static\js\app.js")) {
  throw "PowerShell ko B:\mine project\ScanR folder mein open karke script run karo."
}
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backup = ".\backups\ui_api_fix_$stamp"
New-Item -ItemType Directory -Force -Path $backup | Out-Null
Copy-Item ".\templates\index.html" "$backup\index.html" -Force
Copy-Item ".\static\css\style.css" "$backup\style.css" -Force
Copy-Item ".\static\js\app.js" "$backup\app.js" -Force
Write-Host "Backup: $backup" -ForegroundColor Green

# Add a working theme selector (5 palettes) to the existing interface.
$themeCss = @'
/* ScanR animated theme system: five distinct palettes */
:root[data-palette="midnight"]{--bg:#171923;--side:#171923;--panel:#202330;--panel2:#292d3c;--border:#3a3f50;--text:#e9eaf2;--muted:#a5a9b8;--blue:#7895ff;--cyan:#72d9e8;--green:#65deb1}
:root[data-palette="ocean"]{--bg:#071b28;--side:#082331;--panel:#0e2b3b;--panel2:#12384a;--border:#205267;--text:#e5f7ff;--muted:#9bbdcb;--blue:#38bdf8;--cyan:#5eead4;--green:#5eead4}
:root[data-palette="violet"]{--bg:#171126;--side:#1d1532;--panel:#261b3d;--panel2:#33254e;--border:#4b376a;--text:#f5edff;--muted:#c0b0d6;--blue:#a78bfa;--cyan:#e0aaff;--green:#86efac}
:root[data-palette="light"]{color-scheme:light;--bg:#f4f6fb;--side:#fff;--panel:#fff;--panel2:#edf0f7;--border:#dfe3ed;--text:#202435;--muted:#687087;--blue:#536fce;--cyan:#087f8c;--green:#15803d}
:root[data-palette="graphite"]{--bg:#101214;--side:#151719;--panel:#1b1f22;--panel2:#252a2e;--border:#343b40;--text:#f0f3f5;--muted:#a4adb4;--blue:#9ca3af;--cyan:#d1d5db;--green:#86efac}
body{transition:background-color .28s,color .28s}
.panel,.stat,.sidebar,.vt-topbar,.vt-search-strip,.hero,.nav,.primary,.secondary{transition:background-color .25s,border-color .25s,color .25s,transform .2s}
.stat:hover,.panel:hover{box-shadow:0 8px 26px #00000010}
@keyframes scanrGlow{0%,100%{box-shadow:0 0 0 #7895ff00}50%{box-shadow:0 0 20px #7895ff22}}
.vt-mark{animation:scanrGlow 4s ease-in-out infinite}
'@
Add-Content ".\static\css\style.css" "`r`n$themeCss" -Encoding UTF8

# Fully replace frontend JS with a clean implementation wired to the existing Flask API.
$js = @'
"use strict";
(() => {
  const $ = (s, root=document) => root.querySelector(s);
  const $$ = (s, root=document) => [...root.querySelectorAll(s)];
  const state = { page:"overview", tab:"url", history:[], lastResult:null, lastFileHash:null, api:false, vt:false, palette:"midnight" };
  const esc = value => String(value ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const risk = r => String(r?.risk_level || r?.status || "unknown").toLowerCase().replace(/[\s/-]+/g,"_");
  const riskLabel = r => {
    const v = risk(r);
    if (v.includes("malicious")) return "MALICIOUS";
    if (v.includes("suspicious")) return "SUSPICIOUS";
    if (v.includes("no_detection") || v === "safe") return "NO DETECTIONS";
    if (v.includes("pending") || v.includes("submitted")) return "PENDING";
    return "UNKNOWN";
  };
  const badge = r => `<span class="badge ${esc(risk(r))}">${esc(riskLabel(r))}</span>`;
  const toast = (title, message, type="") => {
    const host=$("#toasts"); if(!host) return;
    const node=document.createElement("div"); node.className=`toast ${type}`;
    node.innerHTML=`<b>${esc(title)}</b><span>${esc(message)}</span>`; host.appendChild(node);
    setTimeout(()=>node.remove(),5200);
  };
  async function api(path, options={}) {
    const response=await fetch(path,{...options,headers:{...(options.body && !(options.body instanceof FormData)?{"Content-Type":"application/json"}:{}),...(options.headers||{})}});
    const raw=await response.text(); let data;
    try { data=raw ? JSON.parse(raw) : {}; } catch { throw new Error(`Backend returned non-JSON response (HTTP ${response.status}). Check Flask terminal.`); }
    if(!response.ok || data.success===false) throw new Error(data.error || data.message || `Request failed (HTTP ${response.status})`);
    return data;
  }
  function setConnection(ok, message) {
    state.api=ok;
    const dot=$("#connectionDot"), apiDot=$("#apiDot");
    if(dot) dot.className="dot "+(ok?"online":"offline");
    if(apiDot) apiDot.className="dot "+(ok?"online":"offline");
    if($("#connectionText")) $("#connectionText").textContent=message || (ok?"Connected":"Offline");
    if($("#apiLabel")) $("#apiLabel").textContent=ok?"API Connected":"API unavailable";
    if($("#settingApi")) $("#settingApi").textContent=ok?"CONNECTED":"OFFLINE";
  }
  function showPage(name) {
    if(!$("#page-"+name)) name="overview";
    state.page=name;
    $$(".page").forEach(p=>p.classList.toggle("active",p.id==="page-"+name));
    $$(".nav[data-page]").forEach(b=>b.classList.toggle("active",b.dataset.page===name));
    $$(".topnav[data-page]").forEach(b=>b.classList.toggle("active",b.dataset.page===name));
    try { history.replaceState(null,"","#"+name); } catch {}
    if(name==="history") renderHistory();
    if(name==="overview") refreshDashboard();
  }
  function setTab(name) {
    state.tab=name;
    $$(".tab").forEach(b=>b.classList.toggle("active",b.dataset.tab===name));
    ["url","file","hash"].forEach(n=>$("#"+n+"Form")?.classList.toggle("hidden",n!==name));
    $("#result")?.classList.add("hidden");
  }
  async function refreshStatus() {
    try {
      const d=await api("/api/status");
      setConnection(true,"Connected");
      state.vt=!!d.virustotal_key_configured;
      if($("#settingVt")) $("#settingVt").textContent=state.vt?"KEY CONFIGURED":"KEY MISSING";
      if($("#heroTitle")) $("#heroTitle").textContent="Your scanner is ready";
      if($("#heroText")) $("#heroText").textContent=state.vt?"Scan URLs and hashes using available VirusTotal reputation data.":"Backend connected, but VirusTotal API key is not configured.";
      return d;
    } catch(e) {
      setConnection(false,"Offline");
      if($("#settingVt")) $("#settingVt").textContent="UNAVAILABLE";
      if($("#heroTitle")) $("#heroTitle").textContent="Backend connection unavailable";
      if($("#heroText")) $("#heroText").textContent="Start Flask in the project terminal, then refresh this page.";
      return null;
    }
  }
  function rowsFor(items, recent=false) {
    if(!items.length) return `<tr><td colspan="${recent?4:6}">No saved scans yet. Analyze a URL or hash to begin.</td></tr>`;
    return items.map(r=>{
      const target=String(r.target||r.url||r.sha256||"—");
      const typ=String(r.scan_type||r.type||"—").toUpperCase();
      const when=r.created_at||r.timestamp||r.scanned_at||"—";
      const st=String(r.status||"unknown").replace(/_/g," ");
      return recent
        ? `<tr><td title="${esc(target)}">${esc(target)}</td><td>${esc(typ)}</td><td>${badge(r)}</td><td>${esc(when)}</td></tr>`
        : `<tr><td>${esc(r.id??r.scan_id??"—")}</td><td title="${esc(target)}">${esc(target)}</td><td>${esc(typ)}</td><td>${esc(st)}</td><td>${badge(r)}</td><td>${esc(when)}</td></tr>`;
    }).join("");
  }
  function normaliseHistory(data) {
    if(Array.isArray(data)) return data;
    return data.items || data.history || data.scans || data.records || [];
  }
  async function loadHistory() {
    const d=await api("/api/history");
    state.history=normaliseHistory(d);
    renderHistory();
    return state.history;
  }
  function renderHistory() {
    const query=($("#search")?.value||"").toLowerCase().trim();
    const filter=$("#filter")?.value||"all";
    const list=state.history.filter(r=>{
      const text=[r.target,r.scan_type,r.status,r.risk_level,r.sha256].join(" ").toLowerCase();
      const v=risk(r);
      const match=filter==="all" || (filter==="malicious"&&v.includes("malicious")) || (filter==="suspicious"&&v.includes("suspicious")) || (filter==="unknown"&&(v.includes("unknown")||v.includes("pending")||v.includes("submitted"))) || (filter==="no_detections"&&(v.includes("no_detection")||v==="safe"));
      return text.includes(query)&&match;
    });
    if($("#history")) $("#history").innerHTML=rowsFor(list);
    if($("#count")) $("#count").textContent=`Showing ${list.length} of ${state.history.length} records`;
  }
  function renderBreakdown(items) {
    const groups=[
      ["Malicious",items.filter(r=>risk(r).includes("malicious")).length,"#ff777f"],
      ["Suspicious",items.filter(r=>risk(r).includes("suspicious")).length,"#f3c36c"],
      ["No detections",items.filter(r=>risk(r).includes("no_detection")||risk(r)==="safe").length,"#65deb1"],
      ["Unknown / pending",items.filter(r=>!["malicious","suspicious","no_detections","safe"].some(x=>risk(r).includes(x))).length,"#b19aff"]
    ];
    const host=$("#breakdown"); if(!host)return;
    const total=Math.max(items.length,1);
    host.innerHTML=groups.map(([name,n,color])=>`<div><div class="bar-head">${esc(name)}<span>${n}</span></div><div class="bar"><i style="width:${Math.min(100,n/total*100)}%;background:${color}"></i></div></div>`).join("");
  }
  async function refreshDashboard() {
    const status=await refreshStatus();
    if(!status)return;
    try {
      const items=await loadHistory();
      const count=(fn)=>items.filter(fn).length;
      if($("#total")) $("#total").textContent=items.length;
      if($("#malicious")) $("#malicious").textContent=count(r=>risk(r).includes("malicious"));
      if($("#suspicious")) $("#suspicious").textContent=count(r=>risk(r).includes("suspicious"));
      if($("#unknown")) $("#unknown").textContent=count(r=>["unknown","pending","submitted","error"].some(x=>risk(r).includes(x)));
      if($("#recent")) $("#recent").innerHTML=rowsFor(items.slice(0,5),true);
      renderBreakdown(items);
    } catch(e) { toast("History could not load",e.message,"error"); }
  }
  function renderResult(data, title="Analysis result") {
    state.lastResult=data;
    const host=$("#result"); if(!host)return;
    const stats=data.stats||data.last_analysis_stats||{};
    const malicious=data.malicious??stats.malicious??0;
    const suspicious=data.suspicious??stats.suspicious??0;
    const harmless=data.harmless??stats.harmless??0;
    const undetected=data.undetected??stats.undetected??0;
    const status=data.status||data.analysis_status||"unknown";
    const message=data.message||data.error||"Reputation information is inconclusive.";
    host.innerHTML=`<h2>${esc(title)} &nbsp; ${badge(data)}</h2><p>${esc(message)}</p><div class="result-grid"><div><small>Malicious</small><b style="color:var(--red)">${esc(malicious)}</b></div><div><small>Suspicious</small><b style="color:var(--amber)">${esc(suspicious)}</b></div><div><small>Harmless</small><b>${esc(harmless)}</b></div><div><small>Undetected</small><b>${esc(undetected)}</b></div></div><div class="details"><b>Status:</b> ${esc(status)}${data.scan_id?` &nbsp; <b>Scan ID:</b> ${esc(data.scan_id)}`:""}${data.sha256?`<br><b>SHA-256:</b> ${esc(data.sha256)}`:""}${data.analysis_id?`<br><b>Analysis ID:</b> ${esc(data.analysis_id)}`:""}${data.permalink?`<br><a href="${esc(data.permalink)}" target="_blank" rel="noopener noreferrer">Open external report</a>`:""}</div><div class="result-actions"><button class="secondary" id="copyResult">Copy result JSON</button><button class="secondary" id="printResult">Print result</button></div><p class="notice">Important: zero detections, a missing report, or a pending analysis is not proof that a target is safe. ScanR does not automatically open scanned URLs.</p>`;
    host.classList.remove("hidden");
    $("#copyResult")?.addEventListener("click",async()=>{try{await navigator.clipboard.writeText(JSON.stringify(data,null,2));toast("Copied","Result JSON copied.","success")}catch{toast("Copy unavailable","Clipboard permission was denied.","error")}});
    $("#printResult")?.addEventListener("click",()=>window.print());
    host.scrollIntoView({behavior:"smooth",block:"nearest"});
  }
  async function submitScan(path, payload, title) {
    $("#loading")?.classList.remove("hidden");
    $("#result")?.classList.add("hidden");
    const buttons=$$("#urlForm button[type=submit],#hashForm button[type=submit],#fileForm button[type=submit]");
    buttons.forEach(b=>b.disabled=true);
    try {
      const data=await api(path,{method:"POST",body:JSON.stringify(payload)});
      renderResult(data,title);
      toast("Analysis finished",data.message||"Result received.","success");
      await refreshDashboard();
    } catch(e) {
      renderResult({success:false,status:"unknown",risk_level:"unknown",message:e.message}, "Analysis could not be completed");
      toast("Scan error",e.message,"error");
    } finally {
      $("#loading")?.classList.add("hidden");
      buttons.forEach(b=>b.disabled=false);
    }
  }
  function downloadJson(filename,data) {
    const blob=new Blob([JSON.stringify(data,null,2)],{type:"application/json"});
    const url=URL.createObjectURL(blob); const a=document.createElement("a");
    a.href=url;a.download=filename;document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(url);
  }
  async function exportHistory() {
    try { if(!state.history.length) await loadHistory(); downloadJson("scanr-history.json",state.history); toast("Export ready","History JSON downloaded.","success"); }
    catch(e){toast("Export failed",e.message,"error")}
  }
  function setupPalette() {
    const names=["midnight","ocean","violet","light","graphite"];
    const labels={midnight:"Midnight",ocean:"Ocean",violet:"Violet",light:"Light",graphite:"Graphite"};
    const current=document.documentElement.dataset.palette;
    state.palette=names.includes(current)?current:(localStorage.getItem("scanr-palette")||"midnight");
    if(!names.includes(state.palette))state.palette="midnight";
    const apply=()=>{document.documentElement.dataset.palette=state.palette;document.documentElement.dataset.theme=state.palette==="light"?"light":"dark";localStorage.setItem("scanr-palette",state.palette);["theme","theme2"].forEach(id=>{const b=$("#"+id);if(b)b.textContent="Theme: "+labels[state.palette]+" ▾"});};
    const choose=()=>{
      const currentIndex=names.indexOf(state.palette);
      const next=names[(currentIndex+1)%names.length];
      const choice=prompt("Choose ScanR theme by number:\n1. Midnight\n2. Ocean\n3. Violet\n4. Light\n5. Graphite\n\nCurrent: "+labels[state.palette],String(names.indexOf(state.palette)+1));
      if(choice===null)return;
      const n=Number(choice);
      if(Number.isInteger(n)&&n>=1&&n<=5){state.palette=names[n-1];apply();toast("Theme changed",labels[state.palette]+" theme enabled.","success")}
      else toast("Theme unchanged","Enter a number from 1 to 5.","error");
    };
    apply();$("#theme")?.addEventListener("click",choose);$("#theme2")?.addEventListener("click",choose);
  }
  function wire() {
    $$(".nav[data-page],.topnav[data-page]").forEach(b=>b.addEventListener("click",()=>showPage(b.dataset.page)));
    $$("[data-goto]").forEach(b=>b.addEventListener("click",()=>showPage(b.dataset.goto)));
    $$("[data-tab]").forEach(b=>b.addEventListener("click",()=>setTab(b.dataset.tab)));
    $("#refresh")?.addEventListener("click",refreshDashboard);
    $("#search")?.addEventListener("input",renderHistory);
    $("#filter")?.addEventListener("change",renderHistory);
    $("#exportHistory")?.addEventListener("click",exportHistory);
    $("#reportHistory")?.addEventListener("click",exportHistory);
    $("#reportJson")?.addEventListener("click",()=>{if(state.lastResult)downloadJson("scanr-result.json",state.lastResult);else toast("No latest result","Run an analysis first.","error")});
    $("#reportPdf")?.addEventListener("click",()=>{showPage("reports");window.print()});
    $("#urlForm")?.addEventListener("submit",e=>{e.preventDefault();const url=$("#url").value.trim();if(!/^https?:\/\/\S+$/i.test(url)){toast("Invalid URL","Enter a complete http:// or https:// URL.","error");return}submitScan("/api/scan/url",{url},"URL reputation")});
    $("#hashForm")?.addEventListener("submit",e=>{e.preventDefault();const hash=$("#hash").value.trim();if(!/^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(hash)){toast("Invalid hash","Use a valid MD5, SHA-1 or SHA-256 hexadecimal hash.","error");return}submitScan("/api/scan/hash",{hash},"Hash reputation")});
    $("#fileForm")?.addEventListener("submit",async e=>{
      e.preventDefault();const file=$("#file").files?.[0];if(!file){toast("Choose a file","Select a file first.","error");return}
      if(file.size>10*1024*1024){toast("File too large","The current ScanR limit is 10 MB.","error");return}
      $("#loading")?.classList.remove("hidden");$("#result")?.classList.add("hidden");
      try {
        if(!crypto.subtle)throw new Error("Secure SHA-256 calculation is unavailable in this browser context.");
        const digest=await crypto.subtle.digest("SHA-256",await file.arrayBuffer());
        const hash=[...new Uint8Array(digest)].map(b=>b.toString(16).padStart(2,"0")).join("");
        state.lastFileHash=hash;
        renderResult({status:"unknown",risk_level:"unknown",message:"SHA-256 calculated locally. Checking hash reputation; the file itself has not been uploaded.",sha256:hash},"Local file fingerprint");
        await submitScan("/api/scan/file",{filename:file.name,sha256:hash},"File hash reputation");
      } catch(err){renderResult({status:"unknown",risk_level:"unknown",message:err.message},"File fingerprint");toast("File check failed",err.message,"error")}
      finally{$("#loading")?.classList.add("hidden")}
    });
  }
  document.addEventListener("DOMContentLoaded",async()=>{
    $("#year")&&($("#year").textContent=new Date().getFullYear());
    setupPalette();wire();
    const requested=location.hash.replace("#","");
    showPage(["overview","scanner","history","reports","settings"].includes(requested)?requested:"overview");
    await refreshDashboard();
    if(!state.api)toast("Backend unavailable","Confirm the Flask server is running on 127.0.0.1:5000.","error");
  });
})();
'@
Set-Content ".\static\js\app.js" $js -Encoding UTF8

# Ensure template has correct root references; compile backend without changing its API logic.
& ".\.venv\Scripts\python.exe" -m compileall -q app.py scanner database
if ($LASTEXITCODE -ne 0) { throw "Python syntax check failed. Backup remains at $backup" }

Write-Host ""
Write-Host "ScanR UI/API wiring updated and backup saved." -ForegroundColor Green
Write-Host "Now stop Flask with Ctrl+C and restart it:" -ForegroundColor Yellow
Write-Host '  & ".\.venv\Scripts\python.exe" app.py'
Write-Host "Then open http://127.0.0.1:5000 and press Ctrl+F5."
Write-Host "Five themes: Midnight, Ocean, Violet, Light, Graphite. Click Theme to select."
Write-Host "If an endpoint returns an error, the UI will show the actual error; it will not invent vendor detections."
