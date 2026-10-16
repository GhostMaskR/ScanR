$ErrorActionPreference = "Stop"

# ScanR Phase 3 one-file installer
# Run this script from the ScanR project folder.
$ProjectPath = (Get-Location).Path
$Python = Join-Path $ProjectPath ".venv\Scripts\python.exe"

if (!(Test-Path (Join-Path $ProjectPath "app.py"))) {
    throw "app.py not found. Open PowerShell in B:\mine project\ScanR and run this file again."
}
if (!(Test-Path $Python)) {
    throw ".venv Python not found: $Python"
}

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backup = Join-Path $ProjectPath "backups\phase3_onefile_$stamp"
New-Item -ItemType Directory -Force -Path $backup, (Join-Path $ProjectPath "templates"), (Join-Path $ProjectPath "static\css"), (Join-Path $ProjectPath "static\js") | Out-Null

foreach ($rel in @("app.py","templates\index.html","static\css\style.css","static\js\app.js")) {
    $src = Join-Path $ProjectPath $rel
    if (Test-Path $src) {
        $dest = Join-Path $backup $rel
        New-Item -ItemType Directory -Force -Path (Split-Path $dest -Parent) | Out-Null
        Copy-Item $src $dest -Force
    }
}
Write-Host "Backup created: $backup" -ForegroundColor Green

$html = @'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#0b1020">
<title>ScanR | Threat Intelligence</title>
<link rel="stylesheet" href="/static/css/style.css">
<script src="/static/js/app.js" defer></script>
</head>
<body>
<div class="layout">
<aside class="sidebar" id="sidebar">
  <a class="brand" href="#overview"><span class="logo">◈</span><span>Scan<span class="cyan">R</span><small>THREAT INTELLIGENCE</small></span></a>
  <p class="caption">WORKSPACE</p>
  <button class="nav active" data-page="overview">▦ <span>Overview</span></button>
  <button class="nav" data-page="scanner">⌕ <span>Quick Scan</span></button>
  <button class="nav" data-page="history">◷ <span>Scan History</span></button>
  <button class="nav" data-page="reports">▤ <span>Reports</span></button>
  <p class="caption">SYSTEM</p>
  <button class="nav" data-page="settings">⚙ <span>Settings</span></button>
  <div class="side-bottom"><span class="dot" id="apiDot"></span><span id="apiLabel">Checking API...</span><small>ScanR · Phase 3</small></div>
</aside>
<main>
<header class="topbar">
  <button class="menu" id="menu">☰</button>
  <div><div class="crumb">Workspace / <b id="pageName">Overview</b></div><small>Threat intelligence and security analysis</small></div>
  <div class="top-actions"><span class="connection"><i id="connectionDot" class="dot"></i><span id="connectionText">Connecting</span></span><button id="theme" class="icon-btn" title="Toggle theme">☼</button><button class="primary" data-goto="scanner">＋ New Scan</button></div>
</header>
<div class="content">
<section class="page active" id="page-overview">
  <div class="eyebrow">— SECURITY OVERVIEW</div><h1>Security <span class="gradient">Dashboard</span></h1>
  <p class="muted">Review real scan activity from your ScanR backend.</p>
  <div class="hero"><div><div class="eyebrow">SCANR SECURITY ENGINE</div><h2 id="heroTitle">Your security workspace</h2><p id="heroText">Connect to the backend to start analyzing targets.</p></div><button class="secondary" data-goto="scanner">Start scanning →</button></div>
  <div class="section-title"><div><h2>Scan Overview</h2><p class="muted">Statistics from saved records, not sample data</p></div><button class="secondary" id="refresh">↻ Refresh</button></div>
  <div class="stats">
    <article class="stat"><span>Total scans</span><strong id="total">—</strong><small>Saved records</small></article>
    <article class="stat red"><span>Malicious</span><strong id="malicious">—</strong><small>Classified malicious</small></article>
    <article class="stat amber"><span>Suspicious</span><strong id="suspicious">—</strong><small>Classified suspicious</small></article>
    <article class="stat purple"><span>Unknown / pending</span><strong id="unknown">—</strong><small>Needs review</small></article>
  </div>
  <div class="columns">
    <section class="panel"><div class="section-title"><div><h2>Recent scans</h2><p class="muted">Latest database records</p></div><button class="link" data-goto="history">View all →</button></div><div class="table-wrap"><table><thead><tr><th>Target</th><th>Type</th><th>Risk</th><th>Time</th></tr></thead><tbody id="recent"><tr><td colspan="4">Loading history...</td></tr></tbody></table></div></section>
    <section class="panel"><h2>Detection breakdown</h2><p class="muted">Classification of saved scans</p><div id="breakdown" class="breakdown">Loading...</div><p class="notice">ⓘ No detections does not guarantee that a target is safe.</p></section>
  </div>
</section>
<section class="page" id="page-scanner">
  <div class="eyebrow">— ANALYSIS WORKSPACE</div><h1>Quick <span class="gradient">Scan</span></h1><p class="muted">Scan URLs, file hashes and known hashes.</p>
  <div class="columns scanner-columns">
    <section class="panel">
      <div class="tabs"><button class="tab active" data-tab="url">↗ URL</button><button class="tab" data-tab="file">▤ File</button><button class="tab" data-tab="hash">⌗ Hash</button></div>
      <form id="urlForm"><label for="url">Website URL</label><input id="url" type="url" placeholder="https://example.com" required><small>Enter a complete HTTP or HTTPS URL.</small><button class="primary full" type="submit">Analyze URL →</button></form>
      <form id="fileForm" class="hidden"><label for="file">Select a file (max 10 MB)</label><input id="file" type="file" required><small>The browser calculates SHA-256; the file itself is not uploaded by this interface.</small><button class="primary full" type="submit">Calculate hash &amp; check report →</button></form>
      <form id="hashForm" class="hidden"><label for="hash">File hash</label><input id="hash" placeholder="MD5, SHA-1 or SHA-256" required><small>Paste a hexadecimal hash to look up its reputation.</small><button class="primary full" type="submit">Check hash →</button></form>
      <div id="loading" class="loading hidden"><span class="spinner"></span> Analyzing target...</div>
      <div id="result" class="result hidden" aria-live="polite"></div>
    </section>
    <aside class="panel"><h2>How ScanR works</h2><div class="step"><b>01</b><div><strong>Submit target</strong><small>Provide a URL, file or hash.</small></div></div><div class="step"><b>02</b><div><strong>Analyze evidence</strong><small>Backend validation and reputation lookup.</small></div></div><div class="step"><b>03</b><div><strong>Review findings</strong><small>Check the result and its limitations.</small></div></div><p class="notice">Private files are not automatically uploaded by this UI.</p></aside>
  </div>
</section>
<section class="page" id="page-history">
  <div class="eyebrow">— ACTIVITY LOG</div><h1>Scan <span class="gradient">History</span></h1><p class="muted">Saved records from your local database.</p>
  <section class="panel"><div class="toolbar"><input id="search" type="search" placeholder="Search target, type or status"><select id="filter"><option value="all">All risks</option><option value="malicious">Malicious</option><option value="suspicious">Suspicious</option><option value="unknown">Unknown / pending</option><option value="no_detections">No detections</option></select><button id="exportHistory" class="secondary">Export JSON</button></div><div class="table-wrap"><table><thead><tr><th>ID</th><th>Target</th><th>Type</th><th>Status</th><th>Risk</th><th>Time</th></tr></thead><tbody id="history"><tr><td colspan="6">Loading history...</td></tr></tbody></table></div><p class="muted count" id="count"></p></section>
</section>
<section class="page" id="page-reports">
  <div class="eyebrow">— SECURITY DOCUMENTATION</div><h1>Scan <span class="gradient">Reports</span></h1><p class="muted">Export JSON or print a detailed scan report to PDF.</p>
  <div class="columns"><section class="panel"><h2>Latest scan report</h2><p class="muted">Run a scan, then export its result as JSON or print/save as PDF.</p><button id="reportJson" class="primary">Export latest JSON</button> <button id="reportPdf" class="secondary">Print / Save PDF</button></section><section class="panel"><h2>History export</h2><p class="muted">Download all currently loaded scan history as JSON.</p><button id="reportHistory" class="secondary">Export history JSON</button></section></div>
  <section class="panel report-note"><h2>Report interpretation</h2><p class="muted">Reports include the available classification, target, scan ID, detection counts and technical response. Unknown or pending findings must not be interpreted as safe.</p></section>
</section>
<section class="page" id="page-settings">
  <div class="eyebrow">— PREFERENCES</div><h1>Application <span class="gradient">Settings</span></h1><p class="muted">Current service and interface status.</p>
  <div class="panel setting"><div><b>Flask API</b><p class="muted">Local backend connection</p></div><strong id="settingApi">Checking...</strong></div>
  <div class="panel setting"><div><b>VirusTotal configuration</b><p class="muted">Only configuration status is displayed; the key is never shown.</p></div><strong id="settingVt">Checking...</strong></div>
  <div class="panel setting"><div><b>Theme</b><p class="muted">Switch between dark and light appearance.</p></div><button class="secondary" id="theme2">Toggle theme</button></div>
  <div class="panel setting"><div><b>Storage</b><p class="muted">Scan history uses the local SQLite database.</p></div><strong>LOCAL</strong></div>
</section>
<footer>ScanR · <span id="year"></span> <span>Evidence-based results · No AI/ML predictions</span></footer>
</div>
</main>
</div>
<div id="toasts" class="toasts" aria-live="polite"></div>
</body>
</html>
'@
Set-Content (Join-Path $ProjectPath "templates\index.html") $html -Encoding UTF8

$css = @'
:root{color-scheme:dark;--bg:#090e19;--side:#0b1120;--panel:#111a2a;--panel2:#172238;--border:#263249;--text:#edf3ff;--muted:#91a0b9;--cyan:#59e0e5;--blue:#78aaff;--red:#ff7b87;--amber:#f4c66a;--purple:#b19aff;--green:#65e5b0}
:root[data-theme=light]{color-scheme:light;--bg:#f3f6fb;--side:#fff;--panel:#fff;--panel2:#edf3fc;--border:#dce4ef;--text:#18243b;--muted:#62718a}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 "Segoe UI",Inter,system-ui,sans-serif}button,input,select{font:inherit}button{cursor:pointer;transition:transform .18s,background .18s,border-color .18s}button:focus-visible,input:focus-visible,select:focus-visible{outline:2px solid var(--cyan);outline-offset:2px}.layout{min-height:100vh}.sidebar{position:fixed;inset:0 auto 0 0;width:245px;background:var(--side);border-right:1px solid var(--border);padding:25px 16px;display:flex;flex-direction:column;z-index:10;transition:transform .25s}.brand{display:flex;align-items:center;gap:12px;text-decoration:none;color:var(--text);font-size:22px;font-weight:800;padding:0 8px 35px}.brand small{display:block;font-size:8px;letter-spacing:1.7px;color:var(--muted);margin-top:3px}.logo{display:grid;place-items:center;width:44px;height:44px;border-radius:14px;background:#143043;color:var(--cyan);font-size:29px;border:1px solid #245367}.cyan{color:var(--cyan)}.caption{font-size:10px;color:var(--muted);letter-spacing:1.7px;font-weight:800;padding-left:10px;margin:0 0 9px}.nav{display:flex;gap:13px;align-items:center;text-align:left;border:1px solid transparent;border-radius:10px;background:none;color:var(--muted);padding:12px;width:100%;margin:3px 0}.nav:hover{background:var(--panel);color:var(--text)}.nav.active{background:linear-gradient(90deg,#17304a,#142033);border-color:#284664;color:var(--text);box-shadow:inset 3px 0 var(--blue)}.nav:first-letter{color:var(--cyan)}.side-bottom{margin-top:auto;padding:15px 9px;border:1px solid var(--border);border-radius:12px;font-size:12px}.side-bottom small{display:block;color:var(--muted);margin:8px 0 0}.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--amber);margin-right:8px}.dot.online{background:var(--green);box-shadow:0 0 9px #65e5b088}.dot.offline{background:var(--red)}main{margin-left:245px;min-width:0}.topbar{height:76px;position:sticky;top:0;z-index:5;display:flex;align-items:center;justify-content:space-between;gap:12px;padding:14px 30px;border-bottom:1px solid var(--border);background:color-mix(in srgb,var(--bg) 91%,transparent);backdrop-filter:blur(16px)}.crumb{font-size:12px;color:var(--muted)}.crumb b{color:var(--text)}.topbar small{display:block;color:var(--muted);font-size:10px;margin-top:3px}.top-actions{display:flex;align-items:center;gap:9px}.connection{font-size:10px;color:var(--muted);border:1px solid var(--border);padding:7px 9px;border-radius:30px}.primary,.secondary,.icon-btn,.menu{border-radius:9px;padding:10px 13px;font-weight:700;font-size:11px}.primary{background:linear-gradient(100deg,var(--cyan),var(--blue));border:0;color:#071321}.primary:hover{transform:translateY(-1px);box-shadow:0 6px 20px #59a6ff30}.secondary,.icon-btn,.menu{background:var(--panel);color:var(--text);border:1px solid var(--border)}.secondary:hover,.icon-btn:hover{border-color:var(--cyan)}.menu{display:none}.content{max-width:1500px;margin:auto;padding:30px}.page{display:none;animation:appear .3s ease}.page.active{display:block}@keyframes appear{from{opacity:0;transform:translateY(7px)}to{opacity:1;transform:translateY(0)}}h1{font-size:clamp(27px,3vw,36px);letter-spacing:-1px;line-height:1.2;margin:9px 0}.gradient{background:linear-gradient(95deg,var(--cyan),var(--blue),var(--purple));color:var(--cyan);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}.eyebrow{font-size:10px;color:var(--cyan);font-weight:800;letter-spacing:1.6px}.muted{color:var(--muted);font-size:12px}.hero{margin:25px 0;padding:25px;border-radius:15px;border:1px solid #2a4860;background:radial-gradient(ellipse at 85% 0,#21405766,transparent 55%),linear-gradient(110deg,#14243a,#101a2d);display:flex;align-items:center;justify-content:space-between;gap:18px;animation:rise .5s ease}@keyframes rise{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}.hero h2{font-size:19px;margin:5px 0}.hero p{font-size:12px;color:#b2c3da;margin:0}.section-title{display:flex;justify-content:space-between;align-items:center;gap:12px;margin:25px 0 14px}.section-title h2,.panel h2{font-size:15px;margin:0 0 3px}.section-title p,.panel>p{margin:0}.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}.stat,.panel{border:1px solid var(--border);background:var(--panel);border-radius:14px}.stat{padding:18px;transition:transform .2s,border-color .2s;overflow:hidden}.stat:hover{transform:translateY(-3px);border-color:#3b6386}.stat span{font-size:11px;color:var(--muted)}.stat strong{display:block;font-size:32px;letter-spacing:-1px;margin:9px 0 2px}.stat small{font-size:10px;color:var(--muted)}.red strong{color:var(--red)}.amber strong{color:var(--amber)}.purple strong{color:var(--purple)}.columns{display:grid;grid-template-columns:minmax(0,1.5fr) minmax(250px,.8fr);gap:16px;margin-top:18px}.panel{padding:20px;min-width:0}.table-wrap{overflow-x:auto;margin-top:14px}table{width:100%;border-collapse:collapse;text-align:left;white-space:nowrap}th{font-size:9px;letter-spacing:.8px;color:var(--muted);text-transform:uppercase;background:var(--panel2)}td,th{padding:12px 10px;border-bottom:1px solid var(--border);font-size:11px}td{color:var(--muted)}td:first-child{color:var(--text);max-width:230px;overflow:hidden;text-overflow:ellipsis}.link{border:0;background:none;color:var(--cyan);font-size:11px}.badge{display:inline-block;border-radius:30px;padding:4px 8px;font-size:9px;font-weight:800;border:1px solid var(--border)}.badge.malicious{color:var(--red);background:#ff7b8710}.badge.suspicious{color:var(--amber)}.badge.no_detections,.badge.safe{color:var(--green)}.badge.unknown,.badge.pending,.badge.error{color:var(--muted)}.breakdown{display:grid;gap:17px;margin:22px 0}.bar-head{display:flex;justify-content:space-between;font-size:11px;margin-bottom:7px}.bar-head span{color:var(--muted)}.bar{height:6px;background:var(--panel2);border-radius:9px;overflow:hidden}.bar i{display:block;height:100%;border-radius:9px;transition:width .6s}.notice{margin-top:20px;padding:12px;border-radius:9px;background:#f4c66a0b;color:var(--muted);font-size:10px;border:1px solid #f4c66a22}.tabs{display:flex;gap:5px;padding:5px;border:1px solid var(--border);border-radius:10px;margin-bottom:24px;background:var(--bg)}.tab{flex:1;border:1px solid transparent;background:none;color:var(--muted);padding:10px;border-radius:8px;font-size:11px;font-weight:700}.tab.active{background:var(--panel2);border-color:var(--border);color:var(--text)}form label{display:block;font-size:12px;font-weight:700;margin:10px 0}input,select{width:100%;min-height:43px;background:var(--bg);border:1px solid var(--border);border-radius:9px;padding:10px 12px;color:var(--text);font-size:12px}input::placeholder{color:var(--muted)}form small{display:block;color:var(--muted);font-size:10px;margin-top:8px;line-height:1.6}.full{width:100%;margin-top:19px;min-height:44px}.hidden{display:none!important}.step{display:flex;gap:12px;margin:22px 0}.step>b{display:grid;place-items:center;min-width:31px;height:31px;border:1px solid var(--border);border-radius:8px;color:var(--cyan)}.step strong,.step small{display:block}.step strong{font-size:11px}.step small{font-size:10px;color:var(--muted);margin-top:4px}.loading{display:flex;align-items:center;gap:10px;margin-top:20px;padding:14px;border:1px solid var(--border);border-radius:10px;color:var(--muted);font-size:12px}.spinner{width:20px;height:20px;border:2px solid #59a6ff33;border-top-color:var(--cyan);border-radius:50%;animation:spin .8s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}.result{margin-top:20px;padding:17px;border:1px solid var(--border);border-radius:12px;background:var(--panel2);animation:appear .3s}.result h2{font-size:16px;margin:0 0 8px}.result p{font-size:11px;color:var(--muted);overflow-wrap:anywhere}.result-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;margin:14px 0}.result-grid div{padding:10px;border:1px solid var(--border);border-radius:8px}.result-grid small,.result-grid b{display:block}.result-grid small{color:var(--muted);font-size:9px}.result-grid b{font-size:18px;margin-top:5px}.details{font-size:10px;color:var(--muted);overflow-wrap:anywhere}.result-actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px}.toolbar{display:flex;gap:9px;flex-wrap:wrap;margin-bottom:15px}.toolbar input{flex:1 1 200px}.toolbar select{width:auto;min-width:140px}.count{padding-top:14px}.report-note{margin-top:16px}.setting{display:flex;align-items:center;justify-content:space-between;gap:16px;margin:12px 0;padding:18px}.setting p{margin:5px 0 0}.setting strong{font-size:11px;color:var(--cyan)}footer{display:flex;justify-content:space-between;gap:12px;border-top:1px solid var(--border);margin-top:28px;padding:18px 0;color:var(--muted);font-size:10px}.toasts{position:fixed;right:20px;bottom:20px;z-index:50;display:grid;gap:8px;width:min(350px,calc(100vw - 30px))}.toast{background:var(--panel2);border:1px solid var(--border);padding:13px;border-radius:10px;box-shadow:0 12px 40px #0003;font-size:11px;animation:appear .2s}.toast b{display:block;margin-bottom:4px}.toast span{color:var(--muted);overflow-wrap:anywhere}.toast.error{border-color:#ff7b8766}.toast.success{border-color:#65e5b066}
@media(max-width:1150px){.sidebar{width:215px}main{margin-left:215px}.content{padding:24px}.stats{grid-template-columns:repeat(2,minmax(0,1fr))}.columns{grid-template-columns:minmax(0,1fr)}}@media(max-width:800px){.sidebar{transform:translateX(-105%);box-shadow:0 20px 60px #0006}.sidebar.open{transform:translateX(0)}main{margin-left:0}.menu{display:block}.topbar{padding:12px 15px}.content{padding:22px 15px}.topbar small{display:none}.connection{font-size:0}.connection .dot{margin:0}.hero{align-items:flex-start;flex-direction:column}.scanner-columns{grid-template-columns:1fr}}@media(max-width:480px){.stats{gap:9px}.stat{padding:12px}.stat strong{font-size:27px}.top-actions{gap:5px}.top-actions .primary{font-size:0;padding:9px}.top-actions .primary:after{content:"+";font-size:19px}.result-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.panel{padding:14px}.section-title{align-items:flex-start}.setting{align-items:flex-start;flex-direction:column}footer{flex-direction:column}}@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.01ms!important;animation-iteration-count:1!important;transition-duration:.01ms!important;scroll-behavior:auto!important}}@media print{.sidebar,.topbar,footer,button{display:none!important}main{margin:0}.page{display:none!important}.page.active{display:block!important}.panel,.result{background:#fff;color:#111;box-shadow:none}.muted,.result p,td{color:#333}}
'@
Set-Content (Join-Path $ProjectPath "static\css\style.css") $css -Encoding UTF8

$js = @'
"use strict";
(() => {
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
const state={history:[],latest:null,api:false};
const esc=s=>String(s??"—").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const norm=s=>String(s??"unknown").toLowerCase().replace(/[\s-]+/g,"_");
function toast(title,message,type="info"){const n=document.createElement("div");n.className="toast "+type;const b=document.createElement("b"),s=document.createElement("span");b.textContent=title;s.textContent=message;n.append(b,s);$("#toasts").append(n);setTimeout(()=>n.remove(),4500)}
function target(r){return r?.target||r?.url||r?.file_name||r?.filename||r?.hash||r?.file_hash||"Target not recorded"}
function type(r){const t=norm(r?.scan_type||r?.type||r?.scan_method);return t.includes("url")?"URL":t.includes("file")?"File":t.includes("hash")?"Hash":r?.url?"URL":r?.filename?"File":"Scan"}
function risk(r){let s=norm(r?.risk_level||r?.status||r?.classification);if(s.includes("malicious")||s==="infected")return ["malicious","MALICIOUS"];if(s.includes("suspicious"))return ["suspicious","SUSPICIOUS"];if(s.includes("pending")||s.includes("queued")||s.includes("analysis_submitted"))return ["pending","PENDING"];if(s.includes("no_detection")||s==="clean"||s==="safe"||s==="harmless")return ["no_detections","NO DETECTIONS"];if(s==="error"||s.includes("failed"))return ["error","ERROR"];return ["unknown","UNKNOWN"]}
function date(r){let d=new Date(r?.created_at||r?.timestamp||r?.scan_time||"");return isNaN(d)? "—":d.toLocaleString()}
function counts(r){let s=r?.stats||r?.statistics||r?.last_analysis_stats||r?.detections||{};return {malicious:r?.malicious??s.malicious??"—",suspicious:r?.suspicious??s.suspicious??"—",harmless:r?.harmless??s.harmless??"—",undetected:r?.undetected??s.undetected??"—"}}
async function api(path,options={}){let res=await fetch(path,{...options,headers:{"Content-Type":"application/json",...(options.headers||{})},cache:"no-store"});let d;try{d=await res.json()}catch{d={message:"Server returned a non-JSON response"}}if(!res.ok||d?.success===false){let e=new Error(d?.message||d?.error||`HTTP ${res.status}`);e.data=d;throw e}return d}
function extract(d){if(Array.isArray(d))return d;for(const k of ["items","history","records","scans","data"])if(Array.isArray(d?.[k]))return d[k];return []}
function badge(r){let [k,label]=risk(r);return `<span class="badge ${k}">${label}</span>`}
function render(){
let m=0,s=0,u=0,n=0;state.history.forEach(r=>{let k=risk(r)[0];if(k==="malicious")m++;else if(k==="suspicious")s++;else if(k==="unknown"||k==="pending"||k==="error")u++;else n++});
$("#total").textContent=state.history.length;$("#malicious").textContent=m;$("#suspicious").textContent=s;$("#unknown").textContent=u;
let recent=[...state.history].reverse().slice(0,6);
$("#recent").innerHTML=recent.length?recent.map(r=>`<tr><td title="${esc(target(r))}">${esc(target(r))}</td><td>${esc(type(r))}</td><td>${badge(r)}</td><td>${esc(date(r))}</td></tr>`).join(""):`<tr><td colspan="4">No saved scans yet. Run your first scan.</td></tr>`;
let items=[["Malicious",m,"#ff7b87"],["Suspicious",s,"#f4c66a"],["No detections",n,"#65e5b0"],["Unknown / pending",u,"#b19aff"]],max=Math.max(1,...items.map(x=>x[1]));
$("#breakdown").innerHTML=items.map(x=>`<div><div class="bar-head"><span>${x[0]}</span><b>${x[1]}</b></div><div class="bar"><i style="width:${x[1]/max*100}%;background:${x[2]}"></i></div></div>`).join("");
renderHistory()
}
function renderHistory(){let q=norm($("#search").value),f=$("#filter").value;let list=state.history.filter(r=>(norm([target(r),type(r),r.status,r.id,r.scan_id].join(" ")).includes(q))&&(f==="all"||risk(r)[0]===f||(f==="unknown"&&["unknown","pending","error"].includes(risk(r)[0]))));$("#history").innerHTML=list.length?list.map(r=>`<tr><td>#${esc(r.id??r.scan_id??"—")}</td><td title="${esc(target(r))}">${esc(target(r))}</td><td>${esc(type(r))}</td><td>${esc(r.status||"unknown")}</td><td>${badge(r)}</td><td>${esc(date(r))}</td></tr>`).join(""):`<tr><td colspan="6">No matching records.</td></tr>`;$("#count").textContent=`Showing ${list.length} of ${state.history.length} records`}
async function loadHistory(){try{state.history=extract(await api("/api/history"));render()}catch(e){$("#recent").innerHTML=`<tr><td colspan="4">${esc(e.message)}</td></tr>`;$("#history").innerHTML=`<tr><td colspan="6">${esc(e.message)}</td></tr>`}}
async function status(){try{let d=await api("/api/status");state.api=true;$("#apiDot").className="dot online";$("#connectionDot").className="dot online";$("#apiLabel").textContent="API Connected";$("#connectionText").textContent="Connected";$("#settingApi").textContent="CONNECTED";let ok=Boolean(d.virustotal_key_configured??d.virustotal_configured??d.vt_configured);$("#settingVt").textContent=ok?"CONFIGURED":"NOT CONFIGURED";$("#heroTitle").textContent=ok?"Your scanner is ready":"Backend connected";$("#heroText").textContent=ok?"Scan URLs, inspect hashes and review available threat reports.":"Backend responds, but check VirusTotal configuration."}catch(e){state.api=false;$("#apiDot").className="dot offline";$("#connectionDot").className="dot offline";$("#apiLabel").textContent="API Offline";$("#connectionText").textContent="Offline";$("#settingApi").textContent="OFFLINE";$("#settingVt").textContent="UNKNOWN";$("#heroText").textContent="Start Flask and refresh this page to reconnect.";toast("Backend unavailable",e.message,"error")}}
function page(name){$$(".page").forEach(x=>x.classList.toggle("active",x.id==="page-"+name));$$(".nav").forEach(x=>x.classList.toggle("active",x.dataset.page===name));$("#pageName").textContent=({overview:"Overview",scanner:"Quick Scan",history:"Scan History",reports:"Reports",settings:"Settings"}[name]||name);$("#sidebar").classList.remove("open");if(name==="history"||name==="overview")loadHistory();location.hash=name}
$$(".nav").forEach(b=>b.addEventListener("click",()=>page(b.dataset.page)));$$("[data-goto]").forEach(b=>b.addEventListener("click",()=>page(b.dataset.goto)));$("#menu").onclick=()=>$("#sidebar").classList.toggle("open");
document.addEventListener("click",e=>{if(innerWidth<800&&!e.target.closest("#sidebar")&&!e.target.closest("#menu"))$("#sidebar").classList.remove("open")});
function setTheme(t){document.documentElement.dataset.theme=t;try{localStorage.setItem("scanr-theme",t)}catch{}}
try{setTheme(localStorage.getItem("scanr-theme")==="light"?"light":"dark")}catch{setTheme("dark")}
function toggleTheme(){setTheme(document.documentElement.dataset.theme==="light"?"dark":"light")}$("#theme").onclick=toggleTheme;$("#theme2").onclick=toggleTheme;
$("#refresh").onclick=async()=>{await status();await loadHistory();toast("Refreshed","Dashboard data refreshed.","success")};
$("#search").oninput=renderHistory;$("#filter").onchange=renderHistory;
function exportJson(d,name){let u=URL.createObjectURL(new Blob([JSON.stringify(d,null,2)],{type:"application/json"}));let a=document.createElement("a");a.href=u;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(u),1000)}
$("#exportHistory").onclick=()=>exportJson(state.history,"scanr-history.json");$("#reportHistory").onclick=()=>exportJson(state.history,"scanr-reports.json");
function printReport(r){if(!r){toast("No report","Run a scan first.","info");return}let w=window.open("","_blank","width=850,height=700");if(!w){toast("Pop-up blocked","Allow pop-ups for localhost.","error");return}let c=counts(r);w.document.write(`<!doctype html><title>ScanR Report</title><style>body{font:14px Arial;margin:35px;color:#172033}h1{border-bottom:2px solid;padding-bottom:12px}table{border-collapse:collapse;width:100%}td{padding:10px;border-bottom:1px solid #ddd;overflow-wrap:anywhere}td:first-child{width:180px;color:#555}.notice{margin-top:24px;padding:12px;background:#fff8e6}</style><h1>ScanR — Threat Intelligence Report</h1><p>Generated: ${esc(new Date().toLocaleString())}</p><h2>${esc(risk(r)[1])}</h2><p>${esc(r.message||"Review available scan evidence and limitations.")}</p><h3>Detection statistics</h3><table>${Object.entries(c).map(([k,v])=>`<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`).join("")}</table><h3>Technical details</h3><table>${Object.entries(r).map(([k,v])=>`<tr><td>${esc(k)}</td><td>${esc(typeof v==="object"?JSON.stringify(v):v)}</td></tr>`).join("")}</table><p class="notice">No detections do not guarantee safety. Unknown or pending findings require further investigation.</p><script>window.onload=()=>window.print();<\/script>`);w.document.close()}
$("#reportPdf").onclick=()=>printReport(state.latest);$("#reportJson").onclick=()=>state.latest?exportJson(state.latest,"scanr-report.json"):toast("No report","Run a scan first.","info");
function showResult(r){state.latest=r;let c=counts(r),k=risk(r);let msg=r.message||r.analysis_message||(k[0]==="no_detections"?"No detections were reported. This is not proof that the target is safe.":"Review the available scan result and its limitations.");$("#result").innerHTML=`<h2>Scan result · <span class="badge ${k[0]}">${k[1]}</span></h2><p>${esc(msg)}</p><div class="result-grid">${Object.entries(c).map(([a,b])=>`<div><small>${esc(a)}</small><b>${esc(b)}</b></div>`).join("")}</div><div class="details">${Object.entries({target:target(r),scan_id:r.scan_id??r.id??"—",status:r.status??"unknown",risk_level:r.risk_level??"unknown",sha256:r.sha256??"—",scan_method:r.scan_method??"—"}).map(([a,b])=>`<p><b>${esc(a)}:</b> ${esc(b)}</p>`).join("")}</div><div class="result-actions"><button class="secondary" id="resultJson">Export JSON</button><button class="secondary" id="resultPdf">Print / Save PDF</button></div>`;$("#result").classList.remove("hidden");$("#resultJson").onclick=()=>exportJson(state.latest,"scanr-result.json");$("#resultPdf").onclick=()=>printReport(state.latest)}
async function runScan(path,body,label){$("#loading").classList.remove("hidden");$("#result").classList.add("hidden");$$("form button[type=submit]").forEach(b=>b.disabled=true);try{let d=await api(path,{method:"POST",body:JSON.stringify(body)});showResult(d.result||d.scan||d.report||d);toast(label,"Response received from backend.","success");await loadHistory()}catch(e){showResult({...e.data,status:e.data?.status||"error",risk_level:e.data?.risk_level||"unknown",message:e.data?.message||e.message});toast(label+" failed",e.message,"error");await loadHistory()}finally{$("#loading").classList.add("hidden");$$("form button[type=submit]").forEach(b=>b.disabled=false)}}
$("#urlForm").onsubmit=e=>{e.preventDefault();let url=$("#url").value.trim();if(!/^https?:\/\//i.test(url))return toast("Invalid URL","Use HTTP or HTTPS.","error");runScan("/api/scan/url",{url},"URL scan")};
$("#hashForm").onsubmit=e=>{e.preventDefault();let hash=$("#hash").value.trim();if(!/^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$/.test(hash))return toast("Invalid hash","Use a valid hexadecimal MD5, SHA-1 or SHA-256 hash.","error");runScan("/api/scan/hash",{hash},"Hash scan")};
$("#fileForm").onsubmit=async e=>{e.preventDefault();let f=$("#file").files?.[0];if(!f)return toast("Select a file","Choose a file first.","error");if(f.size>10*1024*1024)return toast("File too large","Maximum supported size is 10 MB.","error");if(!crypto?.subtle)return toast("Hash unavailable","Use localhost or HTTPS to calculate SHA-256.","error");$("#loading").classList.remove("hidden");try{let digest=await crypto.subtle.digest("SHA-256",await f.arrayBuffer());let hash=[...new Uint8Array(digest)].map(x=>x.toString(16).padStart(2,"0")).join("");let d=await api("/api/scan/file",{method:"POST",body:JSON.stringify({filename:f.name,file_name:f.name,sha256:hash,hash})});let r=d.result||d.scan||d.report||d;showResult({...r,target:r.target||f.name,filename:r.filename||f.name,sha256:r.sha256||hash});toast("File hash checked","The file itself was not uploaded by this UI.","success");await loadHistory()}catch(err){showResult({status:err.data?.status||"unknown",risk_level:err.data?.risk_level||"unknown",message:err.data?.message||err.message,target:f.name});toast("File scan failed",err.message,"error")}finally{$("#loading").classList.add("hidden")}};
$$(".tab").forEach(b=>b.onclick=()=>{$$(".tab").forEach(x=>x.classList.toggle("active",x===b));["url","file","hash"].forEach(k=>$("#"+k+"Form").classList.toggle("hidden",k!==b.dataset.tab));$("#result").classList.add("hidden")});
$("#year").textContent=new Date().getFullYear();let initial=location.hash.slice(1);page(["overview","scanner","history","reports","settings"].includes(initial)?initial:"overview");(async()=>{await status();await loadHistory()})();
})();
'@
Set-Content (Join-Path $ProjectPath "static\js\app.js") $js -Encoding UTF8

# Connect only the homepage; keep existing scanner API endpoints intact.
$appPath = Join-Path $ProjectPath "app.py"
$app = Get-Content $appPath -Raw
if ($app -notmatch '(?m)^from flask import .*render_template') {
    if ($app -match '(?m)^from flask import ') {
        $app = [regex]::Replace($app, '(?m)^from flask import ([^\r\n]+)', '$0', 1)
        $app = "from flask import render_template`r`n" + $app
    } else {
        $app = "from flask import render_template`r`n" + $app
    }
}
$rootPattern = '(?s)@app\.(?:get|route)\(["'']\/["'']\).*?(?=\r?\n@app\.|\r?\nif __name__\s*==|\z)'
if ($app -match $rootPattern) {
    $newRoot = @'
@app.get("/")
def index():
    return render_template("index.html")

'@
    $app = [regex]::Replace($app, $rootPattern, $newRoot, 1)
    Set-Content $appPath $app -Encoding UTF8
} elseif ($app -notmatch '(?m)^@app\.get\(["'']\/["'']\)') {
    Add-Content $appPath "`r`n`r`n@app.get('/')`r`ndef index():`r`n    return render_template('index.html')`r`n" -Encoding UTF8
}

& $Python -m compileall -q app.py scanner database
if ($LASTEXITCODE -ne 0) {
    throw "Python syntax check failed. Your backup is at $backup"
}

Write-Host ""
Write-Host "ScanR Phase 3 frontend installed." -ForegroundColor Green
Write-Host "Backup: $backup"
Write-Host "Next run: & '.\.venv\Scripts\python.exe' app.py"
Write-Host "Open: http://127.0.0.1:5000"
Write-Host "Then press Ctrl+F5 in your browser."
Write-Host "Note: This creates the UI and connects the homepage. Verify scanner request fields against your existing backend."
