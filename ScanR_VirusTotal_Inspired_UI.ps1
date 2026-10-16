$ErrorActionPreference = "Stop"
$ProjectPath = (Get-Location).Path
$Python = Join-Path $ProjectPath ".venv\Scripts\python.exe"

if (!(Test-Path ".\app.py")) { throw "Open PowerShell in B:\mine project\ScanR first." }
foreach ($f in @(".\templates\index.html",".\static\css\style.css",".\static\js\app.js")) {
    if (!(Test-Path $f)) { throw "Required frontend file missing: $f" }
}

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backup = Join-Path $ProjectPath "backups\virustotal_inspired_$stamp"
New-Item -ItemType Directory -Force -Path (Join-Path $backup "templates"), (Join-Path $backup "static\css"), (Join-Path $backup "static\js") | Out-Null
Copy-Item ".\templates\index.html" (Join-Path $backup "templates\index.html") -Force
Copy-Item ".\static\css\style.css" (Join-Path $backup "static\css\style.css") -Force
Copy-Item ".\static\js\app.js" (Join-Path $backup "static\js\app.js") -Force
Write-Host "Backup created: $backup" -ForegroundColor Green

# VirusTotal's pasted HTML is only its application shell. The actual interface is loaded
# from a separate bundled JavaScript file and its private APIs. This creates an original
# ScanR interface inspired by a threat-intelligence portal, without copying VT source.

$html = @'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#171923">
<title>ScanR | Threat Intelligence</title>
<link rel="stylesheet" href="/static/css/style.css">
<script src="/static/js/app.js" defer></script>
</head>
<body>
<header class="vt-topbar">
  <a class="vt-brand" href="#overview"><span class="vt-mark">S</span><span>Scan<span class="vt-brand-r">R</span><small>THREAT INTELLIGENCE</small></span></a>
  <nav class="vt-topnav"><button data-page="overview" class="topnav active">Dashboard</button><button data-page="scanner" class="topnav">Analyze</button><button data-page="history" class="topnav">History</button><button data-page="reports" class="topnav">Reports</button></nav>
  <div class="vt-top-actions"><span class="connection"><i id="connectionDot" class="dot"></i><span id="connectionText">Connecting</span></span><button id="theme" class="icon-btn" title="Toggle theme">Theme</button></div>
</header>
<div class="vt-search-strip">
  <div class="vt-search-inner"><div class="search-symbol">SCAN</div><div><strong>Analyze suspicious files, domains, IPs and URLs</strong><small>ScanR combines local validation with available VirusTotal reputation data.</small></div><button class="primary" data-goto="scanner">New analysis</button></div>
</div>
<div class="layout">
<aside class="sidebar" id="sidebar">
  <p class="caption">ANALYSIS</p>
  <button class="nav active" data-page="overview"><span class="nav-icon">OV</span><span>Overview</span></button>
  <button class="nav" data-page="scanner"><span class="nav-icon">URL</span><span>URL / Hash scan</span></button>
  <button class="nav" data-page="history"><span class="nav-icon">LOG</span><span>Scan history</span></button>
  <button class="nav" data-page="reports"><span class="nav-icon">PDF</span><span>Reports</span></button>
  <p class="caption system-caption">PREFERENCES</p>
  <button class="nav" data-page="settings"><span class="nav-icon">SET</span><span>Settings</span></button>
  <div class="side-bottom"><span class="dot" id="apiDot"></span><span id="apiLabel">Checking API...</span><small>Local ScanR engine</small></div>
</aside>
<main>
<div class="content">
<section class="page active" id="page-overview">
  <div class="page-heading"><div><div class="eyebrow">SCANR / THREAT INTELLIGENCE</div><h1>Dashboard</h1><p class="muted">A unified view of scan activity and threat findings.</p></div><button class="secondary" id="refresh">Refresh data</button></div>
  <div class="hero"><div class="hero-copy"><div class="eyebrow">LOCAL ANALYSIS ENGINE</div><h2 id="heroTitle">Your security workspace</h2><p id="heroText">Connect to the backend to start analyzing targets.</p></div><button class="primary" data-goto="scanner">+ Analyze target</button></div>
  <div class="stats">
    <article class="stat"><div class="stat-top"><span class="stat-mark">ALL</span><span class="stat-label">TOTAL SCANS</span></div><strong id="total">-</strong><small>Saved database records</small></article>
    <article class="stat red"><div class="stat-top"><span class="stat-mark">MAL</span><span class="stat-label">MALICIOUS</span></div><strong id="malicious">-</strong><small>Classified malicious</small></article>
    <article class="stat amber"><div class="stat-top"><span class="stat-mark">SUS</span><span class="stat-label">SUSPICIOUS</span></div><strong id="suspicious">-</strong><small>Classified suspicious</small></article>
    <article class="stat purple"><div class="stat-top"><span class="stat-mark">UNK</span><span class="stat-label">UNKNOWN / PENDING</span></div><strong id="unknown">-</strong><small>Needs further review</small></article>
  </div>
  <div class="columns">
    <section class="panel"><div class="section-title"><div><h2>Latest analyses</h2><p class="muted">Recent records saved by ScanR</p></div><button class="link" data-goto="history">View history &gt;</button></div><div class="table-wrap"><table><thead><tr><th>Target</th><th>Type</th><th>Risk</th><th>Last analysis</th></tr></thead><tbody id="recent"><tr><td colspan="4">Loading history...</td></tr></tbody></table></div></section>
    <section class="panel"><h2>Detection summary</h2><p class="muted">Based on saved scan classifications</p><div id="breakdown" class="breakdown">Loading...</div><p class="notice">No detections does not guarantee that a target is safe.</p></section>
  </div>
</section>
<section class="page" id="page-scanner">
  <div class="page-heading"><div><div class="eyebrow">SCANR / ANALYZE</div><h1>Analyze a target</h1><p class="muted">Look up a URL, file hash or known hash.</p></div></div>
  <section class="panel scan-panel">
    <div class="tabs"><button class="tab active" data-tab="url">URL</button><button class="tab" data-tab="file">FILE HASH</button><button class="tab" data-tab="hash">HASH LOOKUP</button></div>
    <form id="urlForm"><label for="url">URL to analyze</label><input id="url" type="url" placeholder="https://example.com" required><small>Submit a complete HTTP or HTTPS URL.</small><button class="primary full" type="submit">Search / Analyze URL</button></form>
    <form id="fileForm" class="hidden"><label for="file">Choose a local file (maximum 10 MB)</label><input id="file" type="file" required><small>ScanR calculates SHA-256 in your browser and checks reputation. The file content is not uploaded by this interface.</small><button class="primary full" type="submit">Calculate SHA-256</button></form>
    <form id="hashForm" class="hidden"><label for="hash">MD5, SHA-1 or SHA-256</label><input id="hash" placeholder="Paste hexadecimal hash" required><button class="primary full" type="submit">Search hash</button></form>
    <div id="loading" class="loading hidden"><span class="spinner"></span> Checking available reputation data...</div>
    <div id="result" class="result hidden" aria-live="polite"></div>
  </section>
  <section class="panel workflow-panel"><h2>Analysis notes</h2><p class="muted">ScanR uses validation and available external reputation results. A missing report or a pending analysis is not a clean verdict.</p></section>
</section>
<section class="page" id="page-history">
  <div class="page-heading"><div><div class="eyebrow">SCANR / RECORDS</div><h1>Scan history</h1><p class="muted">Saved local analysis records.</p></div></div>
  <section class="panel"><div class="toolbar"><input id="search" type="search" placeholder="Search target, type or status"><select id="filter"><option value="all">All risks</option><option value="malicious">Malicious</option><option value="suspicious">Suspicious</option><option value="unknown">Unknown / pending</option><option value="no_detections">No detections</option></select><button id="exportHistory" class="secondary">Export JSON</button></div><div class="table-wrap"><table><thead><tr><th>ID</th><th>Target</th><th>Type</th><th>Status</th><th>Risk</th><th>Time</th></tr></thead><tbody id="history"><tr><td colspan="6">Loading history...</td></tr></tbody></table></div><p class="muted count" id="count"></p></section>
</section>
<section class="page" id="page-reports">
  <div class="page-heading"><div><div class="eyebrow">SCANR / EXPORTS</div><h1>Reports</h1><p class="muted">Export findings for documentation and review.</p></div></div>
  <div class="columns"><section class="panel"><h2>Latest analysis</h2><p class="muted">Run a scan before exporting a detailed report.</p><div class="report-actions"><button id="reportJson" class="primary">Export JSON</button><button id="reportPdf" class="secondary">Print / Save PDF</button></div></section><section class="panel"><h2>History export</h2><p class="muted">Download all currently loaded history records.</p><button id="reportHistory" class="secondary">Export history JSON</button></section></div>
  <section class="panel report-note"><h2>Interpreting results</h2><p class="muted">Malicious and suspicious results need attention. Unknown, unavailable and pending reports are inconclusive. A clean reputation result is not a guarantee of safety.</p></section>
</section>
<section class="page" id="page-settings">
  <div class="page-heading"><div><div class="eyebrow">SCANR / CONFIGURATION</div><h1>Settings</h1><p class="muted">Service health and local preferences.</p></div></div>
  <div class="panel setting"><div><b>Flask API</b><p class="muted">Local backend connection</p></div><strong id="settingApi">Checking...</strong></div>
  <div class="panel setting"><div><b>VirusTotal API</b><p class="muted">Only configuration status is shown; secret keys are not displayed.</p></div><strong id="settingVt">Checking...</strong></div>
  <div class="panel setting"><div><b>Appearance</b><p class="muted">Change the dashboard theme.</p></div><button class="secondary" id="theme2">Toggle theme</button></div>
  <div class="panel setting"><div><b>Storage</b><p class="muted">Local SQLite scan history.</p></div><strong>LOCAL</strong></div>
</section>
<footer><span>ScanR | <span id="year"></span></span><span>Independent project; not affiliated with VirusTotal.</span></footer>
</div>
</main>
</div>
<div id="toasts" class="toasts" aria-live="polite"></div>
</body>
</html>
'@
Set-Content ".\templates\index.html" $html -Encoding UTF8

$css = @'
:root{color-scheme:dark;--bg:#171923;--side:#171923;--panel:#202330;--panel2:#292d3c;--border:#3a3f50;--text:#e9eaf2;--muted:#a5a9b8;--blue:#7895ff;--cyan:#72d9e8;--red:#ff777f;--amber:#f3c36c;--purple:#b19aff;--green:#65deb1}
:root[data-theme=light]{color-scheme:light;--bg:#f5f6fa;--side:#fff;--panel:#fff;--panel2:#edf0f7;--border:#dfe3ed;--text:#202435;--muted:#687087}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 "Segoe UI",Inter,system-ui,sans-serif;-webkit-font-smoothing:antialiased}button,input,select{font:inherit}button{cursor:pointer;transition:background .18s,border-color .18s,transform .18s}button:focus-visible,input:focus-visible,select:focus-visible{outline:2px solid var(--blue);outline-offset:2px}.vt-topbar{height:67px;display:flex;align-items:center;gap:28px;padding:0 26px;border-bottom:1px solid var(--border);background:var(--side);position:sticky;top:0;z-index:20}.vt-brand{display:flex;align-items:center;gap:10px;min-width:215px;text-decoration:none;color:var(--text);font-size:21px;font-weight:800;line-height:1}.vt-brand small{display:block;font-size:8px;letter-spacing:1.7px;color:var(--muted);margin-top:6px}.vt-mark{display:grid;place-items:center;width:38px;height:38px;border-radius:11px;background:#27324e;color:#94b5ff;font-weight:900;font-size:23px}.vt-brand-r{color:#8ba6ff}.vt-topnav{display:flex;align-self:stretch;gap:5px}.topnav{padding:0 15px;background:none;color:var(--muted);border:0;border-bottom:2px solid transparent;font-size:12px}.topnav:hover,.topnav.active{color:var(--text);border-bottom-color:var(--blue)}.vt-top-actions{display:flex;align-items:center;gap:10px;margin-left:auto}.icon-btn,.primary,.secondary,.menu{border-radius:6px;padding:9px 13px;font-size:11px;font-weight:700}.primary{background:#536fce;color:white;border:1px solid #6c87e6}.primary:hover{background:#6481e5;transform:translateY(-1px)}.secondary,.icon-btn,.menu{background:var(--panel2);color:var(--text);border:1px solid var(--border)}.secondary:hover,.icon-btn:hover{border-color:var(--blue)}.vt-search-strip{background:#202330;border-bottom:1px solid var(--border);padding:16px 28px}.vt-search-inner{max-width:1550px;margin:auto;display:flex;align-items:center;gap:14px}.search-symbol{display:grid;place-items:center;width:43px;height:43px;border-radius:9px;background:#303c5c;color:#a5baff;font-size:9px;font-weight:900;letter-spacing:1px}.vt-search-inner strong,.vt-search-inner small{display:block}.vt-search-inner strong{font-size:13px}.vt-search-inner small{color:var(--muted);font-size:11px;margin-top:3px}.vt-search-inner .primary{margin-left:auto;white-space:nowrap}.layout{min-height:calc(100vh - 137px)}.sidebar{position:fixed;left:0;top:137px;bottom:0;width:230px;padding:22px 13px;background:var(--side);border-right:1px solid var(--border);display:flex;flex-direction:column;z-index:10;overflow-y:auto}.caption{font-size:9px;color:var(--muted);letter-spacing:1.5px;font-weight:800;padding:0 10px;margin:0 0 9px}.nav{display:flex;gap:10px;align-items:center;text-align:left;border:1px solid transparent;border-radius:7px;background:none;color:var(--muted);padding:10px;width:100%;margin:2px 0;font-size:12px}.nav:hover{background:var(--panel);color:var(--text)}.nav.active{background:#2b3144;border-color:#424c68;color:var(--text)}.nav-icon{display:inline-grid;place-items:center;width:29px;height:25px;border-radius:5px;background:var(--panel2);border:1px solid var(--border);color:#9db2ff;font-size:8px;font-weight:900;letter-spacing:.3px;flex-shrink:0}.nav.active .nav-icon{background:#394b7a;border-color:#536cae;color:#fff}.system-caption{margin-top:25px}.side-bottom{margin-top:auto;padding:13px 10px;border:1px solid var(--border);border-radius:8px;font-size:11px;background:var(--panel)}.side-bottom small{display:block;color:var(--muted);margin-top:7px}.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--amber);margin-right:7px}.dot.online{background:var(--green);box-shadow:0 0 8px #65deb155}.dot.offline{background:var(--red)}.connection{font-size:10px;color:var(--muted);border:1px solid var(--border);padding:7px 9px;border-radius:20px;white-space:nowrap}.content{margin-left:230px;max-width:1600px;padding:27px 30px 20px}.page{display:none;animation:fadein .24s ease}.page.active{display:block}@keyframes fadein{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:translateY(0)}}.page-heading{display:flex;align-items:center;justify-content:space-between;gap:15px;margin-bottom:22px}.eyebrow{font-size:9px;color:#8ca7ff;font-weight:800;letter-spacing:1.5px}h1{font-size:27px;letter-spacing:-.5px;line-height:1.25;margin:7px 0}.muted{color:var(--muted);font-size:11px;margin:0}.hero{display:flex;justify-content:space-between;align-items:center;gap:18px;padding:21px 23px;border:1px solid #3a4665;border-radius:10px;background:linear-gradient(110deg,#242c43,#202330);margin-bottom:21px}.hero h2{font-size:17px;margin:6px 0}.hero p{color:#c2c9dc;font-size:11px;margin:0}.hero .primary{white-space:nowrap}.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:13px;margin-bottom:19px}.stat,.panel{background:var(--panel);border:1px solid var(--border);border-radius:9px;min-width:0}.stat{padding:16px;transition:transform .18s,border-color .18s}.stat:hover{transform:translateY(-2px);border-color:#687db8}.stat-top{display:flex;align-items:center;justify-content:space-between;gap:7px}.stat-mark{display:grid;place-items:center;width:29px;height:25px;border-radius:5px;background:var(--panel2);border:1px solid var(--border);font-size:8px;font-weight:900;color:#a4b5ff}.stat-label{font-size:8px;color:var(--muted);letter-spacing:.6px;font-weight:800}.stat strong{display:block;font-size:30px;letter-spacing:-.8px;margin:10px 0 1px}.stat small{font-size:10px;color:var(--muted)}.red strong{color:var(--red)}.amber strong{color:var(--amber)}.purple strong{color:var(--purple)}.columns{display:grid;grid-template-columns:minmax(0,1.5fr) minmax(260px,.9fr);gap:14px;margin-top:14px}.panel{padding:17px}.section-title{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:0 0 12px}.section-title h2,.panel h2{font-size:13px;margin:0 0 4px}.link{background:none;border:0;color:#9eb3ff;font-size:10px}.table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;text-align:left;white-space:nowrap}th{font-size:9px;color:var(--muted);font-weight:700;background:var(--panel2)}td,th{padding:11px 9px;border-bottom:1px solid var(--border);font-size:10px}td{color:var(--muted)}td:first-child{color:var(--text);max-width:240px;overflow:hidden;text-overflow:ellipsis}tbody tr:hover{background:var(--panel2)}tbody tr:last-child td{border-bottom:0}.badge{display:inline-block;border-radius:4px;padding:3px 7px;font-size:8px;font-weight:800;letter-spacing:.4px;border:1px solid var(--border)}.badge.malicious{color:var(--red);background:#ff777f0d;border-color:#ff777f40}.badge.suspicious{color:var(--amber);border-color:#f3c36c40}.badge.no_detections,.badge.safe{color:var(--green);border-color:#65deb140}.badge.unknown,.badge.pending,.badge.error{color:var(--muted)}.breakdown{display:grid;gap:15px;margin:20px 0}.bar-head{display:flex;justify-content:space-between;font-size:10px;margin-bottom:6px}.bar-head span{color:var(--muted)}.bar{height:5px;background:var(--panel2);border-radius:6px;overflow:hidden}.bar i{display:block;height:100%;border-radius:6px;transition:width .5s}.notice{margin-top:15px;padding:10px;border-radius:6px;background:#f3c36c0b;color:var(--muted);font-size:10px;border:1px solid #f3c36c25;line-height:1.6}.scan-panel{max-width:1000px}.tabs{display:flex;gap:5px;border-bottom:1px solid var(--border);margin:-2px 0 19px;padding-bottom:8px}.tab{background:none;color:var(--muted);border:0;border-bottom:2px solid transparent;padding:9px 15px;font-size:10px;font-weight:800}.tab.active{color:#a9bcff;border-bottom-color:#849cff}.scan-panel form{max-width:780px}.scan-panel label{display:block;font-size:11px;font-weight:700;margin:12px 0 7px}.scan-panel input,.toolbar input,.toolbar select{width:100%;min-height:40px;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:10px 11px;color:var(--text);font-size:11px}.scan-panel form small{display:block;color:var(--muted);font-size:10px;margin-top:7px}.full{margin-top:15px;min-width:170px}.hidden{display:none!important}.loading{display:flex;align-items:center;gap:10px;margin-top:17px;padding:12px;border:1px solid var(--border);border-radius:7px;color:var(--muted);font-size:11px}.spinner{width:17px;height:17px;border:2px solid #849cff30;border-top-color:#849cff;border-radius:50%;animation:spin .8s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}.result{margin-top:18px;padding:16px;border:1px solid var(--border);border-radius:8px;background:var(--panel2);animation:fadein .25s}.result h2{font-size:14px;margin:0 0 8px}.result p{font-size:10px;color:var(--muted);overflow-wrap:anywhere}.result-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;margin:12px 0}.result-grid div{padding:9px;border:1px solid var(--border);border-radius:6px}.result-grid small,.result-grid b{display:block}.result-grid small{font-size:9px;color:var(--muted)}.result-grid b{font-size:17px;margin-top:4px}.details{font-size:10px;color:var(--muted);overflow-wrap:anywhere}.result-actions,.report-actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}.workflow-panel,.report-note{margin-top:14px}.toolbar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:13px}.toolbar input{flex:1 1 190px}.toolbar select{width:auto;min-width:145px}.count{padding-top:12px}.setting{display:flex;align-items:center;justify-content:space-between;gap:15px;margin:11px 0;padding:15px}.setting p{margin:5px 0 0}.setting strong{font-size:10px;color:#9eb3ff}.toasts{position:fixed;right:18px;bottom:18px;z-index:50;display:grid;gap:8px;width:min(340px,calc(100vw - 30px))}.toast{background:var(--panel2);border:1px solid var(--border);padding:12px;border-radius:8px;box-shadow:0 10px 35px #0004;font-size:10px;animation:fadein .2s}.toast b,.toast span{display:block}.toast b{margin-bottom:4px}.toast span{color:var(--muted);overflow-wrap:anywhere}.toast.error{border-color:#ff777f66}.toast.success{border-color:#65deb166}footer{display:flex;justify-content:space-between;gap:10px;border-top:1px solid var(--border);margin-top:25px;padding:15px 0;color:var(--muted);font-size:9px}
@media(max-width:1100px){.vt-brand{min-width:auto}.vt-topbar{gap:15px;padding:0 17px}.stats{grid-template-columns:repeat(2,minmax(0,1fr))}.columns{grid-template-columns:minmax(0,1fr)}}@media(max-width:800px){.vt-topbar{height:auto;min-height:61px;flex-wrap:wrap;padding:10px 13px;gap:10px}.vt-brand{flex:1}.vt-topnav{order:3;width:100%;height:38px;overflow:auto}.topnav{padding:0 12px;white-space:nowrap}.vt-search-strip{padding:12px}.vt-search-inner small{display:none}.sidebar{top:112px;width:205px;transform:translateX(-105%);box-shadow:0 15px 40px #0006;transition:transform .2s}.sidebar.open{transform:translateX(0)}.content{margin-left:0;padding:21px 14px}.vt-top-actions{margin-left:0}.hero{align-items:flex-start;flex-direction:column}.hero .primary{align-self:flex-start}.connection{font-size:0}.connection .dot{margin:0}}@media(max-width:480px){.vt-brand{font-size:18px}.vt-mark{width:33px;height:33px}.vt-top-actions .icon-btn{font-size:0;padding:8px}.vt-top-actions .icon-btn:after{content:"T";font-size:12px}.vt-search-inner{gap:9px}.vt-search-inner strong{font-size:11px}.vt-search-inner .primary{font-size:0;padding:9px}.vt-search-inner .primary:after{content:"+";font-size:18px}.stats{gap:8px}.stat{padding:11px}.stat strong{font-size:26px}.stat-label{font-size:7px}.result-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.panel{padding:13px}.setting{align-items:flex-start;flex-direction:column}footer{flex-direction:column}.page-heading{align-items:flex-start}}@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.01ms!important;animation-iteration-count:1!important;transition-duration:.01ms!important;scroll-behavior:auto!important}}@media print{.vt-topbar,.vt-search-strip,.sidebar,button,footer{display:none!important}.content{margin:0}.page{display:none!important}.page.active{display:block!important}.panel,.result{background:#fff;color:#111;box-shadow:none}}
'@
Set-Content ".\static\css\style.css" $css -Encoding UTF8

# Preserve existing app.js interactions; ensure top navigation buttons are wired to the same page navigation.
$jsPath = ".\static\js\app.js"
$js = Get-Content $jsPath -Raw
if ($js -notmatch 'vt-topnav') {
    $js += @'

// Additional top navigation for the VirusTotal-inspired ScanR layout.
document.querySelectorAll(".topnav[data-page]").forEach(button => {
  button.addEventListener("click", () => {
    const name = button.dataset.page;
    document.querySelectorAll(".page").forEach(page => page.classList.toggle("active", page.id === "page-" + name));
    document.querySelectorAll(".nav[data-page]").forEach(nav => nav.classList.toggle("active", nav.dataset.page === name));
    document.querySelectorAll(".topnav[data-page]").forEach(nav => nav.classList.toggle("active", nav === button));
    const pageName = document.getElementById("pageName");
    if (pageName) pageName.textContent = name.charAt(0).toUpperCase() + name.slice(1);
    try { history.replaceState(null, "", "#" + name); } catch (_) {}
    if (name === "history" || name === "overview") {
      const refresh = document.getElementById("refresh");
      if (refresh && name === "overview") refresh.click();
      else if (name === "history") document.querySelector('[data-page="history"].nav')?.click();
    }
  });
});
'@
    Set-Content $jsPath $js -Encoding UTF8
}

& $Python -m compileall -q app.py scanner database
if ($LASTEXITCODE -ne 0) { throw "Python syntax check failed. Backup: $backup" }

Write-Host ""
Write-Host "ScanR VirusTotal-inspired UI installed." -ForegroundColor Green
Write-Host "Backup: $backup"
Write-Host "Restart Flask: press Ctrl+C in its terminal, then run:" -ForegroundColor Yellow
Write-Host '  & ".\.venv\Scripts\python.exe" app.py'
Write-Host "Open http://127.0.0.1:5000 and press Ctrl+F5."
Write-Host "This is an original ScanR UI inspired by threat-intelligence portals, not a copy of VirusTotal's private bundled application."
