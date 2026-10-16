$ErrorActionPreference = "Stop"
$ProjectPath = (Get-Location).Path
$Python = Join-Path $ProjectPath ".venv\Scripts\python.exe"

if (!(Test-Path (Join-Path $ProjectPath "app.py"))) {
    throw "Open PowerShell in B:\mine project\ScanR before running this script."
}
if (!(Test-Path (Join-Path $ProjectPath "templates\index.html"))) {
    throw "templates\index.html was not found."
}
if (!(Test-Path (Join-Path $ProjectPath "static\css\style.css"))) {
    throw "static\css\style.css was not found."
}

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backup = Join-Path $ProjectPath "backups\ui_reference_style_$stamp"
New-Item -ItemType Directory -Force -Path (Join-Path $backup "templates"), (Join-Path $backup "static\css") | Out-Null
Copy-Item ".\templates\index.html" (Join-Path $backup "templates\index.html") -Force
Copy-Item ".\static\css\style.css" (Join-Path $backup "static\css\style.css") -Force
Write-Host "Backup created: $backup" -ForegroundColor Green

# ASCII-only interface copy avoids broken glyphs in terminals/editors with inconsistent encodings.
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
  <a class="brand" href="#overview"><span class="logo">S</span><span>Scan<span class="cyan">R</span><small>THREAT INTELLIGENCE</small></span></a>
  <p class="caption">WORKSPACE</p>
  <button class="nav active" data-page="overview"><span class="nav-icon">OV</span><span>Overview</span></button>
  <button class="nav" data-page="scanner"><span class="nav-icon">SC</span><span>Quick Scan</span></button>
  <button class="nav" data-page="history"><span class="nav-icon">HI</span><span>Scan History</span></button>
  <button class="nav" data-page="reports"><span class="nav-icon">RP</span><span>Reports</span></button>
  <p class="caption system-caption">SYSTEM</p>
  <button class="nav" data-page="settings"><span class="nav-icon">ST</span><span>Settings</span></button>
  <div class="side-bottom"><span class="dot" id="apiDot"></span><span id="apiLabel">Checking API...</span><small>ScanR | Phase 3</small></div>
</aside>
<main>
<header class="topbar">
  <button class="menu" id="menu" aria-label="Open navigation">MENU</button>
  <div><div class="crumb">Workspace / <b id="pageName">Overview</b></div><small>Threat intelligence and security analysis</small></div>
  <div class="top-actions"><span class="connection"><i id="connectionDot" class="dot"></i><span id="connectionText">Connecting</span></span><button id="theme" class="icon-btn" title="Toggle theme">THEME</button><button class="primary" data-goto="scanner">+ New Scan</button></div>
</header>
<div class="content">
<section class="page active" id="page-overview">
  <div class="eyebrow">SECURITY OVERVIEW / LIVE WORKSPACE</div><h1>Security <span class="gradient">Dashboard</span></h1>
  <p class="muted">A clear view of real scan activity from your local ScanR backend.</p>
  <div class="hero"><div class="hero-copy"><div class="eyebrow">SCANR SECURITY ENGINE</div><h2 id="heroTitle">Your security workspace</h2><p id="heroText">Connect to the backend to start analyzing targets.</p><div class="hero-tags"><span>URL reputation</span><span>Hash lookup</span><span>Scan history</span></div></div><button class="secondary" data-goto="scanner">Start scanning &gt;</button></div>
  <div class="section-title"><div><h2>Scan Overview</h2><p class="muted">Statistics from saved records - no sample data</p></div><button class="secondary" id="refresh">Refresh</button></div>
  <div class="stats">
    <article class="stat"><div class="stat-top"><span class="stat-mark">ALL</span><span class="stat-label">TOTAL SCANS</span></div><strong id="total">-</strong><small>Saved database records</small></article>
    <article class="stat red"><div class="stat-top"><span class="stat-mark">MAL</span><span class="stat-label">MALICIOUS</span></div><strong id="malicious">-</strong><small>Classified malicious</small></article>
    <article class="stat amber"><div class="stat-top"><span class="stat-mark">SUS</span><span class="stat-label">SUSPICIOUS</span></div><strong id="suspicious">-</strong><small>Classified suspicious</small></article>
    <article class="stat purple"><div class="stat-top"><span class="stat-mark">UNK</span><span class="stat-label">UNKNOWN / PENDING</span></div><strong id="unknown">-</strong><small>Needs further review</small></article>
  </div>
  <div class="columns">
    <section class="panel"><div class="section-title"><div><h2>Recent scans</h2><p class="muted">Latest records from your local database</p></div><button class="link" data-goto="history">View all &gt;</button></div><div class="table-wrap"><table><thead><tr><th>Target</th><th>Type</th><th>Risk</th><th>Time</th></tr></thead><tbody id="recent"><tr><td colspan="4">Loading history...</td></tr></tbody></table></div></section>
    <section class="panel"><h2>Detection breakdown</h2><p class="muted">Classification of saved scans</p><div id="breakdown" class="breakdown">Loading...</div><p class="notice">Important: no detections does not prove a target is safe.</p></section>
  </div>
</section>
<section class="page" id="page-scanner">
  <div class="eyebrow">ANALYSIS WORKSPACE</div><h1>Quick <span class="gradient">Scan</span></h1><p class="muted">Analyze a URL, check a file hash, or look up a known hash.</p>
  <div class="columns scanner-columns">
    <section class="panel scan-panel">
      <div class="tabs"><button class="tab active" data-tab="url">URL SCAN</button><button class="tab" data-tab="file">FILE HASH</button><button class="tab" data-tab="hash">HASH LOOKUP</button></div>
      <form id="urlForm"><label for="url">Website URL</label><input id="url" type="url" placeholder="https://example.com" required><small>Enter a complete HTTP or HTTPS URL.</small><button class="primary full" type="submit">Analyze URL</button></form>
      <form id="fileForm" class="hidden"><label for="file">Select a file (max 10 MB)</label><input id="file" type="file" required><small>The browser calculates SHA-256. This form does not upload the file contents.</small><button class="primary full" type="submit">Calculate SHA-256 and check report</button></form>
      <form id="hashForm" class="hidden"><label for="hash">File hash</label><input id="hash" placeholder="MD5, SHA-1 or SHA-256" required><small>Paste a hexadecimal hash for a reputation lookup.</small><button class="primary full" type="submit">Check hash</button></form>
      <div id="loading" class="loading hidden"><span class="spinner"></span> Analyzing target...</div>
      <div id="result" class="result hidden" aria-live="polite"></div>
    </section>
    <aside class="panel"><div class="eyebrow">WORKFLOW</div><h2>How ScanR works</h2><div class="step"><b>01</b><div><strong>Submit target</strong><small>Provide a URL, file or hash.</small></div></div><div class="step"><b>02</b><div><strong>Check available evidence</strong><small>Validation and VirusTotal reputation lookup.</small></div></div><div class="step"><b>03</b><div><strong>Review findings</strong><small>Read the result and its limitations.</small></div></div><p class="notice">Private file contents are not automatically uploaded by this interface.</p></aside>
  </div>
</section>
<section class="page" id="page-history">
  <div class="eyebrow">ACTIVITY LOG</div><h1>Scan <span class="gradient">History</span></h1><p class="muted">Saved records from your local SQLite database.</p>
  <section class="panel"><div class="toolbar"><input id="search" type="search" placeholder="Search target, type or status"><select id="filter"><option value="all">All risks</option><option value="malicious">Malicious</option><option value="suspicious">Suspicious</option><option value="unknown">Unknown / pending</option><option value="no_detections">No detections</option></select><button id="exportHistory" class="secondary">Export JSON</button></div><div class="table-wrap"><table><thead><tr><th>ID</th><th>Target</th><th>Type</th><th>Status</th><th>Risk</th><th>Time</th></tr></thead><tbody id="history"><tr><td colspan="6">Loading history...</td></tr></tbody></table></div><p class="muted count" id="count"></p></section>
</section>
<section class="page" id="page-reports">
  <div class="eyebrow">SECURITY DOCUMENTATION</div><h1>Scan <span class="gradient">Reports</span></h1><p class="muted">Export a JSON report or print a formatted report to PDF.</p>
  <div class="columns"><section class="panel"><h2>Latest scan report</h2><p class="muted">Run a scan first, then export its result.</p><div class="report-actions"><button id="reportJson" class="primary">Export latest JSON</button><button id="reportPdf" class="secondary">Print / Save PDF</button></div></section><section class="panel"><h2>History export</h2><p class="muted">Download loaded scan history as JSON.</p><button id="reportHistory" class="secondary">Export history JSON</button></section></div>
  <section class="panel report-note"><h2>Report interpretation</h2><p class="muted">Reports show available classifications, scan IDs and detection counts. Unknown or pending findings must not be interpreted as safe.</p></section>
</section>
<section class="page" id="page-settings">
  <div class="eyebrow">PREFERENCES</div><h1>Application <span class="gradient">Settings</span></h1><p class="muted">Current service and interface status.</p>
  <div class="panel setting"><div><b>Flask API</b><p class="muted">Local backend connection</p></div><strong id="settingApi">Checking...</strong></div>
  <div class="panel setting"><div><b>VirusTotal configuration</b><p class="muted">The API key is never displayed here.</p></div><strong id="settingVt">Checking...</strong></div>
  <div class="panel setting"><div><b>Appearance</b><p class="muted">Switch between dark and light mode.</p></div><button class="secondary" id="theme2">Toggle theme</button></div>
  <div class="panel setting"><div><b>Scan history</b><p class="muted">Records are stored in the local SQLite database.</p></div><strong>LOCAL</strong></div>
</section>
<footer><span>ScanR | <span id="year"></span></span><span>Evidence-based results | No AI/ML predictions</span></footer>
</div>
</main>
</div>
<div id="toasts" class="toasts" aria-live="polite"></div>
</body>
</html>
'@
Set-Content ".\templates\index.html" $html -Encoding UTF8

# Append a visual refinement layer; existing functional CSS and responsive rules are preserved.
$polish = @'

/* ScanR reference-inspired visual refinement */
.brand{letter-spacing:-.5px}.logo{font-size:22px;font-weight:900;box-shadow:0 0 25px #59e0e515}
.nav{gap:11px;min-height:43px}.nav-icon{display:inline-grid;place-items:center;width:29px;height:27px;border-radius:8px;background:var(--panel2);border:1px solid var(--border);color:var(--cyan);font-size:8px;font-weight:900;letter-spacing:.4px;flex-shrink:0}.nav.active .nav-icon{background:#1c4960;border-color:#2b7187;color:#fff}
.system-caption{margin-top:28px}.topbar{box-shadow:0 5px 25px #00008}.content{max-width:1600px}.hero{position:relative;overflow:hidden;min-height:150px}.hero:after{content:"";position:absolute;width:210px;height:210px;border:1px solid #59e0e51c;border-radius:50%;right:12%;top:-135px;box-shadow:0 0 0 25px #59e0e508,0 0 0 50px #59e0e506;pointer-events:none}.hero-copy{position:relative;z-index:1}.hero-tags{display:flex;flex-wrap:wrap;gap:7px;margin-top:16px}.hero-tags span{font-size:9px;color:#b6d4e6;padding:5px 8px;border:1px solid #35506a;border-radius:20px;background:#0c1727aa}.hero .secondary{position:relative;z-index:1;white-space:nowrap}
.stat{position:relative;min-height:143px}.stat:after{content:"";position:absolute;right:-30px;bottom:-45px;width:110px;height:110px;border-radius:50%;border:1px solid #7caaff10;box-shadow:0 0 0 13px #7caaff04;pointer-events:none}.stat-top{display:flex;align-items:center;justify-content:space-between;gap:8px}.stat-mark{display:grid;place-items:center;width:32px;height:29px;border-radius:8px;background:var(--panel2);border:1px solid var(--border);font-size:8px!important;font-weight:900;color:var(--cyan)!important;letter-spacing:.5px}.stat-label{font-size:9px!important;letter-spacing:.7px;font-weight:800}.stat strong{font-size:35px;margin:12px 0 1px;position:relative;z-index:1}.stat small{position:relative;z-index:1}.panel{box-shadow:0 8px 25px #00005}.panel .section-title{margin-top:0}.table-wrap table tbody tr{transition:background .15s}.table-wrap tbody tr:hover{background:var(--panel2)}.table-wrap tbody tr:last-child td{border-bottom:0}.badge{letter-spacing:.4px}.primary,.secondary,.icon-btn{min-height:38px}.primary{box-shadow:0 5px 16px #59a6ff17}.tabs{gap:7px}.tab{letter-spacing:.3px}.scan-panel{padding:22px}.report-actions{display:flex;gap:9px;flex-wrap:wrap;margin-top:18px}.setting{box-shadow:none}.side-bottom{background:linear-gradient(130deg,var(--panel),transparent)}.eyebrow{letter-spacing:1.5px}.section-title h2,.panel h2{letter-spacing:-.2px}.notice{line-height:1.6}.toasts .toast{backdrop-filter:blur(14px)}
@media(max-width:800px){.hero:after{right:-70px}.hero-tags{gap:5px}.stat{min-height:128px}}
@media(max-width:480px){.hero-tags span{font-size:8px}.stat-label{font-size:8px!important}.nav-icon{width:26px}.topbar .menu{font-size:9px;padding:9px}.connection{padding:7px}.hero{padding:18px}}
'@
Add-Content ".\static\css\style.css" $polish -Encoding UTF8

# Confirm Python syntax and expected frontend element IDs before finishing.
& $Python -m compileall -q app.py scanner database
if ($LASTEXITCODE -ne 0) { throw "Python syntax check failed. Backup: $backup" }

$htmlCheck = Get-Content ".\templates\index.html" -Raw
foreach ($id in @("page-overview","page-scanner","page-history","page-reports","page-settings","urlForm","fileForm","hashForm","recent","history","breakdown","apiDot","theme","theme2")) {
    if ($htmlCheck -notmatch ('id="' + [regex]::Escape($id) + '"')) {
        throw "Expected frontend element missing: $id. Restore from backup: $backup"
    }
}
Write-Host ""
Write-Host "ScanR UI style update completed." -ForegroundColor Green
Write-Host "Backup: $backup"
Write-Host "Next: press Ctrl+C in the Flask terminal, then run:" -ForegroundColor Yellow
Write-Host '  & ".\.venv\Scripts\python.exe" app.py'
Write-Host "Open http://127.0.0.1:5000 and press Ctrl+F5."
Write-Host "This updates the dashboard appearance and text only; it does not claim to test all scan/report workflows."
