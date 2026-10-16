// ScanR URL Protection - service worker (MV3)
// Key stays in backend. This only talks to YOUR ScanR backend.
const BACKEND = "http://127.0.0.1:5000";
const TIMEOUT_MS = 3000;          // slow/unreachable backend => fail-open
const VERDICT_TTL_MS = 10 * 60 * 1000;
const ALLOW_TTL_MS = 30 * 60 * 1000;
const MAX_POLLS = 8;              // 8 x 30s = ~4 min of waiting for VT
const BLOCK = new Set(["malicious", "suspicious"]);
const WARNING_BASE = chrome.runtime.getURL("warning.html");

async function sget(key) {
  const o = await chrome.storage.session.get(key);
  return o[key] || {};
}
async function sset(key, val) {
  await chrome.storage.session.set({ [key]: val });
}

async function checkUrl(url) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), TIMEOUT_MS);
  try {
    const r = await fetch(BACKEND + "/api/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: ctl.signal,
    });
    if (!r.ok) return { verdict: "error" };
    return await r.json();
  } catch (e) {
    return { verdict: "error" };          // fail-open
  } finally {
    clearTimeout(t);
  }
}

function warningUrl(url, res) {
  const q = new URLSearchParams({ u: url, v: res.verdict, d: res.detail || "" });
  return WARNING_BASE + "?" + q.toString();
}

async function isAllowed(url) {
  const allowed = await sget("allowed");
  return allowed[url] && allowed[url] > Date.now();
}

async function addPending(tabId, url) {
  const p = await sget("pending");
  p[url] = { tabId, tries: 0 };
  await sset("pending", p);
  chrome.alarms.create("scanr-poll", { periodInMinutes: 0.5 });
}

async function handle(tabId, url, res) {
  if (BLOCK.has(res.verdict)) {
    if (await isAllowed(url)) return;
    chrome.tabs.update(tabId, { url: warningUrl(url, res) });
  } else if (res.verdict === "pending") {
    await addPending(tabId, url);
  }
}

chrome.webNavigation.onBeforeNavigate.addListener(async (d) => {
  if (d.frameId !== 0) return;
  const url = d.url;
  if (!/^https?:/i.test(url) || url.startsWith(BACKEND)) return;
  if (await isAllowed(url)) return;

  const memo = await sget("verdicts");
  const hit = memo[url];
  let res;
  if (hit && hit.exp > Date.now()) {
    res = hit.res;
  } else {
    res = await checkUrl(url);
    if (res.verdict !== "error" && res.verdict !== "pending") {
      memo[url] = { res, exp: Date.now() + VERDICT_TTL_MS };
      await sset("verdicts", memo);
    }
  }
  await handle(d.tabId, url, res);
});

chrome.alarms.onAlarm.addListener(async (a) => {
  if (a.name !== "scanr-poll") return;
  const pending = await sget("pending");
  const urls = Object.keys(pending);
  if (!urls.length) { chrome.alarms.clear("scanr-poll"); return; }
  for (const url of urls) {
    const item = pending[url];
    const res = await checkUrl(url);
    if (res.verdict === "pending" && ++item.tries < MAX_POLLS) continue;
    delete pending[url];
    if (BLOCK.has(res.verdict)) {
      try {
        const tab = await chrome.tabs.get(item.tabId);
        if (tab.url === url && !(await isAllowed(url))) {
          chrome.tabs.update(item.tabId, { url: warningUrl(url, res) });
        }
      } catch (e) { /* tab closed */ }
    }
  }
  await sset("pending", pending);
});

// messages from warning page
chrome.runtime.onMessage.addListener((msg, sender, send) => {
  if (sender.id !== chrome.runtime.id) return;
  (async () => {
    if (msg.type === "allow" && /^https?:/i.test(msg.url)) {
      const allowed = await sget("allowed");
      allowed[msg.url] = Date.now() + ALLOW_TTL_MS;
      await sset("allowed", allowed);
    }
    if (msg.type === "goback" && sender.tab) {
      chrome.tabs.update(sender.tab.id, { url: "chrome://newtab/" });
    }
    send({ ok: true });
  })();
  return true;
});
