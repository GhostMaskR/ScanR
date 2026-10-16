"""
ScanR URL Protection backend  (NEW FILE - existing code untouched)

Register in app.py with exactly two lines (before app.run):
    from protection import protection_bp
    app.register_blueprint(protection_bp)

Check order (cheapest first, VT is LAST):
    skip rules -> allowlist -> local blocklist/feeds -> SQLite cache -> VT queue
VT key stays in backend .env only (VT_API_KEY or VIRUSTOTAL_API_KEY).
"""
import base64
import ipaddress
import os
import sqlite3
import threading
import time
from urllib.parse import urlsplit

import requests
from flask import Blueprint, jsonify, request

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

protection_bp = Blueprint("protection", __name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "protection_cache.db")
BLOCKLIST_FILE = os.path.join(BASE_DIR, "blocklist.txt")   # manual: one host per line
FEED_FILE = os.path.join(BASE_DIR, "feed_urls.txt")         # from update_feeds.py: one URL per line

VT_KEY = (os.getenv("VT_API_KEY") or os.getenv("VIRUSTOTAL_API_KEY")
          or os.getenv("VT_KEY") or "")
VT_MIN_GAP = 16          # seconds between VT calls (free key = 4/min)
VT_DAILY_CAP = 450       # keep headroom under the 500/day limit
MAX_RETRIES = 4

# TTL per verdict (seconds)
TTL = {"clean": 24 * 3600, "suspicious": 6 * 3600, "malicious": 6 * 3600}

# Big trusted domains. NOTE: never add user-content hosts (github.io, blogspot.com,
# sites.google.com, etc.) - attackers host phishing there.
ALLOWLIST = {
    "google.com", "youtube.com", "microsoft.com", "live.com", "office.com",
    "apple.com", "amazon.com", "wikipedia.org", "github.com", "stackoverflow.com",
    "mozilla.org", "cloudflare.com", "linkedin.com", "python.org", "npmjs.com",
    "tryhackme.com", "portswigger.net", "virustotal.com", "anthropic.com",
}

_lock = threading.Lock()
_jobs = []               # [{"url","stage","not_before","tries"}]
_pending = set()
_worker_started = False
_last_vt_call = 0.0


# ---------------------------------------------------------------- helpers
def _db():
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.execute("CREATE TABLE IF NOT EXISTS cache("
                "url TEXT PRIMARY KEY, verdict TEXT, detail TEXT, source TEXT, ts REAL)")
    con.execute("CREATE TABLE IF NOT EXISTS quota(day TEXT PRIMARY KEY, n INTEGER)")
    return con


def normalize(raw):
    """Return (normalized_url, host) or (None, reason) if it should be skipped."""
    try:
        p = urlsplit(raw.strip())
    except ValueError:
        return None, "bad url"
    if p.scheme not in ("http", "https") or not p.hostname:
        return None, "not http(s)"
    host = p.hostname.lower().rstrip(".")
    if host in ("localhost",) or host.endswith((".local", ".internal", ".lan")):
        return None, "local host"
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return None, "private ip"
    except ValueError:
        pass
    port = f":{p.port}" if p.port and p.port not in (80, 443) else ""
    path = p.path or "/"
    q = f"?{p.query}" if p.query else ""
    return f"{p.scheme}://{host}{port}{path}{q}", host


def _host_in(host, domains):
    return any(host == d or host.endswith("." + d) for d in domains)


_file_cache = {}
def _load_lines(path):
    """Load a text file into a set, reloading only when mtime changes."""
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return set()
    hit = _file_cache.get(path)
    if hit and hit[0] == mtime:
        return hit[1]
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        data = {ln.strip().lower().rstrip("/") for ln in f
                if ln.strip() and not ln.startswith("#")}
    _file_cache[path] = (mtime, data)
    return data


def _cache_get(url):
    con = _db()
    try:
        row = con.execute("SELECT verdict,detail,source,ts FROM cache WHERE url=?", (url,)).fetchone()
    finally:
        con.close()
    if row and time.time() - row[3] < TTL.get(row[0], 0):
        return {"verdict": row[0], "detail": row[1], "source": row[2] or "cache"}
    return None


def _cache_put(url, verdict, detail, source):
    con = _db()
    try:
        con.execute("INSERT OR REPLACE INTO cache VALUES(?,?,?,?,?)",
                    (url, verdict, detail, source, time.time()))
        con.commit()
    finally:
        con.close()


def _quota_used():
    day = time.strftime("%Y-%m-%d", time.gmtime())
    con = _db()
    try:
        row = con.execute("SELECT n FROM quota WHERE day=?", (day,)).fetchone()
    finally:
        con.close()
    return row[0] if row else 0


def _quota_inc():
    day = time.strftime("%Y-%m-%d", time.gmtime())
    con = _db()
    try:
        con.execute("INSERT INTO quota VALUES(?,1) ON CONFLICT(day) DO UPDATE SET n=n+1", (day,))
        con.commit()
    finally:
        con.close()


# ---------------------------------------------------------------- VT worker
def _vt_verdict(stats):
    mal = stats.get("malicious", 0)
    sus = stats.get("suspicious", 0)
    if mal >= 3:
        return "malicious"
    if mal >= 1 or sus >= 2:
        return "suspicious"
    return "clean"          # means "no detections found", NOT "safe"


def _vt_call(method, path, **kw):
    global _last_vt_call
    wait = VT_MIN_GAP - (time.time() - _last_vt_call)
    if wait > 0:
        time.sleep(wait)
    _last_vt_call = time.time()
    _quota_inc()
    return requests.request(method, "https://www.virustotal.com/api/v3" + path,
                            headers={"x-apikey": VT_KEY}, timeout=20, **kw)


def _process(job):
    url = job["url"]
    uid = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    r = _vt_call("GET", f"/urls/{uid}")
    if r.status_code == 200:
        attr = r.json().get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats") or {}
        if attr.get("last_analysis_date") and sum(stats.values()) > 0:
            v = _vt_verdict(stats)
            detail = f"VT: {stats.get('malicious', 0)} malicious, {stats.get('suspicious', 0)} suspicious"
            _cache_put(url, v, detail, "virustotal")
            return True
        job["stage"] = "wait"          # submitted but analysis not ready yet
    elif r.status_code == 404:
        if job["stage"] != "wait":
            _vt_call("POST", "/urls", data={"url": url})
        job["stage"] = "wait"
    elif r.status_code == 429:
        job["not_before"] = time.time() + 65
        return False
    else:
        job["tries"] = MAX_RETRIES      # auth error etc. -> give up
    job["tries"] += 1
    job["not_before"] = time.time() + 25
    return job["tries"] >= MAX_RETRIES  # True = finished/give up


def _worker():
    while True:
        job = None
        with _lock:
            now = time.time()
            for j in _jobs:
                if j["not_before"] <= now:
                    job = j
                    break
        if not job:
            time.sleep(1)
            continue
        if _quota_used() >= VT_DAILY_CAP:
            with _lock:
                _jobs.remove(job)
                _pending.discard(job["url"])
            continue
        try:
            done = _process(job)
        except Exception:
            job["tries"] += 1
            job["not_before"] = time.time() + 30
            done = job["tries"] >= MAX_RETRIES
        if done:
            with _lock:
                if job in _jobs:
                    _jobs.remove(job)
                _pending.discard(job["url"])


def _enqueue(url):
    global _worker_started
    with _lock:
        if url in _pending:
            return
        _pending.add(url)
        _jobs.append({"url": url, "stage": "lookup", "not_before": 0, "tries": 0})
        if not _worker_started:
            threading.Thread(target=_worker, daemon=True).start()
            _worker_started = True


# ---------------------------------------------------------------- core check
def check_url(raw):
    url, host = normalize(raw)
    if not url:
        return {"verdict": "skipped", "detail": host, "source": "rules"}

    if _host_in(host, ALLOWLIST):
        return {"verdict": "allowlisted", "detail": "trusted domain", "source": "allowlist"}

    if _host_in(host, _load_lines(BLOCKLIST_FILE)):
        return {"verdict": "malicious", "detail": "host in local blocklist", "source": "blocklist"}

    if url.lower().rstrip("/") in _load_lines(FEED_FILE):
        return {"verdict": "malicious", "detail": "URL in threat feed", "source": "feed"}

    cached = _cache_get(url)
    if cached:
        return cached

    if not VT_KEY:
        return {"verdict": "unknown", "detail": "no VT key configured", "source": "none"}
    if _quota_used() >= VT_DAILY_CAP:
        return {"verdict": "quota", "detail": "VT daily quota reached", "source": "quota"}

    _enqueue(url)
    return {"verdict": "pending", "detail": "queued for VirusTotal", "source": "queue"}


@protection_bp.route("/api/check", methods=["POST", "GET"])
def api_check():
    data = request.get_json(silent=True) or {}
    raw = data.get("url") or request.args.get("url") or ""
    if not raw or len(raw) > 4096:
        return jsonify({"verdict": "skipped", "detail": "missing/oversized url"}), 400
    return jsonify(check_url(raw))


@protection_bp.route("/api/check/status")
def api_status():
    with _lock:
        n = len(_jobs)
    return jsonify({"vt_used_today": _quota_used(), "vt_cap": VT_DAILY_CAP,
                    "queue": n, "vt_key_loaded": bool(VT_KEY)})
