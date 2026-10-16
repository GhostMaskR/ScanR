"""
ScanR Downloads watcher (D1) - NEW FILE, runs as its own process.

    python file_watch.py                     # watch C:\\Users\\<you>\\Downloads
    python file_watch.py --dir "D:\\dl"      # watch another folder
    python file_watch.py --file C:\\x\\a.exe  # check one file once
    python file_watch.py --hash <sha256>     # check one hash (no file needed)

Rules:
 * Only the SHA-256 hash goes to VirusTotal. The file is NEVER uploaded.
 * Alert only. Never deletes / moves / quarantines anything.
 * Re-uses protection.py: same VT key, same SQLite cache, same daily quota counter.
 * "unknown" (hash not in VT) and "clean" (no detections) do NOT mean safe.
"""
import argparse
import ctypes
import hashlib
import os
import queue
import re
import sys
import threading
import time
from pathlib import Path

import requests

import protection as P          # VT_KEY, cache, quota counter, verdict rule

SKIP_EXT = {".crdownload", ".tmp", ".part", ".partial", ".download", ".opdownload"}
LOG_FILE = Path(__file__).with_name("watch_log.txt")
VT_GAP = 16                      # seconds between VT calls (free key = 4/min)

_vt_lock = threading.Lock()
_last_vt = 0.0
_seen = {}                       # path -> (size, mtime) already handled


# ------------------------------------------------------------------ output
def log(msg):
    line = time.strftime("%Y-%m-%d %H:%M:%S ") + msg
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


def notify(title, msg):
    """Windows toast (winotify) -> fallback message box. Never raises."""
    try:
        from winotify import Notification
        Notification(app_id="ScanR", title=title, msg=msg, duration="long").show()
        return
    except Exception:
        pass
    try:
        threading.Thread(
            target=lambda: ctypes.windll.user32.MessageBoxW(0, msg, title, 0x30 | 0x1000),
            daemon=True).start()
    except Exception:
        log("(notification unavailable) " + title + " - " + msg)


# ------------------------------------------------------------------ hashing
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def wait_stable(path, timeout=180):
    """True once the file size stops changing and the file can be opened."""
    end = time.time() + timeout
    last = -1
    while time.time() < end:
        try:
            size = os.path.getsize(path)
            with open(path, "rb"):
                pass
        except OSError:
            time.sleep(1.5)
            last = -1
            continue
        if size > 0 and size == last:
            return True
        last = size
        time.sleep(1.5)
    return False


# ------------------------------------------------------------------ VT lookup
def lookup(sha):
    key = "hash:" + sha
    cached = P._cache_get(key)
    if cached:
        return cached
    if not P.VT_KEY:
        return {"verdict": "unknown", "detail": "no VT key in .env", "source": "none"}

    global _last_vt
    for _ in range(3):
        if P._quota_used() >= P.VT_DAILY_CAP:
            return {"verdict": "quota", "detail": "VT daily quota reached", "source": "quota"}
        with _vt_lock:
            wait = VT_GAP - (time.time() - _last_vt)
            if wait > 0:
                time.sleep(wait)
            _last_vt = time.time()
            P._quota_inc()
            try:
                r = requests.get("https://www.virustotal.com/api/v3/files/" + sha,
                                 headers={"x-apikey": P.VT_KEY}, timeout=20)
            except requests.RequestException as e:
                return {"verdict": "error", "detail": "network: " + type(e).__name__, "source": "vt"}
        if r.status_code == 200:
            attr = r.json().get("data", {}).get("attributes", {})
            stats = attr.get("last_analysis_stats") or {}
            if sum(stats.values()) == 0:
                return {"verdict": "unknown", "detail": "VT has no analysis yet", "source": "vt"}
            v = P._vt_verdict(stats)
            detail = "VT: %d malicious, %d suspicious" % (stats.get("malicious", 0), stats.get("suspicious", 0))
            P._cache_put(key, v, detail, "virustotal")
            return {"verdict": v, "detail": detail, "source": "virustotal"}
        if r.status_code == 404:
            return {"verdict": "unknown",
                    "detail": "hash not in VirusTotal (file was NOT uploaded)", "source": "vt"}
        if r.status_code == 429:
            time.sleep(65)
            continue
        return {"verdict": "error", "detail": "VT HTTP %d" % r.status_code, "source": "vt"}
    return {"verdict": "error", "detail": "VT rate-limited", "source": "vt"}


# ------------------------------------------------------------------ handling
def report(name, sha, res):
    v = res["verdict"]
    log("%-10s %s  sha256=%s  (%s)" % (v.upper(), name, sha, res["detail"]))
    if v == "malicious":
        notify("ScanR: MALICIOUS file downloaded",
               "%s\n%s\nDo NOT open it. (ScanR did not delete it.)" % (name, res["detail"]))
    elif v == "suspicious":
        notify("ScanR: suspicious file downloaded",
               "%s\n%s\nBe careful before opening." % (name, res["detail"]))


def process(path):
    p = Path(path)
    if p.suffix.lower() in SKIP_EXT or p.name == LOG_FILE.name or p.name.startswith("~$"):
        return
    if not p.is_file():
        return
    if not wait_stable(p):
        log("SKIP       %s (file never became readable/stable)" % p.name)
        return
    try:
        st = p.stat()
        sig = (st.st_size, int(st.st_mtime))
        if _seen.get(str(p)) == sig:
            return
        _seen[str(p)] = sig
        sha = sha256_file(p)
    except OSError as e:
        log("SKIP       %s (%s)" % (p.name, e))
        return
    report(p.name, sha, lookup(sha))


# ------------------------------------------------------------------ watching
def watch(folder):
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer

    q = queue.Queue()

    class H(FileSystemEventHandler):
        def on_created(self, e):
            if not e.is_directory:
                q.put(e.src_path)

        def on_moved(self, e):            # browsers rename .crdownload -> final name
            if not e.is_directory:
                q.put(e.dest_path)

    def worker():
        while True:
            path = q.get()
            try:
                process(path)
            except Exception as ex:       # never let the worker die
                log("ERROR      %s: %r" % (path, ex))

    threading.Thread(target=worker, daemon=True).start()
    obs = Observer()
    obs.schedule(H(), str(folder), recursive=False)
    obs.start()
    log("Watching %s  (VT key loaded: %s, hash-only, alert-only)" % (folder, bool(P.VT_KEY)))
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        obs.stop()
        obs.join()


def main():
    ap = argparse.ArgumentParser(description="ScanR Downloads watcher")
    ap.add_argument("--dir", help="folder to watch (default: ~/Downloads)")
    ap.add_argument("--file", help="check one file and exit")
    ap.add_argument("--hash", help="check one SHA-256 and exit")
    a = ap.parse_args()

    if a.hash:
        h = a.hash.strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", h):
            sys.exit("not a SHA-256 (need 64 hex chars)")
        report("(hash only)", h, lookup(h))
        time.sleep(2)                      # let a toast/message box appear
        return
    if a.file:
        process(a.file)
        time.sleep(2)
        return

    folder = Path(a.dir or os.getenv("SCANR_WATCH_DIR") or (Path.home() / "Downloads"))
    if not folder.is_dir():
        sys.exit("folder not found: %s" % folder)
    watch(folder)


if __name__ == "__main__":
    main()
