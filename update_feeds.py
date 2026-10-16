"""Download free threat feeds into feed_urls.txt (exact-URL match, no VT quota used).
Run manually or daily:  python update_feeds.py
Feeds can change terms/auth (abuse.ch now pushes API keys) - failures are skipped."""
import os
import requests

FEEDS = [
    "https://urlhaus.abuse.ch/downloads/text_online/",
    "https://openphish.com/feed.txt",
]
out = set()
for u in FEEDS:
    try:
        r = requests.get(u, timeout=30, headers={"User-Agent": "ScanR/0.1"})
        r.raise_for_status()
        n = 0
        for ln in r.text.splitlines():
            ln = ln.strip()
            if ln.startswith("http"):
                out.add(ln.lower().rstrip("/"))
                n += 1
        print(f"[ok]   {u} -> {n} urls")
    except Exception as e:
        print(f"[fail] {u} -> {e}")

path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "feed_urls.txt")
if out:
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(out)))
    print(f"saved {len(out)} urls -> {path}")
else:
    print("nothing downloaded, old feed_urls.txt kept")
