"""vt_extra.py - Relations / Behavior / Community endpoints for ScanR.
Read-only calls to VirusTotal API v3. Does not touch existing scan logic."""
import base64
import json
import os
import re
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, jsonify, request

bp = Blueprint("vt_extra", __name__)
BASE = Path(__file__).resolve().parent
VT = "https://www.virustotal.com/api/v3"
TTL = 120
_cache = {}

HASH_RE = re.compile(r"^(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$")

URL_RELS = [
    "contacted_domains", "contacted_ips", "communicating_files", "downloaded_files",
    "redirects_to", "redirecting_urls", "referrer_files", "referrer_urls",
    "embedded_js_files", "submissions",
]
FILE_RELS = [
    "contacted_urls", "contacted_domains", "contacted_ips", "execution_parents",
    "bundled_files", "dropped_files", "itw_urls", "itw_domains", "similar_files",
    "compressed_parents",
]
KEEP = (
    "url", "last_final_url", "meaningful_name", "type_description", "last_analysis_stats",
    "country", "as_owner", "reputation", "tags", "last_analysis_date", "size", "title",
)


# ---------------------------------------------------------------- helpers
def _read_env_file():
    out = {}
    p = BASE / ".env"
    if p.exists():
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.replace("export ", "").strip()
            out[k] = v.strip().strip('"').strip("'")
    return out


def _api_key():
    pool = dict(_read_env_file())
    pool.update(os.environ)
    for name in ("VT_API_KEY", "VIRUSTOTAL_API_KEY", "VIRUSTOTAL_KEY", "VT_KEY", "VT_APIKEY"):
        if pool.get(name):
            return pool[name]
    for name, val in pool.items():
        u = name.upper()
        if val and ("VT" in u or "VIRUSTOTAL" in u) and "KEY" in u:
            return val
    return None


def _vt_get(path):
    now = time.time()
    hit = _cache.get(path)
    if hit and now - hit[0] < TTL:
        return hit[1]
    key = _api_key()
    if not key:
        return 0, {"error": "VirusTotal API key not found (checked .env and environment variables)."}
    req = urllib.request.Request(VT + path, headers={"x-apikey": key, "accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            res = (r.status, json.loads(r.read().decode("utf-8")))
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode("utf-8"))
        except Exception:
            body = {}
        return e.code, body
    except Exception as e:
        return 502, {"error": "Could not reach VirusTotal: " + type(e).__name__}
    _cache[path] = (now, res)
    return res


def _explain(status, body):
    e = body.get("error") if isinstance(body, dict) else None
    detail = e.get("message") if isinstance(e, dict) else (e if isinstance(e, str) else "")
    if status in (0, 502):
        return detail or "Backend error."
    table = {
        401: "VirusTotal API key is missing or invalid.",
        403: "Your VirusTotal key is not allowed to use this endpoint (premium-only data).",
        404: "VirusTotal has no data for this item yet.",
        429: "VirusTotal rate limit reached (free key = 4 requests/minute). Wait 60 seconds and try again.",
    }
    return table.get(status) or detail or ("VirusTotal returned HTTP %s" % status)


def _fail(msg):
    return jsonify({"ok": False, "error": msg})


def _target():
    kind = (request.args.get("kind") or "").lower()
    value = (request.args.get("id") or "").strip()
    if kind == "file":
        if not HASH_RE.match(value):
            return None, None, "Invalid file hash."
        return "/files/" + value.lower(), "file", None
    if kind == "url":
        if not re.match(r"^https?://", value, re.I) or len(value) > 2048:
            return None, None, "Invalid URL."
        uid = base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")
        return "/urls/" + uid, "url", None
    return None, None, "Unknown kind (use url or file)."


def _d(ts):
    try:
        return datetime.fromtimestamp(int(ts), timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return str(ts)


def _s(v, n=300):
    s = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)
    return s if len(s) <= n else s[:n] + "..."


def _slim(item):
    a = item.get("attributes") or {}
    return {
        "id": item.get("id"),
        "type": item.get("type"),
        "attributes": {k: a[k] for k in KEEP if k in a},
    }


def _fmt(x):
    if isinstance(x, str):
        return _s(x, 200)
    if isinstance(x, dict):
        if "signature_description" in x:
            return _s("%s %s (%s)" % (x.get("id", ""), x.get("signature_description", ""), x.get("severity", "")), 200)
        if "destination_ip" in x:
            return "%s:%s/%s" % (x.get("destination_ip"), x.get("destination_port", "?"), x.get("transport_layer_protocol", ""))
        if "hostname" in x:
            return _s("%s %s" % (x["hostname"], x.get("resolved_ips", "")), 200)
        if "url" in x:
            return _s("%s %s" % (x.get("request_method", ""), x["url"]), 200)
        return _s(", ".join("%s=%s" % (k, v) for k, v in x.items()), 200)
    return _s(x, 200)


def _kv(d, limit=25):
    rows = []
    for k, v in list((d or {}).items())[:limit]:
        rows.append([str(k), _s(v, 300)])
    return rows


# ---------------------------------------------------------------- routes
@bp.route("/api/x/relations", methods=["GET"])
def relations():
    path, kind, err = _target()
    if err:
        return _fail(err)
    allowed = URL_RELS if kind == "url" else FILE_RELS
    rel = request.args.get("rel") or allowed[0]
    if rel not in allowed:
        return _fail("Unknown relationship.")
    st, body = _vt_get("%s/%s?limit=20" % (path, rel))
    if st != 200:
        return _fail(_explain(st, body))
    data = body.get("data", [])
    if isinstance(data, dict):
        data = [data]
    items = [_slim(i) for i in data if isinstance(i, dict)]
    return jsonify({
        "ok": True, "kind": kind, "rel": rel, "rels": allowed,
        "count": (body.get("meta") or {}).get("count"), "items": items,
    })


@bp.route("/api/x/behavior", methods=["GET"])
def behavior():
    path, kind, err = _target()
    if err:
        return _fail(err)

    if kind == "url":
        st, body = _vt_get(path)
        if st != 200:
            return _fail(_explain(st, body))
        a = (body.get("data") or {}).get("attributes") or {}
        sections = []
        main = [
            ["Final URL", a.get("last_final_url")],
            ["HTTP status", a.get("last_http_response_code")],
            ["Title", a.get("title")],
            ["Content length", a.get("last_http_response_content_length")],
            ["Content SHA-256", a.get("last_http_response_content_sha256")],
            ["Last analysis", _d(a["last_analysis_date"]) if a.get("last_analysis_date") else None],
            ["First submission", _d(a["first_submission_date"]) if a.get("first_submission_date") else None],
            ["Times submitted", a.get("times_submitted")],
        ]
        main = [[k, _s(v)] for k, v in main if v not in (None, "")]
        if main:
            sections.append({"title": "Final response (what VirusTotal crawler saw)", "kv": main})
        chain = a.get("redirection_chain") or []
        if chain:
            sections.append({"title": "Redirection chain", "list": [_s(c, 300) for c in chain[:25]]})
        hdr = a.get("last_http_response_headers") or {}
        if hdr:
            sections.append({"title": "HTTP response headers", "kv": _kv(hdr, 20)})
        cats = a.get("categories") or {}
        if cats:
            sections.append({"title": "Categories (by vendor)", "kv": _kv(cats, 15)})
        trk = a.get("trackers") or {}
        if trk:
            sections.append({"title": "Trackers", "list": ["%s (%s)" % (k, len(v) if isinstance(v, list) else 1) for k, v in list(trk.items())[:25]]})
        links = a.get("outgoing_links") or []
        if links:
            sections.append({"title": "Outgoing links (%d)" % len(links), "list": [_s(x, 250) for x in links[:25]]})
        meta = a.get("html_meta") or {}
        if meta:
            sections.append({"title": "HTML meta", "kv": _kv(meta, 15)})
        return jsonify({
            "ok": True, "kind": kind, "sections": sections,
            "note": "VirusTotal has no sandbox behavior for URLs. This is the crawler/response data it recorded.",
        })

    st, body = _vt_get(path + "/behaviour_summary")
    if st == 404:
        return _fail("No sandbox behavior report from VirusTotal for this file.")
    if st != 200:
        return _fail(_explain(st, body))
    data = body.get("data") or {}
    if isinstance(data, dict) and isinstance(data.get("attributes"), dict):
        data = data["attributes"]
    order = [
        "tags", "verdicts", "mitre_attack_techniques", "calls_highlighted", "command_executions",
        "processes_created", "files_written", "files_deleted", "files_opened",
        "registry_keys_set", "registry_keys_opened", "mutexes_created", "modules_loaded",
        "services_started", "dns_lookups", "ip_traffic", "http_conversations", "text_highlighted",
    ]
    keys = [k for k in order if k in data] + [k for k in data if k not in order]
    sections = []
    for k in keys:
        v = data[k]
        if isinstance(v, list) and v:
            sections.append({"title": "%s (%d)" % (k.replace("_", " ").title(), len(v)), "list": [_fmt(x) for x in v[:25]]})
        if len(sections) >= 14:
            break
    if not sections:
        return _fail("VirusTotal returned an empty behavior summary for this file.")
    return jsonify({"ok": True, "kind": kind, "sections": sections,
                    "note": "Sandbox behavior summary from VirusTotal."})


@bp.route("/api/x/community", methods=["GET"])
def community():
    path, kind, err = _target()
    if err:
        return _fail(err)
    st1, obj = _vt_get(path)
    st2, com = _vt_get(path + "/comments?limit=20")
    if st1 != 200 and st2 != 200:
        return _fail(_explain(st1, obj))
    a = ((obj.get("data") or {}).get("attributes") or {}) if st1 == 200 else {}
    comments = []
    if st2 == 200:
        for c in com.get("data", []):
            ca = c.get("attributes") or {}
            comments.append({
                "date": _d(ca["date"]) if ca.get("date") else "",
                "text": _s(ca.get("text", ""), 1200),
                "votes": ca.get("votes") or {},
                "tags": ca.get("tags") or [],
            })
    return jsonify({
        "ok": True, "kind": kind,
        "reputation": a.get("reputation"),
        "total_votes": a.get("total_votes") or {},
        "comments": comments,
        "comments_note": None if st2 == 200 else _explain(st2, com),
    })