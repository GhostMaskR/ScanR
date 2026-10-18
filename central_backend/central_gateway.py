import os
import re
import time
from collections import defaultdict, deque
from threading import Lock

import requests
from flask import Flask, jsonify, request, Response

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

VT_BASE = "https://www.virustotal.com/api/v3"
VT_API_KEY = os.getenv("VT_API_KEY", "").strip()
REQUEST_TIMEOUT = (5, 25)

# This is intentionally an allow-listed proxy, not an arbitrary URL proxy.
HASH_RE = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}|[a-fA-F0-9]{128})$")
URL_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,4096}$")
ANALYSIS_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,512}$")
RELATIONS = {
    "contacted_domains", "contacted_ips", "referrer_files",
    "communicating_files", "bundled_files", "dropped_files",
    "execution_parents", "embedded_domains", "embedded_ips", "urls",
    "subdomains", "collections", "comments", "votes", "graphs",
    "behaviours", "behaviour_summary", "network_location",
    "downloaded_files", "redirecting_urls", "redirects_to",
    "redirects_from", "similar_files", "itw_urls", "sigma_analysis",
}

# In-memory rate limiting is suitable only for a small single-instance starter.
# Configure a persistent shared limiter before scaling to multiple instances.
RATE_WINDOW_SECONDS = 60
RATE_MAX_PER_WINDOW = 20
DAILY_WINDOW_SECONDS = 24 * 60 * 60
RATE_MAX_PER_DAY = 250
_request_times = defaultdict(deque)
_daily_times = defaultdict(deque)
_rate_lock = Lock()


def error(message, status=400):
    return jsonify({"success": False, "error": message}), status


def client_ip():
    # On Render, REMOTE_ADDR may be the platform proxy address. If deploying
    # elsewhere, configure trusted proxy handling rather than trusting arbitrary
    # X-Forwarded-For values from the public internet.
    return request.remote_addr or "unknown"


def is_rate_limited(ip):
    now = time.time()
    with _rate_lock:
        minute = _request_times[ip]
        while minute and now - minute[0] >= RATE_WINDOW_SECONDS:
            minute.popleft()
        day = _daily_times[ip]
        while day and now - day[0] >= DAILY_WINDOW_SECONDS:
            day.popleft()
        if len(minute) >= RATE_MAX_PER_WINDOW or len(day) >= RATE_MAX_PER_DAY:
            return True
        minute.append(now)
        day.append(now)
        return False


def validate_route(method, path):
    parts = path.strip("/").split("/")
    if method == "GET" and len(parts) == 2 and parts[0] == "files" and HASH_RE.fullmatch(parts[1]):
        return True
    if method == "GET" and len(parts) == 2 and parts[0] == "urls" and URL_ID_RE.fullmatch(parts[1]):
        return True
    if method == "POST" and parts == ["urls"]:
        return True
    if method == "GET" and len(parts) == 2 and parts[0] == "analyses" and ANALYSIS_ID_RE.fullmatch(parts[1]):
        return True
    if method == "GET" and len(parts) == 4 and parts[0] in ("files", "urls") and parts[2] == "relationships":
        resource_id, relation = parts[1], parts[3]
        if relation not in RELATIONS:
            return False
        if parts[0] == "files" and HASH_RE.fullmatch(resource_id):
            return True
        if parts[0] == "urls" and URL_ID_RE.fullmatch(resource_id):
            return True
    return False


@app.get("/health")
def health():
    return jsonify({
        "project": "ScanR Central Gateway",
        "status": "running",
        "api_key_configured": bool(VT_API_KEY),
    })


@app.get("/")
def index():
    return jsonify({
        "service": "ScanR Central VirusTotal Gateway",
        "status": "running",
        "message": "Use the documented ScanR client endpoints. No VirusTotal key is exposed here.",
    })


@app.route("/vt/v3/<path:vt_path>", methods=["GET", "POST"])
def proxy_virustotal(vt_path):
    if not VT_API_KEY:
        return error("Central gateway is missing its VT_API_KEY environment secret.", 503)

    if not validate_route(request.method, vt_path):
        return error("Unsupported VirusTotal endpoint or invalid resource identifier.", 400)

    ip = client_ip()
    if is_rate_limited(ip):
        return error("Gateway rate limit reached. Please wait and retry later.", 429)

    headers = {
        "x-apikey": VT_API_KEY,
        "accept": "application/json",
        "user-agent": "ScanR-Central-Gateway/1.0",
    }
    params = {}
    if request.method == "GET":
        # Keep only a small set of safe query parameters.
        for key in ("limit", "cursor", "filter", "order", "relationships"):
            if key in request.args:
                params[key] = request.args.get(key)

    data = None
    if request.method == "POST" and vt_path == "urls":
        submitted_url = request.form.get("url", "").strip()
        if not submitted_url or len(submitted_url) > 2048:
            return error("A URL between 1 and 2048 characters is required.", 400)
        if not submitted_url.lower().startswith(("http://", "https://")):
            return error("Only HTTP and HTTPS URLs are accepted.", 400)
        data = {"url": submitted_url}

    try:
        upstream = requests.request(
            request.method,
            f"{VT_BASE}/{vt_path}",
            headers=headers,
            params=params,
            data=data,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
        )
    except requests.Timeout:
        return error("VirusTotal request timed out. Please retry later.", 504)
    except requests.RequestException:
        app.logger.exception("Central gateway could not reach VirusTotal")
        return error("Central gateway could not connect to VirusTotal.", 502)

    content_type = upstream.headers.get("Content-Type", "application/json")
    # Pass through provider JSON and status, but never return request headers/key.
    return Response(upstream.content, status=upstream.status_code, content_type=content_type)


@app.errorhandler(413)
def too_large(_exc):
    return error("Request exceeds the gateway size limit.", 413)


@app.errorhandler(429)
def too_many(_exc):
    return error("Gateway rate limit reached.", 429)


if __name__ == "__main__":
    # Local development only. Use Gunicorn/Render in production.
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "8000")), debug=False)
