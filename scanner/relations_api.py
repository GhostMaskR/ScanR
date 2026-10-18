import os
import base64
import requests

from flask import jsonify, request

VT_BASE = "https://www.virustotal.com/api/v3"
ALLOWED_RELATIONS = {
    "contacted_domains", "contacted_ips", "referrer_files",
    "communicating_files", "bundled_files", "dropped_files",
    "execution_parents", "embedded_domains", "embedded_ips", "urls",
    "subdomains", "collections", "comments", "votes", "graphs",
    "behaviours", "behaviour_summary", "network_location",
    "downloaded_files", "redirecting_urls", "redirects_to",
    "redirects_from", "similar_files", "itw_urls", "sigma_analysis",
}


def _service_config():
    central_url = os.getenv("SCANR_CENTRAL_API_URL", "").strip().rstrip("/")
    key = os.getenv("VT_API_KEY", "").strip()
    if central_url:
        if not central_url.startswith("https://"):
            return None, None, "SCANR_CENTRAL_API_URL must use HTTPS."
        return f"{central_url}/vt/v3", {}, None
    if key:
        return VT_BASE, {"x-apikey": key}, None
    return None, None, "Configure SCANR_CENTRAL_API_URL or VT_API_KEY."


def _url_id(value):
    return base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")


def _request_vt(path, params=None):
    base, headers, config_error = _service_config()
    if not base:
        return None, (jsonify({"success": False, "error": config_error}), 503)

    headers = dict(headers)
    headers["accept"] = "application/json"
    headers["user-agent"] = "ScanR-Relations/1.0"

    try:
        response = requests.get(
            f"{base}/{path.lstrip('/')}",
            headers=headers,
            params=params or {},
            timeout=(5, 25),
            allow_redirects=False,
        )
        try:
            payload = response.json()
        except ValueError:
            payload = {"error": {"message": "Scanning service returned a non-JSON response."}}

        if response.status_code >= 400:
            if isinstance(payload.get("error"), dict):
                message = payload["error"].get("message")
            else:
                message = payload.get("error")
            message = message or f"Scanning service returned HTTP {response.status_code}."
            status = response.status_code if response.status_code in (400, 401, 403, 404, 429) else 502
            return None, (jsonify({"success": False, "error": message, "upstream_status": response.status_code}), status)

        return payload, None
    except requests.Timeout:
        return None, (jsonify({"success": False, "error": "Scanning service timed out."}), 504)
    except requests.RequestException:
        return None, (jsonify({"success": False, "error": "Could not connect to the configured scanning service."}), 502)


def register_relations_routes(app):
    @app.get("/api/file/<resource_id>/<relation>")
    def scanr_file_relation(resource_id, relation):
        relation = relation.strip().lower()
        if relation not in ALLOWED_RELATIONS:
            return jsonify({"success": False, "error": "Unsupported relationship name.", "allowed_relations": sorted(ALLOWED_RELATIONS)}), 400
        if not resource_id or len(resource_id) > 128 or not all(c in "0123456789abcdefABCDEF" for c in resource_id) or len(resource_id) not in (32, 40, 64, 128):
            return jsonify({"success": False, "error": "This endpoint requires a valid file hash."}), 400

        payload, error = _request_vt(f"files/{resource_id.lower()}/relationships/{relation}", {"limit": 40})
        if error:
            return error
        return jsonify({"success": True, "source": "virustotal", "resource_type": "file", "resource_id": resource_id.lower(), "relationship": relation, "result": payload})

    @app.post("/api/relations")
    def scanr_live_relations():
        body = request.get_json(silent=True) or {}
        kind = str(body.get("kind", "file")).strip().lower()
        identifier = str(body.get("id", "")).strip()
        relation = str(body.get("relation", "")).strip().lower()

        if kind not in ("file", "url"):
            return jsonify({"success": False, "error": "kind must be 'file' or 'url'."}), 400
        if relation not in ALLOWED_RELATIONS:
            return jsonify({"success": False, "error": "Unsupported relationship name.", "allowed_relations": sorted(ALLOWED_RELATIONS)}), 400
        if not identifier or len(identifier) > 4096:
            return jsonify({"success": False, "error": "A valid resource id is required."}), 400

        if kind == "url":
            if not identifier.startswith(("http://", "https://")):
                return jsonify({"success": False, "error": "URL relationships require an http:// or https:// URL."}), 400
            resource_id = _url_id(identifier)
            endpoint = f"urls/{resource_id}/relationships/{relation}"
        else:
            if len(identifier) not in (32, 40, 64, 128) or not all(c in "0123456789abcdefABCDEF" for c in identifier):
                return jsonify({"success": False, "error": "File id must be a valid MD5, SHA-1, SHA-256, or supported hash."}), 400
            resource_id = identifier.lower()
            endpoint = f"files/{resource_id}/relationships/{relation}"

        payload, error = _request_vt(endpoint, {"limit": 40})
        if error:
            return error
        return jsonify({"success": True, "source": "virustotal", "resource_type": kind, "resource_id": resource_id, "relationship": relation, "result": payload})

    @app.get("/api/relations/status")
    def scanr_relations_status():
        central_url = os.getenv("SCANR_CENTRAL_API_URL", "").strip()
        direct_key = os.getenv("VT_API_KEY", "").strip()
        return jsonify({
            "success": True,
            "feature": "live_virustotal_relations",
            "api_key_configured": bool(central_url or direct_key),
            "mode": "central" if central_url else ("direct" if direct_key else "unconfigured"),
            "supported_relations": sorted(ALLOWED_RELATIONS),
        })
