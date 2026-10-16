import os
import base64
import requests

from flask import jsonify, request

VT_BASE = "https://www.virustotal.com/api/v3"

# Only allow known VirusTotal relationship names.
ALLOWED_RELATIONS = {
    "contacted_domains",
    "contacted_ips",
    "referrer_files",
    "communicating_files",
    "bundled_files",
    "dropped_files",
    "execution_parents",
    "embedded_domains",
    "embedded_ips",
    "urls",
    "subdomains",
    "collections",
    "comments",
    "votes",
    "graphs",
    "behaviours",
    "behaviour_summary",
    "network_location",
    "downloaded_files",
    "redirecting_urls",
    "redirects_to",
    "redirects_from",
    "similar_files",
    "itw_urls",
    "sigma_analysis",
}

def _vt_headers():
    key = os.getenv("VT_API_KEY", "").strip()
    if not key:
        return None
    return {"x-apikey": key, "accept": "application/json"}

def _url_id(value):
    # VirusTotal URL IDs are URL-safe Base64 without padding.
    return base64.urlsafe_b64encode(
        value.encode("utf-8")
    ).decode("ascii").rstrip("=")

def _request_vt(path, params=None):
    headers = _vt_headers()
    if not headers:
        return None, (
            jsonify({
                "success": False,
                "error": "VT_API_KEY is not configured on the backend."
            }), 503
        )

    try:
        response = requests.get(
            f"{VT_BASE}/{path.lstrip('/')}",
            headers=headers,
            params=params or {},
            timeout=25
        )

        try:
            payload = response.json()
        except ValueError:
            payload = {"error": {"message": "VirusTotal returned a non-JSON response."}}

        if response.status_code >= 400:
            message = (
                payload.get("error", {}).get("message")
                if isinstance(payload.get("error"), dict)
                else None
            ) or f"VirusTotal request failed with HTTP {response.status_code}"

            return None, (
                jsonify({
                    "success": False,
                    "error": message,
                    "upstream_status": response.status_code
                }),
                response.status_code
                if response.status_code in (400, 401, 403, 404, 429)
                else 502
            )

        return payload, None

    except requests.Timeout:
        return None, (
            jsonify({
                "success": False,
                "error": "VirusTotal request timed out. Please try again."
            }), 504
        )
    except requests.RequestException:
        return None, (
            jsonify({
                "success": False,
                "error": "Could not connect to VirusTotal."
            }), 502
        )

def register_relations_routes(app):
    @app.get("/api/file/<resource_id>/<relation>")
    def scanr_file_relation(resource_id, relation):
        relation = relation.strip().lower()

        if relation not in ALLOWED_RELATIONS:
            return jsonify({
                "success": False,
                "error": "Unsupported relationship name.",
                "allowed_relations": sorted(ALLOWED_RELATIONS)
            }), 400

        if not resource_id or len(resource_id) > 512:
            return jsonify({
                "success": False,
                "error": "Invalid resource identifier."
            }), 400

        # Existing legacy route is intended for file hashes.
        # URL scans should use /api/relations with kind=url.
        if not all(c in "0123456789abcdefABCDEF" for c in resource_id):
            return jsonify({
                "success": False,
                "error": "This legacy endpoint expects a file hash. Use /api/relations for URL relationships."
            }), 400

        if len(resource_id) not in (32, 40, 64, 128):
            return jsonify({
                "success": False,
                "error": "Invalid file hash length."
            }), 400

        payload, error = _request_vt(
            f"files/{resource_id.lower()}/relationships/{relation}",
            {"limit": 40}
        )
        if error:
            return error

        return jsonify({
            "success": True,
            "source": "virustotal",
            "resource_type": "file",
            "resource_id": resource_id.lower(),
            "relationship": relation,
            "result": payload
        })

    @app.post("/api/relations")
    def scanr_live_relations():
        body = request.get_json(silent=True) or {}

        kind = str(body.get("kind", "file")).strip().lower()
        identifier = str(body.get("id", "")).strip()
        relation = str(body.get("relation", "")).strip().lower()

        if kind not in ("file", "url"):
            return jsonify({
                "success": False,
                "error": "kind must be 'file' or 'url'."
            }), 400

        if relation not in ALLOWED_RELATIONS:
            return jsonify({
                "success": False,
                "error": "Unsupported relationship name.",
                "allowed_relations": sorted(ALLOWED_RELATIONS)
            }), 400

        if not identifier or len(identifier) > 4096:
            return jsonify({
                "success": False,
                "error": "A valid resource id is required."
            }), 400

        if kind == "url":
            if not identifier.startswith(("http://", "https://")):
                return jsonify({
                    "success": False,
                    "error": "URL relationships require an http:// or https:// URL."
                }), 400
            resource_id = _url_id(identifier)
            endpoint = f"urls/{resource_id}/relationships/{relation}"
        else:
            if (
                len(identifier) not in (32, 40, 64, 128)
                or not all(c in "0123456789abcdefABCDEF" for c in identifier)
            ):
                return jsonify({
                    "success": False,
                    "error": "File id must be a valid MD5, SHA-1, SHA-256, or supported hash."
                }), 400
            resource_id = identifier.lower()
            endpoint = f"files/{resource_id}/relationships/{relation}"

        payload, error = _request_vt(endpoint, {"limit": 40})
        if error:
            return error

        return jsonify({
            "success": True,
            "source": "virustotal",
            "resource_type": kind,
            "resource_id": resource_id,
            "relationship": relation,
            "result": payload
        })

    @app.get("/api/relations/status")
    def scanr_relations_status():
        configured = bool(os.getenv("VT_API_KEY", "").strip())
        return jsonify({
            "success": True,
            "feature": "live_virustotal_relations",
            "api_key_configured": configured,
            "supported_relations": sorted(ALLOWED_RELATIONS)
        })
