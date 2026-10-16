from flask import render_template
import os
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, jsonify, request

from database.db import (
    init_db,
    save_scan,
    get_history,
    get_scan_by_id,
    count_scans,
)
from scanner.virustotal import VirusTotalError
from scanner.url_scanner import scan_url
from scanner.hash_scanner import scan_hash
from scanner.file_scanner import scan_uploaded_file

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
app.config["JSON_SORT_KEYS"] = False


def api_error(message, status_code):
    return jsonify({
        "success": False,
        "error": message,
    }), status_code


def save_result(
    scan_type,
    target,
    result,
    sha256=None,
    status_override=None,
    message_override=None,
):
    return save_scan(
        scan_type=scan_type,
        target=str(target)[:2048],
        sha256=sha256 or result.get("sha256"),
        status=status_override or result.get("status", "unknown"),
        risk_level=result.get("risk_level", "unknown"),
        malicious=result.get("malicious"),
        suspicious=result.get("suspicious"),
        harmless=result.get("harmless"),
        undetected=result.get("undetected"),
        source="virustotal",
        message=message_override or result.get("message"),
    )


def handle_vt_error(exc):
    if exc.status_code == 404:
        return 404
    if exc.status_code == 429:
        return 429
    if exc.status_code in (401, 403):
        return 503
    return 503


init_db()


@app.get("/")
def index():
    return app.send_static_file("index.html")

@app.get("/health")
def health():
    return jsonify({
        "project": "ScanR",
        "status": "running",
        "phase": 2,
        "database": "initialized",
    })


@app.get("/api/status")
def api_status():
    return jsonify({
        "project": "ScanR",
        "api_version": "v1",
        "status": "ready",
        "virustotal_key_configured": bool(
            os.getenv("VT_API_KEY", "").strip()
        ),
        "total_saved_scans": count_scans(),
    })


@app.post("/api/scan/url")
def scan_url_endpoint():
    body = request.get_json(silent=True)

    if not isinstance(body, dict):
        return api_error(
            "Send a JSON body containing a url field.",
            400,
        )

    url = body.get("url")

    if not isinstance(url, str) or not url.strip():
        return api_error("The url field is required.", 400)

    try:
        result = scan_url(url)
        scan_id = save_result("url", url, result)
        result["scan_id"] = scan_id

        return jsonify({
            "success": True,
            "result": result,
        })

    except ValueError as exc:
        return api_error(str(exc), 400)

    except VirusTotalError as exc:
        return api_error(
            str(exc),
            handle_vt_error(exc),
        )

    except Exception:
        app.logger.exception("URL scan failed")
        return api_error(
            "Unexpected server error during URL scanning.",
            500,
        )


@app.post("/api/scan/hash")
def scan_hash_endpoint():
    body = request.get_json(silent=True)

    if not isinstance(body, dict):
        return api_error(
            "Send a JSON body containing a hash field.",
            400,
        )

    file_hash = body.get("hash")

    if not isinstance(file_hash, str) or not file_hash.strip():
        return api_error("The hash field is required.", 400)

    file_hash = file_hash.strip().lower()

    try:
        result = scan_hash(file_hash)

        scan_id = save_result(
            "hash",
            file_hash,
            result,
            sha256=result.get("sha256"),
        )
        result["scan_id"] = scan_id

        return jsonify({
            "success": True,
            "result": result,
        })

    except ValueError as exc:
        return api_error(str(exc), 400)

    except VirusTotalError as exc:
        if exc.status_code == 404:
            valid_hash, hash_type = (
                __import__("scanner.hash_utils", fromlist=["validate_hash"])
                .validate_hash(file_hash)
            )

            if valid_hash:
                result = {
                    "status": "unknown",
                    "risk_level": "unknown",
                    "message": (
                        "No VirusTotal report was found. "
                        "This hash is unknown, not confirmed safe."
                    ),
                    "malicious": None,
                    "suspicious": None,
                    "harmless": None,
                    "undetected": None,
                    "hash": file_hash,
                    "hash_type": hash_type,
                    "sha256": (
                        file_hash if hash_type == "sha256" else None
                    ),
                }

                scan_id = save_result(
                    "hash",
                    file_hash,
                    result,
                )
                result["scan_id"] = scan_id

                return jsonify({
                    "success": True,
                    "result": result,
                })

        return api_error(
            str(exc),
            handle_vt_error(exc),
        )

    except Exception:
        app.logger.exception("Hash scan failed")
        return api_error(
            "Unexpected server error during hash scanning.",
            500,
        )


@app.post("/api/scan/file")
def scan_file_endpoint():
    if "file" not in request.files:
        return api_error(
            "Upload a file using the multipart field named file.",
            400,
        )

    uploaded_file = request.files["file"]

    if not uploaded_file.filename:
        return api_error("A file must be selected.", 400)

    filename = Path(uploaded_file.filename).name[:255]

    try:
        result = scan_uploaded_file(uploaded_file)

        scan_id = save_result(
            "file",
            filename,
            result,
            sha256=result.get("sha256"),
        )
        result["scan_id"] = scan_id

        return jsonify({
            "success": True,
            "result": result,
        })

    except ValueError as exc:
        return api_error(str(exc), 400)

    except VirusTotalError as exc:
        return api_error(
            str(exc),
            handle_vt_error(exc),
        )

    except Exception:
        app.logger.exception("File scan failed")
        return api_error(
            "Unexpected server error during file scanning.",
            500,
        )


@app.get("/api/history")
def history_endpoint():
    try:
        limit = int(request.args.get("limit", 50))
        offset = int(request.args.get("offset", 0))
    except ValueError:
        return api_error(
            "limit and offset must be integers.",
            400,
        )

    if not 1 <= limit <= 100:
        return api_error(
            "limit must be between 1 and 100.",
            400,
        )

    if offset < 0:
        return api_error(
            "offset cannot be negative.",
            400,
        )

    return jsonify({
        "success": True,
        "total": count_scans(),
        "limit": limit,
        "offset": offset,
        "items": get_history(limit, offset),
    })


@app.get("/api/history/<int:scan_id>")
def scan_detail_endpoint(scan_id):
    record = get_scan_by_id(scan_id)

    if record is None:
        return api_error("Scan record not found.", 404)

    return jsonify({
        "success": True,
        "result": record,
    })


@app.errorhandler(413)
def request_too_large(error):
    return api_error(
        "Request exceeds the configured 10 MB limit.",
        413,
    )


@app.errorhandler(404)
def route_not_found(error):
    return api_error("API route not found.", 404)


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        use_reloader=False,
    )


