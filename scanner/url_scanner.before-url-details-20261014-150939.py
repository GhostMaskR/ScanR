import base64
import re
from urllib.parse import urlsplit

from scanner.virustotal import VirusTotalClient, VirusTotalError


def validate_url(value):
    if not isinstance(value, str):
        raise ValueError("URL must be a string.")

    value = value.strip()

    if not value or len(value) > 2048:
        raise ValueError("URL must contain between 1 and 2048 characters.")

    if any(ord(char) < 32 for char in value):
        raise ValueError("URL contains invalid control characters.")

    try:
        parts = urlsplit(value)
        hostname = parts.hostname
        _ = parts.port
    except ValueError as exc:
        raise ValueError("Malformed URL.") from exc

    if parts.scheme.lower() not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not hostname:
        raise ValueError("URL must include a hostname.")

    if parts.username is not None or parts.password is not None:
        raise ValueError("URLs containing embedded credentials are not accepted.")

    if hostname in ("localhost",) or hostname.endswith(".localhost"):
        raise ValueError("Localhost URLs are not accepted.")

    if hostname.endswith(".local"):
        raise ValueError("Local network hostnames are not accepted.")

    return value


def make_url_id(url):
    encoded = base64.urlsafe_b64encode(
        url.encode("utf-8")
    ).decode("ascii")

    return encoded.rstrip("=")


def classify_stats(stats):
    stats = stats or {}

    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)

    if malicious > 0:
        status = "malicious"
        risk_level = "high"
        message = "One or more security engines marked this target malicious."
    elif suspicious > 0:
        status = "suspicious"
        risk_level = "elevated"
        message = "One or more security engines marked this target suspicious."
    else:
        status = "no_detections"
        risk_level = "unknown"
        message = (
            "No malicious or suspicious detections were reported in these "
            "statistics. This is not proof that the target is safe."
        )

    return {
        "status": status,
        "risk_level": risk_level,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "message": message,
    }


def extract_report(report):
    data = report.get("data", {})
    attributes = data.get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})

    result = classify_stats(stats)

    result["analysis_date"] = attributes.get("last_analysis_date")
    result["reputation"] = attributes.get("reputation")
    result["resource_type"] = data.get("type")

    # Preserve the complete vendor-wise VirusTotal report.
    result["last_analysis_results"] = (
        attributes.get("last_analysis_results") or {}
    )
    result["last_analysis_stats"] = stats
    result["names"] = attributes.get("names") or []
    result["meaningful_name"] = attributes.get("meaningful_name")
    result["url"] = attributes.get("url")

    return result

def scan_url(url):
    url = validate_url(url)
    client = VirusTotalClient()
    url_id = make_url_id(url)

    try:
        report = client.get_url_report(url_id)
        result = extract_report(report)
        result["scan_method"] = "existing_report"
        return result

    except VirusTotalError as exc:
        if exc.status_code != 404:
            raise

    # If no report exists, request VirusTotal to analyse the URL.
    submission = client.submit_url(url)
    analysis_id = submission.get("data", {}).get("id")

    return {
        "status": "analysis_submitted",
        "risk_level": "unknown",
        "malicious": None,
        "suspicious": None,
        "harmless": None,
        "undetected": None,
        "analysis_id": analysis_id,
        "message": (
            "URL submitted to VirusTotal. A completed report is not yet "
            "available from this request. Submit a new scan after analysis "
            "has completed to retrieve the report."
        ),
        "scan_method": "submitted_for_analysis",
    }
