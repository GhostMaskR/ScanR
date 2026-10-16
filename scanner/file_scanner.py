from pathlib import Path

from scanner.hash_utils import hash_stream
from scanner.virustotal import VirusTotalClient, VirusTotalError
from scanner.url_scanner import extract_report

MAX_FILE_SIZE = 10 * 1024 * 1024


def scan_uploaded_file(file_storage):
    if not file_storage or not file_storage.filename:
        raise ValueError("A file must be selected.")

    stream = file_storage.stream

    try:
        stream.seek(0, 2)
        file_size = stream.tell()
        stream.seek(0)
    except (OSError, ValueError) as exc:
        raise ValueError("Unable to read uploaded file.") from exc

    if file_size <= 0:
        raise ValueError("Empty files cannot be scanned.")

    if file_size > MAX_FILE_SIZE:
        raise ValueError("File exceeds the 10 MB limit.")

    sha256 = hash_stream(stream)

    client = VirusTotalClient()

    try:
        report = client.get_file_report(sha256)
        result = extract_report(report)
        result["scan_method"] = "existing_hash_report"
    except VirusTotalError as exc:
        if exc.status_code == 404:
            return {
                "status": "unknown",
                "risk_level": "unknown",
                "sha256": sha256,
                "file_size": file_size,
                "malicious": None,
                "suspicious": None,
                "harmless": None,
                "undetected": None,
                "message": (
                    "No report found for this file hash. The file was not "
                    "uploaded. Unknown does not mean safe."
                ),
                "scan_method": "hash_lookup_only",
            }
        raise

    result["sha256"] = sha256
    result["file_size"] = file_size

    return result
