from scanner.hash_utils import validate_hash
from scanner.virustotal import VirusTotalClient
from scanner.url_scanner import extract_report


def scan_hash(file_hash):
    if not isinstance(file_hash, str):
        raise ValueError("Hash must be a string.")

    file_hash = file_hash.strip().lower()
    valid, hash_type = validate_hash(file_hash)

    if not valid:
        raise ValueError(
            "Enter a valid MD5, SHA-1 or SHA-256 hash."
        )

    client = VirusTotalClient()
    report = client.get_file_report(file_hash)

    result = extract_report(report)
    result["hash"] = file_hash
    result["hash_type"] = hash_type
    result["sha256"] = file_hash if hash_type == "sha256" else None
    result["scan_method"] = "hash_lookup"

    return result
