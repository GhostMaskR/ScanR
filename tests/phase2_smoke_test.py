from scanner.hash_utils import validate_hash, hash_bytes
from scanner.url_scanner import validate_url, classify_stats

assert validate_hash("a" * 64) == (True, "sha256")
assert validate_hash("a" * 40) == (True, "sha1")
assert validate_hash("a" * 32) == (True, "md5")
assert validate_hash("invalid")[0] is False

digest = hash_bytes(b"ScanR")
assert len(digest) == 64
assert all(c in "0123456789abcdef" for c in digest)

assert validate_url("https://example.com") == "https://example.com"

for bad_url in (
    "file:///C:/Windows/win.ini",
    "http://localhost/",
):
    try:
        validate_url(bad_url)
        raise AssertionError("Rejected URL was accepted: " + bad_url)
    except ValueError:
        pass

malicious = classify_stats({"malicious": 2, "suspicious": 0})
assert malicious["status"] == "malicious"
assert malicious["risk_level"] == "high"

suspicious = classify_stats({"malicious": 0, "suspicious": 1})
assert suspicious["status"] == "suspicious"

unknown = classify_stats({})
assert unknown["status"] == "no_detections"
assert unknown["risk_level"] == "unknown"

print("CORE_TESTS_OK")
