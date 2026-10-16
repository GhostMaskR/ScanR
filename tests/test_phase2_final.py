import unittest
import tempfile
from pathlib import Path

from scanner.hash_utils import validate_hash, hash_bytes
from scanner.url_scanner import validate_url, classify_stats
from database.db import init_db, save_scan, get_history


class ScanRCoreTests(unittest.TestCase):

    def test_hash_formats(self):
        self.assertEqual(
            validate_hash("a" * 64),
            (True, "sha256"),
        )
        self.assertEqual(
            validate_hash("a" * 40),
            (True, "sha1"),
        )
        self.assertEqual(
            validate_hash("a" * 32),
            (True, "md5"),
        )
        self.assertFalse(validate_hash("invalid")[0])

    def test_sha256_output_format(self):
        digest = hash_bytes(b"ScanR")
        self.assertEqual(len(digest), 64)
        self.assertTrue(
            all(char in "0123456789abcdef" for char in digest)
        )

    def test_valid_url(self):
        self.assertEqual(
            validate_url("https://example.com"),
            "https://example.com",
        )

    def test_reject_invalid_schemes(self):
        for value in (
            "file:///C:/Windows/win.ini",
            "ftp://example.com",
            "http://localhost/",
            "http://user:pass@example.com",
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    validate_url(value)

    def test_malicious_classification(self):
        result = classify_stats({
            "malicious": 2,
            "suspicious": 0,
        })
        self.assertEqual(result["status"], "malicious")
        self.assertEqual(result["risk_level"], "high")

    def test_suspicious_classification(self):
        result = classify_stats({
            "malicious": 0,
            "suspicious": 1,
        })
        self.assertEqual(result["status"], "suspicious")

    def test_no_detection_is_not_safe(self):
        result = classify_stats({})
        self.assertEqual(result["status"], "no_detections")
        self.assertEqual(result["risk_level"], "unknown")
        self.assertIn("not proof", result["message"])

    def test_flask_health(self):
        import app
        client = app.app.test_client()
        response = client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["status"], "running")

    def test_invalid_hash_endpoint(self):
        import app
        client = app.app.test_client()
        response = client.post(
            "/api/scan/hash",
            json={"hash": "invalid"},
        )
        self.assertEqual(response.status_code, 400)

    def test_history_endpoint(self):
        import app
        client = app.app.test_client()
        response = client.get("/api/history")
        self.assertEqual(response.status_code, 200)
        self.assertIn("items", response.json)


if __name__ == "__main__":
    unittest.main(verbosity=2)
