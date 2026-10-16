import os
import requests

from dotenv import load_dotenv
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

API_BASE = "https://www.virustotal.com/api/v3"
REQUEST_TIMEOUT = (5, 20)


class VirusTotalError(Exception):
    def __init__(self, message, status_code=None):
        super().__init__(message)
        self.status_code = status_code


class VirusTotalClient:
    def __init__(self):
        self.api_key = os.getenv("VT_API_KEY", "").strip()

        if not self.api_key:
            raise VirusTotalError(
                "VirusTotal API key is not configured. Add VT_API_KEY to .env."
            )

        self.session = requests.Session()
        self.session.headers.update({
            "x-apikey": self.api_key,
            "Accept": "application/json",
            "User-Agent": "ScanR-Security-Scanner/1.0",
        })

    def _request(self, method, endpoint, **kwargs):
        url = f"{API_BASE}/{endpoint.lstrip('/')}"

        try:
            response = self.session.request(
                method,
                url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
                **kwargs
            )
        except requests.Timeout as exc:
            raise VirusTotalError(
                "VirusTotal request timed out. Try again later."
            ) from exc
        except requests.RequestException as exc:
            raise VirusTotalError(
                "Unable to connect to VirusTotal."
            ) from exc

        if response.status_code == 401:
            raise VirusTotalError(
                "VirusTotal API key is invalid or unauthorized.",
                401
            )

        if response.status_code == 403:
            raise VirusTotalError(
                "VirusTotal denied the request. Check API permissions.",
                403
            )

        if response.status_code == 404:
            raise VirusTotalError(
                "No VirusTotal report was found for this target.",
                404
            )

        if response.status_code == 429:
            raise VirusTotalError(
                "VirusTotal API rate limit reached. Try again later.",
                429
            )

        if response.status_code >= 400:
            raise VirusTotalError(
                f"VirusTotal returned HTTP {response.status_code}.",
                response.status_code
            )

        try:
            return response.json()
        except ValueError as exc:
            raise VirusTotalError(
                "VirusTotal returned an invalid JSON response."
            ) from exc

    def get_file_report(self, file_hash):
        return self._request("GET", f"files/{file_hash}")

    def get_url_report(self, url_id):
        return self._request("GET", f"urls/{url_id}")

    def submit_url(self, url):
        return self._request("POST", "urls", data={"url": url})

    def get_analysis(self, analysis_id):
        return self._request("GET", f"analyses/{analysis_id}")
