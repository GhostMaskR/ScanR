import os
import requests
from dotenv import load_dotenv
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

VT_DIRECT_BASE = "https://www.virustotal.com/api/v3"
REQUEST_TIMEOUT = (5, 25)


class VirusTotalError(Exception):
    def __init__(self, message, status_code=None):
        super().__init__(message)
        self.status_code = status_code


class VirusTotalClient:
    def __init__(self):
        self.central_url = os.getenv("SCANR_CENTRAL_API_URL", "").strip().rstrip("/")
        self.api_key = os.getenv("VT_API_KEY", "").strip()

        if self.central_url:
            if not self.central_url.startswith("https://"):
                raise VirusTotalError(
                    "SCANR_CENTRAL_API_URL must use HTTPS in shared central mode."
                )
            self.api_base = f"{self.central_url}/vt/v3"
            self.mode = "central"
        else:
            if not self.api_key:
                raise VirusTotalError(
                    "Configure SCANR_CENTRAL_API_URL for shared mode, or VT_API_KEY for local-only mode."
                )
            self.api_base = VT_DIRECT_BASE
            self.mode = "direct"

        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "User-Agent": "ScanR-Security-Scanner/1.0",
        })
        # Never send the user's/local VT key to the central gateway.
        if self.mode == "direct":
            self.session.headers["x-apikey"] = self.api_key

    def _request(self, method, endpoint, **kwargs):
        url = f"{self.api_base}/{endpoint.lstrip('/')}"

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
                "Scan request timed out. Try again later."
            ) from exc
        except requests.RequestException as exc:
            raise VirusTotalError(
                "Unable to connect to the configured VirusTotal service."
            ) from exc

        if response.status_code == 401:
            raise VirusTotalError(
                "VirusTotal credentials are invalid or unauthorized.",
                401
            )
        if response.status_code == 403:
            raise VirusTotalError(
                "The upstream service denied this request. Check API plan/permissions.",
                403
            )
        if response.status_code == 404:
            raise VirusTotalError(
                "No VirusTotal report was found for this target.",
                404
            )
        if response.status_code == 429:
            raise VirusTotalError(
                "Rate limit reached. Wait before trying again.",
                429
            )
        if response.status_code >= 400:
            raise VirusTotalError(
                f"Scanning service returned HTTP {response.status_code}.",
                response.status_code
            )

        try:
            return response.json()
        except ValueError as exc:
            raise VirusTotalError(
                "Scanning service returned an invalid JSON response."
            ) from exc

    def get_file_report(self, file_hash):
        return self._request("GET", f"files/{file_hash}")

    def get_url_report(self, url_id):
        return self._request("GET", f"urls/{url_id}")

    def submit_url(self, url):
        return self._request("POST", "urls", data={"url": url})

    def get_analysis(self, analysis_id):
        return self._request("GET", f"analyses/{analysis_id}")
