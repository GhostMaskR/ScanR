# ScanR

**A Web-Based Threat Intelligence and Security Analysis Platform**

ScanR is a cybersecurity project designed to help users analyze URLs, files, and file hashes using VirusTotal intelligence and a Flask-based web interface.

> **Status:** Features and integrations may vary by module. Verify each feature in the current source code before relying on it in production.

## Features

- **URL Analysis:** Submit a URL for security analysis.
- **File Analysis:** Analyze files using supported scanning workflows.
- **Hash Lookup:** Check supported file hashes against threat intelligence.
- **VirusTotal Integration:** Uses the VirusTotal API v3.
- **Scan History:** Includes database-related scan history components.
- **Web Interface:** Flask-powered application with a web frontend.
- **Protection Components:** Includes separate protection and feed-related modules; these should be configured and tested before use.

## Technology Stack

- Python
- Flask
- Requests
- python-dotenv
- SQLite/database components
- VirusTotal API v3
- HTML, CSS, and JavaScript

## Requirements

- Python 3.10 or newer recommended
- A VirusTotal API key
- Git
- Internet connectivity for API-based lookups

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/TocsiVector/ScanR.git
cd ScanR
```

### 2. Create a virtual environment

**Windows PowerShell:**

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, use this command for the current terminal session only:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Configure the VirusTotal API key

Create a `.env` file in the project root. Do not upload this file to GitHub.

Example:

```dotenv
VT_API_KEY=paste_your_own_virustotal_api_key_here
```

Replace the placeholder with your own API key from VirusTotal.

Never commit or share your real API key. Keep `.env` private and use `.env.example` only as a template.

### 5. Run the application

```powershell
python app.py
```

Open the local URL printed by Flask in your terminal. If the application uses the default Flask development server, it is commonly:

```text
http://127.0.0.1:5000
```

If the application reports a missing configuration, dependency, or API error, check the terminal output and confirm that your API key and dependencies are configured correctly.

## API Endpoints

The following endpoints are part of the project's intended/current backend interface. Confirm their availability in `app.py` and registered modules before integrating another application.

| Endpoint | Purpose |
|---|---|
| `/` | Web interface |
| `/api/status` | Application or scanner status |
| `/health` | Health check |
| `/api/history` | Scan history |
| `/api/scan/url` | URL scanning |
| `/api/scan/file` | File scanning |
| `/api/scan/hash` | Hash lookup |
| `/api/relations` | Supported threat-intelligence relationships |

Some endpoints may require specific request methods, parameters, or API-plan permissions. Check the source code for the exact request format.

## Project Structure

```text
ScanR/
├── app.py
├── requirements.txt
├── .env.example
├── database/
├── scanner/
├── scanr_protection/
├── static/
├── files/
├── tests/
└── README.md
```

The repository may contain additional scripts and modules. This overview lists the main project areas, not an exhaustive inventory.

## Security Notes

- Use ScanR only on files, URLs, and systems you are authorized to analyze.
- Never expose your VirusTotal API key.
- API access, quotas, and available intelligence depend on your VirusTotal account and plan.
- A clean or inconclusive scan is not proof that a file or URL is safe.
- Do not use the Flask development server as a production deployment.
- Review protection and browser-extension components before enabling them.

## Testing

Run the available tests from the project root:

```powershell
python -m pytest
```

Tests may require additional configuration. Review individual test files and their prerequisites if a test fails.

## Limitations

- Results depend on VirusTotal availability, API limits, and vendor detections.
- Some relationship endpoints may be restricted by the API plan.
- Protection modules and integrations require separate verification.
- This project is not a replacement for a full endpoint protection or enterprise security product.

## Contributing

1. Fork the repository.
2. Create a feature branch.
3. Make a focused change.
4. Test your changes.
5. Submit a pull request with a clear description.

## License

See the [LICENSE](LICENSE) file.

## Repository

[https://github.com/TocsiVector/ScanR](https://github.com/TocsiVector/ScanR)
