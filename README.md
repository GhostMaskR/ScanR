::: {align="center"}
`<img src="https://capsule-render.vercel.app/api?type=waving&color=0:050816,45:102A43,100:00C896&height=220&section=header&text=ScanR&fontSize=76&fontColor=FFFFFF&fontAlignY=35&desc=THREAT%20INTELLIGENCE%20%7C%20SECURITY%20ANALYSIS&descAlignY=58&descSize=16&animation=twinkling" width="100%" alt="ScanR cybersecurity banner" />`{=html}

# ScanR

**Analyze. Investigate. Understand.**

A Python and Flask web application for supported URL, file, hash, and
threat-intelligence workflows using VirusTotal API v3.

[Repository](https://github.com/GhostMaskR/ScanR) ·
[Installation](#installation) · [API Reference](#api-reference) ·
[Security](#security-notes)

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-Web%20Application-000000?style=for-the-badge&logo=flask&logoColor=white)
![VirusTotal](https://img.shields.io/badge/Threat%20Intelligence-VirusTotal-394EFF?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Development-orange?style=for-the-badge)
:::

> **Project status:** ScanR is under active development. Core unit tests
> and the Phase 2 smoke test have passed in the current development
> environment. End-to-end VirusTotal scanning through the central
> gateway still requires verification. Feature availability depends on
> configuration, implementation, VirusTotal permissions, and API limits.

## Overview

ScanR brings supported security-analysis workflows into one Flask web
interface. It includes URL analysis, file analysis, hash lookups,
relationship queries, scan-history routes, and application status
checks.

VirusTotal provides threat-intelligence data; it does not guarantee that
an item is safe or malicious. Results can vary with the submitted item,
available vendor detections, analysis time, API permissions, and service
response.

## Features

-   **URL analysis** --- submit a URL through the supported scanning
    workflow.
-   **File analysis** --- analyze supported files through the backend.
-   **Hash lookup** --- look up supported file hashes when VirusTotal
    has a matching record.
-   **Relationship queries** --- request supported file or URL
    relationships where available to the configured API account.
-   **Scan history** --- use the configured database-backed history
    workflows.
-   **Status and health checks** --- inspect application and module
    status.
-   **Central or direct VirusTotal configuration** --- use a configured
    ScanR central gateway, or a local VirusTotal API key.

Protection, feed, and extension-related components should be treated as
separate features until they have been tested in the intended
environment.

## Technology stack

-   Python and Flask
-   HTML, CSS, and JavaScript
-   SQLite/database components
-   Requests and python-dotenv
-   VirusTotal API v3
-   Git and GitHub

## Architecture

``` mermaid
flowchart TD
    U[User] --> UI[ScanR Web Interface]
    UI --> APP[Flask Backend]
    APP --> URL[URL Analysis]
    APP --> FILE[File Analysis]
    APP --> HASH[Hash Lookup]
    URL --> VT[ScanR Central Gateway or VirusTotal API v3]
    FILE --> VT
    HASH --> VT
    VT --> RESULT[Analysis Response]
    RESULT --> UI
    APP -. Supported history workflows .-> DB[(Local Database)]
```

In central mode, ScanR sends supported VirusTotal requests to the
configured gateway. The gateway should keep its VirusTotal key
server-side; the key must never be placed in frontend code or committed
to the repository. In direct mode, ScanR uses the local `VT_API_KEY`
setting.

## Repository structure

``` text
ScanR/
├── app.py
├── requirements.txt
├── .env.example
├── database/
├── scanner/
│   ├── file_scanner.py
│   ├── hash_scanner.py
│   ├── hash_utils.py
│   ├── relations_api.py
│   ├── url_scanner.py
│   └── virustotal.py
├── static/
│   └── index.html
├── tests/
├── reports/
├── LICENSE
└── README.md
```

This is a simplified overview; the repository may contain additional
modules and scripts.

## Installation

### Requirements

-   Python 3.10 or newer recommended
-   Git
-   Internet access for online threat-intelligence lookups
-   Either a configured ScanR central gateway URL or your own VirusTotal
    API key

### 1. Clone the repository

``` bash
git clone https://github.com/GhostMaskR/ScanR.git
cd ScanR
```

### 2. Create and activate a virtual environment

**Windows PowerShell**

``` powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, allow it for the current process only:

``` powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\.venv\Scripts\Activate.ps1
```

**Linux/macOS**

``` bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

``` bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Configure ScanR

Create a local `.env` file in the repository root. Start with
`.env.example`, then configure **one** of the supported modes.

**Option A --- Central gateway**

``` dotenv
SCANR_CENTRAL_API_URL=https://your-deployed-scanr-gateway.example
```

Replace the example with the real HTTPS URL of a gateway you are
authorized to use. A central gateway must be deployed, reachable,
configured with a server-side VirusTotal key, and protected against
abuse. The placeholder URL is not a working service.

**Option B --- Direct VirusTotal API**

``` dotenv
VT_API_KEY=your_own_virustotal_api_key
```

Use your own valid key. Keep `.env` local and untracked. Never put a
real key in frontend code, screenshots, issues, README files, or
commits.

### 5. Start the application

``` powershell
python app.py
```

Open the local address printed by Flask. The default development address
is commonly `http://127.0.0.1:5000`.

> Run the Flask development server locally only. Public deployment
> requires production-grade hosting, access controls, rate limiting,
> logging, and a security review.

## API reference

These routes are present in the current application structure. For exact
request schemas and response fields, check the corresponding route
handlers in the current code.

  --------------------------------------------------------------------------------------
  Method                  Endpoint                               Purpose
  ----------------------- -------------------------------------- -----------------------
  `GET`                   `/`                                    Web interface

  `GET`                   `/health`                              Application health
                                                                 check

  `GET`                   `/api/status`                          Application and scanner
                                                                 configuration status

  `GET`                   `/api/history`                         Scan history

  `GET`                   `/api/history/<scan_id>`               Individual history
                                                                 entry

  `POST`                  `/api/scan/url`                        URL analysis

  `POST`                  `/api/scan/file`                       File analysis

  `POST`                  `/api/scan/hash`                       Hash analysis

  `GET`                   `/api/file/<resource_id>/<relation>`   File relationship
                                                                 lookup

  `POST`                  `/api/relations`                       Relationship query

  `GET`                   `/api/relations/status`                Relationship module
                                                                 status
  --------------------------------------------------------------------------------------

### Useful local checks

``` powershell
Invoke-RestMethod -Uri "http://127.0.0.1:5000/health"
Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/status"
Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/history"
```

For URL, file, hash, and relationship scans, inspect the relevant route
to confirm required JSON keys, form fields, limits, and error responses.
VirusTotal may return errors or no report when an item is unknown, an
endpoint is unavailable, an API limit is reached, or the account lacks
permission.

## Testing

From the repository root, run the built-in tests:

``` powershell
python -m unittest discover -s tests -p "test_*.py" -v
python -m tests.phase2_smoke_test
```

In the current development environment, the reported results were:

-   10 unit tests passed.
-   Phase 2 smoke test printed `CORE_TESTS_OK`.
-   Python syntax checks passed for `app.py`, `scanner/virustotal.py`,
    and `scanner/relations_api.py`.
-   `git diff --cached --check` passed before the integration commit.

These checks do **not** establish that every feature works on every
machine. In particular, perform an end-to-end URL or file scan through
the configured gateway before claiming that central VirusTotal scanning
is verified.

### Manual verification checklist

-   [ ] Dependencies install successfully in a fresh virtual
    environment.
-   [ ] `.env` contains a valid central gateway URL or local VirusTotal
    key.
-   [ ] Flask starts and `/health` responds.
-   [ ] The homepage opens.
-   [ ] URL analysis handles valid and invalid input without crashing.
-   [ ] File analysis handles permitted test files and reports errors
    clearly.
-   [ ] Hash lookup handles valid hashes and missing reports.
-   [ ] History endpoints work with empty and populated history.
-   [ ] Relationship endpoints handle unsupported relationships and
    upstream errors.
-   [ ] A real, harmless test URL is successfully processed through the
    intended VirusTotal configuration.

Use only harmless, authorized test inputs. Do not mark checks complete
unless they have actually been run.

## Security notes

-   **Protect API keys.** Keep `.env` out of Git. Commit only
    placeholders in `.env.example`.
-   **Protect the gateway.** A shared gateway must keep its VirusTotal
    key server-side and enforce rate limits and suitable access
    controls. Do not expose an unrestricted personal API key through a
    public endpoint.
-   **Keep Flask local by default.** Do not expose the development
    server directly to the public internet.
-   **Consider privacy.** Sending URLs, files, or identifiers to
    VirusTotal shares data with an external service. Do not submit
    confidential material without authorization.
-   **Interpret results carefully.** Zero detections or a missing report
    does not prove an item is safe.
-   **Respect quotas and permissions.** VirusTotal endpoints and
    relationships may be limited by account plan and API terms.
-   **Do not treat ScanR as a full antivirus or EDR replacement.** It is
    a development project for supported analysis workflows.

If an API key has been exposed, revoke or rotate it through the
provider's official account controls.

## Roadmap

-   [ ] Verify central-gateway URL, file, hash, and relationship scans
    end to end.
-   [ ] Expand automated tests for gateway errors, timeouts, and API
    limits.
-   [ ] Add genuine screenshots from a running instance.
-   [ ] Improve setup and troubleshooting documentation.
-   [ ] Verify protection, feed, and extension components separately.
-   [ ] Review deployment security before any public hosting.

## Contributing

1.  Fork [GhostMaskR/ScanR](https://github.com/GhostMaskR/ScanR).
2.  Create a branch for a focused change.
3.  Keep secrets, local databases, scan artifacts, and private reports
    out of commits.
4.  Run relevant tests and manually verify affected workflows.
5.  Update documentation when behavior or configuration changes.
6.  Open a pull request with the problem, changes, and actual test
    results.

Please do not describe a feature as complete unless its implementation
and expected behavior have been verified.

## Troubleshooting

```{=html}
<details>
```
```{=html}
<summary>
```
`<strong>`{=html}ScanR does not start`</strong>`{=html}
```{=html}
</summary>
```
Activate the virtual environment, install `requirements.txt`, run
`python app.py` from the repository root, and inspect the complete
terminal error. Confirm the Python version and installed dependencies.

```{=html}
</details>
```
```{=html}
<details>
```
```{=html}
<summary>
```
`<strong>`{=html}The API key or gateway is not
detected`</strong>`{=html}
```{=html}
</summary>
```
Confirm `.env` is in the project root and the variable is spelled
exactly `VT_API_KEY` or `SCANR_CENTRAL_API_URL`. Check that the gateway
URL uses HTTPS and points to a deployed service. Do not paste secrets
into an issue or screenshot.

```{=html}
</details>
```
```{=html}
<details>
```
```{=html}
<summary>
```
`<strong>`{=html}A URL or hash has no report`</strong>`{=html}
```{=html}
</summary>
```
VirusTotal may not have a report for every item. A missing report is not
the same as a clean result. Check the input format and the response
returned by ScanR.

```{=html}
</details>
```
```{=html}
<details>
```
```{=html}
<summary>
```
`<strong>`{=html}A relationship request returns 403`</strong>`{=html}
```{=html}
</summary>
```
The requested relationship may not be available to the configured
VirusTotal account or plan. Check the provider's current permissions and
API documentation.

```{=html}
</details>
```
```{=html}
<details>
```
```{=html}
<summary>
```
`<strong>`{=html}Can every user use the same central
gateway?`</strong>`{=html}
```{=html}
</summary>
```
Only if the gateway operator intentionally provides access, has
configured a server-side key, and has suitable rate limits and abuse
protections. A repository clone alone does not grant gateway access.
Otherwise, configure your own VirusTotal API key in the local `.env`
file.

```{=html}
</details>
```
## License

See the repository's [LICENSE](LICENSE) file for the applicable terms.

::: {align="center"}
**ScanR --- Analyze. Investigate. Understand.**

[GitHub Repository](https://github.com/GhostMaskR/ScanR)

`<sub>`{=html}Cybersecurity development project · Built with Python and
Flask`</sub>`{=html}
:::
