# ScanR — Threat Intelligence & Security Analysis

![ScanR Animated Cybersecurity Banner](https://capsule-render.vercel.app/api?type=waving&color=0:050816,35:102A43,70:064E3B,100:00C896&height=240&section=header&text=ScanR&fontSize=78&fontColor=FFFFFF&fontAlignY=34&desc=THREAT%20INTELLIGENCE%20%7C%20SECURITY%20ANALYSIS&descAlignY=58&descSize=16&animation=twinkling)

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-Web%20Framework-000000?style=for-the-badge&logo=flask&logoColor=white)
![VirusTotal](https://img.shields.io/badge/Threat%20Intelligence-VirusTotal-394EFF?style=for-the-badge)
![Project Status](https://img.shields.io/badge/Status-Under%20Development-orange?style=for-the-badge)
![License](https://img.shields.io/badge/License-See%20LICENSE-blue?style=for-the-badge)

**Analyze. Investigate. Understand.**

ScanR is a Python and Flask-based cybersecurity web application for supported URL, file, hash, and threat-intelligence workflows using VirusTotal API v3.

> **Project status:** ScanR is under active development. Core unit tests and the Phase 2 smoke test passed in the reported development environment. Successful end-to-end URL and file scanning through the central gateway has not yet been independently confirmed. A successful Git push or passing unit tests does not prove every scanning feature works.

**Repository:** [GhostMaskR/ScanR](https://github.com/GhostMaskR/ScanR)

![Animated typing banner](https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=600&size=18&duration=2600&pause=700&color=00C896&center=true&vCenter=true&width=800&lines=Analyze+Suspicious+URLs;Investigate+Files+and+Hashes;Explore+Threat+Intelligence;Make+Security+Analysis+Clear)

---

## Table of Contents

1. [Overview](#overview)
2. [Project Goals](#project-goals)
3. [Design Principles](#design-principles)
4. [Features](#features)
5. [Feature Status](#feature-status)
6. [Technology Stack](#technology-stack)
7. [Architecture](#architecture)
8. [Repository Structure](#repository-structure)
9. [Requirements](#requirements)
10. [Installation](#installation)
11. [Configuration](#configuration)
12. [Run ScanR](#run-scanr)
13. [API Reference](#api-reference)
14. [Scan Workflows](#scan-workflows)
15. [Results and Interpretation](#results-and-interpretation)
16. [Database and History](#database-and-history)
17. [Testing](#testing)
18. [Manual Verification Checklist](#manual-verification-checklist)
19. [Security and Privacy](#security-and-privacy)
20. [Central Gateway Notes](#central-gateway-notes)
21. [Troubleshooting](#troubleshooting)
22. [Performance and Reliability](#performance-and-reliability)
23. [Accessibility and UI](#accessibility-and-ui)
24. [Development Workflow](#development-workflow)
25. [Contribution Guide](#contribution-guide)
26. [Roadmap](#roadmap)
27. [FAQ](#faq)
28. [Glossary](#glossary)
29. [Disclaimer](#disclaimer)
30. [License](#license)

---

## Overview

ScanR brings supported security-analysis workflows into a single web interface. The Flask backend coordinates application routes and scanner modules, while configured VirusTotal integration can provide external threat-intelligence data.

The project is designed as a practical cybersecurity development and learning platform. It provides a foundation for investigating URLs, files, hashes, and supported relationships without claiming to replace professional security products.

ScanR combines several common building blocks:

- A web interface served by Flask.
- Backend modules for URL, file, and hash workflows.
- VirusTotal API v3 integration for supported lookups.
- Relationship-query routes.
- Application health and status routes.
- Database-backed history components.
- Local environment-based configuration.
- Automated tests for selected core behavior.

Not every repository component has been verified end to end. Treat feature descriptions as a guide to the current project structure, not as a production-readiness guarantee.

### Who is ScanR for?

- Students learning cybersecurity application development.
- Developers exploring Flask-based security tools.
- Security learners practicing authorized threat-intelligence workflows.
- Contributors interested in testing, documentation, and defensive analysis.
- Users who need a local interface for supported analysis operations.

### What ScanR is not

- It is not a guaranteed malware verdict engine.
- It is not a complete antivirus replacement.
- It is not an enterprise EDR platform.
- It does not guarantee a report exists for every URL, file, or hash.
- It does not guarantee that a zero-detection result means an item is safe.
- It does not grant access to paid or restricted VirusTotal API capabilities.

---

## Project Goals

### Unified analysis experience

Bring supported workflows into one application so users can start an investigation from the same interface.

### Clear backend boundaries

Keep route handling, scanning logic, configuration, and database workflows separated where practical.

### Safe configuration

Keep credentials outside frontend code and source control. Support local configuration without embedding secrets in the repository.

### Honest result handling

Represent missing reports, upstream errors, unsupported relationships, and unknown verdicts without manufacturing a safe or malicious conclusion.

### Testable behavior

Use repeatable unit tests and smoke tests for selected core behavior, then add end-to-end tests as integration coverage improves.

### Maintainable documentation

Document setup, configuration, endpoints, known limitations, and troubleshooting in a form that new contributors can follow.

---

## Design Principles

### Accuracy before appearance

A polished interface is useful only when it presents the actual state of the underlying scan. Never show synthetic threat data as if it came from VirusTotal.

### Fail safely

Missing configuration, timeouts, invalid input, and upstream failures should produce clear errors instead of silently implying success.

### Keep secrets server-side

API keys belong in protected environment configuration. They must not appear in HTML, JavaScript, public documentation, screenshots, logs, or commits.

### Minimize unnecessary data sharing

Submitting a URL or file to an external threat-intelligence provider may disclose information. Users should understand this before submitting sensitive material.

### Prefer explicit status

Distinguish between configured, reachable, requested, completed, unavailable, and failed states. These states are not interchangeable.

### Keep claims verifiable

Only describe a feature as complete after its implementation and expected behavior have been tested.

---

## Features

### URL analysis

ScanR includes a URL-analysis workflow in its application structure. It is intended to submit supported URL inputs to the configured scanning implementation and present available results.

Expected considerations:

- URL validation may reject unsupported schemes.
- The upstream provider may not have a report for a URL.
- URL submissions can create an external data-sharing event.
- API quotas and permissions can affect the response.
- An error response must not be treated as a clean verdict.

### File analysis

The repository contains file-analysis components and a file-scan endpoint.

Expected considerations:

- File size and request-size limits may apply.
- Only permitted, harmless test files should be used for manual verification.
- The upstream provider may require a file upload or may return a report for an existing hash.
- File uploads can disclose the file to an external service.
- The exact request format is defined by the current route handler.

### Hash lookup

ScanR includes hash-analysis workflows for supported file hashes.

Common hash formats may include MD5, SHA-1, and SHA-256, subject to the validation implemented by the application.

A hash lookup does not require uploading the original file when a matching external report already exists. A missing record means that the provider has no available report for that lookup; it does not establish that the file is benign.

### Threat-intelligence lookups

VirusTotal API v3 can provide information about supported resources. The data returned depends on the resource, the endpoint, provider permissions, and the account's API plan.

ScanR should preserve the difference between provider data and local application interpretation.

### Relationship queries

The application exposes relationship-query routes for supported file and URL investigations.

Examples of relationship names may include related domains, IP addresses, or other resource associations, depending on the allowlist and provider support in the current code.

Not every relationship is available for every resource or account. A provider `403`, `404`, or `429` should be interpreted according to the returned status and message.

### Scan history

Database components support local scan-history workflows. History results depend on the database being initialized and the relevant routes being available.

Local history is not automatically a cloud synchronization service. Do not assume history is shared between separate clones or machines.

### Health and status endpoints

Health and status routes help distinguish application startup from selected configuration states.

A healthy Flask process does not prove that the external VirusTotal service is reachable or that an end-to-end scan will succeed.

### Central gateway configuration

The current code supports a central gateway configuration path for VirusTotal requests. The gateway must be deployed, reachable, configured with a server-side provider credential, and compatible with the client routes.

The central gateway's real URL/file scanning path remains pending independent end-to-end verification.

---

## Feature Status

| Area | Current evidence | Status |
|---|---|---|
| Flask application | Local health endpoint returned a running response | Verified locally |
| Core unit tests | 10 tests passed in the reported environment | Passed |
| Phase 2 smoke test | Printed `CORE_TESTS_OK` | Passed |
| Python syntax | Selected modules compiled successfully | Passed |
| GitHub integration commit | Commit `89c32bf` was pushed | Pushed |
| URL scan via central gateway | No independent successful end-to-end result confirmed | Pending |
| File scan via central gateway | No independent successful end-to-end result confirmed | Pending |
| Relationship integration | Routes and input validation reviewed; full provider success not confirmed | Partially verified |
| Fresh-clone setup | Not yet independently tested on a clean machine | Pending |
| Protection/feed components | Must be verified separately | Not confirmed |

Passing unit tests establishes only the behavior covered by those tests. It does not prove that every external API request or feature works.

---

## Technology Stack

| Technology | Role |
|---|---|
| Python | Backend language |
| Flask | Web server and route framework |
| HTML | Web interface structure |
| CSS | Visual styling |
| JavaScript | Frontend interactions |
| SQLite/database modules | Local records and history workflows |
| Requests | HTTP client |
| python-dotenv | Local environment configuration |
| VirusTotal API v3 | External threat-intelligence service |
| Git | Version control |
| GitHub | Source-code hosting and collaboration |

---

## Architecture

```mermaid
flowchart TD
    USER[User] --> UI[ScanR Web Interface]
    UI --> APP[Flask Backend]
    APP --> URL[URL Analysis]
    APP --> FILE[File Analysis]
    APP --> HASH[Hash Lookup]
    APP --> REL[Relationship Queries]
    URL --> SERVICE[Configured VirusTotal Service]
    FILE --> SERVICE
    HASH --> SERVICE
    REL --> SERVICE
    SERVICE --> RESULT[Provider Response]
    RESULT --> APP
    APP --> UI
    APP -. Supported history workflows .-> DB[(Local Database)]
```

### Request lifecycle

1. A user submits an input through the interface or API.
2. Flask routes the request to the relevant handler.
3. The handler validates the input and checks required configuration.
4. A scanner module or relationship client makes the supported request.
5. The configured service returns a response or error.
6. The backend processes the response and returns an application result.
7. Supported database routes may store or retrieve local history.

### Central mode

In central mode, ScanR sends supported requests to the configured ScanR gateway. The gateway is expected to hold the VirusTotal key on the server side.

### Direct mode

In direct mode, ScanR uses the local VirusTotal API key configured for that environment.

### Database boundary

Database behavior is local to the configured application unless a separate synchronization mechanism is explicitly implemented.

---

## Repository Structure

```text
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
├── files/
├── tests/
├── reports/
├── LICENSE
└── README.md
```

This is a simplified overview. Additional scripts, blueprints, configuration files, and modules may exist in the repository.

---

## Requirements

Before installing ScanR, prepare the following:

- Python 3.10 or newer is recommended.
- Git must be installed and available in the terminal.
- A compatible virtual environment is recommended.
- Dependencies must be installable from `requirements.txt`.
- Internet access is required for external threat-intelligence requests.
- Configure either an authorized central gateway or a local VirusTotal key.
- Ensure the configured provider account permits the endpoints you intend to use.

Some components may require additional configuration or provider permissions.

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/GhostMaskR/ScanR.git
cd ScanR
```

### 2. Create a virtual environment

#### Windows PowerShell

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If activation is blocked, allow it for the current PowerShell process only:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\.venv\Scripts\Activate.ps1
```

#### Linux or macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Review any dependency installation errors before continuing.

### 4. Configure the application

Create a local `.env` file in the project root using a secure text editor. Start from the variable names in `.env.example` and select the configuration mode that applies to you.

Do not paste a real API key into a terminal command. Do not commit `.env`.

### 5. Start the application

```powershell
python app.py
```

Open the local URL printed by the application. The default Flask development address is commonly `http://127.0.0.1:5000`, but the actual address depends on the app configuration.

---

## Configuration

ScanR currently has two intended configuration modes.

### Option A: central gateway

Set `SCANR_CENTRAL_API_URL` in your local `.env` file to the real HTTPS URL of a deployed gateway that you are authorized to use.

The example value in `.env.example` is a placeholder and is not a working service.

A usable gateway must:

- Be deployed and reachable.
- Have the provider credential configured server-side.
- Support the paths expected by ScanR.
- Return compatible response formats.
- Handle upstream errors and timeouts.
- Apply appropriate access controls and rate limits.
- Be monitored for abuse and availability.

Cloning ScanR does not automatically grant access to a shared gateway.

### Option B: direct VirusTotal configuration

Configure your own VirusTotal API key in the local `.env` file using a secure editor.

Use a valid key associated with your own account and follow VirusTotal's current terms, quotas, and permissions.

Never put a real key in:

- Frontend HTML or JavaScript.
- Git-tracked source files.
- README files or public documentation.
- Screenshots, issue reports, or pull requests.
- Logs that may be shared.
- Public deployment settings that expose the value to clients.

### Configuration precedence

When both central and direct configuration values are present, inspect the current client implementation to confirm which mode is selected. Do not assume that the presence of both settings means both are used simultaneously.

### Configuration validation

Before a real scan, confirm that:

- The expected environment variable is spelled correctly.
- The `.env` file is in the expected project root.
- The configured gateway URL uses HTTPS.
- The gateway is deployed and reachable.
- The provider credential is valid and stored securely.
- The provider account has permission for the requested endpoint.

---

## Run ScanR

Start the Flask application from the repository root with the virtual environment activated:

```powershell
python app.py
```

Then open the local address printed in the terminal.

### Development server warning

The Flask development server is for local development. Do not expose it directly to the public internet.

Public deployment requires a production server, secure environment configuration, rate limiting, access controls, logging, monitoring, and a security review.

---

## API Reference

The following endpoints are present in the current application structure. The corresponding route handlers are the authoritative source for exact request schemas, validation rules, and response fields.

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/` | Web interface |
| `GET` | `/health` | Health check |
| `GET` | `/api/status` | Application/scanner status |
| `GET` | `/api/history` | Scan history |
| `GET` | `/api/history/<scan_id>` | Individual history record |
| `POST` | `/api/scan/url` | URL-analysis workflow |
| `POST` | `/api/scan/file` | File-analysis workflow |
| `POST` | `/api/scan/hash` | Hash-analysis workflow |
| `GET` | `/api/file/<resource_id>/<relation>` | File relationship lookup |
| `POST` | `/api/relations` | Relationship query |
| `GET` | `/api/relations/status` | Relationship module status |

### Health endpoint

Use the health endpoint to check whether the local application responds:

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:5000/health"
```

A health response does not prove that the external VirusTotal service is working.

### Application status

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/status"
```

Review the status fields returned by the running version of the application.

### Scan history

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/history"
```

The response depends on database initialization and the current history implementation.

### URL, file, and hash requests

Inspect the route handler before constructing requests for `/api/scan/url`, `/api/scan/file`, or `/api/scan/hash`.

Do not guess form fields or JSON keys from the route name alone.

### Relationship requests

The relationship routes validate resource identifiers and supported relationship names. The exact allowlist and accepted payload fields are defined by the current code.

Provider responses may include authorization errors, missing-resource errors, or rate-limit responses.

### API stability

These routes are project interfaces, not a promise of long-term API compatibility. Recheck the code when upgrading to a new branch or release.

---

## Scan Workflows

### URL workflow

1. Enter a URL supported by the current validator.
2. Submit it through the ScanR interface.
3. The backend validates the input.
4. The configured scanning service is queried when required.
5. The interface presents the available result or error.

Expected failure cases include invalid schemes, missing configuration, upstream timeouts, missing reports, and API permission errors.

### File workflow

1. Choose a permitted test file.
2. Submit the file through the supported interface.
3. The backend applies request and input validation.
4. The configured analysis path processes the request.
5. The result is presented if available.

Do not use confidential files for tests unless you have authorization to send them to the external provider.

### Hash workflow

1. Provide a supported hash format.
2. The backend validates the input.
3. The configured service is queried for an available report.
4. ScanR displays the response or a clear error.

A valid hash does not guarantee that a provider report exists.

### Relationship workflow

1. Choose a resource kind supported by the current endpoint.
2. Provide a valid identifier or URL according to the handler.
3. Select a relationship allowed by the current implementation.
4. ScanR sends the query to the configured service.
5. The application presents the provider response or error.

Some relationships may be restricted by provider account permissions.

---

## Results and Interpretation

### Malicious

A malicious classification indicates that the application has interpreted the available result as malicious according to its current logic. Review the underlying detections and context before taking action.

### Suspicious

A suspicious result indicates that the available data or classification logic warrants further investigation. It is not equivalent to a confirmed malware finding.

### No detections

Zero detections do not prove safety. The resource may be new, unknown, or not detected by the vendors that analyzed it.

### Unknown or unavailable

An unknown state can mean that no report was available or that the application did not have enough information to assign a reliable classification.

### Provider error

An upstream error means the requested operation did not complete successfully. It must not be displayed as a clean verdict.

### Use context

Interpret results alongside source, behavior, file origin, execution context, timestamps, and other authorized evidence.

---

## Database and History

ScanR includes database-related components for local application data and scan history.

### Local storage

Local database files may contain user activity, scan records, identifiers, and analysis metadata. Treat them as potentially sensitive.

### Initialization

The application should initialize its database using the project's existing setup workflow. Follow the repository code and dependencies rather than assuming a database file can be copied to every environment unchanged.

### History behavior

History endpoints depend on the configured database and the current implementation. A new clone may have an empty database even when another installation has previous records.

### Git handling

Do not commit local database files or private scan artifacts unless the project explicitly requires a safe, sanitized fixture.

### Backups

Keep local backups outside public commits. Confirm the destination before running cleanup or replacement operations.

---

## Testing

Run tests from the repository root with the project's virtual environment activated.

### Core unit tests

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

### Phase 2 smoke test

```powershell
python -m tests.phase2_smoke_test
```

If direct script execution has an import-path issue, run the module form from the repository root. Do not modify code just to hide a test import error without understanding it.

### Syntax validation

```powershell
python -m py_compile app.py scanner/virustotal.py scanner/relations_api.py
```

### Git diff validation

```powershell
git diff --check
git diff --cached --check
```

These commands validate syntax and whitespace; they do not exercise every external service request.

### Previously reported results

- 10 core unit tests passed in the reported development environment.
- The Phase 2 smoke test printed `CORE_TESTS_OK`.
- Selected Python modules compiled successfully.
- The integration commit was pushed to the remote branch.

These are historical results from the development session. Rerun tests after making additional changes.

---

## Manual Verification Checklist

### Fresh installation

- [ ] Clone the repository into a clean directory.
- [ ] Create a fresh virtual environment.
- [ ] Install the dependencies.
- [ ] Configure the selected service mode securely.
- [ ] Start the Flask application.
- [ ] Open the local interface.

### Health and status

- [ ] Health endpoint responds.
- [ ] Status endpoint responds.
- [ ] Missing configuration is reported clearly.
- [ ] Invalid configuration is handled safely.

### URL scanning

- [ ] Valid, harmless test URL is accepted by the validator.
- [ ] Invalid schemes are rejected.
- [ ] Missing report is handled correctly.
- [ ] Upstream errors do not become safe verdicts.
- [ ] Central gateway URL scan succeeds end to end.

### File scanning

- [ ] Permitted test file can be submitted.
- [ ] Oversized or invalid input is handled safely.
- [ ] File analysis returns an understandable response.
- [ ] Central gateway file scan succeeds end to end.

### Hash scanning

- [ ] Supported hash formats are accepted.
- [ ] Invalid hash formats are rejected.
- [ ] Missing provider reports are represented clearly.

### Relationship queries

- [ ] Unsupported relationship is rejected.
- [ ] Invalid resource identifier is rejected.
- [ ] Provider authorization error is surfaced clearly.
- [ ] Rate limiting is handled.

### Security

- [ ] No secrets are present in tracked files.
- [ ] `.env` remains untracked.
- [ ] The database is not unintentionally staged.
- [ ] Local reports and backups remain private.
- [ ] Public gateway access is appropriately restricted.

---

## Security and Privacy

### Protect API keys

Keep credentials in local environment configuration or a secure deployment secret store. Never commit `.env` or place a real key in the frontend.

If a key is exposed, revoke or rotate it through the provider's official account controls.

### Protect the central gateway

A shared gateway must keep its upstream credential on the server side. It should use appropriate access controls, rate limits, monitoring, and abuse protection.

Do not expose an unrestricted personal API key through a public endpoint.

### Respect privacy

Submitting URLs, files, hashes, or other identifiers to VirusTotal may disclose information to an external service. Review organizational requirements before submitting confidential material.

### Use authorized inputs

Only analyze files, URLs, and systems you are permitted to investigate.

### Keep the app local by default

The Flask development server is not a hardened public deployment. Public hosting requires a production server and a separate security review.

### Interpret results responsibly

Do not treat missing reports or zero detections as proof of safety.

### Limit logging

Avoid logging API keys, sensitive request bodies, confidential file contents, or other unnecessary secrets.

### Dependency hygiene

Keep dependencies updated through a reviewed process. Test compatibility after dependency changes.

### Do not overstate protection

ScanR is a development project for supported analysis workflows, not a full antivirus or EDR replacement.

---

## Central Gateway Notes

### What central mode means

Central mode sends supported ScanR requests to a configured gateway rather than directly using the local VirusTotal key.

### What central mode does not mean

- It does not mean every clone automatically has gateway access.
- It does not guarantee that the gateway is always available.
- It does not guarantee that the upstream key has permission for every endpoint.
- It does not guarantee that a scan will return a report.
- It does not remove the need for rate limiting and access controls.

### Gateway compatibility

The gateway and ScanR client must agree on request paths, HTTP methods, payloads, response formats, timeout behavior, and error handling.

### Gateway health versus scan success

A successful health response proves only that the health route responded. A real scan must be tested separately.

### Deployment configuration

Use the actual deployed HTTPS URL in the local environment configuration. Do not publish credentials in README files or issue reports.

### End-to-end verification

Before claiming the central integration is complete, test a harmless URL and a permitted file through the deployed gateway and confirm the expected upstream response.

---

## Troubleshooting

### The app does not start

Check the active Python environment, dependency installation, current directory, and full terminal traceback.

### A module import fails

Run commands from the repository root and activate the correct virtual environment. Confirm that the expected package and files exist.

### The health endpoint fails

Check whether the Flask application started, which port it uses, and whether another process is using that port.

### The status endpoint reports unconfigured

Review the expected environment variable names and the location of the local `.env` file. Do not expose the actual credential while debugging.

### The gateway cannot be reached

Verify the deployed service URL, HTTPS configuration, deployment status, network connectivity, and gateway logs.

### A scan times out

Check connectivity, upstream availability, timeout settings, and provider response time. Do not repeatedly submit large requests without checking rate limits.

### A scan returns 400

Review input validation, required fields, resource identifier format, and relationship allowlists.

### A scan returns 401 or 403

The upstream credential may be missing, invalid, or unauthorized for the requested operation. Check configuration and provider permissions securely.

### A scan returns 404

The route or resource may not exist, or the provider may not have the requested report or relationship.

### A scan returns 429

The service may be rate-limiting requests. Respect the provider's limits and retry policy.

### A scan returns 502 or 504

The backend may be reporting an upstream failure or timeout. Inspect sanitized logs and gateway health without exposing credentials.

### History is empty

A fresh database may have no records. Confirm the scan was saved and that the application is reading the expected database.

### The README banner does not render

Check the Markdown preview, image URL, and network access to the external banner service. The README uses standard Markdown image syntax rather than Pandoc HTML wrappers.

### Tests pass but live scans fail

Unit tests may mock external behavior or cover only local logic. Verify configuration, endpoint compatibility, provider permissions, and actual network requests.

---

## Development Workflow

### Before changing code

- Review the current route and module behavior.
- Identify the scope of the change.
- Avoid editing unrelated files.
- Keep secrets and local artifacts out of commits.

### During development

- Use a virtual environment.
- Run focused tests after a change.
- Preserve established request and response contracts unless intentionally changing them.
- Keep error messages clear and safe.

### Before committing

- Review the staged file list.
- Inspect the staged diff.
- Confirm `.env` and local databases are not staged.
- Run tests relevant to the change.
- Check for accidental credentials.

### After pushing

- Verify the commit exists on the intended branch.
- Confirm the working tree state.
- Test deployed behavior separately when applicable.

---

## Contribution Guide

Contributions, bug reports, documentation fixes, and focused improvements are welcome.

1. Fork the [ScanR repository](https://github.com/GhostMaskR/ScanR).
2. Create a branch for a focused change.
3. Keep credentials, local databases, scan artifacts, and private reports out of commits.
4. Run the relevant tests.
5. Manually verify behavior affected by the change.
6. Update documentation when configuration or API behavior changes.
7. Open a pull request describing the problem, the implementation, and actual test results.

### Pull request checklist

- [ ] The change has a clear purpose.
- [ ] The diff contains only intended files.
- [ ] No secrets or local artifacts are included.
- [ ] Relevant tests were run.
- [ ] Error behavior was considered.
- [ ] Documentation was updated where needed.
- [ ] Unverified behavior is not described as complete.

---

## Roadmap

- [ ] Verify central-gateway URL scanning end to end.
- [ ] Verify central-gateway file scanning end to end.
- [ ] Verify hash lookups through the intended configuration.
- [ ] Verify supported relationship requests through the intended configuration.
- [ ] Add integration tests for gateway timeouts and upstream errors.
- [ ] Improve configuration validation and user-facing diagnostics.
- [ ] Add genuine screenshots from a running instance.
- [ ] Improve fresh-clone setup documentation.
- [ ] Review protection and feed-related modules separately.
- [ ] Review production deployment requirements before public hosting.
- [ ] Continue improving accessibility and responsive behavior.

---

## Disclaimer

ScanR is provided for educational, development, and authorized defensive security analysis.

The project does not guarantee that every scan will succeed or that every result is accurate, complete, or current. External service availability, account permissions, rate limits, configuration, and implementation details can affect behavior.

Use the application responsibly and comply with applicable laws, service terms, organizational policies, and privacy requirements.

Do not use ScanR as the sole basis for high-impact security decisions.

---

## License

See the repository's [LICENSE](LICENSE) file for the applicable terms.

![ScanR Footer Banner](https://capsule-render.vercel.app/api?type=waving&color=0:00C896,55:102A43,100:050816&height=130&section=footer&animation=twinkling)

**ScanR — Analyze. Investigate. Understand.**

[GitHub Repository](https://github.com/GhostMaskR/ScanR)

*Cybersecurity development project · Built with Python and Flask*

---

## Appendix — Release Readiness Checklist

- [ ] Clean installation completed.
- [ ] Dependencies installed successfully.
- [ ] Local configuration reviewed securely.
- [ ] No real credentials are committed.
- [ ] Unit tests passed in the current environment.
- [ ] Smoke test passed in the current environment.
- [ ] Health endpoint verified.
- [ ] URL scanning tested end to end.
- [ ] File scanning tested end to end.
- [ ] Hash lookup behavior verified.
- [ ] Relationship routes tested with valid and invalid input.
- [ ] Empty and populated history behavior checked.
- [ ] Timeout and provider-error behavior checked.
- [ ] Rate-limit behavior considered.
- [ ] Public gateway access protected where applicable.
- [ ] Production deployment reviewed separately.
- [ ] Logs reviewed for sensitive data.
- [ ] README status claims match actual test evidence.
- [ ] Known limitations documented.
- [ ] Intended branch and commit verified.

## Final Project Statement

ScanR is a developing cybersecurity application focused on supported security-analysis and threat-intelligence workflows. The current codebase includes a Flask web interface, scanning modules, relationship endpoints, status routes, and database-related components.

The reported development checks include ten passing core unit tests, a passing Phase 2 smoke test, syntax validation for selected modules, and a successful GitHub integration push.

Central-gateway end-to-end URL and file scanning remains pending independent verification. This README intentionally does not represent that behavior as complete.

Use ScanR only with authorized inputs, secure configuration, and a clear understanding of external data sharing and provider limitations.

**ScanR — Analyze. Investigate. Understand.**
