# VulnScan Pro — Smart Web Application Vulnerability Scanner

A full-stack web application security scanner with real-time scan progress,
authenticated multi-user projects, and automated PDF/JSON reporting.

> ⚠️ **Authorized testing only.** Only scan systems you own or have explicit
> written permission to test. See [Security Notes](#-security-notes).

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Node.js 18+ *(optional — only needed to run the Playwright end-to-end tests)*

### Setup
```bash
# From the repository root
pip install -r requirements.txt
cp .env.example .env          # then edit .env with your own secrets
python backend_app.py
```

The server starts on `http://127.0.0.1:5000`. Flask serves the frontend
(`vuln-scanner-app.html` + `static/app.js`) directly at that URL — open it in
any modern browser. A default admin account (`admin` / `admin123`) is created on
first run and is **forced to change its password at first login**.

In this default mode, scans run in an in-process background thread — **no Redis or
Celery worker required**. To scale scans out to a dedicated worker, see
[Async Scans](#-async-scans-celery--redis) below.

### Docker

Runs the full stack (Flask web app + Redis + Celery worker) together:

```bash
docker compose up --build
```

The app is then available at `http://127.0.0.1:5000`. Set strong `SECRET_KEY` /
`JWT_SECRET_KEY` (e.g. in a local `.env`) before any non-local use — compose reads
them from your environment.

## 📋 Features

### Core Scanning
Each check below is implemented in `VulnerabilityScanner` (`backend_app.py`) and
is designed to confirm findings (probe + evidence) rather than flag by name:

- **SQL Injection** — error-based detection against a library of DB error signatures
- **Reflected XSS** — payload-reflection testing with an HTML-entity-encoded
  false-positive guard (an escaped `&lt;script&gt;` reflection is *not* flagged)
- **CSRF** — flags POST forms that carry no anti-CSRF token field
- **Security Headers** — missing `X-Frame-Options`, `X-Content-Type-Options`,
  `Strict-Transport-Security`, `Content-Security-Policy`, `X-XSS-Protection`
- **Insecure Transport** — flags targets served over plain HTTP instead of HTTPS
- **Sensitive Files / Information Disclosure** — content-confirmed probing of
  paths like `/.git/HEAD`, `/.env`, `/phpinfo.php`, `/web.config`, swagger/openapi
- **Open Redirect** — canary-confirmed (only fires on a real redirect to the canary)
- **CORS Misconfiguration** — wildcard origin and reflected-origin (± credentials)
- **Clickjacking** — missing `X-Frame-Options` / CSP `frame-ancestors`
- **SSRF** — evidence-based (metadata reflection, redirect-to-internal, or a
  reproducible timing signature); never flags on a URL-ish parameter alone
- **IDOR** — active cross-identity object-access testing using a second credential
  (`auth_secondary` in the scan config); flags only a confirmed authorization
  bypass (B reads A's object while a non-owned probe id is denied), never on assumption

### Dashboard
- Risk-score gauge
- Severity-breakdown donut chart
- Recent activity / scan feed
- Aggregate statistics (projects, targets, scans, vulnerabilities) via
  `GET /api/dashboard/stats`

### Reports & Scheduling
- **PDF** — full executive report generated with ReportLab
- **JSON** — machine-readable structured output
- **Scheduled Scans** — cron-expression-based recurring scans (background worker)

### Security Hardening (the app itself)
- JWT auth with access/refresh tokens
- bcrypt password hashing (work factor ≥ 12)
- Account lockout + IP rate limiting + progressive delay on `/api/auth/login`
  (locked / wrong-password / unknown-user are indistinguishable in body & timing)
- Server-side input validation & sanitization (Pydantic v2)
- Email verification and password-reset flows
- Security response headers set on every response (see `add_security_headers`)
- CORS locked to an explicit origin allowlist

## ⚡ Async Scans (Celery + Redis)

Scan execution has two interchangeable backends, selected by the `REDIS_URL`
environment variable — a single `dispatch_scan()` entry point hides which is used:

| `REDIS_URL` | Backend | Infrastructure |
|-------------|---------|----------------|
| **unset** (default) | in-process background thread | none — just `python backend_app.py` |
| set (e.g. `redis://localhost:6379/0`) | Celery worker over Redis | Redis + a Celery worker process |

With Redis configured, scan progress is relayed from the worker back to browser
clients through a Redis-backed Socket.IO message queue, so real-time updates keep
working across processes. Run the worker with:

```bash
celery -A backend_app.celery_app worker --pool=threads --concurrency=4
```

Or use `docker compose up --build`, which wires up Redis, the web app, and the
worker together. If `REDIS_URL` is set but Celery/redis aren't importable, the app
logs a warning and transparently falls back to threading.

## 🗺 Roadmap

Planned work that is **not** in the repository yet — tracked here rather than
listed as a shipped feature:

- **CSV Report Export** — spreadsheet-compatible export (currently PDF + JSON only)
- **Postgres backend** — the SQLite default tolerates only light multi-writer load;
  Postgres is recommended when running the Celery worker under real concurrency

## 🔧 API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/auth/register | New user registration |
| POST | /api/auth/login | User authentication |
| POST | /api/auth/refresh | Exchange refresh token for a new access token |
| GET | /api/projects | List user projects |
| POST | /api/projects | Create project |
| GET | /api/projects/:id/targets | List a project's targets |
| POST | /api/targets | Add target |
| POST | /api/scans | Start a vulnerability scan |
| GET | /api/scans/:id | Get scan status |
| GET | /api/scans/:id/vulnerabilities | Get all findings for a scan |
| GET | /api/scans/:id/report/pdf | Download the PDF report |
| GET | /api/scans/:id/report/json | Download the JSON report |
| GET | /api/schedules | List scheduled scans |
| GET | /api/dashboard/stats | Dashboard statistics |

Real-time scan progress is pushed over Socket.IO (`scan_progress` events; join a
scan room with the `join_scan` event).

## 🏗 Architecture

```
┌──────────────────┐   REST / WebSocket   ┌──────────────────┐   SQL    ┌──────────┐
│  Vanilla JS SPA  │◄────────────────────►│   Flask API      │◄────────►│  SQLite  │
│  HTML/CSS/JS     │                      │   + Socket.IO    │          │          │
│  (served by Flask)│                     │   (Port 5000)    │          └──────────┘
└──────────────────┘                      └──────────────────┘
                                                   │
                                           ┌───────▼────────┐
                                           │ Scanner Engine │
                                           │ + ReportLab    │
                                           └────────────────┘
```

**Tech stack:** Python 3.11+ · Flask · Flask-SocketIO (eventlet) ·
Flask-JWT-Extended · Flask-SQLAlchemy · Flask-Bcrypt · Pydantic v2 · SQLite ·
ReportLab · BeautifulSoup4 + requests (scanner engine) · vanilla JS / HTML / CSS
frontend · Playwright (end-to-end tests).

## 🧪 Testing & CI

```bash
pip install -r requirements-dev.txt
pytest                              # hermetic unit/integration tests (Flask test client)
python integration_smoke_test.py    # live-server smoke test (requires a running server)
```

Every push and pull request runs [`.github/workflows/ci.yml`](.github/workflows/ci.yml):
it installs dependencies, runs `pytest` (**the build fails on any test failure**),
then runs `pip-audit` (dependency CVE scan) and `bandit` (static security lint) as
**non-blocking** checks whose findings are surfaced in the logs.

## 🔐 Security Notes

- Always obtain explicit written permission before scanning any target.
- This tool is intended for authorized security testing only.
- Illegal use of this tool is strictly prohibited.
- The default admin credentials (`admin` / `admin123`) must be changed — the app
  forces a password change on first login and refuses to boot in production with
  default `SECRET_KEY` / `JWT_SECRET_KEY` values.
- Never commit a real `.env`. See `.env.example` for the required keys.

## 🎓 Project Information

**Type:** Portfolio project — Web Application Security / VAPT
**Tech Stack:** Python Flask, vanilla JS frontend, SQLite, ReportLab
**OWASP Coverage:** A01–A03, A05–A07, A09
