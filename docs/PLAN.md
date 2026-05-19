# LHSec — Project Plan

> **LHSec** is an open, self-hosted security auditing platform that helps operators discover, track and report vulnerabilities across a portfolio of institutions and their public IP space.

---

## Table of Contents

1. [Goals & Non-Goals](#1-goals--non-goals)
2. [High-Level Architecture](#2-high-level-architecture)
3. [Data Model](#3-data-model)
4. [Feature Breakdown](#4-feature-breakdown)
5. [Tech Stack](#5-tech-stack)
6. [Directory Layout](#6-directory-layout)
7. [Milestones & Roadmap](#7-milestones--roadmap)
8. [External Tools & Dependencies](#8-external-tools--dependencies)
9. [Security & Operational Notes](#9-security--operational-notes)

---

## 1. Goals & Non-Goals

### Goals
- Manage a **registry of institutions** (name, metadata) each mapped to one or more **public IPv4/IPv6 ranges or addresses**.
- **Automatically resolve** domains and subdomains that point to those IPs (reverse DNS, certificate transparency, passive DNS, brute-force).
- Run **active scans** (port scanning, service fingerprinting, vulnerability detection) against discovered surfaces using industry-standard tools.
- Present findings in a **web UI** that supports launching scans in the background, monitoring live progress, and browsing results.
- Generate **per-institution PDF/HTML reports** focused on critical and high-severity findings, ready to send to the institution's security contact.
- Track **remediation status** — mark findings as acknowledged, in-progress, or resolved across scan cycles.

### Non-Goals
- Not an authenticated pen-test / exploitation framework.
- Not a replacement for a full SIEM or EDR.
- Scanning outside of explicitly registered IPs is explicitly prevented by design.

---

## 2. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                          Browser / UI                           │
│          (HTML + TailwindCSS + Alpine.js / HTMX)                │
└────────────────────────┬────────────────────────────────────────┘
                         │ HTTP/REST + WebSocket (progress)
┌────────────────────────▼────────────────────────────────────────┐
│                     FastAPI Backend                             │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐ │
│  │  REST API    │  │  WebSocket   │  │  Background Task Queue │ │
│  │  /api/v1/… │  │  /ws/tasks/… │  │  (Celery or asyncio)   │ │
│  └──────────────┘  └──────────────┘  └────────────────────────┘ │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                   Service Layer                          │   │
│  │  InstitutionSvc  │  ScanSvc  │  FindingSvc  │ ReportSvc  │   │
│  └──────────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    Data Layer (SQLite / PostgreSQL)      │   │
│  │              SQLAlchemy ORM  +  Alembic migrations       │   │
│  └──────────────────────────────────────────────────────────┘   │
└────────────────────────┬────────────────────────────────────────┘
                         │ subprocess / docker exec
┌────────────────────────▼────────────────────────────────────────┐
│                    Tool Wrappers                                 │
│   nmap  │  dnsx  │  subfinder  │  amass  │  nuclei  │  httpx    │
└─────────────────────────────────────────────────────────────────┘
```

**Data flow for a typical scan:**

```
Institution + IPs
      │
      ▼
[1] Reverse DNS + CT logs + Passive DNS   ──► Domains / Subdomains
      │
      ▼
[2] HTTP(S) probe (httpx)                 ──► Live web services
      │
      ▼
[3] Port scan (nmap)                      ──► Open ports / services
      │
      ▼
[4] Vulnerability scan (nuclei)           ──► Raw findings (JSONL)
      │
      ▼
[5] Normalise → store in DB               ──► Findings table
      │
      ▼
[6] Report generation (Jinja2 → PDF)      ──► institution_report.pdf
```

---

## 3. Data Model

```
Institution
  id            PK
  name          str
  slug          str (unique)
  contact_email str?
  notes         text?
  created_at    datetime

IpRange
  id            PK
  institution_id FK → Institution
  cidr          str  (e.g. "203.0.113.0/28" or "203.0.113.5/32")
  label         str?
  created_at    datetime

Domain
  id            PK
  institution_id FK → Institution
  fqdn          str
  source        enum (reverse_dns | ct_log | passive_dns | brute)
  resolved_ip   str?
  first_seen    datetime
  last_seen     datetime

ScanJob
  id            PK (uuid)
  institution_id FK → Institution  (null = global)
  scan_type     enum (discovery | portscan | vuln | full)
  status        enum (pending | running | done | failed)
  started_at    datetime?
  finished_at   datetime?
  config        JSON  (tool flags, templates, …)
  log_output    text  (streamed stdout/stderr)

Finding
  id            PK
  scan_job_id   FK → ScanJob
  institution_id FK → Institution
  domain        str?
  ip            str?
  port          int?
  protocol      str?
  severity      enum (info | low | medium | high | critical)
  template_id   str  (nuclei template id)
  name          str
  description   text
  evidence      text
  cvss_score    float?
  cve_ids       JSON  (list of strings)
  remediation   text?
  status        enum (open | acknowledged | fixed | false_positive)
  first_seen    datetime
  last_seen     datetime

Report
  id            PK
  institution_id FK → Institution
  generated_at  datetime
  format        enum (pdf | html)
  severity_filter JSON  (e.g. ["critical","high"])
  file_path     str
```

---

## 4. Feature Breakdown

### 4.1 Institution & IP Management
- CRUD for institutions with name, contact, notes.
- Add/edit/delete IP ranges (CIDR notation) per institution.
- Validate no overlapping ranges across institutions.
- Import from CSV (bulk onboarding).

### 4.2 Discovery Pipeline
- **Reverse DNS** via `dnsx` on each IP in the registered ranges.
- **Certificate Transparency** via `subfinder` (crtsh, certspotter sources).
- **Passive DNS** via `amass intel`.
- **Subdomain brute-force** (optional, toggled per scan).
- Results deduplicated and stored in `Domain` table with source attribution.

### 4.3 Active Scanning
- **HTTP probe**: `httpx` to identify live web services, titles, tech stack, TLS info.
- **Port scan**: `nmap` with configurable preset profiles (quick / full / stealth).
- **Vulnerability scan**: `nuclei` with configurable template tags/severity filters.
  - Default focus: `critical,high` severities.
  - Support for custom template paths.

### 4.4 Background Task System
- Each scan job runs as a background task (Celery + Redis **or** asyncio `subprocess` for simpler deployments).
- Real-time log streaming to the UI via **WebSocket**.
- Jobs can be cancelled.
- Job history is persisted.

### 4.5 Web UI

#### Dashboard
- Summary cards: institutions count, open findings by severity, active scan jobs.
- Recent critical/high findings feed.

#### Institutions
- List/detail view.
- IP ranges panel.
- Associated domains.
- Findings per institution grouped by severity.
- Quick-launch scan buttons.

#### Scan Management
- Launch scan modal: choose institution, scan type, tool options.
- Active jobs list with live **progress bar** and **collapsible log output**.
- Job history table (filterable by institution, type, status).

#### Findings
- Filterable/sortable table (institution, severity, status, date).
- Finding detail modal: full evidence, affected asset, CVE links, remediation advice.
- Bulk status update (acknowledge / mark fixed / false positive).
- Severity trend chart over time.

#### Reports
- Generate report modal: choose institution, severity filter, format (PDF/HTML).
- Report list with download links.
- Report preview in-browser.

### 4.6 Reporting
- Jinja2 templates rendered with **WeasyPrint** (PDF) or served as HTML.
- Per-institution report includes:
  - Executive summary (findings count by severity).
  - Asset inventory (IPs, domains).
  - Critical & high findings table with CVE references and remediation steps.
  - Methodology section.
  - Appendix with all findings (medium, low, info).

---

## 5. Tech Stack

| Layer | Technology |
|---|---|
| Backend framework | **FastAPI** (Python 3.12+) |
| ORM / migrations | **SQLAlchemy 2** + **Alembic** |
| Database | **SQLite** (dev) → **PostgreSQL** (prod) |
| Background tasks | **asyncio subprocess** (simple) or **Celery + Redis** (scale) |
| Real-time | **WebSocket** (FastAPI native) |
| Frontend | **Jinja2** server-side templates + **TailwindCSS** + **Alpine.js** |
| Charts | **Chart.js** (severity trend) |
| PDF generation | **WeasyPrint** |
| Containerisation | **Docker** + **docker-compose** |
| Tool runtime | Host binaries or dedicated **scanner Docker image** |
| Testing | **pytest** + **httpx** (async test client) |
| Linting / format | **ruff** + **black** |

---

## 6. Directory Layout

```
lhsec/
├── docs/
│   ├── PLAN.md              ← this file
│   └── screenshots/
├── backend/
│   ├── app/
│   │   ├── main.py          ← FastAPI app factory
│   │   ├── config.py        ← settings (pydantic-settings)
│   │   ├── database.py      ← engine + session
│   │   ├── models/          ← SQLAlchemy ORM models
│   │   ├── schemas/         ← Pydantic request/response schemas
│   │   ├── api/
│   │   │   └── v1/
│   │   │       ├── institutions.py
│   │   │       ├── scans.py
│   │   │       ├── findings.py
│   │   │       └── reports.py
│   │   ├── services/        ← business logic
│   │   ├── tasks/           ← background scan orchestration
│   │   └── tools/           ← wrappers: nmap, nuclei, httpx, dnsx, subfinder
│   ├── alembic/
│   ├── tests/
│   └── requirements.txt
├── frontend/
│   ├── templates/           ← Jinja2 HTML templates
│   │   ├── base.html
│   │   ├── dashboard.html
│   │   ├── institutions/
│   │   ├── scans/
│   │   ├── findings/
│   │   └── reports/
│   ├── static/
│   │   ├── css/             ← compiled TailwindCSS
│   │   └── js/              ← Alpine.js, Chart.js bundles
│   └── tailwind.config.js
├── scanner/
│   └── Dockerfile           ← image with nmap, nuclei, httpx, dnsx, subfinder
├── docker-compose.yml
├── docker-compose.prod.yml
└── README.md
```

---

## 7. Milestones & Roadmap

### Milestone 1 — Foundation (Week 1–2)
- [ ] Project skeleton: FastAPI app, DB setup, Alembic migrations.
- [ ] Institution + IpRange CRUD API + UI (list, create, edit, delete).
- [ ] Base HTML layout with TailwindCSS (sidebar, navbar, responsive).
- [ ] Docker Compose with app + scanner container.

### Milestone 2 — Discovery (Week 3–4)
- [ ] Tool wrappers: `dnsx`, `subfinder`, `amass`.
- [ ] Background task runner with WebSocket log streaming.
- [ ] Scan job model + API endpoints.
- [ ] Discovery scan UI: launch modal + live progress modal.
- [ ] Domain results storage and display per institution.

### Milestone 3 — Active Scanning (Week 5–6)
- [ ] Tool wrappers: `nmap`, `httpx`, `nuclei`.
- [ ] Full scan pipeline: discovery → probe → portscan → vuln scan.
- [ ] Finding normalisation from nuclei JSONL output.
- [ ] Findings table UI with filters and detail modal.
- [ ] Bulk status management.

### Milestone 4 — Reporting (Week 7)
- [ ] Jinja2 + WeasyPrint PDF report template.
- [ ] HTML report variant.
- [ ] Report generation endpoint + download.
- [ ] Report management UI.

### Milestone 5 — Polish & Hardening (Week 8)
- [ ] Dashboard with charts (Chart.js severity trends).
- [ ] CSV import for institutions/IPs.
- [ ] User authentication (HTTP Basic or API key gating).
- [ ] Scan scheduling (cron-style via APScheduler).
- [ ] Documentation (README, API docs via Swagger).
- [ ] Full test coverage for service layer.

---

## 8. External Tools & Dependencies

| Tool | Purpose | Install |
|---|---|---|
| **nmap** | Port scanning & service detection | apt / brew |
| **nuclei** (ProjectDiscovery) | Template-based vuln detection | go install / binary |
| **httpx** (ProjectDiscovery) | HTTP probing & fingerprinting | go install / binary |
| **dnsx** (ProjectDiscovery) | Reverse DNS & DNS resolution | go install / binary |
| **subfinder** (ProjectDiscovery) | Subdomain enumeration via passive sources | go install / binary |
| **amass** | OSINT subdomain & IP mapping | go install / binary |
| **nuclei-templates** | Official CVE/vuln template library | auto-update via nuclei |

All tools will be encapsulated inside the `scanner/` Docker image to ensure reproducible environments.

---

## 9. Security & Operational Notes

- **Scope enforcement**: The tool will only scan IPs/domains that resolve back to a registered institution IP range. Any target outside the registered scope is rejected.
- **Rate limiting**: Scan profiles include configurable rate/concurrency limits to avoid overwhelming targets.
- **Audit log**: Every scan job, status change, and report generation is logged with timestamp and (future) operator identity.
- **Credential-free**: LHSec performs unauthenticated external scanning only. No credentials or authenticated scanning paths are supported in v1.
- **Legal notice**: Users are responsible for obtaining written authorisation from each institution before running any scans. LHSec should be deployed on a network with egress that institutions have been informed about.
- **Data sensitivity**: Findings may contain sensitive technical details. Restrict access to the LHSec web UI to authorised operators (VPN / firewall rules recommended).
- **TLS**: Production deployments must sit behind a TLS-terminating reverse proxy (nginx / Caddy).
