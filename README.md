# LHSec

A self-hosted security auditing platform for managing organisations, discovering their internet-exposed assets and running automated vulnerability scans — all from a single web UI.

> **Status:** Early proof-of-concept. Designed for internal red-team / security-audit workflows.

---

## Features

| Area | Capability |
|---|---|
| **Asset management** | Import organisations with public IP ranges via CSV or JSON; add domains manually |
| **Domain discovery** | IP-based discovery: TLS certificate probing, HTTP redirect harvesting, reverse DNS, Amass |
| **Certificate Transparency** | crt.sh (free) + SSLMate Certspotter (optional API key) per root domain |
| **Port scanning** | Nmap service discovery across 48 common ports; results stored per organisation |
| **Vulnerability scanning** | Nuclei v3 with official ProjectDiscovery template profiles; service-aware targets |
| **Live scan output** | Real-time log streaming via WebSocket with REST polling fallback |
| **Findings management** | Severity-grouped findings with CVSS scores, CVE IDs, evidence and status tracking |
| **Scan control** | Stop individual scans or kill all running scans from the UI |

---

## Tech stack

- **Backend:** Python 3.12 · FastAPI · SQLAlchemy 2 · SQLite · Jinja2
- **Frontend:** TailwindCSS · Alpine.js · Lucide icons · WebSocket
- **External tools:** [Nuclei](https://github.com/projectdiscovery/nuclei) · [httpx](https://github.com/projectdiscovery/httpx) · [Amass](https://github.com/owasp-amass/amass) · Nmap
- **Package manager:** [uv](https://github.com/astral-sh/uv)

---

## Prerequisites

| Tool | Minimum version | Install |
|---|---|---|
| Python | 3.12 | [python.org](https://www.python.org) |
| uv | latest | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| Nuclei | v3 | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| httpx (PD) | v1 | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| Nmap | 7+ | `apt install nmap` / `brew install nmap` |
| Amass | v4 | `go install github.com/owasp-amass/amass/v4/...@latest` |

Go binaries land in `~/go/bin/` by default. Make sure that directory is on your `PATH`:

```bash
export PATH="$HOME/go/bin:$PATH"
```

### Install Nuclei template profiles

LHSec uses official ProjectDiscovery [community profiles](https://github.com/projectdiscovery/nuclei-templates/tree/main/profiles):

```bash
nuclei -update-templates
```

Profiles are installed under `~/nuclei-templates/profiles/` automatically.

---

## Quick start

```bash
# 1 — Clone and enter the backend directory
git clone https://github.com/your-org/lhsec.git
cd lhsec/backend

# 2 — Copy environment config
cp .env.example .env
# Edit .env if needed (see Configuration section below)

# 3 — Install dependencies
uv sync

# 4 — Run the server
export PATH="$HOME/go/bin:$PATH"
uv run uvicorn app.main:app --host 0.0.0.0 --port 8005 --reload
```

Open **http://localhost:8005** in your browser.

---

## Configuration

All settings are read from `backend/.env` (copy from `.env.example`):

```ini
# Database
DATABASE_URL=sqlite:///./data/lhsec.db

# CT log enrichment (crt.sh is always enabled; Certspotter needs a key)
CERTSPOTTER_API_KEY=

# External tool paths (defaults assume ~/go/bin is on PATH)
NUCLEI_BINARY=nuclei
HTTPX_BINARY=~/.go/bin/httpx
NMAP_BINARY=nmap

# App
APP_DEBUG=true
```

The SQLite database is created automatically at first run. To start fresh, delete `backend/data/lhsec.db`.

---

## Importing organisations

Go to **Organisations → Import** and upload a CSV or JSON file.

### CSV

```csv
name,ips,contact_email,notes
"Acme Corp","1.2.3.4,203.0.113.0/28",security@acme.com,"Main datacenter"
"Beta University","198.51.100.0/24",it@beta.edu,
```

### JSON

```json
[
  {
    "name": "Acme Corp",
    "ips": ["1.2.3.4", "203.0.113.0/28"],
    "contact_email": "security@acme.com"
  }
]
```

- Importing the same organisation name a second time **updates** it (upsert).
- Both individual IPs (`1.2.3.4`) and CIDR ranges (`203.0.113.0/28`) are accepted.

See [`docs/IMPORT_FORMAT.md`](docs/IMPORT_FORMAT.md) for the full format reference.

---

## Scan workflow

```
Import org (IPs)
    │
    ▼
IP Discovery ──► TLS cert probing
                 HTTP redirect harvesting     → Root domains
                 Reverse DNS
                 Amass (best-effort)
    │
    ▼
CT Discovery ──► crt.sh / Certspotter         → Subdomains (with resolved IPs)
    │
    ▼
Port Scan ─────► Nmap (-sV, 48 ports)         → Services table
    │
    ▼
Nuclei Scan ───► httpx pre-filter
                 Service-aware targets         → Findings
                 Template profile + speed
```

### Scan types

| Type | Trigger | What it does |
|---|---|---|
| **IP Discovery** | Org detail → *Discover* | Probes org IPs via TLS, HTTP, rDNS and Amass to find root domains |
| **CT Discovery** | Root domain row → *CT* | Queries Certificate Transparency logs for subdomains of a root domain |
| **Port Scan** | Org detail → *Port Scan* | Runs `nmap -sV` against all org IPs across 48 common ports |
| **Nuclei scan** | Org detail → *Scan* | Full org vulnerability scan using discovered services and domains |
| **Quick scan** | Shield icon on any host | Single-target Nuclei scan — bypasses org-wide discovery |

---

## Nuclei scan options

### Speed profiles

| Profile | Rate limit | Concurrency | Best for |
|---|---|---|---|
| **Stealth** | 3 req/s | 3 | WAF-protected targets, avoid triggering blocks |
| **Balanced** | 20 req/s | 10 | General-purpose (recommended default) |
| **Fast** | 50 req/s | 25 | Internal or trusted networks |

### Template sets

LHSec maps scan scope to official ProjectDiscovery `-profile` flags:

| Set | Profile flag | What it tests |
|---|---|---|
| **Recommended** | `recommended` | CVEs + misconfigs + SSL + DNS — best starting point |
| **CVEs** | `cves` | Known CVEs only |
| **CISA KEV** | `kev` | CISA Known Exploited Vulnerabilities |
| **Misconfigs** | `misconfigurations` | Exposed panels, insecure defaults, leaked configs |
| **Default logins** | `default-login` | Default / weak credentials on common services |

---

## Project structure

```
lhsec/
├── backend/
│   ├── app/
│   │   ├── api/v1/          # REST endpoints (organizations, scans, findings)
│   │   ├── services/
│   │   │   ├── ct_lookup.py     # crt.sh + Certspotter + IP discovery
│   │   │   ├── nuclei_runner.py # Nuclei subprocess, target builder, JSONL parser
│   │   │   ├── nmap_runner.py   # Nmap subprocess, XML parser, service upsert
│   │   │   └── importer.py      # CSV / JSON bulk import
│   │   ├── tasks/
│   │   │   └── manager.py       # Async task manager + WebSocket broadcast
│   │   ├── models.py        # SQLAlchemy ORM models
│   │   ├── schemas.py       # Pydantic request/response schemas
│   │   ├── config.py        # Settings + scan profiles
│   │   ├── database.py      # SQLite engine setup
│   │   └── main.py          # FastAPI app, Jinja2 filters, lifespan
│   ├── templates/           # Jinja2 + TailwindCSS templates
│   │   ├── base.html
│   │   ├── dashboard.html
│   │   ├── organizations/
│   │   ├── scans/
│   │   └── findings/
│   ├── data/                # SQLite DB (git-ignored)
│   ├── .env.example
│   └── pyproject.toml
└── docs/
    └── IMPORT_FORMAT.md
```

---

## Data model

```
Organization
 ├── IpRange[]       CIDR blocks belonging to this org
 ├── Domain[]        Discovered FQDNs (source: reverse_dns | crt_sh | certspotter | amass | manual)
 ├── Service[]       Open ports found by nmap (ip, port, protocol, service_name, product, version)
 ├── ScanJob[]       Audit trail of every scan run
 └── Finding[]       Nuclei results (template, severity, host, evidence, CVEs, CVSS)
```

### Domain sources

| Source | How it is found |
|---|---|
| `tls_cert` | CN / SANs extracted from TLS certificates on common HTTPS ports |
| `http_redirect` | Hostname extracted from HTTP `Location:` redirect headers |
| `reverse_dns` | PTR record for each org IP |
| `amass` | Amass intel mode (WHOIS / passive sources) |
| `crt_sh` | crt.sh Certificate Transparency search |
| `certspotter` | SSLMate Certspotter CT search |
| `manual` | Added manually via the UI |

---

## API

The REST API is available at `/api/v1/`. Interactive docs at **http://localhost:8005/docs**.

Key endpoints:

```
GET  /api/v1/organizations                     List all organisations
POST /api/v1/organizations                     Create organisation
GET  /api/v1/organizations/{id}                Organisation detail
POST /api/v1/organizations/import              Bulk import (CSV/JSON)

POST /api/v1/scans/ct-discovery                Launch IP discovery scan
POST /api/v1/scans/ct-subdomain                Launch CT subdomain scan
POST /api/v1/scans/port-scan                   Launch Nmap port scan
POST /api/v1/scans/nuclei                      Launch Nuclei scan
POST /api/v1/scans/{job_id}/stop               Stop a running scan
POST /api/v1/scans/kill-all                    Stop all running scans
GET  /api/v1/scans/{job_id}                    Scan job status + log

GET  /api/v1/findings                          All findings (filterable)
GET  /api/v1/findings/{org_id}                 Findings for one org

WS   /ws/scans/{job_id}                        Live log stream
```

---

## Notes & limitations

- **No authentication.** LHSec is intended to run on a private network or behind a VPN/reverse proxy. Do not expose it to the internet without adding auth.
- **SQLite only.** Sufficient for auditing dozens of organisations; swap `DATABASE_URL` for a PostgreSQL DSN for larger deployments (no code changes required, Alembic migrations not yet set up).
- **No migration system.** Drop `data/lhsec.db` to reset the schema during development.
- **Nuclei scans are active.** They generate real network traffic towards target hosts. Ensure you have written authorisation before scanning any system you do not own.

---

## License

MIT
