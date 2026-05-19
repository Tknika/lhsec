# LHSec — Backend

Security Auditing Platform backend (FastAPI + SQLite).

## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) (`curl -LsSf https://astral.sh/uv/install.sh | sh`)
- [nuclei](https://nuclei.projectdiscovery.io/) in `$PATH` for vulnerability scanning

## Quick start

```bash
# 1. Clone and enter the backend directory
cd backend

# 2. Copy env file and edit as needed
cp .env.example .env

# 3. Install dependencies and create virtualenv
uv sync

# 4. Create the data directory
mkdir -p ../data/nuclei_results

# 5. Run the development server
uv run uvicorn app.main:app --reload --port 8000
```

Open http://localhost:8000

## Key endpoints

| URL | Description |
|---|---|
| `GET /` | Dashboard |
| `GET /organizations` | Organization list + import |
| `GET /organizations/{id}` | Detail, CT discovery, Nuclei scan |
| `GET /scans` | All scan jobs |
| `GET /scans/{id}` | Live log output |
| `GET /findings` | All findings |
| `POST /api/v1/organizations/import/csv` | Bulk import CSV |
| `POST /api/v1/organizations/import/json` | Bulk import JSON |
| `POST /api/v1/scans/ct-discovery` | Launch CT discovery |
| `POST /api/v1/scans/nuclei` | Launch Nuclei scan |
| `WS  /api/v1/scans/{id}/ws` | Real-time log stream |

Full interactive API docs: http://localhost:8000/docs

## CT Log sources

| Source | Key needed | Config |
|---|---|---|
| [crt.sh](https://crt.sh) | No | Always active |
| [SSLMate Certspotter](https://sslmate.com/certspotter) | Yes | Set `CERTSPOTTER_API_KEY` in `.env` |

## Nuclei scan

Nuclei must be installed: https://github.com/projectdiscovery/nuclei

```bash
# Install nuclei (Go required)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Or download binary from releases
# https://github.com/projectdiscovery/nuclei/releases
```

Default severity filter: `critical,high` (configurable via `NUCLEI_DEFAULT_SEVERITY`).

## Import formats

See [docs/IMPORT_FORMAT.md](../docs/IMPORT_FORMAT.md) for CSV and JSON format reference.
