from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.api.v1.router import api_router
from app.database import SessionLocal, init_db

# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    # Reset any jobs left in running/pending state from previous server instance
    from app.tasks.manager import reset_stale_jobs
    db = SessionLocal()
    try:
        n = reset_stale_jobs(db)
        if n:
            import logging
            logging.getLogger("lhsec").info(f"Startup: reset {n} stale job(s) to failed")
    finally:
        db.close()

    # Check nuclei template health once at startup (quick, non-blocking)
    import asyncio, shutil, logging
    from app.config import settings
    _log = logging.getLogger("lhsec")
    nuclei_bin = shutil.which(settings.nuclei_binary) or settings.nuclei_binary
    try:
        proc = await asyncio.create_subprocess_exec(
            nuclei_bin, "-validate",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
        output = stderr.decode(errors="replace")
        runtime_errors = [l for l in output.splitlines() if "runtime error" in l.lower() or "could not compile" in l.lower()]
        if runtime_errors:
            _log.warning(f"nuclei -validate: {len(runtime_errors)} broken template(s): " + " | ".join(runtime_errors[:5]))
        else:
            _log.info("nuclei -validate: all templates OK")
    except Exception as e:
        _log.warning(f"nuclei -validate skipped: {e}")
    yield


# ── App factory ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="LHSec",
    description="Security Auditing Platform",
    version="0.1.0",
    lifespan=lifespan,
)

# API routes
app.include_router(api_router)

# Static files & templates
BASE_DIR = Path(__file__).parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# ── Custom Jinja2 filters ────────────────────────────────────────────────────

def _ip_in_cidrs(ip: str | None, cidrs: list[str]) -> bool:
    """Check if an IP address falls within any of the given CIDR ranges."""
    if not ip or not cidrs:
        return False
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in cidrs:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False

templates.env.filters["ip_in_cidrs"] = _ip_in_cidrs
templates.env.globals["ip_in_cidrs"] = _ip_in_cidrs

def _is_external_domain(fqdn: str, cidrs: list[str]) -> bool:
    """Resolve *fqdn* and check if its IP isn't in *cidrs*. Returns True if external or unresolvable."""
    if not cidrs:
        return True
    import socket
    try:
        ip = socket.gethostbyname(fqdn)
    except Exception:
        return True  # can't resolve -> assume external
    return not _ip_in_cidrs(ip, cidrs)

templates.env.globals["is_external_domain"] = _is_external_domain

def _expand_cidr(cidr: str) -> list[str]:
    """Expand a CIDR like 192.168.1.0/24 to a list of individual IPs."""
    import ipaddress
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        # Use hosts only (exclude network & broadcast for IPv4)
        if net.num_addresses <= 256:
            return [str(ip) for ip in net.hosts()]
        # For larger ranges, just show first ~16 as preview
        ips = list(net.hosts())
        return [str(ip) for ip in ips[:16]]
    except ValueError:
        return [cidr]  # return as-is if can't parse

templates.env.filters["expand_cidr"] = _expand_cidr
templates.env.globals["expand_cidr"] = _expand_cidr

static_dir = BASE_DIR / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


# ── UI routes ─────────────────────────────────────────────────────────────────

def _db() -> Session:
    db = SessionLocal()
    try:
        return db
    finally:
        pass  # caller must close


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    from app.models import Organization, ScanJob, Finding

    db = SessionLocal()
    try:
        organizations = db.query(Organization).all()
        recent_jobs = (
            db.query(ScanJob)
            .order_by(ScanJob.started_at.desc())
            .limit(5)
            .all()
        )
        critical_findings = (
            db.query(Finding)
            .filter(Finding.severity == "critical", Finding.status == "open")
            .order_by(Finding.first_seen.desc())
            .limit(10)
            .all()
        )
        high_findings = (
            db.query(Finding)
            .filter(Finding.severity == "high", Finding.status == "open")
            .order_by(Finding.first_seen.desc())
            .limit(10)
            .all()
        )

        # Stats
        from sqlalchemy import func
        severity_counts: dict[str, int] = {}
        for row in (
            db.query(Finding.severity, func.count(Finding.id))
            .filter(Finding.status == "open")
            .group_by(Finding.severity)
            .all()
        ):
            severity_counts[row[0]] = row[1]

        return templates.TemplateResponse(
            request=request,
            name="dashboard.html",
            context={
                "organizations": organizations,
                "recent_jobs": recent_jobs,
                "critical_findings": critical_findings,
                "high_findings": high_findings,
                "severity_counts": severity_counts,
                "total_organizations": len(organizations),
            },
        )
    finally:
        db.close()


@app.get("/organizations", response_class=HTMLResponse)
async def organizations_page(request: Request):
    from app.models import Organization

    db = SessionLocal()
    try:
        organizations = db.query(Organization).order_by(Organization.name).all()
        return templates.TemplateResponse(
            request=request,
            name="organizations/list.html",
            context={"organizations": organizations},
        )
    finally:
        db.close()


@app.get("/organizations/{organization_id}", response_class=HTMLResponse)
async def organization_detail(request: Request, organization_id: int):
    from app.models import Organization, ScanJob, Finding

    db = SessionLocal()
    try:
        org = db.get(Organization, organization_id)
        if not org:
            return HTMLResponse("Not found", status_code=404)

        recent_jobs = (
            db.query(ScanJob)
            .filter(ScanJob.organization_id == organization_id)
            .order_by(ScanJob.started_at.desc())
            .limit(10)
            .all()
        )
        findings = (
            db.query(Finding)
            .filter(
                Finding.organization_id == organization_id,
                Finding.status == "open",
            )
            .order_by(Finding.first_seen.desc())
            .all()
        )
        findings.sort(
            key=lambda f: ["critical", "high", "medium", "low", "info", "unknown"].index(
                f.severity if f.severity in ["critical", "high", "medium", "low", "info", "unknown"] else "unknown"
            )
        )
        return templates.TemplateResponse(
            request=request,
            name="organizations/detail.html",
            context={
                "org": org,
                "recent_jobs": recent_jobs,
                "findings": findings,
                "services": org.services,
            },
        )
    finally:
        db.close()


@app.get("/scans", response_class=HTMLResponse)
async def scans_page(request: Request):
    from app.models import ScanJob, Organization

    db = SessionLocal()
    try:
        jobs = (
            db.query(ScanJob)
            .order_by(ScanJob.started_at.desc())
            .limit(100)
            .all()
        )
        return templates.TemplateResponse(
            request=request,
            name="scans/list.html",
            context={"jobs": jobs},
        )
    finally:
        db.close()


@app.get("/scans/{job_id}", response_class=HTMLResponse)
async def scan_detail(request: Request, job_id: str):
    from app.models import ScanJob

    db = SessionLocal()
    try:
        job = db.get(ScanJob, job_id)
        if not job:
            return HTMLResponse("Not found", status_code=404)
        return templates.TemplateResponse(
            request=request,
            name="scans/detail.html",
            context={"job": job},
        )
    finally:
        db.close()


@app.get("/findings", response_class=HTMLResponse)
async def findings_page(request: Request, organization_id: int | None = None):
    from app.models import Finding, Organization

    db = SessionLocal()
    try:
        q = db.query(Finding)
        if organization_id:
            q = q.filter(Finding.organization_id == organization_id)
        findings = q.order_by(Finding.first_seen.desc()).limit(1000).all()
        severity_order = ["critical", "high", "medium", "low", "info", "unknown"]
        findings.sort(
            key=lambda f: severity_order.index(f.severity)
            if f.severity in severity_order
            else 99
        )
        organizations = db.query(Organization).order_by(Organization.name).all()
        return templates.TemplateResponse(
            request=request,
            name="findings/list.html",
            context={
                "findings": findings,
                "organizations": organizations,
                "selected_organization_id": organization_id,
            },
        )
    finally:
        db.close()