from __future__ import annotations

import json
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Organization, ScanJob
from app.schemas import ScanJobCreate, ScanJobOut, ScanJobStatus
from app.tasks.manager import (
    launch_ct_discovery,
    launch_ct_subdomain,
    launch_nuclei_scan,
    launch_port_scan,
    stop_job,
    kill_all_running,
    ws_manager,
)

router = APIRouter(prefix="/scans", tags=["scans"])


# ── List all scan jobs ────────────────────────────────────────────────────────

@router.get("/", response_model=List[ScanJobOut])
def list_scan_jobs(
    organization_id: Optional[int] = None,
    db: Session = Depends(get_db),
):
    q = db.query(ScanJob).order_by(ScanJob.started_at.desc())
    if organization_id:
        q = q.filter(ScanJob.organization_id == organization_id)
    jobs = q.limit(200).all()
    # Don't return full log_output in list view
    for j in jobs:
        j.log_output = None
    return jobs


@router.get("/{job_id}", response_model=ScanJobOut)
def get_scan_job(job_id: str, db: Session = Depends(get_db)):
    job = db.get(ScanJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return job


@router.get("/{job_id}/status", response_model=ScanJobStatus)
def get_scan_job_status(job_id: str, db: Session = Depends(get_db)):
    """Lightweight status poll endpoint (used as WebSocket fallback)."""
    job = db.get(ScanJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return ScanJobStatus(
        id=job.id,
        status=job.status,
        log_output=job.log_output or "",
        findings_count=job.findings_count,
        domains_found=job.domains_found,
        error_message=job.error_message,
    )


# ── Launch scans ──────────────────────────────────────────────────────────────

@router.post("/ct-discovery", response_model=ScanJobOut, status_code=202)
async def start_ct_discovery(body: ScanJobCreate, db: Session = Depends(get_db)):
    org = db.get(Organization, body.organization_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    if not org.ip_ranges:
        raise HTTPException(status_code=400, detail="Organization has no IP ranges defined")
    job = launch_ct_discovery(db, body.organization_id)
    return job


@router.post("/ct-subdomain", response_model=ScanJobOut, status_code=202)
async def start_ct_subdomain(body: ScanJobCreate, db: Session = Depends(get_db)):
    """Run CT log discovery for a specific root domain."""
    org = db.get(Organization, body.organization_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    if not body.domain:
        raise HTTPException(status_code=400, detail="'domain' field required")
    job = launch_ct_subdomain(db, body.organization_id, body.domain)
    return job


@router.post("/port-scan", response_model=ScanJobOut, status_code=202)
async def start_port_scan(body: ScanJobCreate, db: Session = Depends(get_db)):
    """Run nmap service discovery against all org IP ranges."""
    org = db.get(Organization, body.organization_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    if not org.ip_ranges:
        raise HTTPException(status_code=400, detail="Organization has no IP ranges defined")
    job = launch_port_scan(db, body.organization_id)
    return job


@router.post("/nuclei", response_model=ScanJobOut, status_code=202)
async def start_nuclei_scan(body: ScanJobCreate, db: Session = Depends(get_db)):
    org = db.get(Organization, body.organization_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    # Single-target quick scan: no org data required
    if not body.target and not org.ip_ranges and not org.domains:
        raise HTTPException(
            status_code=400,
            detail="Organization has no IP ranges or domains. Run CT discovery first.",
        )
    job = launch_nuclei_scan(
        db, body.organization_id,
        severity=body.severity, profile=body.profile,
        template_set=body.template_set, target=body.target,
    )
    return job


# ── Stop / Kill running jobs ─────────────────────────────────────────────────

@router.post("/{job_id}/resume", response_model=ScanJobOut, status_code=202)
async def resume_scan_job(job_id: str, db: Session = Depends(get_db)):
    """Re-launch a blocked or failed nuclei scan using the same config, forcing stealth profile."""
    job = db.get(ScanJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    if job.scan_type != "nuclei":
        raise HTTPException(status_code=400, detail="Only nuclei scans can be resumed")
    if job.status not in ("blocked", "failed", "stopped"):
        raise HTTPException(
            status_code=409,
            detail=f"Job cannot be resumed (status: {job.status}). Only blocked/failed/stopped scans can be resumed.",
        )
    cfg = job.get_config()
    new_job = launch_nuclei_scan(
        db,
        job.organization_id,
        severity=cfg.get("severity"),
        profile="stealth",          # always resume with stealth to avoid re-triggering WAF
        template_set=cfg.get("template_set"),
        target=cfg.get("target"),
    )
    return new_job


@router.post("/{job_id}/stop")
async def stop_scan_job(job_id: str, db: Session = Depends(get_db)):
    """Stop a single running scan job (kills subprocess + cancels task)."""
    job = db.get(ScanJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    if job.status != "running":
        raise HTTPException(status_code=409, detail=f"Job is not running (status: {job.status})")
    ok = stop_job(job_id, db)
    if not ok:
        # May have already finished between check and stop
        raise HTTPException(status_code=409, detail="Job is no longer active")
    return {"detail": "Job stopped", "job_id": job_id}


@router.post("/kill-all")
async def kill_all_scans(db: Session = Depends(get_db)):
    """Stop all currently running scan jobs."""
    count = kill_all_running(db)
    return {"detail": f"Stopped {count} running job(s)", "stopped": count}


# ── WebSocket log streaming ───────────────────────────────────────────────────

@router.websocket("/{job_id}/ws")
async def scan_job_websocket(job_id: str, websocket: WebSocket, db: Session = Depends(get_db)):
    """
    WebSocket endpoint for real-time log streaming.

    Messages sent from server:
      {"type": "log",    "line": "<log line>"}
      {"type": "status", "status": "running|done|failed"}
      {"type": "history","lines": "<full log so far>"}
    """
    job = db.get(ScanJob, job_id)
    if not job:
        await websocket.close(code=4404)
        return

    await ws_manager.connect(job_id, websocket)

    # Send existing log history immediately
    existing_log = job.log_output or ""
    if existing_log:
        await websocket.send_text(
            json.dumps({"type": "history", "lines": existing_log})
        )

    # Also send current status
    await websocket.send_text(
        json.dumps({"type": "status", "status": job.status})
    )

    try:
        # Keep connection alive; the task manager pushes messages to us.
        while True:
            # Wait for any message (ping/pong keepalive from client)
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(job_id, websocket)