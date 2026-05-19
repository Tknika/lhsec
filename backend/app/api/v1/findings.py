from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Finding
from app.schemas import FindingOut, FindingStatusUpdate

router = APIRouter(prefix="/findings", tags=["findings"])

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info", "unknown"}
VALID_STATUSES = {"open", "acknowledged", "fixed", "false_positive"}


@router.get("/", response_model=List[FindingOut])
def list_findings(
    organization_id: Optional[int] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    scan_job_id: Optional[str] = None,
    limit: int = Query(default=500, le=2000),
    db: Session = Depends(get_db),
):
    q = db.query(Finding)
    if organization_id:
        q = q.filter(Finding.organization_id == organization_id)
    if severity:
        q = q.filter(Finding.severity == severity.lower())
    if status:
        q = q.filter(Finding.status == status)
    if scan_job_id:
        q = q.filter(Finding.scan_job_id == scan_job_id)

    # Order by severity then date
    severity_order = ["critical", "high", "medium", "low", "info", "unknown"]
    results = q.order_by(Finding.first_seen.desc()).limit(limit).all()
    results.sort(
        key=lambda f: (severity_order.index(f.severity) if f.severity in severity_order else 99)
    )
    return results


@router.get("/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: int, db: Session = Depends(get_db)):
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    return f


@router.patch("/{finding_id}/status", response_model=FindingOut)
def update_finding_status(
    finding_id: int, body: FindingStatusUpdate, db: Session = Depends(get_db)
):
    if body.status not in VALID_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Must be one of: {', '.join(VALID_STATUSES)}",
        )
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    f.status = body.status
    db.commit()
    db.refresh(f)
    return f
