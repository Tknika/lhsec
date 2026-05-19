from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Domain, Finding, Organization, IpRange, Service
from app.schemas import (
    ImportResult,
    OrganizationCreate,
    OrganizationOut,
    OrganizationSummary,
    OrganizationUpdate,
    IpRangeCreate,
    IpRangeOut,
    ServiceOut,
    DomainCreate,
    DomainOut,
)
from app.services.importer import import_csv, import_json
from slugify import slugify

router = APIRouter(prefix="/organizations", tags=["organizations"])


# ── Helper ────────────────────────────────────────────────────────────────────

def _get_or_404(db: Session, organization_id: int) -> Organization:
    org = db.get(Organization, organization_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return org


# ── List & Create ─────────────────────────────────────────────────────────────

@router.get("/", response_model=List[OrganizationSummary])
def list_organizations(db: Session = Depends(get_db)):
    organizations = db.query(Organization).order_by(Organization.name).all()
    summaries = []
    for org in organizations:
        summaries.append(
            OrganizationSummary(
                id=org.id,
                name=org.name,
                slug=org.slug,
                contact_email=org.contact_email,
                created_at=org.created_at,
                ip_count=len(org.ip_ranges),
                domain_count=len(org.domains),
                open_critical=org.open_critical,
                open_high=org.open_high,
            )
        )
    return summaries


@router.post("/", response_model=OrganizationOut, status_code=201)
def create_organization(body: OrganizationCreate, db: Session = Depends(get_db)):
    slug = slugify(body.name)
    if db.query(Organization).filter(Organization.slug == slug).first():
        raise HTTPException(status_code=409, detail="Organization already exists")

    org = Organization(
        name=body.name,
        slug=slug,
        contact_email=body.contact_email,
        notes=body.notes,
    )
    db.add(org)
    db.flush()

    for cidr in body.ips:
        db.add(IpRange(organization_id=org.id, cidr=cidr))

    db.commit()
    db.refresh(org)
    return org


@router.get("/{organization_id}", response_model=OrganizationOut)
def get_organization(organization_id: int, db: Session = Depends(get_db)):
    return _get_or_404(db, organization_id)


@router.patch("/{organization_id}", response_model=OrganizationOut)
def update_organization(
    organization_id: int, body: OrganizationUpdate, db: Session = Depends(get_db)
):
    org = _get_or_404(db, organization_id)
    if body.name is not None:
        org.name = body.name
        org.slug = slugify(body.name)
    if body.contact_email is not None:
        org.contact_email = body.contact_email
    if body.notes is not None:
        org.notes = body.notes
    db.commit()
    db.refresh(org)
    return org


@router.delete("/{organization_id}", status_code=204)
def delete_organization(organization_id: int, db: Session = Depends(get_db)):
    org = _get_or_404(db, organization_id)
    db.delete(org)
    db.commit()


# ── IP Ranges ─────────────────────────────────────────────────────────────────

@router.post("/{organization_id}/ips", response_model=IpRangeOut, status_code=201)
def add_ip_range(
    organization_id: int, body: IpRangeCreate, db: Session = Depends(get_db)
):
    org = _get_or_404(db, organization_id)
    ip_range = IpRange(
        organization_id=org.id, cidr=body.cidr, label=body.label
    )
    db.add(ip_range)
    db.commit()
    db.refresh(ip_range)
    return ip_range


@router.delete("/{organization_id}/ips/{ip_id}", status_code=204)
def delete_ip_range(
    organization_id: int, ip_id: int, db: Session = Depends(get_db)
):
    _get_or_404(db, organization_id)
    ip_range = db.get(IpRange, ip_id)
    if not ip_range or ip_range.organization_id != organization_id:
        raise HTTPException(status_code=404, detail="IP range not found")
    db.delete(ip_range)
    db.commit()


# ── Delete organization ───────────────────────────────────────────────────────

@router.delete("/{organization_id}", status_code=204)
def delete_organization(organization_id: int, db: Session = Depends(get_db)):
    org = _get_or_404(db, organization_id)
    db.delete(org)
    db.commit()


# ── Clear domains ─────────────────────────────────────────────────────────────

@router.delete("/{organization_id}/domains", status_code=204)
def clear_domains(
    organization_id: int,
    source: str | None = None,   # optional: 'ip' | 'ct'
    db: Session = Depends(get_db),
):
    """
    Delete discovered domains for an organization.
    source=ip  → remove only amass/reverse_dns domains
    source=ct  → remove only crt_sh/certspotter domains
    (omit)     → remove all
    """
    from app.services.ct_lookup import IP_SOURCES, CT_SOURCES
    _get_or_404(db, organization_id)
    q = db.query(Domain).filter(Domain.organization_id == organization_id)
    if source == "ip":
        q = q.filter(Domain.source.in_(IP_SOURCES))
    elif source == "ct":
        q = q.filter(Domain.source.in_(CT_SOURCES))
    q.delete(synchronize_session=False)
    db.commit()


@router.post("/{organization_id}/domains", response_model=DomainOut, status_code=201)
def add_domain(
    organization_id: int,
    body: DomainCreate,
    db: Session = Depends(get_db),
):
    """
    Manually add a domain to an organization.
    """
    _get_or_404(db, organization_id)
    existing = db.query(Domain).filter_by(
        organization_id=organization_id, fqdn=body.fqdn.lower().strip()
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="Domain already exists for this organization")
    domain = Domain(
        organization_id=organization_id,
        fqdn=body.fqdn.lower().strip(),
        source=body.source or "manual",
        resolved_ip=body.resolved_ip,
    )
    db.add(domain)
    db.commit()
    db.refresh(domain)
    return domain


@router.delete("/{organization_id}/domains/{domain_id}", status_code=204)
def delete_domain(
    organization_id: int,
    domain_id: int,
    db: Session = Depends(get_db),
):
    """Delete a single domain."""
    _get_or_404(db, organization_id)
    domain = db.query(Domain).filter_by(id=domain_id, organization_id=organization_id).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
    db.delete(domain)
    db.commit()


# ── Services ──────────────────────────────────────────────────────────────────

@router.get("/{organization_id}/services", response_model=List[ServiceOut])
def list_services(organization_id: int, db: Session = Depends(get_db)):
    _get_or_404(db, organization_id)
    return (
        db.query(Service)
        .filter_by(organization_id=organization_id)
        .order_by(Service.ip, Service.port)
        .all()
    )


@router.delete("/{organization_id}/services", status_code=204)
def clear_services(organization_id: int, db: Session = Depends(get_db)):
    """Delete all discovered services for an organization."""
    _get_or_404(db, organization_id)
    db.query(Service).filter_by(organization_id=organization_id).delete(synchronize_session=False)
    db.commit()


# ── Import ────────────────────────────────────────────────────────────────────

@router.post("/{organization_id}/domains/resolve-ips")
async def resolve_domain_ips(organization_id: int, db: Session = Depends(get_db)):
    """
    Retroactively resolve IP addresses for CT subdomains with resolved_ip=NULL.
    Runs DNS lookups concurrently via thread pool.
    """
    import asyncio, socket
    _get_or_404(db, organization_id)

    domains = (
        db.query(Domain)
        .filter(
            Domain.organization_id == organization_id,
            Domain.source.in_(["crt_sh", "certspotter"]),
            Domain.resolved_ip.is_(None),
        )
        .all()
    )

    if not domains:
        return {"resolved": 0, "unresolved": 0, "message": "No unresolved CT subdomains found"}

    loop = asyncio.get_event_loop()
    resolved = 0
    unresolved = 0

    async def _resolve(d: Domain) -> None:
        nonlocal resolved, unresolved
        try:
            ip = await loop.run_in_executor(None, socket.gethostbyname, d.fqdn)
            d.resolved_ip = ip
            resolved += 1
        except Exception:
            unresolved += 1

    await asyncio.gather(*[_resolve(d) for d in domains])
    db.commit()
    return {
        "resolved": resolved,
        "unresolved": unresolved,
        "message": f"Resolved {resolved} subdomain(s); {unresolved} did not respond to DNS.",
    }


@router.post("/import/csv", response_model=ImportResult)
async def import_from_csv(
    file: UploadFile = File(...), db: Session = Depends(get_db)
):
    if not file.filename or not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="File must be a .csv")
    content = (await file.read()).decode("utf-8-sig")  # handle BOM
    return import_csv(content, db)


@router.post("/import/json", response_model=ImportResult)
async def import_from_json(
    file: UploadFile = File(...), db: Session = Depends(get_db)
):
    if not file.filename or not file.filename.endswith(".json"):
        raise HTTPException(status_code=400, detail="File must be a .json")
    content = (await file.read()).decode("utf-8")
    return import_json(content, db)