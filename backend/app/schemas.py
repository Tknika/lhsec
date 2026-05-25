from __future__ import annotations

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, EmailStr, field_validator
import ipaddress


# ── IpRange ───────────────────────────────────────────────────────────────────

class IpRangeCreate(BaseModel):
    cidr: str
    label: Optional[str] = None

    @field_validator("cidr")
    @classmethod
    def validate_cidr(cls, v: str) -> str:
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError:
            raise ValueError(f"'{v}' is not a valid IP address or CIDR range")
        return v


class IpRangeOut(BaseModel):
    model_config = {"from_attributes": True}
    id: int
    cidr: str
    label: Optional[str]
    created_at: datetime


# ── Organization ──────────────────────────────────────────────────────────────

class OrganizationCreate(BaseModel):
    name: str
    contact_email: Optional[str] = None
    notes: Optional[str] = None
    ips: List[str] = []


class OrganizationUpdate(BaseModel):
    name: Optional[str] = None
    contact_email: Optional[str] = None
    notes: Optional[str] = None


class OrganizationOut(BaseModel):
    model_config = {"from_attributes": True}
    id: int
    name: str
    slug: str
    contact_email: Optional[str]
    notes: Optional[str]
    created_at: datetime
    ip_ranges: List[IpRangeOut] = []


class OrganizationSummary(BaseModel):
    model_config = {"from_attributes": True}
    id: int
    name: str
    slug: str
    contact_email: Optional[str]
    created_at: datetime
    ip_count: int = 0
    domain_count: int = 0
    open_critical: int = 0
    open_high: int = 0


# ── Import ────────────────────────────────────────────────────────────────────

class ImportResult(BaseModel):
    created: int = 0
    updated: int = 0
    skipped: int = 0
    errors: List[str] = []


# ── Domain ────────────────────────────────────────────────────────────────────

class DomainOut(BaseModel):
    model_config = {"from_attributes": True}
    id: int
    fqdn: str
    source: str
    resolved_ip: Optional[str]
    first_seen: datetime
    last_seen: datetime


class DomainCreate(BaseModel):
    fqdn: str
    source: Optional[str] = "manual"
    resolved_ip: Optional[str] = None


# ── ScanJob ───────────────────────────────────────────────────────────────────

class ScanJobCreate(BaseModel):
    organization_id: int
    scan_type: str
    severity: Optional[str] = None
    templates: Optional[str] = None
    domain: Optional[str] = None
    profile: Optional[str] = None         # speed profile: stealth|balanced|fast
    template_set: Optional[str] = None    # template set: recommended|cves|kev|misconfigurations|default-login
    target: Optional[str] = None          # single-target quick scan (ip/hostname/url)


class RunAllCreate(BaseModel):
    severity: Optional[str] = None
    profile: Optional[str] = None
    template_set: Optional[str] = None


class ScanJobOut(BaseModel):
    model_config = {"from_attributes": True}
    id: str
    organization_id: Optional[int]
    scan_type: str
    status: str
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    findings_count: int
    domains_found: int
    error_message: Optional[str]
    log_output: Optional[str]


class ScanJobStatus(BaseModel):
    id: str
    status: str
    log_output: str
    findings_count: int
    domains_found: int
    error_message: Optional[str] = None


# ── Finding ───────────────────────────────────────────────────────────────────

class FindingOut(BaseModel):
    model_config = {"from_attributes": True}
    id: int
    scan_job_id: str
    organization_id: int
    template_id: str
    name: str
    severity: str
    host: str
    matched_at: Optional[str]
    ip: Optional[str]
    port: Optional[int]
    description: Optional[str]
    cvss_score: Optional[float]
    cve_ids: Optional[str]
    status: str
    first_seen: datetime
    last_seen: datetime


class FindingStatusUpdate(BaseModel):
    status: str  # open | acknowledged | fixed | false_positive


# ── Service ──────────────────────────────────────────────────────────────────

class ServiceOut(BaseModel):
    model_config = {"from_attributes": True}
    id: int
    organization_id: int
    ip: str
    port: int
    protocol: str
    service_name: Optional[str]
    product: Optional[str]
    version: Optional[str]
    tunnel: Optional[str]
    extra_info: Optional[str]
    scheme: str
    is_http: bool
    first_seen: datetime
    last_seen: datetime
