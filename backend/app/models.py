from __future__ import annotations

import json
from datetime import datetime
from typing import List, Optional

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


# ── Organization ──────────────────────────────────────────────────────────────

class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    slug: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    contact_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    ip_ranges: Mapped[List["IpRange"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )
    domains: Mapped[List["Domain"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )
    scan_jobs: Mapped[List["ScanJob"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )
    findings: Mapped[List["Finding"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )
    services: Mapped[List["Service"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )

    @property
    def open_critical(self) -> int:
        return sum(
            1 for f in self.findings if f.severity == "critical" and f.status == "open"
        )

    @property
    def open_high(self) -> int:
        return sum(
            1 for f in self.findings if f.severity == "high" and f.status == "open"
        )


# ── IpRange ───────────────────────────────────────────────────────────────────

class IpRange(Base):
    __tablename__ = "ip_ranges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("organizations.id"), nullable=False
    )
    cidr: Mapped[str] = mapped_column(String(50), nullable=False)
    label: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    organization: Mapped["Organization"] = relationship(back_populates="ip_ranges")


# ── Domain ────────────────────────────────────────────────────────────────────

class Domain(Base):
    __tablename__ = "domains"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("organizations.id"), nullable=False
    )
    fqdn: Mapped[str] = mapped_column(String(500), nullable=False)
    # source: reverse_dns | crt_sh | certspotter | manual
    source: Mapped[str] = mapped_column(String(50), nullable=False, default="manual")
    resolved_ip: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    organization: Mapped["Organization"] = relationship(back_populates="domains")


# ── ScanJob ───────────────────────────────────────────────────────────────────

class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    organization_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("organizations.id"), nullable=True
    )
    # scan_type: ct_discovery | nuclei | full
    scan_type: Mapped[str] = mapped_column(String(50), nullable=False)
    # status: pending | running | done | failed
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    # JSON blob for scan configuration (severity, templates, etc.)
    config: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Accumulated stdout/stderr from the background process
    log_output: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default="")
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    domains_found: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    organization: Mapped[Optional["Organization"]] = relationship(
        back_populates="scan_jobs"
    )
    findings: Mapped[List["Finding"]] = relationship(
        back_populates="scan_job", cascade="all, delete-orphan"
    )

    def get_config(self) -> dict:
        return json.loads(self.config) if self.config else {}

    def set_config(self, cfg: dict) -> None:
        self.config = json.dumps(cfg)


# ── Finding ───────────────────────────────────────────────────────────────────

class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_job_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_jobs.id"), nullable=False
    )
    organization_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("organizations.id"), nullable=False
    )
    template_id: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    # severity: info | low | medium | high | critical | unknown
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="info")
    host: Mapped[str] = mapped_column(String(500), nullable=False)
    matched_at: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    ip: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Raw matched response / curl command
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    # JSON-encoded list of CVE IDs, e.g. '["CVE-2021-44228"]'
    cve_ids: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # status: open | acknowledged | fixed | false_positive
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="open")
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    organization: Mapped["Organization"] = relationship(back_populates="findings")
    scan_job: Mapped["ScanJob"] = relationship(back_populates="findings")

    def get_cve_ids(self) -> list[str]:
        return json.loads(self.cve_ids) if self.cve_ids else []


# ── Service ───────────────────────────────────────────────────────────────────

class Service(Base):
    """Open port / service discovered by nmap on an organization IP."""
    __tablename__ = "services"
    __table_args__ = (
        UniqueConstraint("organization_id", "ip", "port", "protocol", name="uq_service"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    organization_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    ip: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(10), nullable=False, default="tcp")
    # nmap service name (http, https, ssh, ftp, …)
    service_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    # nmap product string (Apache httpd, nginx, OpenSSH, …)
    product: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    version: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    # tunnel: ssl | tls (indicates HTTPS even when service_name is "http")
    tunnel: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    extra_info: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    # WAF detection via wafw00f (cached until re-scanned)
    waf_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    waf_detected_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    organization: Mapped["Organization"] = relationship(back_populates="services")

    @property
    def scheme(self) -> str:
        """Best-guess URL scheme for this service."""
        name = (self.service_name or "").lower()
        tun  = (self.tunnel or "").lower()
        if tun in ("ssl", "tls") or name in ("https", "https-alt", "ssl/http"):
            return "https"
        if "http" in name or name in ("www", "http-proxy", "http-alt", "http-mgmt"):
            return "http"
        return ""

    @property
    def is_http(self) -> bool:
        return self.scheme != ""
