"""
Import organizations from CSV or JSON files.

CSV format (first row is header):
  name,ips,contact_email,notes
  "Acme Corp","1.2.3.4,5.6.7.8,203.0.113.0/28",security@acme.com,"Primary DC"
  "Beta University","198.51.100.0/24",it@beta.edu,""

JSON format (array of objects):
  [
    {
      "name": "Acme Corp",
      "ips": ["1.2.3.4", "5.6.7.8", "203.0.113.0/28"],
      "contact_email": "security@acme.com",
      "notes": "Primary DC"
    }
  ]

Notes:
  - 'ips' can be individual IPv4/IPv6 addresses or CIDR ranges.
  - Existing organizations (matched by name) are updated, not duplicated.
  - IP ranges already assigned to the organization are skipped.
"""
from __future__ import annotations

import csv
import ipaddress
import io
import json
from typing import List

from slugify import slugify
from sqlalchemy.orm import Session

from app.models import Organization, IpRange
from app.schemas import ImportResult
from app.services.contact_domains import ensure_contact_domain


# ── Helpers ───────────────────────────────────────────────────────────────────

def _validate_ip(value: str) -> str | None:
    """Return normalised CIDR string or None if invalid."""
    value = value.strip()
    try:
        ipaddress.ip_network(value, strict=False)
        return value
    except ValueError:
        return None


def _upsert_organization(
    db: Session,
    name: str,
    ips: List[str],
    contact_email: str | None,
    notes: str | None,
    result: ImportResult,
) -> None:
    name = name.strip()
    if not name:
        result.errors.append("Skipping row with empty name.")
        result.skipped += 1
        return

    slug = slugify(name)
    org = db.query(Organization).filter(Organization.slug == slug).first()

    if org is None:
        org = Organization(
            name=name,
            slug=slug,
            contact_email=contact_email or None,
            notes=notes or None,
        )
        db.add(org)
        db.flush()  # get org.id
        result.created += 1
    else:
        if contact_email:
            org.contact_email = contact_email
        if notes:
            org.notes = notes
        result.updated += 1

    # Add IP ranges
    existing_cidrs = {r.cidr for r in org.ip_ranges}
    for raw_ip in ips:
        cidr = _validate_ip(raw_ip)
        if cidr is None:
            result.errors.append(
                f"[{name}] Invalid IP/CIDR '{raw_ip}' — skipped."
            )
            continue
        if cidr not in existing_cidrs:
            db.add(IpRange(organization_id=org.id, cidr=cidr))
            existing_cidrs.add(cidr)

    ensure_contact_domain(db, org)


# ── CSV import ────────────────────────────────────────────────────────────────

def import_csv(content: str, db: Session) -> ImportResult:
    result = ImportResult()
    reader = csv.DictReader(io.StringIO(content))

    required = {"name", "ips"}
    if reader.fieldnames is None or not required.issubset(set(reader.fieldnames)):
        result.errors.append(
            f"CSV must contain at minimum the columns: {', '.join(required)}. "
            f"Found: {reader.fieldnames}"
        )
        return result

    for i, row in enumerate(reader, start=2):  # row 1 is header
        name = row.get("name", "").strip()
        raw_ips_str = row.get("ips", "")
        ips = [ip.strip() for ip in raw_ips_str.split(",") if ip.strip()]
        contact_email = row.get("contact_email", "").strip() or None
        notes = row.get("notes", "").strip() or None

        try:
            _upsert_organization(db, name, ips, contact_email, notes, result)
        except Exception as exc:
            result.errors.append(f"Row {i}: {exc}")
            result.skipped += 1

    db.commit()
    return result


# ── JSON import ───────────────────────────────────────────────────────────────

def import_json(content: str, db: Session) -> ImportResult:
    result = ImportResult()

    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        result.errors.append(f"Invalid JSON: {exc}")
        return result

    if not isinstance(data, list):
        result.errors.append("JSON root must be an array of organization objects.")
        return result

    for i, item in enumerate(data):
        if not isinstance(item, dict):
            result.errors.append(f"Item {i}: expected object, got {type(item).__name__}")
            result.skipped += 1
            continue

        name = item.get("name", "")
        raw_ips = item.get("ips", [])
        if isinstance(raw_ips, str):
            raw_ips = [ip.strip() for ip in raw_ips.split(",") if ip.strip()]
        contact_email = item.get("contact_email") or None
        notes = item.get("notes") or None

        try:
            _upsert_organization(db, name, raw_ips, contact_email, notes, result)
        except Exception as exc:
            result.errors.append(f"Item {i} ({name!r}): {exc}")
            result.skipped += 1

    db.commit()
    return result
