from __future__ import annotations

from email.utils import parseaddr

from sqlalchemy.orm import Session

from app.models import Domain, Organization


def extract_domain_from_email(email: str | None) -> str | None:
    """Extract and normalize domain part from an email address."""
    if not email:
        return None
    _, addr = parseaddr(email.strip())
    if "@" not in addr:
        return None
    domain = addr.rsplit("@", 1)[1].strip().lower().rstrip(".")
    if not domain or "." not in domain:
        return None
    return domain


def ensure_contact_domain(db: Session, org: Organization) -> str | None:
    """
    Ensure org contact_email domain exists in Domain table.

    Returns inserted fqdn when created, else None.
    """
    domain = extract_domain_from_email(org.contact_email)
    if not domain:
        return None

    existing = db.query(Domain).filter_by(organization_id=org.id, fqdn=domain).first()
    if existing:
        return None

    db.add(
        Domain(
            organization_id=org.id,
            fqdn=domain,
            source="contact_email",
        )
    )
    return domain
