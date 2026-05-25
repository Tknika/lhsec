"""
wafw00f WAF detection runner.

Runs wafw00f against web services discovered by nmap (HTTP/HTTPS),
caches the result on the Service record, and skips re-detection
if the last detection was recent enough.

Invoked automatically after port scans complete and before Nuclei scans.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from typing import Callable

from sqlalchemy.orm import Session

from app.models import Service

LogCallback = Callable[[str], None]

# Re-detect WAF after this many hours (0 = every time)
WAF_CACHE_HOURS = 24


def _build_target_for_service(svc: Service) -> str:
    """Build a URL target for wafw00f from a service record."""
    return f"{svc.scheme}://{svc.ip}:{svc.port}"


async def detect_waf_for_services(
    db: Session,
    services: list[Service],
    log: LogCallback,
    force: bool = False,
    timeout: int = 10,
) -> int:
    """
    Run wafw00f against every HTTP/S service in *services*.
    Skips services that have a recent (within WAF_CACHE_HOURS) detection
    unless *force=True*.

    Returns the number of new detections made.
    """
    from wafw00f.main import WAFW00F, buildResultRecord, RequestBlocked

    # Filter to HTTP/S services only
    http_services = [s for s in services if s.is_http]
    if not http_services:
        return 0

    # Determine which need detection
    if not force:
        cutoff = datetime.utcnow() - timedelta(hours=WAF_CACHE_HOURS)
        to_detect = [
            s for s in http_services
            if s.waf_detected_at is None or s.waf_detected_at < cutoff
        ]
        skipped = len(http_services) - len(to_detect)
        if skipped:
            log(f"[wafw00f] Skipping {skipped} service(s) with recent detection (< {WAF_CACHE_HOURS}h)")
    else:
        to_detect = http_services

    if not to_detect:
        return 0

    log(f"[wafw00f] Probing {len(to_detect)} web service(s) for WAF detection…")

    new_detections = 0

    for svc in to_detect:
        target = _build_target_for_service(svc)

        # wafw00f is synchronous and potentially slow — run in executor
        loop = asyncio.get_event_loop()

        def _detect_one(target_url: str, to: int) -> dict | None:
            try:
                attacker = WAFW00F(target_url, timeout=to)
                r = attacker.normalRequest()
                if r is None:
                    return {"waf": None, "error": f"no response from {target_url}"}

                detected, evil_url = attacker.identwaf()
                if detected:
                    return buildResultRecord(target_url, detected, evil_url)
                else:
                    return {"waf": None, "url": target_url}
            except RequestBlocked:
                return {"waf": None, "blocked": True, "url": target_url}
            except Exception as exc:
                return {"waf": None, "error": str(exc)}

        result = await loop.run_in_executor(None, _detect_one, target, timeout)

        if result is None:
            continue

        waf_list = result.get("waf")
        error = result.get("error")
        blocked = result.get("blocked")

        if waf_list:
            svc.waf_name = waf_list[0] if isinstance(waf_list, list) else str(waf_list)
            svc.waf_detected_at = datetime.utcnow()
            new_detections += 1
            log(f"[wafw00f] {target} → {svc.waf_name} ✓")
        elif blocked:
            # No specific WAF fingerprinted but the connection got blocked —
            # that's a strong signal a WAF exists.  Mark it clearly.
            svc.waf_name = "Unknown (blocked)"
            svc.waf_detected_at = datetime.utcnow()
            new_detections += 1
            log(f"[wafw00f] {target} → BLOCKED (unknown WAF) ⚠")
        elif error:
            log(f"[wafw00f] {target} → {error}")
        else:
            svc.waf_name = None
            svc.waf_detected_at = datetime.utcnow()
            log(f"[wafw00f] {target} → no WAF detected")

    if new_detections:
        db.commit()
        log(f"[wafw00f] Done — {new_detections} WAF(s) detected across {len(to_detect)} probed host(s)")

    return new_detections


def clear_waf_results(db: Session, organization_id: int) -> int:
    """Clear all WAF results for an organization (e.g., before re-scan)."""
    count = (
        db.query(Service)
        .filter(
            Service.organization_id == organization_id,
            Service.waf_name.isnot(None),
        )
        .update({"waf_name": None, "waf_detected_at": None})
    )
    db.commit()
    return count