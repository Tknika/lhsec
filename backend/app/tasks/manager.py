"""
In-process background task manager with WebSocket broadcast support.

Design (POC):
  - Tasks run as asyncio.Task objects in the same process.
  - Each task appends log lines to the ScanJob.log_output column (via a new
    DB session so that browsers polling the REST status endpoint see live data).
  - WebSocket clients that subscribe to a job_id receive the same log lines
    in real time, plus a final status message when the job completes.
"""
from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime
from typing import Dict, Set

from fastapi import WebSocket
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import Organization, ScanJob


# ---------------------------------------------------------------------------
# WebSocket connection manager
# ---------------------------------------------------------------------------

class ConnectionManager:
    def __init__(self) -> None:
        # job_id → set of active WebSocket connections
        self._connections: Dict[str, Set[WebSocket]] = {}

    async def connect(self, job_id: str, ws: WebSocket) -> None:
        await ws.accept()
        self._connections.setdefault(job_id, set()).add(ws)

    def disconnect(self, job_id: str, ws: WebSocket) -> None:
        bucket = self._connections.get(job_id)
        if bucket:
            bucket.discard(ws)

    async def send(self, job_id: str, message: str) -> None:
        bucket = self._connections.get(job_id, set())
        dead: Set[WebSocket] = set()
        for ws in bucket:
            try:
                await ws.send_text(message)
            except Exception:
                dead.add(ws)
        bucket -= dead


ws_manager = ConnectionManager()


# ---------------------------------------------------------------------------
# Running task registry
# ---------------------------------------------------------------------------

_running: Dict[str, asyncio.Task] = {}  # job_id → asyncio.Task


# ---------------------------------------------------------------------------
# Log helper
# ---------------------------------------------------------------------------

def _make_log_callback(job_id: str):
    """
    Returns a synchronous log callback.

    The callback:
      1. Appends the line to ScanJob.log_output in the DB.
      2. Schedules a WebSocket broadcast (fire-and-forget).
    """
    def _log(line: str) -> None:
        # Persist log line
        db: Session = SessionLocal()
        try:
            job = db.get(ScanJob, job_id)
            if job:
                current = job.log_output or ""
                job.log_output = current + line + "\n"
                db.commit()
        finally:
            db.close()

        # Broadcast via WebSocket (schedule on the running event loop)
        payload = json.dumps({"type": "log", "line": line})
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.ensure_future(ws_manager.send(job_id, payload))
        except RuntimeError:
            pass

    return _log


# ---------------------------------------------------------------------------
# Task wrappers
# ---------------------------------------------------------------------------

async def _run_ct_discovery(job_id: str, organization_id: int) -> None:
    from app.services.ct_lookup import run_ip_discovery
    from app.models import Domain

    log = _make_log_callback(job_id)
    db: Session = SessionLocal()

    try:
        # Mark running
        job = db.get(ScanJob, job_id)
        if not job:
            return
        job.status = "running"
        job.started_at = datetime.utcnow()
        db.commit()

        await _broadcast_status(job_id, "running")

        inst = db.get(Organization, organization_id)
        if not inst:
            raise ValueError(f"Organization {organization_id} not found")

        ips = [r.cidr for r in inst.ip_ranges]
        log(f"[ct] Starting CT discovery for '{inst.name}' ({len(ips)} IP range(s))")

        results = await run_ip_discovery(
            ips=ips,
            log=log,
        )

        # Persist new domains
        existing_fqdns = {d.fqdn for d in inst.domains}
        new_count = 0
        for rec in results:
            fqdn = rec["fqdn"]
            if fqdn not in existing_fqdns:
                db.add(
                    Domain(
                        organization_id=organization_id,
                        fqdn=fqdn,
                        source=rec["source"],
                        resolved_ip=rec.get("resolved_ip"),
                    )
                )
                existing_fqdns.add(fqdn)
                new_count += 1

        job = db.get(ScanJob, job_id)
        job.domains_found = new_count
        job.status = "done"
        job.finished_at = datetime.utcnow()
        db.commit()

        log(f"[ct] Done — {new_count} new domain(s) saved.")
        await _broadcast_status(job_id, "done")

    except Exception as exc:
        db.rollback()
        log(f"[ct] FAILED: {exc}")
        job = db.get(ScanJob, job_id)
        if job:
            job.status = "failed"
            job.error_message = str(exc)
            job.finished_at = datetime.utcnow()
            db.commit()
        await _broadcast_status(job_id, "failed")
    finally:
        db.close()
        _running.pop(job_id, None)


async def _run_ct_subdomain(job_id: str, organization_id: int, domain: str) -> None:
    """Run CT log discovery for a single root domain."""
    from app.services.ct_lookup import run_ct_for_domain
    from app.config import settings
    from app.models import Domain

    log = _make_log_callback(job_id)
    db: Session = SessionLocal()
    try:
        job = db.get(ScanJob, job_id)
        if not job:
            return
        job.status = "running"
        job.started_at = datetime.utcnow()
        db.commit()
        await _broadcast_status(job_id, "running")

        log(f"[ct] Querying CT logs for domain: {domain}")
        results = await run_ct_for_domain(
            domain=domain,
            log=log,
            certspotter_api_key=settings.certspotter_api_key,
            resolve_ips=True,
        )

        inst = db.get(Organization, organization_id)
        existing_fqdns = {d.fqdn for d in inst.domains}
        new_count = 0
        for rec in results:
            fqdn = rec["fqdn"]
            if fqdn not in existing_fqdns:
                db.add(Domain(
                    organization_id=organization_id,
                    fqdn=fqdn,
                    source=rec["source"],
                    resolved_ip=rec.get("resolved_ip"),
                ))
                existing_fqdns.add(fqdn)
                new_count += 1

        job = db.get(ScanJob, job_id)
        job.domains_found = new_count
        job.status = "done"
        job.finished_at = datetime.utcnow()
        db.commit()
        log(f"[ct] Done — {new_count} new subdomain(s) saved for {domain}.")
        await _broadcast_status(job_id, "done")
    except Exception as exc:
        db.rollback()
        log(f"[ct] FAILED: {exc}")
        job = db.get(ScanJob, job_id)
        if job:
            job.status = "failed"
            job.error_message = str(exc)
            job.finished_at = datetime.utcnow()
            db.commit()
        await _broadcast_status(job_id, "failed")
    finally:
        db.close()
        _running.pop(job_id, None)


async def _run_port_scan(job_id: str, organization_id: int) -> None:
    from app.services.nmap_runner import run_nmap_scan, kill_proc as nmap_kill_proc

    log = _make_log_callback(job_id)
    db: Session = SessionLocal()

    try:
        job = db.get(ScanJob, job_id)
        if not job:
            return
        job.status = "running"
        job.started_at = datetime.utcnow()
        db.commit()
        await _broadcast_status(job_id, "running")

        org = db.get(Organization, organization_id)
        if not org:
            raise ValueError(f"Organization {organization_id} not found")

        # Expand IPs from ip_ranges (CIDRs passed directly to nmap)
        targets = [r.cidr for r in org.ip_ranges]
        if not targets:
            raise ValueError("Organization has no IP ranges defined")

        count = await run_nmap_scan(
            db=db, scan_job=job, targets=targets, log=log
        )

        job = db.get(ScanJob, job_id)
        job.domains_found = count   # reuse field to show service count
        job.status = "done"
        job.finished_at = datetime.utcnow()
        db.commit()
        log(f"[nmap] Scan complete — {count} service(s) discovered.")
        await _broadcast_status(job_id, "done")

    except Exception as exc:
        db.rollback()
        log(f"[nmap] FAILED: {exc}")
        job = db.get(ScanJob, job_id)
        if job:
            job.status = "failed"
            job.error_message = str(exc)
            job.finished_at = datetime.utcnow()
            db.commit()
        await _broadcast_status(job_id, "failed")
    finally:
        db.close()
        _running.pop(job_id, None)


async def _run_nuclei(
    job_id: str, organization_id: int,
    severity: str | None, profile: str | None, template_set: str | None,
    target: str | None = None,
) -> None:
    """
    Full org-wide nuclei scan (target=None) or single-target quick scan.
    When *target* is provided, org-wide discovery is bypassed entirely.
    """
    from app.services.nuclei_runner import build_target_list, run_nuclei_scan, httpx_filter, WAFBlockedError
    from app.models import Service

    log = _make_log_callback(job_id)
    db: Session = SessionLocal()

    try:
        job = db.get(ScanJob, job_id)
        if not job:
            return
        job.status = "running"
        job.started_at = datetime.utcnow()
        db.commit()

        await _broadcast_status(job_id, "running")

        inst = db.get(Organization, organization_id)
        if not inst:
            raise ValueError(f"Organization {organization_id} not found")

        # ── Single-target shortcut ───────────────────────────────────────────
        if target:
            log(f"[nuclei] Quick scan on single target: {target}")

            # Resolve target to IP for service lookup
            import socket as _socket, ipaddress as _ip
            resolved_ip: str | None = None
            try:
                _ip.ip_address(target.split(":")[0])
                resolved_ip = target.split(":")[0]   # already an IP
            except ValueError:
                try:
                    resolved_ip = await asyncio.get_event_loop().run_in_executor(
                        None, _socket.gethostbyname, target
                    )
                except Exception:
                    pass

            # Look up nmap services and expand the target to scheme://host:port entries
            services = db.query(Service).filter_by(organization_id=organization_id).all()
            if resolved_ip and services:
                from app.services.nuclei_runner import build_target_list as _btl
                expanded = _btl([], [(target, resolved_ip)], services=services)
                if len(expanded) > 1 or (expanded and expanded[0] != target):
                    log(f"[nuclei] Expanded to {len(expanded)} target(s) via known services: "
                        f"{', '.join(expanded[:6])}{'…' if len(expanded) > 6 else ''}")
                    all_targets = expanded
                else:
                    all_targets = [target]
            else:
                if not services:
                    log("[nuclei] No port-scan data for this org — scanning default ports only "
                        "(run Port Scan first for full service coverage)")
                all_targets = [target]

            # Split HTTP vs non-HTTP: probe HTTP ones with httpx, bypass for service ports
            http_t    = [t for t in all_targets if "://" in t or ":" not in t]
            service_t = [t for t in all_targets if "://" not in t and ":" in t]

            from app.services.nuclei_runner import tcp_filter as _tcp_filter
            alive_http: list[str] = []
            if http_t:
                alive_http, _ = await httpx_filter(http_t, log, timeout=5)
            alive_service: list[str] = []
            if service_t:
                alive_service = await _tcp_filter(service_t, log, timeout=3)

            targets_combined = alive_http + alive_service
            if not targets_combined:
                log(f"[nuclei] Target {target} is not reachable — aborting.")
                job = db.get(ScanJob, job_id)
                job.status = "done"
                job.finished_at = datetime.utcnow()
                db.commit()
                await _broadcast_status(job_id, "done")
                return

            all_targets = targets_combined
            log(f"[nuclei] Single target ready: {len(all_targets)} target(s)")

        else:

            # Load previously discovered services for this org
            services = db.query(Service).filter_by(organization_id=organization_id).all()
            if services:
                log(f"[nuclei] Using {len(services)} known service(s) from port scan to build targets")
            else:
                log("[nuclei] No port-scan data — targets will use default ports (run Port Scan first for better coverage)")

            # Only scan CT-discovered subdomains + reverse_dns hostnames.
            # For amass root domains: resolve them and include only if they point
            # to one of this organization's own IPs (e.g. www.tolosaldealh.eus → 194.30.90.20).
            # This correctly excludes ISP/CDN domains (sarenet.es → 194.30.6.16).
            # Org IP ranges — expand for service lookup in build_target_list
            ips = [r.cidr for r in inst.ip_ranges]

            SCAN_SOURCES = {"crt_sh", "certspotter", "reverse_dns"}
            inst_ip_set = {r.cidr for r in inst.ip_ranges}

            scan_domains: list[tuple[str, str | None]] = []
            skipped_unresolved: list[str] = []
            skipped_roots: list[str] = []

            loop = asyncio.get_event_loop()
            for d in inst.domains:
                if d.source in SCAN_SOURCES:
                    # Skip subdomains that never resolved — likely deprecated/stale
                    if not d.resolved_ip:
                        skipped_unresolved.append(d.fqdn)
                        continue
                    scan_domains.append((d.fqdn, d.resolved_ip))
                elif d.source == "amass":
                    # Check if the root domain (or www.root) resolves to one of our IPs
                    resolved_in = False
                    for candidate in [d.fqdn, f"www.{d.fqdn}"]:
                        try:
                            ip = await loop.run_in_executor(
                                None, __import__("socket").gethostbyname, candidate
                            )
                            if ip in inst_ip_set:
                                scan_domains.append((candidate, ip))
                                log(f"[nuclei] Including {candidate} → {ip} (organization IP)")
                                resolved_in = True
                        except Exception:
                            pass
                    if not resolved_in:
                        skipped_roots.append(d.fqdn)

            if skipped_unresolved:
                log(f"[nuclei] Skipping {len(skipped_unresolved)} unresolved subdomain(s): "
                    f"{', '.join(skipped_unresolved[:5])}{'…' if len(skipped_unresolved) > 5 else ''}")

            if skipped_roots:
                log(f"[nuclei] Skipping {len(skipped_roots)} external root domain(s): "
                    f"{', '.join(skipped_roots[:5])}{chr(8230) if len(skipped_roots) > 5 else ''}")

            all_targets = build_target_list(ips, scan_domains, services=services)
            # Count HTTP/S vs non-HTTP targets for clarity
            http_targets   = [t for t in all_targets if "://" in t]
            network_targets = [t for t in all_targets if ":" in t and "://" not in t]
            bare_targets   = [t for t in all_targets if ":" not in t]
            log(
                f"[nuclei] Target list for '{inst.name}': "
                f"{len(http_targets)} URL(s), "
                f"{len(network_targets)} host:port(s), "
                f"{len(bare_targets)} bare host(s) "
                f"= {len(all_targets)} total"
            )

        # Pre-filter with httpx: only HTTP/S targets go through httpx.
        # Non-HTTP service targets (host:port like 1.2.3.4:22, example.com:3306)
        # bypass httpx entirely — they'd be filtered out as "dead" since httpx
        # only speaks HTTP. Pass them directly to nuclei for JS/network templates.
        if target:
            targets = all_targets  # already filtered above (single-target)
        else:
            # Split: URL/bare-host targets -> httpx filter
            #        host:port (no scheme) -> bypass (SSH, FTP, DB, etc.)
            http_targets    = [t for t in all_targets if "://" in t or ":" not in t]
            service_targets = [t for t in all_targets if "://" not in t and ":" in t]

            if http_targets:
                alive_http, httpx_summary = await httpx_filter(http_targets, log)
            else:
                alive_http, httpx_summary = [], {}

            alive_service_targets: list[str] = []
            if service_targets:
                from app.services.nuclei_runner import tcp_filter as _tcp_filter
                alive_service_targets = await _tcp_filter(service_targets, log, timeout=3)

            targets = alive_http + alive_service_targets
        if not targets:
            log("[nuclei] No reachable targets after httpx pre-filter — all hosts appear dead or firewalled.")
            job = db.get(ScanJob, job_id)
            job.status = "done"
            job.finished_at = datetime.utcnow()
            db.commit()
            await _broadcast_status(job_id, "done")
            return

        def _on_progress(pct: int) -> None:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.ensure_future(_broadcast_progress(job_id, pct))
            except RuntimeError:
                pass

        count = await run_nuclei_scan(
            db=db,
            scan_job=job,
            targets=targets,
            log=log,
            severity=severity,
            profile=profile,
            template_set=template_set,
            progress_callback=_on_progress,
        )

        job = db.get(ScanJob, job_id)
        job.findings_count = count
        job.status = "done"
        job.finished_at = datetime.utcnow()
        db.commit()

        log(f"[nuclei] Done — {count} finding(s) saved.")
        await _broadcast_status(job_id, "done")

    except WAFBlockedError as waf:
        db.rollback()
        msg = str(waf)
        log(f"[nuclei] BLOCKED: {msg}")
        log(f"[nuclei] Error rate: {waf.rate:.0%} ({waf.errors} errors / {waf.reqs} requests). "
            "Use the Resume button to retry with Stealth profile.")
        job = db.get(ScanJob, job_id)
        if job:
            job.status = "blocked"
            job.error_message = msg
            job.finished_at = datetime.utcnow()
            db.commit()
        await _broadcast_status(job_id, "blocked")

    except Exception as exc:
        db.rollback()
        log(f"[nuclei] FAILED: {exc}")
        job = db.get(ScanJob, job_id)
        if job:
            job.status = "failed"
            job.error_message = str(exc)
            job.finished_at = datetime.utcnow()
            db.commit()
        await _broadcast_status(job_id, "failed")
    finally:
        db.close()
        _running.pop(job_id, None)


async def _broadcast_status(job_id: str, status: str) -> None:
    payload = json.dumps({"type": "status", "status": status})
    await ws_manager.send(job_id, payload)


async def _broadcast_progress(job_id: str, percent: int) -> None:
    payload = json.dumps({"type": "progress", "percent": percent})
    await ws_manager.send(job_id, payload)


# ---------------------------------------------------------------------------
# Stop / Kill
# ---------------------------------------------------------------------------

def stop_job(job_id: str, db: Session) -> bool:
    """Cancel a running job's asyncio task and kill its subprocess if any."""
    from app.services.nuclei_runner import kill_proc as nuclei_kill
    from app.services.nmap_runner import kill_proc as nmap_kill

    task = _running.pop(job_id, None)

    # Kill any subprocess (nuclei, nmap, amass, etc.) first
    nuclei_kill(job_id)
    nmap_kill(job_id)

    if task is None:
        return False

    # Cancel the asyncio task
    if task and not task.done():
        task.cancel()
        async def _await_cancel() -> None:
            try:
                await task
            except asyncio.CancelledError:
                pass
        if _main_loop and _main_loop.is_running():
            _main_loop.call_soon_threadsafe(
                lambda: asyncio.ensure_future(_await_cancel())
            )

    # Update DB record
    job = db.get(ScanJob, job_id)
    if job and job.status == "running":
        log_line = "[lhs] Job stopped by user.\n"
        job.log_output = (job.log_output or "") + log_line
        job.status = "failed"
        job.error_message = "Stopped by user"
        job.finished_at = datetime.utcnow()
        db.commit()

        # Broadcast stopped status
        payload = json.dumps({"type": "log", "line": "[lhs] Job stopped by user."})
        if _main_loop and _main_loop.is_running():
            _main_loop.call_soon_threadsafe(
                lambda: asyncio.ensure_future(ws_manager.send(job_id, payload))
            )
            _main_loop.call_soon_threadsafe(
                lambda: asyncio.ensure_future(_broadcast_status(job_id, "failed"))
            )

    return True


def kill_all_running(db: Session) -> int:
    """Stop all currently running jobs (in-memory tasks + stale DB records)."""
    # 1. Stop in-memory running tasks
    job_ids = list(_running.keys())
    stopped = 0
    for jid in job_ids:
        if stop_job(jid, db):
            stopped += 1

    # 2. Also fix any DB jobs still marked 'running'/'pending' with no active task
    stale = (
        db.query(ScanJob)
        .filter(ScanJob.status.in_(["running", "pending"]))
        .all()
    )
    for job in stale:
        if job.id not in _running:  # not already handled above
            job.log_output = (job.log_output or "") + "[lhs] Job killed (no active process).\n"
            job.status = "failed"
            job.error_message = "Killed: no active process"
            job.finished_at = datetime.utcnow()
            stopped += 1
    db.commit()
    return stopped


def reset_stale_jobs(db: Session) -> int:
    """Called on startup: mark any orphaned running/pending jobs as failed."""
    stale = (
        db.query(ScanJob)
        .filter(ScanJob.status.in_(["running", "pending"]))
        .all()
    )
    count = 0
    for job in stale:
        job.log_output = (job.log_output or "") + "[lhs] Server restarted — job aborted.\n"
        job.status = "failed"
        job.error_message = "Server restarted"
        job.finished_at = datetime.utcnow()
        count += 1
    if count:
        db.commit()
    return count


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

# Store a reference to the main event loop so sync callers can schedule tasks.
_main_loop: asyncio.AbstractEventLoop | None = None


def _schedule(coro):
    """Schedule a coroutine on the stored main event loop."""
    global _main_loop
    if _main_loop is None:
        _main_loop = asyncio.get_event_loop()
    return _main_loop.create_task(coro)


def launch_port_scan(db: Session, organization_id: int) -> ScanJob:
    """Create a ScanJob and schedule an nmap port scan task."""
    job = _create_job(db, organization_id, "port_scan")
    task = _schedule(_run_port_scan(job.id, organization_id))
    _running[job.id] = task
    return job


def launch_ct_subdomain(
    db: Session, organization_id: int, domain: str
) -> ScanJob:
    """Create a ScanJob and run CT log discovery for one domain."""
    cfg = {"domain": domain}
    job = _create_job(db, organization_id, "ct_subdomain", config=cfg)
    task = _schedule(_run_ct_subdomain(job.id, organization_id, domain))
    _running[job.id] = task
    return job


def launch_ct_discovery(db: Session, organization_id: int) -> ScanJob:
    """Create a ScanJob and schedule a CT discovery task."""
    job = _create_job(db, organization_id, "ct_discovery")
    task = _schedule(_run_ct_discovery(job.id, organization_id))
    _running[job.id] = task
    return job


def launch_nuclei_scan(
    db: Session, organization_id: int, severity: str | None = None,
    profile: str | None = None, template_set: str | None = None,
    target: str | None = None,
) -> ScanJob:
    cfg = {"severity": severity or "", "profile": profile or "", "template_set": template_set or ""}
    if target:
        cfg["target"] = target
    job = _create_job(db, organization_id, "nuclei", config=cfg)
    task = _schedule(_run_nuclei(job.id, organization_id, severity, profile, template_set, target))
    _running[job.id] = task
    return job


def _create_job(
    db: Session,
    organization_id: int,
    scan_type: str,
    config: dict | None = None,
) -> ScanJob:
    job = ScanJob(
        id=str(uuid.uuid4()),
        organization_id=organization_id,
        scan_type=scan_type,
        status="pending",
        log_output="",
    )
    if config:
        job.set_config(config)
    db.add(job)
    db.commit()
    db.refresh(job)
    return job
