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
from typing import Dict, Set, Sequence

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


async def _run_port_scan(job_id: str, organization_id: int, profile: str | None = "default") -> None:
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
            db=db, scan_job=job, targets=targets, log=log, profile=profile
        )

        # After port scan, run WAF detection on discovered web services
        try:
            from app.services.wafw00f_runner import detect_waf_for_services
            from app.models import Service
            waf_count = await detect_waf_for_services(
                db=db,
                services=db.query(Service).filter_by(organization_id=organization_id).all(),
                log=log,
            )
            if waf_count:
                log(f"[wafw00f] Detected {waf_count} WAF(s) across web services.")
        except Exception as waf_exc:
            log(f"[wafw00f] WAF detection skipped (non-critical): {waf_exc}")

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
                elif d.source in {"amass", "contact_email"}:
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

        # ── WAF-awareness log ────────────────────────────────────────────
        waf_services = [s for s in services if s.waf_name and s.is_http]
        if waf_services:
            by_waf: dict[str, list[str]] = {}
            for s in waf_services:
                by_waf.setdefault(s.waf_name, []).append(f"{s.scheme}://{s.ip}:{s.port}")
            log(f"[nuclei] ⚠ Known WAFs across {len(waf_services)} endpoint(s):")
            for name, urls in by_waf.items():
                log(f"[nuclei]    {name}: {', '.join(urls)}")
        # ─────────────────────────────────────────────────────────────────

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


def launch_port_scan(db: Session, organization_id: int, profile: str | None = "default") -> ScanJob:
    """Create a ScanJob and schedule an nmap port scan task."""
    job = _create_job(db, organization_id, "port_scan")
    task = _schedule(_run_port_scan(job.id, organization_id, profile))
    _running[job.id] = task
    return job


def _round_robin_target_tuples(per_org: dict[int, list[str]]) -> list[tuple[int, str]]:
    """Interleave targets so consecutive entries rotate organizations."""
    buckets = {k: list(v) for k, v in per_org.items() if v}
    out: list[tuple[int, str]] = []
    while buckets:
        progressed = False
        for org_id in list(buckets.keys()):
            lst = buckets.get(org_id, [])
            if not lst:
                buckets.pop(org_id, None)
                continue
            out.append((org_id, lst.pop(0)))
            progressed = True
            if not lst:
                buckets.pop(org_id, None)
        if not progressed:
            break
    return out


def _record_target_keys(target: str) -> set[str]:
    """Generate matching keys for finding attribution."""
    from urllib.parse import urlparse
    keys: set[str] = {target}
    t = target.strip()
    if not t:
        return keys
    if "://" in t:
        u = urlparse(t)
        if u.hostname:
            keys.add(u.hostname)
        if u.hostname and u.port:
            keys.add(f"{u.hostname}:{u.port}")
        elif u.hostname and u.scheme in ("http", "https"):
            keys.add(f"{u.hostname}:{443 if u.scheme == 'https' else 80}")
    elif ":" in t:
        host, _, _ = t.rpartition(":")
        if host:
            keys.add(host)
    else:
        keys.add(t)
    return keys


async def _probe_target_alive(target: str, timeout: float = 3.0) -> bool:
    """Low-noise TCP reachability probe for URL/bare/service targets."""
    from urllib.parse import urlparse

    host: str | None = None
    ports: list[int] = []
    t = target.strip()
    if not t:
        return False

    try:
        if "://" in t:
            u = urlparse(t)
            host = u.hostname
            if u.port:
                ports = [u.port]
            elif u.scheme == "https":
                ports = [443]
            else:
                ports = [80]
        elif ":" in t:
            host, _, p = t.rpartition(":")
            ports = [int(p)]
        else:
            host = t
            ports = [443, 80]
    except Exception:
        return True

    if not host or not ports:
        return True

    for port in ports:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except Exception:
            continue
    return False


async def _run_nuclei_bulk_interleaved(
    jobs: Sequence[tuple[str, int]],
    *,
    severity: str | None,
    profile: str | None,
    template_set: str | None,
) -> None:
    """Single nuclei process with interleaved cross-org targets and attribution."""
    from app.models import Service
    from app.services.nuclei_runner import (
        build_target_list,
        run_nuclei_scan,
        nuclei_record_to_finding,
        WAFBlockedError,
    )
    import socket

    db: Session = SessionLocal()
    logs = {job_id: _make_log_callback(job_id) for job_id, _ in jobs}
    job_by_org: dict[int, ScanJob] = {}
    findings_per_job: dict[str, int] = {jid: 0 for jid, _ in jobs}

    try:
        # mark all jobs running
        for job_id, org_id in jobs:
            job = db.get(ScanJob, job_id)
            if not job:
                continue
            job.status = "running"
            job.started_at = datetime.utcnow()
            job_by_org[org_id] = job
            db.commit()
            await _broadcast_status(job_id, "running")
            logs[job_id]("[batch] Interleaved run-all nuclei started")

        per_org_targets: dict[int, list[str]] = {}
        target_key_to_org: dict[str, int] = {}

        # build org targets
        for job_id, org_id in jobs:
            org = db.get(Organization, org_id)
            if not org:
                continue
            services = db.query(Service).filter_by(organization_id=org_id).all()
            ips = [r.cidr for r in org.ip_ranges]
            scan_domains: list[tuple[str, str | None]] = []
            inst_ip_set = {r.cidr for r in org.ip_ranges}
            loop = asyncio.get_event_loop()

            for d in org.domains:
                if d.source in {"crt_sh", "certspotter", "reverse_dns"}:
                    if d.resolved_ip:
                        scan_domains.append((d.fqdn, d.resolved_ip))
                elif d.source in {"amass", "contact_email"}:
                    for candidate in [d.fqdn, f"www.{d.fqdn}"]:
                        try:
                            ip = await loop.run_in_executor(None, socket.gethostbyname, candidate)
                            if ip in inst_ip_set:
                                scan_domains.append((candidate, ip))
                                break
                        except Exception:
                            pass

            built = build_target_list(ips, scan_domains, services=services)
            per_org_targets[org_id] = built
            logs[job_id](f"[batch] Built {len(built)} target(s) before precheck")

        # interleaved reachability probing
        alive_per_org: dict[int, list[str]] = {org_id: [] for _, org_id in jobs}
        rr_probe = _round_robin_target_tuples(per_org_targets)
        for org_id, t in rr_probe:
            ok = await _probe_target_alive(t, timeout=3.0)
            if ok:
                alive_per_org.setdefault(org_id, []).append(t)

        for job_id, org_id in jobs:
            alive = len(alive_per_org.get(org_id, []))
            dead = max(0, len(per_org_targets.get(org_id, [])) - alive)
            logs[job_id](f"[batch] Precheck: {alive} alive / {dead} closed-filtered (interleaved across orgs)")

        interleaved = _round_robin_target_tuples(alive_per_org)
        final_targets = [t for _, t in interleaved]
        for org_id, t in interleaved:
            for k in _record_target_keys(t):
                target_key_to_org[k] = org_id

        if not final_targets:
            for job_id, _ in jobs:
                j = db.get(ScanJob, job_id)
                if j:
                    j.status = "done"
                    j.finished_at = datetime.utcnow()
                    db.commit()
                    await _broadcast_status(job_id, "done")
            return

        def _fanout(line: str) -> None:
            for job_id, _ in jobs:
                logs[job_id](line)

        async def _on_finding(record: dict) -> bool:
            from urllib.parse import urlparse
            candidates: set[str] = set()
            host = (record.get("host") or "").strip()
            matched = (record.get("matched-at") or record.get("url") or "").strip()
            ip = (record.get("ip") or "").strip()
            if host:
                candidates.add(host)
                if "://" in host:
                    u = urlparse(host)
                    if u.hostname:
                        candidates.add(u.hostname)
                        if u.port:
                            candidates.add(f"{u.hostname}:{u.port}")
            if matched:
                candidates.add(matched)
                if "://" in matched:
                    u = urlparse(matched)
                    if u.hostname:
                        candidates.add(u.hostname)
                        if u.port:
                            candidates.add(f"{u.hostname}:{u.port}")
            if ip:
                candidates.add(ip)

            org_id = next((target_key_to_org[c] for c in candidates if c in target_key_to_org), None)
            if org_id is None and jobs:
                org_id = jobs[0][1]
            job = job_by_org.get(org_id)
            if not job:
                return False

            finding = nuclei_record_to_finding(record, job.id, org_id)
            db.add(finding)
            findings_per_job[job.id] = findings_per_job.get(job.id, 0) + 1
            db_job = db.get(ScanJob, job.id)
            if db_job:
                db_job.findings_count = findings_per_job[job.id]
            db.commit()
            return True

        owner_job = db.get(ScanJob, jobs[0][0])
        if not owner_job:
            return

        await run_nuclei_scan(
            db=db,
            scan_job=owner_job,
            targets=final_targets,
            log=_fanout,
            severity=severity,
            profile=profile,
            template_set=template_set,
            on_finding=_on_finding,
        )

        for job_id, _ in jobs:
            j = db.get(ScanJob, job_id)
            if j:
                j.status = "done"
                j.finished_at = datetime.utcnow()
                db.commit()
                await _broadcast_status(job_id, "done")
                logs[job_id](f"[batch] Done — {j.findings_count} finding(s)")

    except WAFBlockedError as waf:
        for job_id, _ in jobs:
            j = db.get(ScanJob, job_id)
            if j:
                j.status = "blocked"
                j.error_message = str(waf)
                j.finished_at = datetime.utcnow()
                db.commit()
                await _broadcast_status(job_id, "blocked")
                logs[job_id](f"[batch] BLOCKED: {waf}")
    except Exception as exc:
        for job_id, _ in jobs:
            j = db.get(ScanJob, job_id)
            if j:
                j.status = "failed"
                j.error_message = str(exc)
                j.finished_at = datetime.utcnow()
                db.commit()
                await _broadcast_status(job_id, "failed")
                logs[job_id](f"[batch] FAILED: {exc}")
    finally:
        for job_id, _ in jobs:
            _running.pop(job_id, None)
        db.close()


async def _run_bulk_sequence(
    scan_type: str,
    jobs: Sequence[tuple[str, int]],
    cooldown_seconds: int = 20,
    severity: str | None = None,
    profile: str | None = None,
    template_set: str | None = None,
) -> None:
    """Run one scan per org in sequence with cooldown, or one interleaved nuclei run."""
    if scan_type == "nuclei":
        await _run_nuclei_bulk_interleaved(
            jobs,
            severity=severity,
            profile=profile,
            template_set=template_set,
        )
        return

    for i, (job_id, org_id) in enumerate(jobs):
        if i > 0 and cooldown_seconds > 0:
            log = _make_log_callback(job_id)
            log(f"[batch] Run-All queue: sleeping {cooldown_seconds}s before start (org rotation/WAF safety)")
            await asyncio.sleep(cooldown_seconds)

        if scan_type == "port_scan":
            child = asyncio.create_task(_run_port_scan(job_id, org_id, profile=profile or "default"))
        elif scan_type == "ct_discovery":
            child = asyncio.create_task(_run_ct_discovery(job_id, org_id))
        else:
            raise ValueError(f"Unsupported scan_type for bulk run: {scan_type}")

        _running[job_id] = child
        try:
            await child
        except asyncio.CancelledError:
            break


def launch_bulk_scan(
    db: Session,
    *,
    organization_ids: list[int],
    scan_type: str,
    cooldown_seconds: int = 20,
    severity: str | None = None,
    profile: str | None = None,
    template_set: str | None = None,
) -> list[ScanJob]:
    """
    Queue one job per organization and execute them sequentially.

    This avoids hitting a single org/WAF with a large burst by rotating orgs
    and inserting a cooldown between jobs.
    """
    jobs: list[ScanJob] = []
    job_refs: list[tuple[str, int]] = []

    for org_id in organization_ids:
        cfg: dict = {"batch": True, "cooldown_seconds": cooldown_seconds}
        if scan_type == "nuclei":
            cfg.update({
                "severity": severity or "",
                "profile": profile or "",
                "template_set": template_set or "",
            })
        job = _create_job(db, org_id, scan_type, config=cfg)
        jobs.append(job)
        job_refs.append((job.id, org_id))

    # coordinator task (shared for all jobs in this run-all request)
    coordinator = _schedule(
        _run_bulk_sequence(
            scan_type,
            job_refs,
            cooldown_seconds=cooldown_seconds,
            severity=severity,
            profile=profile,
            template_set=template_set,
        )
    )
    for job in jobs:
        _running[job.id] = coordinator
    return jobs


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
