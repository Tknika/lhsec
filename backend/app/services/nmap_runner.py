"""
Nmap port-scan runner.

Executes nmap against organization IPs, parses the XML output,
and upserts discovered services into the `services` table.

Supports two scan modes via the `profile` parameter:
  - "stealth": Syn-scan (-sS) with low timing (-T1), random host order,
               scan delay, service version detection across top 200+ ports.
               Designed to avoid rate-based blocking, IDS, and WAF triggers.
  - "default": TCP connect scan (-sT) with normal timing (-T4),
                -sV on 48 common ports. Fast but noisy.
"""
from __future__ import annotations

import asyncio
import shutil
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Callable, Dict, List

from sqlalchemy.orm import Session

from app.config import settings
from app.models import Service, ScanJob

LogCallback = Callable[[str], None]

# Module-level registry so stop_job can kill the nmap subprocess
_running_procs: Dict[str, "asyncio.subprocess.Process"] = {}


# ---------------------------------------------------------------------------
# Nmap command builders (per profile)
# ---------------------------------------------------------------------------

def _build_stealth_cmd(nmap_bin: str, targets: list[str]) -> list[str]:
    """
    Build a low-and-slow nmap command designed to avoid rate-based blocking,
    IDS triggers and WAF rate-limiters.

    Key techniques:
      -sS           SYN stealth (no full TCP handshake) — quieter and faster
      -T1           Sneaky timing: inter-probe delay ≈ 15s, 1 port in parallel
      --randomize-hosts   Shuffle target order so no sequential IP scanning
      --scan-delay  5s    Extra 5s pause between probes
      --top-ports   …     Top 200+ most common service ports
      -sV --version-intensity 3    Aggressive version fingerprinting (probe 2-9)
      --max-retries 1     Don't hammer; one retry if probe lost
      --script-timeout 15s  Cap NSE scripts
      --host-timeout 10m    Eventually give up on a single dead host
      --min-parallelism 1 / --max-parallelism 1  Single-thread scanning
      -oX -          XML to stdout
    """
    ports = settings.nmap_stealth_top_ports

    return [
        nmap_bin,
        "-sS",                    # SYN stealth scan (requires root / CAP_NET_RAW)
        "-T1",                    # Sneaky: inter-probe delay ~15 seconds
        "--randomize-hosts",      # Shuffle target order
        "--scan-delay", "5s",     # +5s between probes (cumulative with T1)
        "-sV",                    # Service version detection
        "--version-intensity", str(settings.nmap_stealth_version_intensity),
        "--max-retries", "1",     # One retry if probe lost — no hammering
        "--open",                 # Only report open ports
        "--top-ports", str(ports),
        "--script-timeout", "15s",
        "--host-timeout", "10m",
        "--min-parallelism", "1",
        "--max-parallelism", "1",
        "--max-rtt-timeout", "2s",  # Be patient with slow links; -T1 caps it anyway
        "-oX", "-",              # XML output to stdout
    ] + targets


def kill_proc(job_id: str) -> bool:
    proc = _running_procs.pop(job_id, None)
    if proc and proc.returncode is None:
        try:
            proc.kill()
        except Exception:
            pass
        return True
    return False


# ---------------------------------------------------------------------------
# XML parser
# ---------------------------------------------------------------------------

def _parse_nmap_xml(xml_text: str, organization_id: int) -> List[dict]:
    """
    Parse nmap XML output.  Returns a list of service dicts ready for DB upsert.
    Each dict: {organization_id, ip, port, protocol, service_name, product,
                version, tunnel, extra_info}
    """
    results: list[dict] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return results

    for host_el in root.findall("host"):
        # Get IPv4 address
        ip = None
        for addr_el in host_el.findall("address"):
            if addr_el.get("addrtype") == "ipv4":
                ip = addr_el.get("addr")
                break
        if not ip:
            continue

        ports_el = host_el.find("ports")
        if ports_el is None:
            continue

        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            port_num = int(port_el.get("portid", 0))
            protocol = port_el.get("protocol", "tcp")

            svc_el = port_el.find("service")
            if svc_el is not None:
                service_name = svc_el.get("name", "")
                product      = svc_el.get("product", "") or None
                version      = svc_el.get("version", "") or None
                tunnel       = svc_el.get("tunnel", "") or None
                extra_info   = svc_el.get("extrainfo", "") or None
            else:
                service_name = ""
                product = version = tunnel = extra_info = None

            results.append({
                "organization_id": organization_id,
                "ip":           ip,
                "port":         port_num,
                "protocol":     protocol,
                "service_name": service_name or None,
                "product":      product,
                "version":      version,
                "tunnel":       tunnel,
                "extra_info":   extra_info,
            })

    return results


# ---------------------------------------------------------------------------
# DB upsert
# ---------------------------------------------------------------------------

def upsert_services(db: Session, records: list[dict]) -> int:
    """
    Insert-or-update service records.
    Returns the number of new/updated services.
    """
    count = 0
    for rec in records:
        existing = (
            db.query(Service)
            .filter_by(
                organization_id=rec["organization_id"],
                ip=rec["ip"],
                port=rec["port"],
                protocol=rec["protocol"],
            )
            .first()
        )
        if existing:
            # Update version/product/etc and bump last_seen
            existing.service_name = rec["service_name"]
            existing.product      = rec["product"]
            existing.version      = rec["version"]
            existing.tunnel       = rec["tunnel"]
            existing.extra_info   = rec["extra_info"]
            existing.last_seen    = datetime.utcnow()
        else:
            db.add(Service(**rec))
        count += 1

    db.commit()
    return count


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

async def run_nmap_scan(
    db: Session,
    scan_job: ScanJob,
    targets: list[str],   # IPs and CIDRs
    log: LogCallback,
    profile: str | None = "default",  # "default" or "stealth"
) -> int:
    """
    Run nmap against *targets*, persist discovered services, return service count.

    Profiles:
      - "stealth": SYN scan, T1 timing, randomized hosts, scan-delay,
                   top 200+ ports with version intensity 3.
      - "default": TCP connect, T4 timing, -sV on configured ports.
    """
    nmap_bin = settings.nmap_binary
    if not shutil.which(nmap_bin):
        # Try absolute path
        import os
        nmap_bin = shutil.which("nmap") or "/usr/bin/nmap"
        if not shutil.which(nmap_bin):
            raise FileNotFoundError(
                f"nmap binary not found (configured: {settings.nmap_binary}). "
                "Install nmap: https://nmap.org/download"
            )

    ports = settings.nmap_ports

    # Normalize profile from API input (can be null/empty)
    requested_profile = (profile or "default").strip().lower()
    normalized_profile = {
        "stealth": "stealth",
        "default": "default",
        "balanced": "default",  # currently aliases to default nmap strategy
        "fast": "default",      # currently aliases to default nmap strategy
    }.get(requested_profile, "default")

    if requested_profile not in ("default", "stealth", "balanced", "fast"):
        log(f"[nmap] Unknown profile '{profile}', falling back to default")

    if normalized_profile == "stealth":
        cmd = _build_stealth_cmd(nmap_bin, targets)
        port_desc = "top ports"
    else:
        cmd = [
            nmap_bin,
            "-sV",           # service/version detection
            "--open",        # only show open ports
            "-T4",           # aggressive timing (safe for internet targets)
            "-p", ports,
            "--script-timeout", "10s",
            "-oX", "-",      # XML output to stdout
            "--host-timeout", "5m",  # give up on unresponsive hosts
        ] + targets
        port_desc = f"{len(ports.split(','))} ports"

    log(f"[nmap] [{normalized_profile.upper()}] Scanning {len(targets)} target(s) — {port_desc}…")
    log(f"[nmap] Running: {nmap_bin} {' '.join(cmd[1:8])} … {' '.join(targets)}")

    xml_buf: list[str] = []
    services_count = 0

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _running_procs[scan_job.id] = proc

        # Read stderr for progress lines
        async def read_stderr() -> None:
            assert proc.stderr
            async for line in proc.stderr:
                decoded = line.decode(errors="replace").rstrip()
                if decoded and not decoded.startswith("#"):
                    # nmap prints progress to stderr like:
                    # "Scanning 3 hosts [47 ports/host]"
                    # "Stats: 0:00:05 elapsed; 0 hosts completed (3 up), 3 undergoing Service Scan"
                    if any(kw in decoded for kw in ("Scanning", "Stats:", "Completed", "Service scan")):
                        log(f"[nmap] {decoded}")

        stderr_task = asyncio.create_task(read_stderr())

        # Read full stdout (XML) — nmap writes everything then closes
        assert proc.stdout
        raw = await proc.stdout.read()
        xml_text = raw.decode(errors="replace")

        await stderr_task
        await proc.wait()

        if proc.returncode not in (0, None):
            log(f"[nmap] Process exited with code {proc.returncode}")

        # Parse XML
        records = _parse_nmap_xml(xml_text, scan_job.organization_id)
        if not records:
            log("[nmap] No open ports found.")
            return 0

        # Group by IP for logging
        by_ip: dict[str, list[dict]] = {}
        for r in records:
            by_ip.setdefault(r["ip"], []).append(r)

        for ip, svcs in sorted(by_ip.items()):
            parts = []
            for s in sorted(svcs, key=lambda x: x["port"]):
                label = str(s["port"])
                sname = s["service_name"] or ""
                prod  = s["product"] or ""
                ver   = s["version"] or ""
                tun   = s["tunnel"] or ""
                detail = "/".join(filter(None, [sname, tun]))
                info   = " ".join(filter(None, [prod, ver]))
                parts.append(f"{label}/{detail}" + (f" ({info})" if info else ""))
            log(f"[nmap] {ip}: {len(svcs)} port(s) — {', '.join(parts)}")

        services_count = upsert_services(db, records)
        log(f"[nmap] Done — {services_count} service(s) saved across {len(by_ip)} host(s)")

    except FileNotFoundError:
        log("[nmap] ERROR: nmap binary not found. Install: sudo apt install nmap")
        raise
    finally:
        _running_procs.pop(scan_job.id, None)

    return services_count
