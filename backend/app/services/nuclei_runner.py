"""
Nuclei scan runner.

Builds a target file from organization IPs and discovered domains, then
executes nuclei and parses its JSONL output line-by-line, persisting each
finding to the database in real time.
"""
from __future__ import annotations

import asyncio
import json
import shutil
import signal
import socket
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict

from sqlalchemy.orm import Session

from app.config import settings
from app.models import Finding, ScanJob

LogCallback = Callable[[str], None]

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]

# WAF/firewall block detection via error rate.
# The `errors` field in nuclei stats is a GLOBAL counter across ALL hosts and templates,
# NOT a per-host counter.  A few errors from dead subdomains is completely normal.
# Nuclei's own -mhe flag (default: 30) already drops unresponsive hosts per-host.
#
# We only abort when BOTH conditions are met:
#   1. At least WAF_MIN_REQUESTS have been sent (enough sample)
#   2. The error rate (errors/requests) exceeds WAF_ERROR_RATE_THRESHOLD
#
# Example: 7 errors over 4540 requests = 0.15% → NOT a block
#          450 errors over 800 requests = 56%  → likely blocked
WAF_MIN_REQUESTS = 30           # minimum sample before checking error rate
WAF_ERROR_RATE_THRESHOLD = 0.40  # 40%+ error rate → abort


class WAFBlockedError(RuntimeError):
    """Raised when nuclei's sustained error rate indicates WAF/firewall blocking."""
    def __init__(self, errors: int, reqs: int, rate: float):
        self.errors = errors
        self.reqs   = reqs
        self.rate   = rate
        super().__init__(
            f"Scan aborted: {errors}/{reqs} requests failed ({rate:.0%} error rate) — WAF/firewall block"
        )

# Module-level registry so the task manager can kill running nuclei processes
_running_procs: Dict[str, "asyncio.subprocess.Process"] = {}


def kill_proc(job_id: str) -> bool:
    """Kill a running nuclei subprocess for *job_id*. Returns True if a process was killed."""
    proc = _running_procs.pop(job_id, None)
    if proc and proc.returncode is None:
        try:
            proc.kill()
        except Exception:
            pass
        return True
    return False


# ---------------------------------------------------------------------------
# httpx pre-filter  (replaces simple TCP connectivity check)
# ---------------------------------------------------------------------------

async def tcp_filter(
    targets: list[str],   # expects host:port format (no scheme)
    log: LogCallback,
    timeout: float = 3.0,
    concurrency: int = 100,
) -> list[str]:
    """
    TCP connectivity check for non-HTTP service targets (SSH, FTP, MySQL, …).

    Attempts a raw TCP connection to each host:port.  Returns only the targets
    that accepted the connection (port is open).  Dead / firewalled ports are
    filtered out so nuclei doesn’t waste its error budget on them.

    Uses asyncio.open_connection (no external binary required).
    """
    if not targets:
        return []

    sem = asyncio.Semaphore(concurrency)

    async def _probe(target: str) -> str | None:
        """Return target if port is open, None otherwise."""
        try:
            host, port_s = target.rsplit(":", 1)
            port = int(port_s)
        except ValueError:
            return target  # can’t parse — pass through
        async with sem:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=timeout,
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return target
            except Exception:
                return None

    results = await asyncio.gather(*[_probe(t) for t in targets])
    alive   = [t for t in results if t is not None]
    dead    = len(targets) - len(alive)

    log(f"[tcp-check] {len(alive)} open / {dead} closed/filtered "
        f"(timeout {timeout}s) — service target(s)")
    return alive


async def httpx_filter(
    targets: list[str],
    log: LogCallback,
    timeout: int = 10,
) -> tuple[list[str], dict]:
    """
    Run projectdiscovery/httpx against *targets* and return only the ones
    that respond with a useful HTTP status code.

    Returns (alive_targets, summary_dict).
    """
    import shutil
    import tempfile

    httpx_bin = shutil.which(settings.httpx_binary) or settings.httpx_binary

    # Write targets to temp file
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, prefix="lhsec_httpx_"
    ) as tf:
        tf.write("\n".join(targets))
        targets_file = Path(tf.name)

    log(f"[httpx] Probing {len(targets)} target(s) with httpx…")

    cmd = [
        httpx_bin,
        "-l", str(targets_file),
        "-sc",             # status code
        "-title",          # page title
        "-mc", "200,201,301,302,307,308,401,403,405,500,502,503",  # keep these
        "-silent",
        "-no-color",
        "-timeout", str(timeout),
        "-rl", "150",      # fast — we just want live/dead, not stealth
        "-t", "100",      # threads
        "-o", "/dev/null", # we read from stdout
        "-json",
    ]

    alive: list[str] = []
    status_counts: dict[str, int] = {}
    cdn_hints: list[str] = []

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        assert proc.stdout
        async for raw in proc.stdout:
            line = raw.decode(errors="replace").strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                url  = rec.get("url") or rec.get("input", "")
                sc   = str(rec.get("status-code", ""))
                tech = rec.get("technologies", []) or []
                title = rec.get("title", "")
                cdn_techs = [t for t in tech if any(
                    c in t.lower() for c in ("cloudflare", "akamai", "fastly", "cloudfront", "imperva")
                )]
                if cdn_techs:
                    cdn_hints.append(f"{url} [{', '.join(cdn_techs)}]")
                alive.append(url)
                status_counts[sc] = status_counts.get(sc, 0) + 1
            except Exception:
                pass
        await proc.wait()
    except FileNotFoundError:
        log(f"[httpx] WARNING: httpx binary not found at '{httpx_bin}' — skipping pre-filter")
        targets_file.unlink(missing_ok=True)
        return targets, {}
    finally:
        targets_file.unlink(missing_ok=True)

    dead = len(targets) - len(alive)
    sc_summary = "  ".join(f"HTTP {k}: {v}" for k, v in sorted(status_counts.items()))
    log(f"[httpx] {len(alive)} alive  /  {dead} dead/filtered  |  {sc_summary or 'no responses'}")
    if cdn_hints:
        log(f"[httpx] CDN/WAF detected on {len(cdn_hints)} target(s): "
            + ", ".join(cdn_hints[:5]) + (" …" if len(cdn_hints) > 5 else ""))

    summary = {"alive": len(alive), "dead": dead, "status_counts": status_counts, "cdn": cdn_hints}
    return alive, summary


# ---------------------------------------------------------------------------
# Target list builder
# ---------------------------------------------------------------------------

# Service names nmap reports for HTTP/S traffic
_HTTP_SERVICE_NAMES = {
    "http", "https", "http-proxy", "http-alt", "https-alt",
    "http-mgmt", "www", "ssl/http",
}


def build_target_list(
    ips: list[str],
    domains: list[tuple[str, str | None]],  # (fqdn, resolved_ip)
    services: list | None = None,
) -> list[str]:
    """
    Build a deduplicated Nuclei target list from org IPs, domains, and nmap services.

    Per the Nuclei input-formats docs, valid list-type entries are:
      https://host:port   -> HTTP/S templates probe that specific scheme+port
      http://host:port    -> same
      host:port           -> network/TCP templates (SSH, FTP, MySQL, ...)
      bare IP / domain    -> nuclei probes default ports 80 + 443
      CIDR                -> nuclei expands the range natively

    Logic per host:
      1. If nmap services are known for the IP:
         a. HTTP/S service  ->  scheme://host:port
         b. Non-HTTP service -> host:port  (network/TCP templates)
      2. If NO services known: bare host (nuclei uses defaults 80+443).

    For domains, the caller supplies the stored resolved_ip so we look up
    services without re-doing DNS at scan time.
    """
    import ipaddress as _ipmod

    # Index services by individual IP
    by_ip: dict[str, list] = {}
    if services:
        for svc in services:
            by_ip.setdefault(svc.ip, []).append(svc)

    # Expand small CIDRs to individual IPs for service lookup.
    # Service index keys are individual IPs (from nmap) so CIDRs must be
    # expanded to match. Large ranges (> /24) pass through as-is and
    # nuclei handles them natively.
    individual_ips: list[str] = []
    cidr_fallbacks: list[str] = []
    for raw in ips:
        if "/" in raw:
            try:
                net = _ipmod.ip_network(raw, strict=False)
                if net.num_addresses <= 256:   # /24 and smaller: expand
                    individual_ips.extend(str(h) for h in net.hosts())
                else:
                    cidr_fallbacks.append(raw)  # let nuclei handle large ranges
            except ValueError:
                cidr_fallbacks.append(raw)
        else:
            individual_ips.append(raw)

    targets: list[str] = []
    seen: set[str] = set()

    def add(t: str) -> None:
        t = t.strip()
        if t and t not in seen:
            targets.append(t)
            seen.add(t)

    def _expand_host(host: str, ip_key: str | None = None) -> None:
        """
        Emit all nuclei targets for *host* (IP or FQDN).
        *ip_key*: IP address to use for service lookup
                  (equals host for bare IPs, resolved_ip for FQDNs).
        """
        lookup = ip_key if ip_key else host
        svcs   = by_ip.get(lookup, [])
        if svcs:
            for svc in svcs:
                if svc.is_http:
                    add(f"{svc.scheme}://{host}:{svc.port}")
                else:
                    add(f"{host}:{svc.port}")  # network/TCP templates
        else:
            add(host)  # no scan data - nuclei probes default ports

    # IPs
    for ip in individual_ips:
        _expand_host(ip)
    for cidr in cidr_fallbacks:
        add(cidr)

    # Domains / subdomains
    for fqdn, resolved_ip in domains:
        _expand_host(fqdn, ip_key=resolved_ip)

    return targets



# ---------------------------------------------------------------------------
# Nuclei JSONL result parser
# ---------------------------------------------------------------------------

def parse_nuclei_line(line: str) -> dict | None:
    """Parse a single nuclei JSONL output line. Returns None if not a finding."""
    line = line.strip()
    if not line or not line.startswith("{"):
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None


def nuclei_record_to_finding(
    data: dict,
    scan_job_id: str,
    organization_id: int,
) -> Finding:
    """Convert a parsed nuclei JSONL record to a Finding ORM object."""
    info: dict = data.get("info", {})
    classification: dict = info.get("classification", {})

    # Extract CVE IDs
    cve_list: list[str] = classification.get("cve-id", []) or []
    if isinstance(cve_list, str):
        cve_list = [cve_list]

    # Extract port from matched-at or host field
    port: int | None = None
    matched_at: str = data.get("matched-at", "") or data.get("url", "") or ""
    raw_port: str = str(data.get("port", ""))
    if raw_port.isdigit():
        port = int(raw_port)
    elif matched_at.startswith("https://"):
        port = 443
    elif matched_at.startswith("http://"):
        port = 80

    # Build evidence string (curl command if available)
    evidence_parts = []
    if data.get("curl-command"):
        evidence_parts.append("# Curl command:\n" + data["curl-command"])
    if data.get("request"):
        evidence_parts.append("# Request:\n" + data["request"][:2000])
    if data.get("response"):
        evidence_parts.append("# Response (truncated):\n" + data["response"][:2000])
    evidence = "\n\n".join(evidence_parts) or None

    return Finding(
        scan_job_id=scan_job_id,
        organization_id=organization_id,
        template_id=data.get("template-id", "unknown"),
        name=info.get("name", data.get("template-id", "Unknown")),
        severity=(info.get("severity") or "unknown").lower(),
        host=data.get("host", ""),
        matched_at=matched_at or None,
        ip=data.get("ip") or None,
        port=port,
        description=info.get("description") or None,
        evidence=evidence,
        cvss_score=classification.get("cvss-score") or None,
        cve_ids=json.dumps(cve_list) if cve_list else None,
        status="open",
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
    )


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

async def run_nuclei_scan(
    db: Session,
    scan_job: ScanJob,
    targets: list[str],
    log: LogCallback,
    severity: str | None = None,
    profile: str | None = None,
    template_set: str | None = None,
    extra_args: list[str] | None = None,
    progress_callback: Callable[[int], None] | None = None,
) -> int:
    """
    Execute nuclei against *targets*, stream output to *log*, persist findings.

    Returns the number of findings saved.
    """
    if not targets:
        log("[nuclei] No targets to scan — aborting.")
        return 0

    from app.config import NUCLEI_PROFILES, DEFAULT_NUCLEI_PROFILE, NUCLEI_TEMPLATE_SETS, DEFAULT_NUCLEI_TEMPLATE_SET
    nuclei_bin = shutil.which(settings.nuclei_binary) or settings.nuclei_binary

    # Resolve speed profile flags
    profile_key   = profile if profile in NUCLEI_PROFILES else DEFAULT_NUCLEI_PROFILE
    profile_meta  = NUCLEI_PROFILES[profile_key]
    profile_flags = profile_meta["flags"]

    # Resolve template set
    tset_key  = template_set if template_set in NUCLEI_TEMPLATE_SETS else DEFAULT_NUCLEI_TEMPLATE_SET
    tset_meta = NUCLEI_TEMPLATE_SETS[tset_key]

    # ── Write targets to a temp file ────────────────────────────────────────
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, prefix="lhsec_targets_"
    ) as tf:
        tf.write("\n".join(targets))
        targets_file = Path(tf.name)

    log(f"[nuclei] Wrote {len(targets)} target(s) to {targets_file}")

    # ── Build command ────────────────────────────────────────────────────────
    cmd = [
        nuclei_bin,
        "-l", str(targets_file),
        "-j",       # JSONL findings on stdout
        "-nc",      # no colour codes
        "-stats",   # progress stats on stderr
    ] + profile_flags

    # Template set: use -profile flag for official profiles,
    # or -tags directly for custom tag-based sets (e.g. network-services)
    if "profile_flag" in tset_meta:
        cmd += ["-profile", tset_meta["profile_flag"]]
    elif "tags" in tset_meta:
        cmd += ["-tags", tset_meta["tags"]]
    if "etags" in tset_meta:  # template-set-level exclusions (rare)
        cmd += ["-etags", tset_meta["etags"]]

    # Optional severity override on top of the profile
    if severity:
        cmd += ["-severity", severity]

    # -mhe (max-host-error): nuclei drops a host after this many per-host network errors.
    # Floor raised to 50: with -bs 50 and many targets, a few drops per host is normal.
    try:
        c_idx = profile_flags.index("-c")
        c_val = int(profile_flags[c_idx + 1])
        cmd += ["-mhe", str(max(c_val, 50))]
    except (ValueError, IndexError):
        cmd += ["-mhe", "50"]

    if extra_args:
        cmd.extend(extra_args)

    log(f"[nuclei] Profile: {profile_key} — {profile_meta['description']}")
    log(f"[nuclei] Template set: {tset_key} — {tset_meta['description']}")  
    log(f"[nuclei] Running: {' '.join(cmd)}")

    findings_count = 0

    try:
        nuclei_timeout = 300  # 5 min max for any nuclei scan
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_IGN),
        )
        _running_procs[scan_job.id] = proc

        async def read_stderr() -> None:
            assert proc.stderr
            last_stats: str = ""
            last_logged_pct: int = -1
            last_heartbeat_reqs: int = -1
            loop = asyncio.get_running_loop()
            last_heartbeat_ts: float = loop.time()
            async for line in proc.stderr:
                decoded = line.decode(errors="replace").rstrip()
                if not decoded:
                    continue
                if decoded.startswith("{") and "percent" in decoded:
                    last_stats = decoded
                    try:
                        s = json.loads(decoded)
                        # All nuclei stat values are JSON strings — cast explicitly
                        pct      = int(s.get("percent", 0) or 0)
                        reqs     = int(s.get("requests", 0) or 0)
                        matched  = int(s.get("matched", 0) or 0)
                        errs     = int(s.get("errors", 0) or 0)
                        duration = s.get("duration", "?")
                        # Broadcast real percent to progress bar
                        if progress_callback:
                            progress_callback(pct)
                        note = f" | {errs} conn errors (WAF/fw)" if errs > 0 else ""
                        # Log every 10% step or when a new finding is matched
                        if pct // 10 > last_logged_pct // 10 or matched > 0:
                            last_logged_pct = pct
                            log(f"[nuclei] {pct:3d}%  {reqs} reqs  {matched} matched  {duration}{note}")
                        # Heartbeat every 30s if requests keep increasing but % hasn't moved
                        now = loop.time()
                        if now - last_heartbeat_ts >= 30 and reqs != last_heartbeat_reqs:
                            last_heartbeat_ts = now
                            last_heartbeat_reqs = reqs
                            log(f"[nuclei] heartbeat: {pct:3d}%  {reqs} reqs  {matched} matched  {duration}{note}")
                        # WAF block detection: abort only on sustained high error rate
                        # (not on low absolute counts — a few dead hosts is normal)
                        if reqs >= WAF_MIN_REQUESTS and errs > 0:
                            rate = errs / reqs
                            if rate >= WAF_ERROR_RATE_THRESHOLD:
                                log(f"[nuclei] ⚠️  WAF/firewall block detected: "
                                    f"{errs}/{reqs} requests failed ({rate:.0%} error rate ≥ {WAF_ERROR_RATE_THRESHOLD:.0%} threshold) — aborting.")
                                proc.kill()
                                raise WAFBlockedError(errs, reqs, rate)
                    except WAFBlockedError:
                        raise
                    except Exception as e:
                        log(f"[nuclei] stats parse error: {e} | raw: {decoded[:120]}")
                elif decoded.startswith("[WRN]") or decoded.startswith("[ERR]") or decoded.startswith("[FTL]"):
                    # Suppress known benign noise
                    _noise = (
                        "runtime error (use -validate",   # template skipped, not a scan issue
                        "could not parse template",        # parse-time failure, template excluded
                        "Setting thread count to 0",       # dynamic extractor limitation, harmless
                        "Scan results upload",             # cloud upload disabled, expected
                    )
                    if not any(n in decoded for n in _noise):
                        log(f"[nuclei] {decoded}")
            # Final summary
            if last_stats:
                try:
                    s = json.loads(last_stats)
                    reqs    = int(s.get("requests", 0) or 0)
                    matched = int(s.get("matched", 0) or 0)
                    errs    = int(s.get("errors", 0) or 0)
                    dur     = s.get("duration", "?")
                    note    = f" | {errs} conn errors (WAF/fw)" if errs > 0 else ""
                    log(f"[nuclei] Finished — {reqs} requests, {matched} matched, {dur}{note}")
                except Exception:
                    pass

        # Read stderr in background
        stderr_task = asyncio.create_task(read_stderr())

        # Read stdout line-by-line, parse JSONL findings
        assert proc.stdout
        async for raw_line in proc.stdout:
            line = raw_line.decode(errors="replace").rstrip()
            if not line:
                continue

            record = parse_nuclei_line(line)
            if record:
                # It's a finding
                severity_val = (record.get("info", {}).get("severity") or "unknown").lower()
                name = record.get("info", {}).get("name", record.get("template-id", "?"))
                host = record.get("host", "?")
                log(f"[nuclei] \u2714 [{severity_val.upper()}] {name} @ {host}")

                finding = nuclei_record_to_finding(record, scan_job.id, scan_job.organization_id)
                db.add(finding)

                findings_count += 1
                scan_job.findings_count = findings_count
                db.commit()
            # (stats lines appear on stderr, not stdout — nothing to do here)

        await stderr_task
        await proc.wait()
        return_code = proc.returncode
        log(f"[nuclei] Process exited with code {return_code}")

    except FileNotFoundError:
        log(
            f"[nuclei] ERROR: '{nuclei_bin}' binary not found. "
            "Please install nuclei: https://nuclei.projectdiscovery.io/"
        )
        raise
    finally:
        targets_file.unlink(missing_ok=True)
        _running_procs.pop(scan_job.id, None)

    return findings_count
