"""
Domain discovery services.

Two separate operations:

  run_ip_discovery(ips, log)
      Runs TLS cert extraction, HTTP redirect harvesting, reverse DNS, and amass.
      Returns root domains found directly from IP addresses.
      Source tag: 'tls_cert' | 'http_redirect' | 'reverse_dns' | 'amass'

  run_ct_for_domain(domain, log, certspotter_api_key)
      Queries crt.sh and SSLMate Certspotter for a specific root domain.
      Returns subdomains found in Certificate Transparency logs.
      Source tag: 'crt_sh' | 'certspotter'
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import shutil
import socket
import ssl
import urllib.parse
from typing import Callable

import httpx

LogCallback = Callable[[str], None]
_WILDCARD_RE = re.compile(r"^\*\.")
_DOMAIN_RE   = re.compile(r"^[a-z0-9][a-z0-9\-\.]*\.[a-z]{2,}$")

# Source categories — used in UI for colour coding
IP_SOURCES = {"amass", "reverse_dns", "tls_cert", "http_redirect", "manual"}  # from IP
CT_SOURCES = {"crt_sh", "certspotter"}                               # via CT logs

# Default HTTPS/HTTP ports to probe per IP
_TLS_PROBE_PORTS  = [443, 8443, 4443, 7443, 9443]
_HTTP_PROBE_PORTS = [80, 8080, 8000, 8888]


# ---------------------------------------------------------------------------
# Reverse DNS
# ---------------------------------------------------------------------------

async def _reverse_dns(ip: str, log: LogCallback) -> str | None:
    loop = asyncio.get_event_loop()
    try:
        hostname, _, _ = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
        log(f"[rdns] {ip} -> {hostname}")
        return hostname.lower()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# TLS certificate extraction
# ---------------------------------------------------------------------------

def _extract_tls_domains(ip: str, port: int, timeout: float = 5.0) -> list[str]:
    """Connect TLS to ip:port; return all domain names from the certificate (CN + SANs)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    found: list[str] = []
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                # SANs are authoritative
                for san_type, san_value in cert.get("subjectAltName", []):
                    if san_type == "DNS":
                        name = san_value.strip().lower().lstrip("*.")
                        if _DOMAIN_RE.match(name):
                            found.append(name)
                # Fallback to CN if no SANs
                if not found:
                    for field in cert.get("subject", []):
                        if field[0][0] == "commonName":
                            name = field[0][1].strip().lower().lstrip("*.")
                            if _DOMAIN_RE.match(name):
                                found.append(name)
    except Exception:
        pass
    return list(set(found))


async def _tls_domains_for_ip(
    ip: str, ports: list[int], log: LogCallback
) -> list[tuple[str, str]]:
    """Run TLS cert extraction on each port; return (fqdn, 'tls_cert') pairs."""
    results: list[tuple[str, str]] = []
    loop = asyncio.get_event_loop()
    for port in ports:
        domains = await loop.run_in_executor(
            None, _extract_tls_domains, ip, port, 5.0
        )
        for d in domains:
            log(f"[tls] {ip}:{port} -> {d}")
            results.append((d, "tls_cert"))
    return results


# ---------------------------------------------------------------------------
# HTTP redirect harvesting
# ---------------------------------------------------------------------------

async def _http_redirects_for_ip(
    ip: str, ports: list[int], log: LogCallback
) -> list[tuple[str, str]]:
    """
    Connect HTTP/HTTPS to each port; follow redirects and collect hostnames
    that appear in the Location chain.  Ignores bare IPs.
    """
    results: list[tuple[str, str]] = []
    async with httpx.AsyncClient(
        follow_redirects=True, timeout=5.0, verify=False
    ) as client:
        for scheme, default_port in (("http", 80), ("https", 443)):
            for port in ports:
                url = (
                    f"{scheme}://{ip}"
                    + (f":{port}" if port != default_port else "")
                )
                try:
                    resp = await client.get(url)
                    for r in list(resp.history) + [resp]:
                        host = urllib.parse.urlparse(str(r.url)).hostname or ""
                        try:
                            ipaddress.ip_address(host)
                            continue  # still an IP — skip
                        except ValueError:
                            pass
                        if host and _DOMAIN_RE.match(host):
                            log(f"[http] {ip}:{port} -> {host}")
                            results.append((host, "http_redirect"))
                except Exception:
                    pass

    # deduplicate preserving first-seen source
    seen: set[str] = set()
    unique: list[tuple[str, str]] = []
    for fqdn, src in results:
        if fqdn not in seen:
            seen.add(fqdn)
            unique.append((fqdn, src))
    return unique


# ---------------------------------------------------------------------------
# Amass  (best-effort; often produces nothing for IPs without WHOIS/PTR)
# ---------------------------------------------------------------------------

async def _run_amass(
    individual_ips: list[str],
    cidrs: list[str],
    log: LogCallback,
    timeout: int = 60,
) -> set[str]:
    amass_bin = shutil.which("amass")
    if not amass_bin:
        import os
        candidate = os.path.expanduser("~/go/bin/amass")
        if os.path.isfile(candidate):
            amass_bin = candidate
    if not amass_bin:
        log("[amass] Binary not found — skipping")
        return set()

    cmd = [amass_bin, "intel", "-active"]
    if individual_ips:
        cmd += ["-addr", ",".join(individual_ips)]
    if cidrs:
        cmd += ["-cidr", ",".join(cidrs)]
    if not individual_ips and not cidrs:
        return set()

    log(f"[amass] Running: {' '.join(cmd)}")
    domains: set[str] = set()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )

        async def _read() -> None:
            assert proc.stdout
            async for raw in proc.stdout:
                line = raw.decode().strip()
                if line and "." in line:
                    domains.add(line.lower())
                    log(f"[amass] found: {line}")

        try:
            await asyncio.wait_for(_read(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            log(f"[amass] Timed out after {timeout}s — {len(domains)} partial result(s)")
        finally:
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                proc.kill()
    except Exception as exc:
        log(f"[amass] Error: {exc}")

    log(f"[amass] Discovered {len(domains)} root domain(s)")
    return domains


# ---------------------------------------------------------------------------
# crt.sh
# ---------------------------------------------------------------------------

CRT_SH_URL = "https://crt.sh/"


async def _query_crtsh(
    client: httpx.AsyncClient, domain: str, log: LogCallback
) -> set[str]:
    domains: set[str] = set()
    for attempt in range(3):
        try:
            label = f"(attempt {attempt+1}/3)" if attempt > 0 else ""
            log(f"[crt.sh] Querying: {domain} {label}".strip())
            resp = await client.get(
                CRT_SH_URL,
                params={"q": f"%.{domain}", "output": "json"},
                timeout=30,
            )
            if resp.status_code == 502:
                await asyncio.sleep(2 * (attempt + 1))
                continue
            if resp.status_code == 404:
                break
            resp.raise_for_status()
            for cert in resp.json():
                for name in cert.get("name_value", "").splitlines():
                    name = name.strip().lower()
                    if _WILDCARD_RE.match(name):
                        name = name[2:]
                    if name and "." in name and (
                        name.endswith(f".{domain}") or name == domain
                    ):
                        domains.add(name)
            log(f"[crt.sh] {len(domains)} subdomain(s) for {domain}")
            break
        except Exception as exc:
            log(f"[crt.sh] Error for {domain}: {exc}")
            break
    return domains


# ---------------------------------------------------------------------------
# SSLMate Certspotter
# ---------------------------------------------------------------------------

CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"


async def _query_certspotter(
    client: httpx.AsyncClient, domain: str, api_key: str, log: LogCallback
) -> set[str]:
    domains: set[str] = set()
    after: str | None = None
    try:
        log(f"[certspotter] Querying: {domain}")
        while True:
            params: dict = {
                "domain": domain,
                "include_subdomains": "true",
                "expand": "dns_names",
            }
            if after:
                params["after"] = after
            resp = await client.get(
                CERTSPOTTER_URL,
                params=params,
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=30,
            )
            resp.raise_for_status()
            issuances = resp.json()
            if not issuances:
                break
            for issuance in issuances:
                for name in issuance.get("dns_names", []):
                    name = name.strip().lower()
                    if _WILDCARD_RE.match(name):
                        name = name[2:]
                    if name and "." in name:
                        domains.add(name)
            after = str(issuances[-1]["id"])
            if len(issuances) < 100:
                break
        log(f"[certspotter] {len(domains)} domain(s) for {domain}")
    except Exception as exc:
        log(f"[certspotter] Error for {domain}: {exc}")
    return domains


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

async def run_ip_discovery(
    ips: list[str],
    log: LogCallback,
    amass_timeout: int = 60,
) -> list[dict]:
    """
    Discover root domains from IP addresses using multiple methods in parallel:
      1. TLS certificate extraction (CN + SANs from port 443, 8443, …)
      2. HTTP redirect harvesting (follow redirects on port 80, 443, 8080, …)
      3. Reverse DNS (PTR records)
      4. Amass intel (best-effort, often produces nothing for IPs without WHOIS)

    Returns dicts: {fqdn, source, resolved_ip}
    """
    found: dict[str, dict] = {}
    individual_ips = [ip for ip in ips if "/" not in ip]
    cidrs          = [ip for ip in ips if "/" in ip]
    log(f"[discovery] {len(individual_ips)} IP(s), {len(cidrs)} CIDR(s)")

    # --- 1 + 2 + 3: run TLS probing, HTTP redirects, rDNS, and amass concurrently ---
    log(f"[discovery] Probing TLS certificates, HTTP redirects, reverse DNS, and amass…")

    tls_tasks  = [_tls_domains_for_ip(ip, _TLS_PROBE_PORTS, log) for ip in individual_ips]
    http_tasks = [_http_redirects_for_ip(ip, _HTTP_PROBE_PORTS, log) for ip in individual_ips]
    rdns_tasks = [_reverse_dns(ip, log) for ip in individual_ips]

    # Fast methods first: TLS, HTTP, rDNS run concurrently and return quickly
    tls_results, http_results, rdns_results = await asyncio.gather(
        asyncio.gather(*tls_tasks,  return_exceptions=True),
        asyncio.gather(*http_tasks, return_exceptions=True),
        asyncio.gather(*rdns_tasks, return_exceptions=True),
    )

    for ip, res in zip(individual_ips, tls_results):
        if isinstance(res, Exception):
            continue
        for fqdn, source in res:
            if fqdn not in found:
                found[fqdn] = {"fqdn": fqdn, "source": source, "resolved_ip": ip}

    for ip, res in zip(individual_ips, http_results):
        if isinstance(res, Exception):
            continue
        for fqdn, source in res:
            if fqdn not in found:
                found[fqdn] = {"fqdn": fqdn, "source": source, "resolved_ip": ip}

    for ip, hostname in zip(individual_ips, rdns_results):
        if isinstance(hostname, str) and hostname and hostname not in found:
            found[hostname] = {"fqdn": hostname, "source": "reverse_dns", "resolved_ip": ip}

    log(f"[discovery] TLS/HTTP/rDNS found {len(found)} domain(s) — now running amass (up to {amass_timeout}s)…")

    # Amass: best-effort, reduced timeout, runs last
    amass_domains = await _run_amass(individual_ips, cidrs, log, timeout=amass_timeout)
    for domain in amass_domains:
        if domain not in found:
            found[domain] = {"fqdn": domain, "source": "amass", "resolved_ip": None}

    log(f"[discovery] Found {len(found)} root domain(s) total from IPs")
    return list(found.values())


async def run_ct_for_domain(
    domain: str,
    log: LogCallback,
    certspotter_api_key: str = "",
    resolve_ips: bool = False,
) -> list[dict]:
    """
    Query CT logs (crt.sh + Certspotter) for a specific root domain.
    Returns subdomains: {fqdn, source='crt_sh'|'certspotter', resolved_ip}
    When *resolve_ips* is True, resolves each subdomain to its IP (for external detection).
    """
    found: dict[str, dict] = {}
    async with httpx.AsyncClient(follow_redirects=True) as client:
        tasks = [_query_crtsh(client, domain, log)]
        if certspotter_api_key:
            tasks.append(_query_certspotter(client, domain, certspotter_api_key, log))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                log(f"[ct] Error (source {i}) for {domain}: {result}")
                continue
            source = "crt_sh" if i == 0 else "certspotter"
            for fqdn in result:
                if fqdn not in found:
                    found[fqdn] = {"fqdn": fqdn, "source": source, "resolved_ip": None}

    # Resolve IPs for external detection
    if resolve_ips:
        import socket
        loop = asyncio.get_event_loop()
        resolved_count = 0
        for fqdn in found:
            try:
                ip = await loop.run_in_executor(None, socket.gethostbyname, fqdn)
                found[fqdn]["resolved_ip"] = ip
                resolved_count += 1
            except Exception:
                pass
        if resolved_count:
            log(f"[ct] Resolved {resolved_count}/{len(found)} subdomain(s) for {domain}")

    log(f"[ct] Found {len(found)} subdomain(s) for {domain}")
    return list(found.values())


# Backward-compat alias
async def run_ct_lookup(
    ips: list[str],
    log: LogCallback,
    certspotter_api_key: str = "",
    amass_timeout: int = 120,
) -> list[dict]:
    return await run_ip_discovery(ips, log, amass_timeout=amass_timeout)
