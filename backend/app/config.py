from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path
from typing import Any


# ── Nuclei speed profiles (control rate / concurrency / timeout) ───────────────
#
# Scan strategy reference (docs.projectdiscovery.io/opensource/nuclei/mass-scanning-cli):
#   template-spray (default): runs each template across ALL targets before moving to next
#                             template — stealthier, spreads load, slightly more memory
#   host-spray:               runs ALL templates on one target before moving to next —
#                             more focused, lower memory, better for mass scanning
#
# -mhe (max-host-error): nuclei drops a host after this many per-host network errors
#   default = 30.  We keep the default; do NOT lower it — a few errors from a slow
#   host should not abort the whole host scan.
#
NUCLEI_PROFILES: dict[str, dict[str, Any]] = {
    "stealth": {
        "label": "Stealth",
        "description": "Ultra-low & slow — WAF/Fortinet evasion, template-spray, Safari UA",
        "flags": [
            # Rate / concurrency
            # -rl 1 + -bs 50: each target sees ~1 request per 50 seconds (true spray stealth).
            # -bs 1 would hit the same host 1 req/s which is NOT stealthy.
            "-rl",  "1",
            "-rld", "1s",
            "-c",   "1",
            "-bs",  "50",      # spread across 50 targets — each target: 1 req / 50s
            "-timeout", "6",  # 15s was too high — 104 errors × 15s ≈ 26min wasted waiting
            "-retries", "0",
            # template-spray: distributes each template across -bs targets before moving on
            "-ss", "template-spray",
            # OOB probes off
            "-ni",
            # TLS fingerprint randomisation (JA3)
            "-tlsi",
            # WAF-evasion headers — Safari on macOS
            "-H", "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            "-H", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "-H", "Accept-Language: en-US,en;q=0.5",
            "-H", "Accept-Encoding: gzip, deflate",
            "-H", "Connection: keep-alive",
            # Exclude only the noisiest attack-like templates
            "-etags", "fuzzing,xss,sqli,rce,dos",
        ],
    },
    "balanced": {
        "label": "Balanced",
        "description": "Good coverage, reasonable speed — template-spray (recommended)",
        "flags": [
            "-rl", "20", "-c", "10", "-bs", "20", "-timeout", "10", "-retries", "1",
            "-ss", "template-spray",
            "-ni",
            "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36",
        ],
    },
    "fast": {
        "label": "Fast",
        "description": "High concurrency, host-spray — internal/trusted networks, mass scanning",
        "flags": [
            "-rl", "50", "-c", "25", "-bs", "50", "-timeout", "5", "-retries", "0",
            # host-spray: run all templates per host before moving to next —
            # lower memory usage, recommended for mass scanning (100+ targets)
            "-ss", "host-spray",
            "-ni",
            "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36",
        ],
    },
}
DEFAULT_NUCLEI_PROFILE = "balanced"


# ── Nuclei template sets (control WHAT is tested) ──────────────────────────
# These map directly to the official projectdiscovery community profile files.
# All are detection-only; none execute payloads or modify server state.
NUCLEI_TEMPLATE_SETS: dict[str, dict[str, Any]] = {
    "recommended": {
        "label": "Recommended",
        "description": "Curated by ProjectDiscovery: CVEs, misconfigs, SSL, DNS, TCP, JS — best starting point",
        "profile_flag": "recommended",
    },
    "pentest": {
        "label": "Pentest",
        "description": "Full pentest scope: HTTP, TCP, JavaScript (SSH/FTP/DB), DNS, SSL — excludes DoS/fuzz/OSINT",
        "profile_flag": "pentest",
    },
    "network-services": {
        "label": "Network Services",
        "description": "Non-HTTP services: SSH, FTP, SMTP, MySQL, Redis, MongoDB, PostgreSQL, MSSQL — JavaScript templates",
        # No -profile flag; use -tags to target service-specific JavaScript templates directly
        "tags": "ssh,ftp,smtp,mysql,redis,mongodb,postgresql,mssql,rdp,vnc,ldap,snmp,network,default-login,js",
    },
    "cves": {
        "label": "CVEs",
        "description": "Known CVEs only (http + network + javascript)",
        "profile_flag": "cves",
    },
    "kev": {
        "label": "CISA KEV",
        "description": "CISA Known Exploited Vulnerabilities — highest-priority subset",
        "profile_flag": "kev",
    },
    "misconfigurations": {
        "label": "Misconfigs",
        "description": "Misconfigured services, exposed panels, insecure defaults",
        "profile_flag": "misconfigurations",
    },
    "default-login": {
        "label": "Default Logins",
        "description": "Default / weak credentials on common services (HTTP + SSH + FTP + DB)",
        "profile_flag": "default-login",
    },
}
DEFAULT_NUCLEI_TEMPLATE_SET = "recommended"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Database
    database_url: str = "sqlite:///./data/lhsec.db"

    # CT log sources
    certspotter_api_key: str = ""

    # Nuclei
    nuclei_binary: str = "nuclei"
    nuclei_default_severity: str = "critical,high"
    nuclei_results_dir: str = "../data/nuclei_results"

    # httpx (projectdiscovery) — for pre-scan target filtering
    httpx_binary: str = str(Path.home() / "go" / "bin" / "httpx")

    # Nmap
    nmap_binary: str = "nmap"
    nmap_ports: str = (
        "21,22,23,25,53,80,110,135,139,143,389,443,445,465,587,636,993,995,"
        "1433,1521,2222,3000,3306,3389,4443,4848,5432,5900,6379,7001,7443,"
        "8000,8001,8008,8080,8081,8082,8083,8443,8444,8888,"
        "9000,9090,9200,9443,10000,27017,28017"
    )
    # Stealth profile settings
    nmap_stealth_top_ports: int = 200
    nmap_stealth_version_intensity: int = 3

    # App
    app_debug: bool = True

    @property
    def nuclei_results_path(self) -> Path:
        p = Path(self.nuclei_results_dir)
        p.mkdir(parents=True, exist_ok=True)
        return p


settings = Settings()
