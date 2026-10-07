from __future__ import annotations

from pathlib import Path
from .models import ScanProfile

APP_NAME = "ReconForge"
APP_VERSION = "4.1.1"
DEFAULT_TIMEOUT = 3600
NSE_PROFILES = {
    "basic": "default,discovery,safe",
    "deep": "default,discovery,safe,vuln",
    # Broad local NSE coverage while excluding categories designed for brute-force,
    # DoS, exploit delivery, and intrusive behavior.
    "advanced": "not (brute or dos or exploit or intrusive)",
}
MAX_TAIL = 6000
MAX_PARALLEL = 16
MAX_ADAPTIVE_ACTIONS = 12
TESTSSL_REPO_URL = "https://github.com/testssl/testssl.sh.git"

WEB_PORTS = {
    "80","81","88","443","444","591","593","8000","8008","8080","8081","8088","8443","8888","9000","9080","9443"
}
WEB_SERVICE_TOKENS = {"http", "https", "http-proxy", "ssl/http"}
API_PATH_RE = r"/(api|api/v[0-9]+|swagger|openapi)(/|$)"
SENSITIVE_PATH_RE = r"/(admin|login|auth|api|graphql|swagger|openapi)(/|$)"

DEFAULT_WORDLISTS = {
    "basic": ("common.txt", "raft-small-directories.txt"),
    "deep": ("directory-list-2.3-medium.txt", "raft-medium-directories.txt"),
    "advanced": ("directory-list-2.3-big.txt", "raft-large-directories.txt"),
}

PROFILES = {
    "basic": ScanProfile(
        mode="basic",
        nmap_args=("-Pn", "-T4", "--top-ports", "100"),
        stages=("recon", "web", "adaptive", "validate", "report"),
        fuzzer_preference="ffuf", fuzzer_depth=1, fuzzer_threads=20, fuzzer_rate=50,
        nuclei_rate=50, nuclei_concurrency=25, nikto_tuning="123b", adaptive_budget=4,
        sqlmap_level=1, sqlmap_risk=1, sqlmap_crawl=0,
    ),
    "deep": ScanProfile(
        mode="deep",
        nmap_args=("-Pn", "-T4", "-sV", "-p-"),
        stages=("recon", "web", "adaptive", "validate", "report"),
        fuzzer_preference="feroxbuster", fuzzer_depth=3, fuzzer_threads=40, fuzzer_rate=100,
        nuclei_rate=100, nuclei_concurrency=25, wapiti_level=2, adaptive_budget=7,
        sqlmap_level=1, sqlmap_risk=1, sqlmap_crawl=1,
    ),
    "advanced": ScanProfile(
        mode="advanced",
        nmap_args=("-Pn", "-T4", "-A", "-p-"),
        stages=("recon", "web", "adaptive", "validate", "report"),
        fuzzer_preference="feroxbuster", fuzzer_depth=4, fuzzer_threads=60, fuzzer_rate=150,
        nuclei_rate=150, nuclei_concurrency=30, nikto_tuning="123bde", wapiti_level=2,
        nuclei_dast=False, adaptive_budget=10, sqlmap_level=2, sqlmap_risk=1, sqlmap_crawl=2,
    ),
}

def default_wordlist_candidates(mode: str) -> list[Path]:
    roots = [Path("/usr/share/seclists/Discovery/Web-Content"), Path("/usr/share/SecLists/Discovery/Web-Content")]
    names = DEFAULT_WORDLISTS.get(mode, DEFAULT_WORDLISTS["advanced"])
    return [root / filename for root in roots for filename in names]
