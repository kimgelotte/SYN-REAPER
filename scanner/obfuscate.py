"""
Obfuscation for scans: browser-like User-Agents, realistic headers, and pacing
to reduce blocking and IDS triggers while keeping pen-test quality high.
"""

import os
import random
import time
from typing import Dict

# Set by main.run_scan when --obfuscate is used; read by get_http_headers() at request time.
_obfuscate = False

# Realistic browser User-Agents (Windows/Mac/Linux, Chrome/Firefox/Edge).
# Rotated when obfuscate=True so requests don't all share one fingerprint.
_BROWSER_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
]

SCANNER_USER_AGENT = "SYN-REAPER/1.0"


def set_obfuscate(enabled: bool) -> None:
    """Enable or disable obfuscation for this scan. Call from main.run_scan at start."""
    global _obfuscate
    _obfuscate = enabled


def is_obfuscate() -> bool:
    """Return True if obfuscation is currently enabled (e.g. via --obfuscate or SCAN_OBFUSCATE)."""
    if _obfuscate:
        return True
    val = os.environ.get("SCAN_OBFUSCATE", "").lower().strip()
    return val in ("1", "true", "yes", "on")


def get_user_agent() -> str:
    """Return User-Agent string: browser-like when obfuscate, else scanner identity."""
    if is_obfuscate():
        return random.choice(_BROWSER_USER_AGENTS)
    return SCANNER_USER_AGENT


def get_http_headers(extra: Dict[str, str] | None = None) -> Dict[str, str]:
    """
    Return dict of HTTP headers for requests. When obfuscate is on, uses a random
    browser User-Agent and common browser headers to look like normal traffic.
    Merge with extra (e.g. Authorization) as needed.
    """
    if is_obfuscate():
        headers = {
            "User-Agent": get_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
    else:
        headers = {"User-Agent": SCANNER_USER_AGENT}
    if extra:
        headers.update(extra)
    return headers


def random_delay(base_sec: float = 0.0, jitter_sec: float = 0.0) -> None:
    """Sleep for base_sec + random(0, jitter_sec). Use for pacing between probes/hosts."""
    if base_sec <= 0 and jitter_sec <= 0:
        return
    t = base_sec + (random.uniform(0, jitter_sec) if jitter_sec > 0 else 0)
    if t > 0:
        time.sleep(t)
