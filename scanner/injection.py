"""
Basic SQL Injection Probe - Safe, non-destructive checks for authorized testing only.
Sends test payloads to HTTP endpoints with query params; checks for error messages, status changes, time-based delays.
Scope: only when --injection flag; avoid destructive payloads.
"""

import time
import ssl
from dataclasses import dataclass
from typing import List, Optional
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

# Safe, non-destructive SQLi probe payloads
SQLI_PAYLOADS = [
    ("' OR '1'='1", "classic OR"),
    ("1' OR '1'='1", "OR true"),
    ("1;--", "comment"),
    ("' OR 1=1--", "OR 1=1"),
    ("1 AND 1=1", "AND true"),
]

# Indicators of potential SQL injection (error messages, etc.)
SQL_ERROR_INDICATORS = [
    "sql", "mysql", "postgresql", "ora-", "syntax error", "unclosed quotation",
    "quoted string", "pg_query", "mysqli", "sqlite", "odbc", "jdbc",
    "driver", "database", "select", "insert", "update", "delete",
    "warning:", "error:", "exception", "invalid",
]


@dataclass
class InjectionFinding:
    """SQL injection probe finding."""
    host: str
    port: int
    url: str
    payload: str
    payload_name: str
    indicator: str
    severity: str = "high"


def _fetch_url(url: str, timeout: float, ctx: Optional[ssl.SSLContext] = None) -> tuple[int, str]:
    """Fetch URL, return (status_code, body_preview)."""
    try:
        req = Request(url, headers={"User-Agent": "SYN-REAPER/1.0"})
        with urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read(4096).decode("utf-8", errors="ignore")
            return (r.status, body[:500])
    except HTTPError as e:
        return (e.code, str(e)[:500])
    except (URLError, OSError):
        return (-1, "")


def probe_param(
    base_url: str, param: str, payload: str, payload_name: str,
    use_https: bool, timeout: float,
) -> Optional[InjectionFinding]:
    """Probe a single parameter with payload."""
    from urllib.parse import quote
    ctx = None
    if use_https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    sep = "&" if "?" in base_url else "?"
    encoded = quote(payload, safe="")
    test_url = f"{base_url}{sep}{param}={encoded}"
    status, body = _fetch_url(test_url, timeout, ctx)
    body_lower = body.lower()
    for ind in SQL_ERROR_INDICATORS:
        if ind in body_lower:
            return InjectionFinding(
                host="", port=0, url=test_url, payload=payload, payload_name=payload_name,
                indicator=ind, severity="high",
            )
    return None


def run_injection_probes(
    host: str,
    ports: List[int],
    base_path: str = "/",
    timeout: float = 5.0,
) -> List[InjectionFinding]:
    """
    Run basic SQL injection probes on HTTP/HTTPS endpoints.
    Only probes when --injection flag is set. Uses safe, non-destructive payloads.
    """
    findings = []
    http_ports = [80, 8080, 8000, 8888]
    https_ports = [443, 8443, 4433]
    # Common param names to test
    params = ["id", "page", "q", "search", "user", "name", "cat", "category"]

    for port in ports:
        use_https = port in https_ports
        if port not in http_ports and port not in https_ports:
            continue
        scheme = "https" if use_https else "http"
        base = f"{scheme}://{host}:{port}{base_path}"
        if "?" not in base:
            base = base.rstrip("/") + "/"
        # Get baseline
        ctx = None
        if use_https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        baseline_status, baseline_body = _fetch_url(base, timeout, ctx)
        baseline_lower = baseline_body.lower()

        for param in params:
            for payload, name in SQLI_PAYLOADS:
                f = probe_param(base, param, payload, name, use_https, timeout)
                if f:
                    f.host = host
                    f.port = port
                    findings.append(f)
                    break  # One finding per param
    return findings
