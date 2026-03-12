"""
HTTP Security Headers - OWASP-aligned checks for X-Frame-Options, CSP, HSTS, etc.
"""

import ssl
from dataclasses import dataclass
from typing import List
from urllib.request import Request, urlopen

from scanner.obfuscate import get_http_headers


@dataclass
class HeaderFinding:
    """HTTP security header finding."""
    header: str
    present: bool
    value: str
    severity: str
    message: str
    remediation: str


def check_http_headers(host: str, port: int, use_https: bool = False, timeout: float = 5.0) -> List[HeaderFinding]:
    """Fetch HTTP headers and check for security best practices."""
    findings = []
    scheme = "https" if use_https or port in (443, 8443, 4433) else "http"
    url = f"{scheme}://{host}:{port}/" if (port != 80 and scheme == "http") or (port != 443 and scheme == "https") else f"{scheme}://{host}/"
    ctx = None
    if scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    try:
        req = Request(url, headers=get_http_headers())
        with urlopen(req, timeout=timeout, context=ctx) as r:
            headers = {k.lower(): v for k, v in r.headers.items()}
    except Exception:
        return [HeaderFinding("Connection", False, "", "info", "Could not fetch headers", "")]

    checks = [
        ("x-frame-options", "high", "Prevents clickjacking", "Add X-Frame-Options: DENY or SAMEORIGIN"),
        ("x-content-type-options", "medium", "Prevents MIME sniffing", "Add X-Content-Type-Options: nosniff"),
        ("content-security-policy", "medium", "Mitigates XSS", "Add Content-Security-Policy header"),
        ("strict-transport-security", "high", "Enforces HTTPS", "Add Strict-Transport-Security: max-age=31536000"),
        ("x-xss-protection", "low", "Legacy XSS filter", "Add X-XSS-Protection: 1; mode=block (or rely on CSP)"),
    ]

    for header, sev, desc, rem in checks:
        val = headers.get(header, "")
        present = bool(val)
        msg = f"{desc}: {val[:80]}" if present else f"Missing - {desc}"
        if header == "strict-transport-security" and present:
            if "max-age=0" in val.lower():
                msg = "HSTS max-age=0 - effectively disabled"
                sev = "high"
            elif "max-age" not in val.lower():
                msg = "HSTS present but no max-age"
        findings.append(HeaderFinding(header, present, val, sev, msg, rem if not present else ""))

    return findings


def run_web_header_checks(host: str, ports: List[int], timeout: float = 5.0) -> List[HeaderFinding]:
    """Run header checks on HTTP/HTTPS ports."""
    results = []
    http_ports = [80, 8080, 8000, 8888]
    https_ports = [443, 8443, 4433]
    for port in ports:
        if port in http_ports:
            results.extend(check_http_headers(host, port, use_https=False, timeout=timeout))
        elif port in https_ports:
            results.extend(check_http_headers(host, port, use_https=True, timeout=timeout))
    return results
