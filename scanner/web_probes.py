"""
Web application penetration probes - Safe, non-destructive checks for authorized testing only.
Reflected XSS and path traversal detection. No payload execution; only response analysis.
"""

import ssl
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import quote
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from scanner.obfuscate import get_http_headers


@dataclass
class WebProbeFinding:
    """Result of a web probe (XSS or path traversal)."""
    host: str
    port: int
    check: str  # "reflected_xss" | "path_traversal"
    vulnerable: bool
    details: str
    severity: str = "medium"


# Safe non-executing XSS probe payloads (reflection check only; no script execution)
XSS_PROBE_PAYLOADS = [
    ("<script>alert(1)</script>", "script_tag"),
    ("<img src=x onerror=alert(1)>", "img_onerror"),
    ("\" onfocus=alert(1) autofocus=\"", "event_handler"),
    ("{{constructor.constructor('alert(1)')()}}", "template_literal"),
]

# Path traversal payloads (safe; look for indicators in response)
PATH_TRAVERSAL_PAYLOADS = [
    ("....//....//....//etc/passwd", "root:", "unix_passwd"),
    ("..%2f..%2f..%2fetc%2fpasswd", "root:", "unix_encoded"),
    ("..%252f..%252f..%252fetc%252fpasswd", "root:", "double_encoded"),
    ("....\\\\....\\\\....\\\\windows\\\\win.ini", "[fonts]", "windows_ini"),
]


def _fetch_url(url: str, timeout: float, ctx: Optional[ssl.SSLContext] = None) -> tuple[int, str]:
    """Fetch URL; return (status_code, body_preview)."""
    try:
        req = Request(url, headers=get_http_headers())
        with urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read(8192).decode("utf-8", errors="ignore")
            return (r.status, body)
    except HTTPError as e:
        return (e.code, (e.read(4096).decode("utf-8", errors="ignore") if e.fp else ""))
    except (URLError, OSError):
        return (-1, "")


def run_reflected_xss_probes(
    host: str,
    ports: List[int],
    base_path: str = "/",
    param: str = "q",
    timeout: float = 5.0,
) -> List[WebProbeFinding]:
    """
    Check if user input is reflected in the response without encoding (potential XSS).
    Uses safe payloads that do not execute; only checks for reflection.
    """
    findings: List[WebProbeFinding] = []
    http_ports = [80, 8080, 8000, 8888]
    https_ports = [443, 8443, 4433]

    for port in ports:
        use_https = port in https_ports
        if port not in http_ports and port not in https_ports:
            continue
        scheme = "https" if use_https else "http"
        base = f"{scheme}://{host}:{port}{base_path}".rstrip("/") + "/"
        sep = "&" if "?" in base else "?"
        url_with_param = f"{base}{sep}{param}=test"
        ctx = None
        if use_https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        for payload, name in XSS_PROBE_PAYLOADS:
            encoded = quote(payload, safe="")
            test_url = f"{base}{sep}{param}={encoded}"
            status, body = _fetch_url(test_url, timeout, ctx)
            if status != 200:
                continue
            # Check if payload appears in response (reflected without encoding)
            if payload in body or payload.replace(" ", "") in body.replace(" ", ""):
                findings.append(WebProbeFinding(
                    host=host,
                    port=port,
                    check="reflected_xss",
                    vulnerable=True,
                    details=f"Payload '{name}' reflected in response - possible XSS",
                    severity="high",
                ))
                break  # One finding per port

    return findings


def run_path_traversal_probes(
    host: str,
    ports: List[int],
    base_path: str = "/",
    param: str = "file",
    timeout: float = 5.0,
) -> List[WebProbeFinding]:
    """
    Check for path traversal (LFI) by requesting common payloads and looking for file content indicators.
    Safe: only inspects response for known strings (e.g. root:, [fonts]).
    """
    findings: List[WebProbeFinding] = []
    http_ports = [80, 8080, 8000, 8888]
    https_ports = [443, 8443, 4433]
    params_to_try = ["file", "path", "doc", "document", "page", "include", "path", "template"]

    for port in ports:
        use_https = port in https_ports
        if port not in http_ports and port not in https_ports:
            continue
        scheme = "https" if use_https else "http"
        base = f"{scheme}://{host}:{port}{base_path}".rstrip("/") + "/"
        sep = "&" if "?" in base else "?"
        ctx = None
        if use_https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        found_for_port = False
        for param_name in params_to_try:
            if found_for_port:
                break
            for payload, indicator, payload_name in PATH_TRAVERSAL_PAYLOADS:
                encoded = quote(payload, safe="")
                test_url = f"{base}{sep}{param_name}={encoded}"
                status, body = _fetch_url(test_url, timeout, ctx)
                if indicator.lower() in body.lower():
                    findings.append(WebProbeFinding(
                        host=host,
                        port=port,
                        check="path_traversal",
                        vulnerable=True,
                        details=f"Indicator '{indicator}' in response (payload: {payload_name}) - possible LFI",
                        severity="high",
                    ))
                    found_for_port = True
                    break

    return findings


def run_web_advanced_probes(
    host: str,
    ports: List[int],
    xss: bool = True,
    path_traversal: bool = True,
    timeout: float = 5.0,
) -> List[WebProbeFinding]:
    """Run XSS and/or path traversal probes when --web-advanced is set."""
    results: List[WebProbeFinding] = []
    if xss:
        results.extend(run_reflected_xss_probes(host, ports, timeout=timeout))
    if path_traversal:
        results.extend(run_path_traversal_probes(host, ports, timeout=timeout))
    return results
