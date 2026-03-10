"""
Brute force attempts - For authorized testing only.
Tries common credentials on FTP, SSH, HTTP, MySQL.
Use --bruteforce to enable. Respects --bruteforce-delay.
"""

import base64
import time
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

from scanner.issues import ScanIssue, _normalize_error
from urllib.request import Request, urlopen
from urllib.error import HTTPError

# Default wordlist: (username, password) - common weak credentials
DEFAULT_WORDLIST = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("root", ""),
    ("user", "user"),
    ("user", "password"),
    ("test", "test"),
    ("guest", "guest"),
    ("ftp", "ftp"),
    ("oracle", "oracle"),
    ("mysql", "mysql"),
    ("postgres", "postgres"),
]


@dataclass
class BruteResult:
    """Result of a brute force attempt."""
    host: str
    port: int
    service: str
    username: str
    password: str
    success: bool


def _try_ftp(host: str, port: int, user: str, password: str, timeout: float) -> bool:
    """Try FTP login."""
    try:
        from ftplib import FTP
        ftp = FTP(timeout=timeout)
        ftp.connect(host, port)
        ftp.login(user, password)
        ftp.quit()
        return True
    except Exception:
        return False


def _try_ssh(host: str, port: int, user: str, password: str, timeout: float) -> bool:
    """Try SSH login."""
    try:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, port=port, username=user, password=password, timeout=timeout, allow_agent=False, look_for_keys=False)
        client.close()
        return True
    except ImportError:
        return False
    except Exception:
        return False


def _try_http_basic(host: str, port: int, user: str, password: str, timeout: float, use_https: bool = False) -> bool:
    """Try HTTP/HTTPS Basic Auth. Only success if server returns 401 without auth, 200 with creds."""
    import ssl
    try:
        scheme = "https" if use_https or port in (443, 8443, 4433) else "http"
        url = f"{scheme}://{host}:{port}/" if (port != 80 and not use_https) or (port != 443 and use_https) else f"{scheme}://{host}/"
        ctx = None
        if scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        # First check if auth is required
        req_anon = Request(url, headers={"User-Agent": "SYN-REAPER/1.0"})
        try:
            with urlopen(req_anon, timeout=timeout, context=ctx) as r:
                if r.status == 200:
                    return False  # No auth required - skip
        except HTTPError as e:
            if e.code != 401:
                return False  # Not an auth challenge
        # Server wants auth - try credentials
        creds = base64.b64encode(f"{user}:{password}".encode()).decode()
        req = Request(url, headers={"Authorization": f"Basic {creds}", "User-Agent": "SYN-REAPER/1.0"})
        with urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status == 200
    except HTTPError as e:
        return e.code != 401
    except Exception:
        return False


def _try_mysql(host: str, port: int, user: str, password: str, timeout: float) -> bool:
    """Try MySQL login."""
    try:
        import pymysql
        conn = pymysql.connect(host=host, port=port, user=user, password=password, connect_timeout=int(timeout))
        conn.close()
        return True
    except ImportError:
        return False
    except Exception:
        return False


def _try_postgres(host: str, port: int, user: str, password: str, timeout: float) -> bool:
    """Try PostgreSQL login."""
    try:
        import psycopg2
        conn = psycopg2.connect(host=host, port=port, user=user, password=password, connect_timeout=int(timeout))
        conn.close()
        return True
    except ImportError:
        return False
    except Exception:
        return False


def _try_rdp(host: str, port: int, user: str, password: str, timeout: float) -> bool:
    """Try RDP login. Requires pyrdp or similar; fallback: check if RDP accepts connection."""
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        # RDP sends cookie; we'd need full RDP lib to auth. For now, just verify port is RDP.
        sock.close()
        return False  # No RDP auth library - skip
    except Exception:
        return False


def _try_telnet(host: str, port: int, user: str, password: str, timeout: float) -> bool:
    """Try Telnet login (basic)."""
    try:
        import telnetlib
        tn = telnetlib.Telnet(host, port, timeout=int(timeout))
        tn.read_until(b"login:", timeout=int(timeout))
        tn.write(user.encode() + b"\n")
        tn.read_until(b"password:", timeout=int(timeout))
        tn.write(password.encode() + b"\n")
        result = tn.read_some().decode("utf-8", errors="ignore")
        tn.close()
        return "incorrect" not in result.lower() and "fail" not in result.lower()
    except Exception:
        return False


def _try_http(host: str, port: int, user: str, password: str, timeout: float) -> bool:
    return _try_http_basic(host, port, user, password, timeout, use_https=False)


def _try_https(host: str, port: int, user: str, password: str, timeout: float) -> bool:
    return _try_http_basic(host, port, user, password, timeout, use_https=True)


# Port -> (service, try_func)
BRUTE_HANDLERS = {
    21: ("FTP", _try_ftp),
    22: ("SSH", _try_ssh),
    23: ("Telnet", _try_telnet),
    80: ("HTTP", _try_http),
    443: ("HTTPS", _try_https),
    8080: ("HTTP", _try_http),
    8443: ("HTTPS", _try_https),
    3306: ("MySQL", _try_mysql),
    3389: ("RDP", _try_rdp),
    5432: ("PostgreSQL", _try_postgres),
}


def bruteforce_port(
    host: str,
    port: int,
    wordlist: Optional[List[Tuple[str, str]]] = None,
    timeout: float = 3.0,
    delay: float = 0.5,
    on_attempt: Optional[Callable[[str, int, str, str, str], None]] = None,
) -> Tuple[Optional[BruteResult], Optional[ScanIssue]]:
    """
    Brute force a single port. Returns (result, issue).
    issue is set when bruteforce stops early (e.g., connection reset).
    """
    if port not in BRUTE_HANDLERS:
        return None, None
    service, try_func = BRUTE_HANDLERS[port]
    wordlist = wordlist or DEFAULT_WORDLIST

    for user, password in wordlist:
        try:
            if on_attempt:
                on_attempt(host, port, service, user, password)
            if try_func(host, port, user, password, timeout):
                return BruteResult(host, port, service, user, password, True), None
        except Exception as e:
            return None, ScanIssue(
                phase="bruteforce",
                reason=_normalize_error(e),
                port=port,
                service=service,
                detail=str(e)[:200],
            )
        time.sleep(delay)
    return None, None


def run_bruteforce(
    host: str,
    ports: List[int],
    wordlist_path: Optional[str] = None,
    timeout: float = 3.0,
    delay: float = 0.5,
    on_progress: Optional[Callable[[str, int, str, str, str], None]] = None,
) -> Tuple[List[BruteResult], List[ScanIssue]]:
    """
    Run brute force on all bruteforceable ports.
    Returns (results, issues). issues contains reasons for incomplete/aborted attempts.
    """
    results = []
    issues: List[ScanIssue] = []
    wordlist = None
    if wordlist_path:
        try:
            wordlist = []
            with open(wordlist_path, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if ":" in line and not line.startswith("#"):
                        u, p = line.split(":", 1)
                        wordlist.append((u.strip(), p.strip()))
        except Exception as e:
            issues.append(ScanIssue("bruteforce", f"Failed to load wordlist: {e}", detail=str(e)))

    def _on_attempt(h: str, pt: int, svc: str, u: str, p: str):
        if on_progress:
            on_progress(h, pt, svc, u, p)

    for port in ports:
        if port in BRUTE_HANDLERS:
            r, issue = bruteforce_port(host, port, wordlist, timeout, delay, _on_attempt)
            if r:
                results.append(r)
            elif issue:
                issues.append(issue)
    return results, issues
