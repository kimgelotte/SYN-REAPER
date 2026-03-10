"""
SSL/TLS Security Checks - Protocol, cipher, and certificate validation.
"""

import ssl
import socket
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


@dataclass
class SSLFinding:
    """SSL/TLS finding."""
    host: str
    port: int
    check: str
    severity: str  # critical, high, medium, low, info
    message: str
    remediation: Optional[str] = None


def check_ssl_protocols(host: str, port: int, timeout: float = 5.0) -> List[SSLFinding]:
    """Check which SSL/TLS protocols are supported."""
    findings = []
    # Use PROTOCOL_TLS_CLIENT (or PROTOCOL_TLS) + min/max version; TLSVersion enum
    # cannot be passed directly to SSLContext() in Python 3.10+
    base_proto = getattr(ssl, "PROTOCOL_TLS_CLIENT", None) or getattr(ssl, "PROTOCOL_TLS", ssl.PROTOCOL_TLSv1_2)
    protocols = []
    if hasattr(ssl, "TLSVersion"):
        protocols = [(ssl.TLSVersion.TLSv1_2, "TLS 1.2", "info")]
        if hasattr(ssl.TLSVersion, "TLSv1_3"):
            protocols.insert(0, (ssl.TLSVersion.TLSv1_3, "TLS 1.3", "info"))
        if hasattr(ssl.TLSVersion, "TLSv1_1"):
            protocols.append((ssl.TLSVersion.TLSv1_1, "TLS 1.1", "medium"))
        if hasattr(ssl.TLSVersion, "TLSv1"):
            protocols.append((ssl.TLSVersion.TLSv1, "TLS 1.0", "high"))
    else:
        protocols = [
            (ssl.PROTOCOL_TLSv1_2, "TLS 1.2", "info"),
            (ssl.PROTOCOL_TLSv1_1, "TLS 1.1", "medium"),
            (ssl.PROTOCOL_TLSv1, "TLS 1.0", "high"),
        ]
    for ver, name, sev in protocols:
        try:
            if hasattr(ssl, "TLSVersion") and isinstance(ver, ssl.TLSVersion):
                ctx = ssl.SSLContext(base_proto)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = ver
                ctx.maximum_version = ver
            else:
                ctx = ssl.SSLContext(ver)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=int(timeout)) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    ssock.recv(1024)
            findings.append(SSLFinding(
                host, port, "Protocol",
                "high" if sev == "high" else "medium" if sev == "medium" else "info",
                f"{name} supported",
                "Disable TLS 1.0/1.1" if sev in ("high", "medium") else None,
            ))
        except (ssl.SSLError, ValueError):
            pass
        except (socket.timeout, OSError):
            break
    return findings


def check_weak_ciphers(host: str, port: int, timeout: float = 5.0) -> List[SSLFinding]:
    """Check for weak cipher support (RC4, 3DES, NULL)."""
    findings = []
    weak_suites = [
        ("RC4", "RC4", "critical", "RC4 is broken; disable immediately"),
        ("3DES", "3DES", "high", "3DES is deprecated; use AES"),
        ("NULL", "aNULL", "critical", "NULL cipher provides no encryption"),
    ]
    for name, cipher, sev, remed in weak_suites:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_ciphers(cipher)
            with socket.create_connection((host, port), timeout=int(timeout)) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    ssock.recv(1024)
            findings.append(SSLFinding(
                host, port, "Weak cipher",
                sev, f"{name} cipher supported",
                remed,
            ))
        except (ssl.SSLError, OSError, socket.timeout):
            pass
    return findings


def check_certificate(host: str, port: int, timeout: float = 5.0) -> List[SSLFinding]:
    """Check certificate validity, expiry, and signature."""
    findings = []
    try:
        cert_pem = ssl.get_server_certificate((host, port), timeout=timeout)
        if not CRYPTO_AVAILABLE:
            return [SSLFinding(host, port, "Certificate", "info", "Install cryptography for detailed cert analysis", None)]
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
        now = datetime.utcnow()
        not_after = cert.not_valid_after_utc
        if hasattr(not_after, 'replace') and not_after.tzinfo:
            not_after = not_after.replace(tzinfo=None)
        if not_after < now:
            findings.append(SSLFinding(
                host, port, "Certificate",
                "high", "Certificate expired",
                "Renew certificate",
            ))
        elif (not_after - now).days < 30:
            findings.append(SSLFinding(
                host, port, "Certificate",
                "medium", "Certificate expires within 30 days",
                "Renew certificate",
            ))
        sig_algo = str(cert.signature_algorithm_oid).lower()
        if "md5" in sig_algo or "sha1" in sig_algo:
            findings.append(SSLFinding(
                host, port, "Certificate",
                "high", f"Weak signature algorithm",
                "Use SHA-256 or stronger",
            ))
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            with socket.create_connection((host, port), timeout=int(timeout)) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    pass
        except ssl.SSLCertVerificationError as e:
            if "self-signed" in str(e).lower() or "certificate verify failed" in str(e).lower():
                findings.append(SSLFinding(
                    host, port, "Certificate",
                    "medium", "Self-signed or invalid certificate",
                    "Use valid CA-signed certificate",
                ))
    except ssl.SSLError as e:
        findings.append(SSLFinding(host, port, "Certificate", "info", f"SSL error: {str(e)[:80]}", None))
    except (socket.timeout, OSError):
        pass
    return findings


def run_ssl_checks(host: str, port: int, timeout: float = 5.0) -> List[SSLFinding]:
    """Run all SSL/TLS checks on a host:port."""
    findings = []
    findings.extend(check_ssl_protocols(host, port, timeout))
    findings.extend(check_weak_ciphers(host, port, timeout))
    findings.extend(check_certificate(host, port, timeout))
    return findings
