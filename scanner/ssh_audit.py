"""
SSH Weak Algorithm Detection - Flags deprecated kex, ciphers, MACs per RFC 9142.
"""

from dataclasses import dataclass
from typing import List, Optional

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

# Weak algorithms per RFC 9142 and common advisories
WEAK_KEX = {
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group-exchange-sha1",
    "diffie-hellman-group14-sha1",
}
WEAK_CIPHERS = {"arcfour", "arcfour128", "arcfour256", "3des-cbc", "blowfish-cbc", "cast128-cbc"}
WEAK_MACS = {"hmac-sha1", "hmac-sha1-96", "hmac-md5", "hmac-md5-96"}


@dataclass
class SSHAuditFinding:
    """SSH audit finding."""
    host: str
    port: int
    category: str  # kex, cipher, mac
    algorithm: str
    severity: str
    message: str
    remediation: str = "Upgrade SSH server; disable weak algorithms"


def audit_ssh(host: str, port: int = 22, timeout: float = 5.0) -> List[SSHAuditFinding]:
    """Connect via paramiko and inspect server algorithms for weak/deprecated ones."""
    findings = []
    if not PARAMIKO_AVAILABLE:
        return [SSHAuditFinding(host, port, "info", "N/A", "info", "Install paramiko for SSH audit", "pip install paramiko")]
    # Single connection with weak-only options; if it succeeds, server supports weak algorithms
    weak_kex = list(WEAK_KEX)
    weak_ciphers = ["3des-cbc", "arcfour", "arcfour128", "arcfour256", "blowfish-cbc", "cast128-cbc"]
    weak_macs = ["hmac-sha1", "hmac-md5", "hmac-sha1-96", "hmac-md5-96"]
    try:
        t = paramiko.Transport((host, port))
        t.banner_timeout = timeout
        t.auth_timeout = timeout
        opts = t.get_security_options()
        opts.kex = tuple(weak_kex)
        opts.ciphers = tuple(weak_ciphers)
        opts.macs = tuple(weak_macs)
        t.connect()
        # Connection succeeded - server accepted weak algorithms
        findings.append(SSHAuditFinding(
            host, port, "algorithms", "weak", "high",
            "Server accepts weak KEX/cipher/MAC (diffie-hellman-group1-sha1, arcfour, 3des-cbc, etc.)",
            "Disable diffie-hellman-group1-sha1, arcfour, 3des-cbc; use modern algorithms",
        ))
        t.close()
    except paramiko.SSHException as e:
        err = str(e).lower()
        if "no matching" in err or "algorithm" in err:
            pass  # Server rejected weak - good
        else:
            findings.append(SSHAuditFinding(
                host, port, "error", "N/A", "info",
                f"SSH audit: {e}",
                "",
            ))
    except Exception as e:
        findings.append(SSHAuditFinding(
            host, port, "error", "N/A", "info",
            f"SSH audit failed: {e}",
            "",
        ))
    return findings


def run_ssh_audit(host: str, port: int = 22, timeout: float = 5.0) -> List[SSHAuditFinding]:
    """Run SSH audit for weak algorithms. Returns list of findings."""
    return audit_ssh(host, port, timeout)
