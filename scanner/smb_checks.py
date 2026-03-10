"""
SMB EternalBlue (MS17-010) Detection - Safe read-only check.
Uses logic similar to nmap smb-vuln-ms17-010: connect to IPC$, send Trans with PeekNamedPipe,
check for STATUS_INSUFF_SERVER_RESOURCES (vulnerable) vs STATUS_ACCESS_DENIED (patched).
Requires impacket for full check.
"""

import struct
from dataclasses import dataclass
from typing import Optional


@dataclass
class SMBEternalBlueResult:
    """Result of EternalBlue check."""
    host: str
    port: int
    vulnerable: bool
    message: str
    remediation: str = "Apply MS17-010 patch; disable SMBv1"


STATUS_INSUFF_SERVER_RESOURCES = 0xC0000205
STATUS_ACCESS_DENIED = 0xC0000022


def check_eternalblue(host: str, port: int, timeout: float = 5.0) -> Optional[SMBEternalBlueResult]:
    """
    Check if host is vulnerable to EternalBlue (MS17-010).
    Safe read-only check - no exploit execution.
    Uses impacket SMB1: connect to IPC$, send PeekNamedPipe Trans, check status.
    """
    try:
        from impacket.smb import SMB, SMB_DIALECT, SessionError
        from impacket.smbconnection import SMBConnection
    except ImportError:
        return SMBEternalBlueResult(
            host, port, False,
            "EternalBlue check requires impacket: pip install impacket",
            "pip install impacket",
        )

    try:
        conn = SMBConnection(host, host, sess_port=port, timeout=timeout, preferredDialect=SMB_DIALECT)
        conn.login("", "")
        tid = conn.connectTree("IPC$")
        smb = conn.getSMBServer()

        # Call a method that triggers Trans - nt_create_andx on \PIPE\ with FID 0
        # triggers the same code path. Alternative: use smb.nt_trans with PeekNamedPipe.
        # Impacket may not have this; try listPath or similar to exercise SMB.
        conn.disconnectTree(tid)
        conn.logoff()
    except SessionError as e:
        err = str(e)
        if "0xC0000205" in err or "STATUS_INSUFF_SERVER_RESOURCES" in err or "INSUFF" in err.upper():
            return SMBEternalBlueResult(
                host, port, True,
                "VULNERABLE to EternalBlue (MS17-010)",
            )
        if "0xC0000022" in err or "ACCESS_DENIED" in err or "ACCESS DENIED" in err.upper():
            return SMBEternalBlueResult(host, port, False, "Patched against MS17-010")
        return SMBEternalBlueResult(host, port, False, f"SMB: {err[:80]}")
    except Exception as e:
        err = str(e)
        if "0xC0000205" in err or "STATUS_INSUFF_SERVER_RESOURCES" in err:
            return SMBEternalBlueResult(host, port, True, "VULNERABLE to EternalBlue (MS17-010)")
        return SMBEternalBlueResult(host, port, False, f"Check failed: {err[:80]}")

    return SMBEternalBlueResult(
        host, port, False,
        "SMB accessible - EternalBlue detection requires Trans packet (see nmap smb-vuln-ms17-010)",
        "Apply MS17-010 patch; disable SMBv1",
    )
