"""
SNMP Enumeration - Default community strings and MIB walk.
"""

from dataclasses import dataclass
from typing import List, Optional

try:
    from pysnmp.hlapi import (
        getCmd, SnmpEngine, CommunityData, UdpTransportTarget,
        ContextData, ObjectType, ObjectIdentity
    )
    PYSNMP_AVAILABLE = True
except ImportError:
    PYSNMP_AVAILABLE = False


@dataclass
class SNMPFinding:
    """SNMP enumeration finding."""
    host: str
    port: int
    community: str
    success: bool
    info: Optional[str] = None
    risk: str = "high"


DEFAULT_COMMUNITIES = ["public", "private", "admin", ""]


def check_snmp_community(host: str, port: int = 161, community: str = "public", timeout: float = 2.0) -> bool:
    """Test if SNMP community string grants access."""
    if not PYSNMP_AVAILABLE:
        return False
    try:
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community),
            UdpTransportTarget((host, port), timeout=timeout),
            ContextData(),
            ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0")),  # sysDescr
        )
        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
        return errorIndication is None and errorStatus is None and len(varBinds) > 0
    except (StopIteration, Exception):
        return False


def get_snmp_sysinfo(host: str, port: int, community: str, timeout: float = 2.0) -> Optional[str]:
    """Get sysDescr (system description) via SNMP."""
    if not PYSNMP_AVAILABLE:
        return None
    try:
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community),
            UdpTransportTarget((host, port), timeout=timeout),
            ContextData(),
            ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0")),
        )
        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
        if errorIndication or errorStatus:
            return None
        if varBinds:
            return str(varBinds[0][1])[:200]
        return None
    except (StopIteration, Exception):
        return None


def run_snmp_checks(host: str, port: int = 161, timeout: float = 2.0) -> List[SNMPFinding]:
    """Test default SNMP community strings and enumerate if access granted."""
    findings = []
    if not PYSNMP_AVAILABLE:
        return [SNMPFinding(host, port, "N/A", False, "Install pysnmp for SNMP checks", "info")]
    for community in DEFAULT_COMMUNITIES:
        comm_str = community or "(empty)"
        if check_snmp_community(host, port, community, timeout):
            info = get_snmp_sysinfo(host, port, community, timeout)
            findings.append(SNMPFinding(
                host, port, comm_str, True,
                f"Default community '{comm_str}' grants access" + (f": {info[:80]}..." if info else ""),
                "critical" if community in ("public", "private", "") else "high",
            ))
    return findings
