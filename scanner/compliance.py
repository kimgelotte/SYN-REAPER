"""
Compliance framework mappings - CIS, PCI-DSS, NIST 800-53.
"""

from typing import Dict, List, Optional

# Check type -> compliance controls
# Format: check_id -> (CIS, PCI-DSS, NIST)
COMPLIANCE_MAP: Dict[str, Dict[str, List[str]]] = {
    "port:21": {"cis": ["4.1", "9.1"], "pci_dss": ["2.2"], "nist": ["AC-17", "SC-8"]},
    "port:22": {"cis": ["4.1", "5.1"], "pci_dss": ["2.2", "8.2"], "nist": ["AC-17", "IA-2"]},
    "port:23": {"cis": ["4.1"], "pci_dss": ["2.2"], "nist": ["AC-17", "SC-8"]},
    "port:80": {"cis": ["4.2", "9.2"], "pci_dss": ["2.2", "6.5"], "nist": ["SC-8", "SI-10"]},
    "port:443": {"cis": ["4.2"], "pci_dss": ["2.2", "4.1"], "nist": ["SC-8", "SC-13"]},
    "port:135": {"cis": ["9.1"], "pci_dss": ["1.4"], "nist": ["AC-17", "SC-7"]},
    "port:139": {"cis": ["4.1", "9.1"], "pci_dss": ["2.2"], "nist": ["AC-17", "SC-8"]},
    "port:445": {"cis": ["4.1", "9.1"], "pci_dss": ["2.2"], "nist": ["AC-17", "SC-8"]},
    "port:3306": {"cis": ["4.1", "6.1"], "pci_dss": ["2.2", "8.2"], "nist": ["AC-17", "IA-2"]},
    "port:3389": {"cis": ["4.1", "5.1"], "pci_dss": ["2.2", "8.2"], "nist": ["AC-17", "IA-2"]},
    "port:5432": {"cis": ["4.1", "6.1"], "pci_dss": ["2.2", "8.2"], "nist": ["AC-17", "IA-2"]},
    "port:6379": {"cis": ["4.1", "6.1"], "pci_dss": ["2.2", "8.2"], "nist": ["AC-17", "IA-2"]},
    "port:27017": {"cis": ["4.1", "6.1"], "pci_dss": ["2.2", "8.2"], "nist": ["AC-17", "IA-2"]},
    "ssl_weak": {"cis": ["4.2"], "pci_dss": ["4.1"], "nist": ["SC-8", "SC-13"]},
    "ssl_cert": {"cis": ["4.2"], "pci_dss": ["4.1"], "nist": ["SC-8", "SC-13"]},
    "http_headers": {"cis": ["4.2", "9.2"], "pci_dss": ["6.5"], "nist": ["SI-10"]},
    "snmp_default": {"cis": ["4.1"], "pci_dss": ["2.2"], "nist": ["AC-17"]},
    "smb_null": {"cis": ["4.1", "9.1"], "pci_dss": ["2.2"], "nist": ["AC-17"]},
    "eternalblue": {"cis": ["4.1", "7.1"], "pci_dss": ["6.2"], "nist": ["SI-2", "RA-5"]},
    "redis_no_auth": {"cis": ["4.1", "6.1"], "pci_dss": ["2.2", "8.2"], "nist": ["AC-17", "IA-2"]},
    "mongodb_no_auth": {"cis": ["4.1", "6.1"], "pci_dss": ["2.2", "8.2"], "nist": ["AC-17", "IA-2"]},
    "container_api": {"cis": ["4.1", "6.1"], "pci_dss": ["2.2"], "nist": ["AC-17", "SC-7"]},
}

# Compliance profiles: which checks to run
COMPLIANCE_PROFILES = {
    "cis": {"name": "CIS Controls", "controls": ["cis"]},
    "pci-dss": {"name": "PCI-DSS", "controls": ["pci_dss"]},
    "nist": {"name": "NIST 800-53", "controls": ["nist"]},
    "all": {"name": "All Frameworks", "controls": ["cis", "pci_dss", "nist"]},
}


def get_controls_for_check(check_id: str, framework: Optional[str] = None) -> List[str]:
    """Get compliance control IDs for a check."""
    entry = COMPLIANCE_MAP.get(check_id, {})
    if framework:
        return entry.get(framework, [])
    result = []
    for controls in entry.values():
        result.extend(controls)
    return list(dict.fromkeys(result))


def get_controls_for_port(port: int, framework: Optional[str] = None) -> List[str]:
    """Get compliance controls for a port-based finding."""
    return get_controls_for_check(f"port:{port}", framework)


def get_controls_for_exploit(check: str, framework: Optional[str] = None) -> List[str]:
    """Get compliance controls for an exploit type."""
    check_lower = (check or "").lower()
    if "eternalblue" in check_lower or "ms17-010" in check_lower:
        return get_controls_for_check("eternalblue", framework)
    if "snmp" in check_lower:
        return get_controls_for_check("snmp_default", framework)
    if "null session" in check_lower or "smb" in check_lower:
        return get_controls_for_check("smb_null", framework)
    if "ssl" in check_lower or "certificate" in check_lower:
        return get_controls_for_check("ssl_cert", framework)
    if "header" in check_lower:
        return get_controls_for_check("http_headers", framework)
    if "container" in check_lower or "docker" in check_lower:
        return get_controls_for_check("container_api", framework)
    if "redis" in check_lower or "no auth" in check_lower:
        return get_controls_for_check("redis_no_auth", framework)
    if "mongo" in check_lower:
        return get_controls_for_check("mongodb_no_auth", framework)
    return []


def get_controls_dict_for_exploit(check: str) -> Dict[str, List[str]]:
    """Get full compliance controls dict for an exploit type."""
    check_lower = (check or "").lower()
    key = None
    if "eternalblue" in check_lower or "ms17-010" in check_lower:
        key = "eternalblue"
    elif "snmp" in check_lower:
        key = "snmp_default"
    elif "null session" in check_lower or ("smb" in check_lower and "eternalblue" not in check_lower):
        key = "smb_null"
    elif "ssl" in check_lower or "certificate" in check_lower:
        key = "ssl_cert"
    elif "header" in check_lower:
        key = "http_headers"
    elif "container" in check_lower or "docker" in check_lower:
        key = "container_api"
    elif "redis" in check_lower or "no auth" in check_lower:
        key = "redis_no_auth"
    elif "mongo" in check_lower:
        key = "mongodb_no_auth"
    return dict(COMPLIANCE_MAP.get(key or "", {}))
