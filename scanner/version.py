"""
Version Detection & CVE Lookup - Parse banners for version strings and provide CVE guidance.
"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

# Common CVE references for known vulnerable versions (service -> version pattern -> CVEs)
CVE_LOOKUP = {
    "OpenSSH": [
        (r"OpenSSH_([0-9]+\.[0-9]+)", {"7.4": ["CVE-2018-15473"], "7.2": ["CVE-2016-0777", "CVE-2016-0778"]}),
    ],
    "Apache": [
        (r"Apache/([0-9]+\.[0-9]+\.[0-9]+)", {"2.4.49": ["CVE-2021-41773"], "2.4.50": ["CVE-2021-42013"]}),
    ],
    "nginx": [
        (r"nginx/([0-9]+\.[0-9]+\.[0-9]+)", {"1.18.0": ["CVE-2021-23017"], "1.20.0": ["CVE-2022-41741"]}),
    ],
    "Redis": [
        (r"redis_version:([0-9]+\.[0-9]+\.[0-9]+)", {"4.0.0": ["CVE-2018-11206"], "5.0.0": ["CVE-2022-24834"]}),
    ],
    "MySQL": [
        (r"([0-9]+\.[0-9]+\.[0-9]+)", {"5.7.0": ["CVE-2016-6662"], "8.0.0": ["CVE-2021-3711"]}),
    ],
}


@dataclass
class VersionFinding:
    """Version and CVE finding."""
    host: str
    port: int
    service: str
    version: str
    raw_banner: str
    cve_refs: List[str]
    guidance: str


def parse_version_from_banner(banner: str, port: int) -> Optional[tuple[str, str]]:
    """Extract (service, version) from banner. Returns None if not parseable."""
    if not banner or not banner.strip():
        return None
    banner = banner.strip()

    # SSH: SSH-2.0-OpenSSH_8.2
    m = re.search(r"SSH-2\.0-(.+)", banner, re.I)
    if m:
        return ("SSH", m.group(1).strip())

    # HTTP Server header: Server: nginx/1.18.0
    m = re.search(r"Server:\s*([^\r\n]+)", banner, re.I)
    if m:
        return ("HTTP", m.group(1).strip())

    # FTP: 220 ProFTPD 1.3.5a Server
    m = re.search(r"220\s+(.+)", banner, re.I)
    if m:
        return ("FTP", m.group(1).strip())

    # Redis: redis_version:6.2.6
    m = re.search(r"redis_version:([0-9.]+)", banner, re.I)
    if m:
        return ("Redis", m.group(1))

    # MySQL: 5.7.0 or similar in banner
    if port == 3306:
        m = re.search(r"([0-9]+\.[0-9]+\.[0-9]+)", banner)
        if m:
            return ("MySQL", m.group(1))

    # Generic: X.Y.Z pattern
    m = re.search(r"([A-Za-z0-9_-]+)/([0-9]+\.[0-9]+(?:\.[0-9]+)?)", banner)
    if m:
        return (m.group(1), m.group(2))

    return ("Unknown", banner[:80])


def lookup_cves(service: str, version: str, raw_banner: str = "") -> List[str]:
    """Look up known CVEs for service/version. Returns list of CVE IDs."""
    refs = []
    search_text = f"{service} {version} {raw_banner}"
    for svc, patterns in CVE_LOOKUP.items():
        if svc.lower() not in service.lower() and svc.lower() not in search_text.lower():
            continue
        for pat, version_cves in patterns:
            m = re.search(pat, search_text, re.I)
            if m:
                v = m.group(1) if m.lastindex else version
                if v in version_cves:
                    refs.extend(version_cves[v])
                else:
                    for ver, cves in version_cves.items():
                        if v.startswith(ver) or (ver in v and len(v) <= len(ver) + 2):
                            refs.extend(cves)
                            break
    return list(dict.fromkeys(refs))


def get_version_finding(host: str, port: int, banner: Optional[str]) -> Optional[VersionFinding]:
    """Parse banner and return VersionFinding with CVE guidance."""
    if not banner:
        return None
    parsed = parse_version_from_banner(banner, port)
    if not parsed:
        return None
    service, version = parsed
    cve_refs = lookup_cves(service, version)
    guidance = ""
    if cve_refs:
        guidance = f"Check: {', '.join(cve_refs)}"
    else:
        guidance = "Verify version is patched; check NVD for CVEs"
    return VersionFinding(
        host=host,
        port=port,
        service=service,
        version=version,
        raw_banner=banner[:200],
        cve_refs=cve_refs,
        guidance=guidance,
    )
