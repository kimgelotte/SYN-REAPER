"""
CVE lookup and CVSS scoring - NVD API with local fallback.
"""

import json
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Local CVE data: CVE_ID -> (cvss_score, severity)
# Extend as needed; NVD API fills in when available
LOCAL_CVE_DB: Dict[str, Tuple[float, str]] = {
    "CVE-2018-15473": (5.3, "medium"),
    "CVE-2016-0777": (4.0, "medium"),
    "CVE-2016-0778": (4.0, "medium"),
    "CVE-2021-41773": (9.8, "critical"),
    "CVE-2021-42013": (9.8, "critical"),
    "CVE-2021-23017": (8.1, "high"),
    "CVE-2022-41741": (5.3, "medium"),
    "CVE-2018-11206": (9.8, "critical"),
    "CVE-2022-24834": (9.8, "critical"),
    "CVE-2016-6662": (7.5, "high"),
    "CVE-2021-3711": (7.5, "high"),
    "CVE-2017-0143": (7.0, "high"),  # EternalBlue
    "CVE-2017-0144": (8.1, "high"),
}


def _risk_to_cvss(risk: str) -> float:
    """Map risk level to approximate CVSS score."""
    return {"critical": 9.0, "high": 7.5, "medium": 5.0, "low": 3.0}.get(risk, 5.0)


def get_cve_cvss(cve_id: str) -> Optional[Tuple[float, str]]:
    """Get CVSS score and severity for a CVE. Returns (score, severity) or None."""
    cve_id = cve_id.upper().strip()
    if cve_id in LOCAL_CVE_DB:
        return LOCAL_CVE_DB[cve_id]
    # Try NVD API (free, rate limited; 5 requests/min without API key)
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        req = urllib.request.Request(url, headers={"User-Agent": "SYN-REAPER/1.0"})
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read().decode())
        vulns = data.get("vulnerabilities", [])
        if vulns:
            metrics = vulns[0].get("cve", {}).get("metrics", {})
            for m in metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", []) or metrics.get("cvssMetricV2", []):
                score = float(m.get("cvssData", {}).get("baseScore", 0))
                sev = m.get("cvssData", {}).get("baseSeverity", "MEDIUM").lower()
                return (score, sev)
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, KeyError):
        pass
    return None


def cvss_for_finding(risk: str, cve_refs: Optional[List[str]] = None) -> Tuple[float, str]:
    """Get best CVSS for a finding. Uses CVE if available, else risk-based."""
    score = 0.0
    for cve in (cve_refs or []):
        info = get_cve_cvss(cve)
        if info and info[0] > score:
            score, sev = info[0], info[1]
    if score == 0:
        score = _risk_to_cvss(risk)
        sev = risk
    return (round(score, 1), sev)
