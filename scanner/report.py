"""Report generation for scan results."""

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Severity order for sorting (higher = more severe)
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _risk_score(findings: List[Dict], exploits: List[Dict]) -> float:
    """Compute aggregate host risk score 0-10."""
    score = 0.0
    for f in findings:
        score += SEVERITY_ORDER.get(f.get("risk", "medium"), 2) * 0.5
    for e in exploits:
        if "EternalBlue" in str(e) or "VULNERABLE" in str(e).upper():
            score += 2.0
        else:
            score += 1.0
    return min(10.0, score)


def _sort_findings_by_severity(findings: List[Dict]) -> List[Dict]:
    """Sort findings by severity (critical first)."""
    return sorted(findings, key=lambda f: -SEVERITY_ORDER.get(f.get("risk", "medium"), 2))


def _suggested_action(item: Dict, is_exploit: bool = False) -> str:
    """Derive suggested action from a finding or exploit entry."""
    if is_exploit:
        check = (item.get("check") or "").lower()
        details = (item.get("details") or "").lower()
        if "remediation" in item and item["remediation"]:
            return item["remediation"]
        if "ssl" in check or "certificate" in check:
            if "self-signed" in details:
                return "Accept if internal device; use valid cert for public-facing"
            return "Verify certificate validity; renew if expired"
        if "header" in check:
            return "Add missing security headers to web server config"
        if "accessible path" in check or ("path" in check and "returns 200" in details):
            return "Verify path is intentional; restrict if sensitive"
        if "snmp" in check:
            return "Change default community strings; use SNMPv3"
        if "eternalblue" in details or "ms17-010" in details:
            return "Apply MS17-010 patch; disable SMBv1"
        if "anonymous" in details or "null session" in details:
            return "Disable anonymous access; require authentication"
        if "no authentication" in details or "no auth" in details:
            return "Enable authentication; restrict network access"
        if "brute" in check:
            return "Change credentials; use strong passwords"
        if "container" in check or "docker" in check or "kubernetes" in check:
            return "Restrict API access; require authentication"
        if "version" in check:
            return "Update to patched version; check NVD for CVEs"
        return "Review and remediate as needed"
    # Finding
    if item.get("remediation"):
        return item["remediation"]
    risk = item.get("risk", "medium")
    if risk == "critical":
        return "Address immediately; restrict access"
    if risk == "high":
        return "Patch or harden; verify configuration"
    if risk == "medium":
        return "Review; update if outdated"
    return "Monitor; low priority"


@dataclass
class HostResult:
    """Scan results for a single host."""
    host: str
    open_tcp: List[int]
    open_udp: List[Tuple[int, str]]
    fingerprint: Optional[str]
    findings: List[Dict[str, Any]]
    exploits: List[Dict[str, str]] = field(default_factory=list)
    device: Optional[str] = None
    device_vendor: Optional[str] = None
    issues: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ScanReport:
    """Full scan report."""
    target: str
    scan_type: str
    timestamp: str
    hosts: List[HostResult] = field(default_factory=list)
    compliance_profile: Optional[str] = None

    def add_host(
        self,
        host: str,
        open_tcp: List[int],
        open_udp: List[Tuple[int, str]],
        fingerprint: Optional[str],
        findings: List[Dict[str, Any]],
        exploits: Optional[List[Dict[str, str]]] = None,
        device: Optional[str] = None,
        device_vendor: Optional[str] = None,
        issues: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        """Add a host's results to the report."""
        self.hosts.append(
            HostResult(
                host=host,
                open_tcp=open_tcp,
                open_udp=open_udp,
                fingerprint=fingerprint,
                findings=findings,
                exploits=exploits or [],
                device=device,
                device_vendor=device_vendor,
                issues=issues or [],
            )
        )

    def _control_matrix(self) -> List[Dict[str, Any]]:
        """Build compliance control matrix from all findings."""
        matrix = []
        for h in self.hosts:
            for f in h.findings:
                ctrl = f.get("compliance_controls") or {}
                for fw, ids in ctrl.items():
                    for cid in ids:
                        matrix.append({
                            "framework": fw,
                            "control_id": cid,
                            "host": h.host,
                            "finding": f"{f.get('service', '')} port {f.get('port', '')}",
                            "status": "FAIL",
                            "cvss": f.get("cvss_score"),
                        })
            for e in h.exploits:
                ctrl = e.get("compliance_controls") or {}
                for fw, ids in ctrl.items():
                    for cid in ids:
                        matrix.append({
                            "framework": fw,
                            "control_id": cid,
                            "host": h.host,
                            "finding": e.get("check", ""),
                            "status": "FAIL",
                            "cvss": None,
                        })
        return matrix

    def _html_control_matrix(self) -> str:
        """HTML for compliance control matrix section."""
        matrix = self._control_matrix()
        if not matrix:
            return ""
        rows = []
        for m in matrix[:50]:  # Limit for display
            rows.append(
                f"<tr><td>{m['framework']}</td><td>{m['control_id']}</td><td>{m['host']}</td>"
                f"<td>{m['finding']}</td><td style='color:#e74c3c'>{m['status']}</td>"
                f"<td>{m.get('cvss') or '-'}</td></tr>"
            )
        return f"""
  <h2>Compliance Control Matrix</h2>
  <table>
    <thead><tr><th>Framework</th><th>Control</th><th>Host</th><th>Finding</th><th>Status</th><th>CVSS</th></tr></thead>
    <tbody>{"".join(rows)}</tbody>
  </table>
"""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "target": self.target,
            "scan_type": self.scan_type,
            "timestamp": self.timestamp,
            "compliance_profile": self.compliance_profile,
            "compliance_control_matrix": self._control_matrix(),
            "hosts": [
                {
                    "host": h.host,
                    "open_tcp": h.open_tcp,
                    "open_udp": [{"port": p, "status": s} for p, s in h.open_udp],
                    "fingerprint": h.fingerprint,
                    "findings": [
                        {
                            **f,
                            "suggested_action": _suggested_action(f, is_exploit=False),
                            "cvss_score": f.get("cvss_score"),
                            "compliance_controls": f.get("compliance_controls"),
                        }
                        for f in _sort_findings_by_severity(h.findings)
                    ],
                    "exploits": [
                        {
                            **e,
                            "suggested_action": _suggested_action(e, is_exploit=True),
                            "compliance_controls": e.get("compliance_controls"),
                        }
                        for e in h.exploits
                    ],
                    "device": h.device,
                    "device_vendor": h.device_vendor,
                    "issues": h.issues,
                    "risk_score": round(_risk_score(h.findings, h.exploits), 1),
                }
                for h in self.hosts
            ],
        }

    def write_json(self, path: str) -> None:
        """Write report as JSON."""
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    def write_txt(self, path: str) -> None:
        """Write report as plain text."""
        lines = [
            "=" * 60,
            "SECURITY SCAN REPORT",
            "=" * 60,
            f"Target:    {self.target}",
            f"Scan type: {self.scan_type}",
            f"Date:      {self.timestamp}",
            f"Hosts:     {len(self.hosts)}",
            "",
        ]
        for h in self.hosts:
            lines.extend([
                "-" * 40,
                f"Host: {h.host}",
                f"  Device: {h.device or 'Unknown'}" + (f" ({h.device_vendor})" if h.device_vendor else ""),
                f"  TCP: {', '.join(map(str, h.open_tcp)) or 'none'}",
                f"  UDP: {', '.join(f'{p}({s})' for p, s in h.open_udp) or 'none'}",
            ])
            if h.fingerprint:
                lines.append(f"  OS:  {h.fingerprint}")
            risk = _risk_score(h.findings, h.exploits)
            lines.append(f"  Risk score: {risk:.1f}/10")
            for i in h.issues:
                port_str = f" port {i['port']}" if i.get('port') else ""
                lines.append(f"  ! {i.get('phase', '')}{port_str}: {i.get('reason', '')}")
            for e in h.exploits:
                action = _suggested_action(e, is_exploit=True)
                lines.append(f"  EXPLOIT: {e.get('check', '')} - {e.get('details', '')}")
                lines.append(f"      Suggested action: {action}")
            for f in _sort_findings_by_severity(h.findings):
                action = _suggested_action(f, is_exploit=False)
                lines.append(f"  [{f['port']}] {f['service']} - {f['risk'].upper()}")
                lines.append(f"      {f['notes']}")
                lines.append(f"      Suggested action: {action}")
                if f.get("cve_refs"):
                    lines.append(f"      CVE refs: {', '.join(f['cve_refs'])}")
                if f.get("banner"):
                    lines.append(f"      Banner: {f['banner'][:80]}...")
            lines.append("")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    def write_html(self, path: str) -> None:
        """Write report as HTML."""
        risk_colors = {"critical": "#c0392b", "high": "#e74c3c", "medium": "#f39c12", "low": "#27ae60"}

        rows = []
        for h in self.hosts:
            device_str = (h.device or "Unknown") + (f" ({h.device_vendor})" if h.device_vendor else "")
            for i in h.issues:
                rows.append(
                    f"<tr><td>{h.host}</td><td>{device_str}</td><td colspan='5' style='color:#e74c3c'>"
                    f"! {i.get('phase', '')} port {i.get('port', '')}: {i.get('reason', '')}</td>"
                    f"<td>Investigate</td></tr>"
                )
            for e in h.exploits:
                action = _suggested_action(e, is_exploit=True)
                ctrl = e.get("compliance_controls") or {}
                ctrl_str = ", ".join(f"{k}:{','.join(v)}" for k, v in ctrl.items()) if ctrl else "-"
                rows.append(
                    f"<tr><td>{h.host}</td><td>{device_str}</td><td colspan='2'>EXPLOIT</td>"
                    f"<td style='color:#e74c3c;font-weight:bold'>!</td><td>-</td>"
                    f"<td>{e.get('check', '')}</td><td>{e.get('details', '')}</td><td>-</td>"
                    f"<td>{ctrl_str}</td><td>{action}</td></tr>"
                )
            for f in _sort_findings_by_severity(h.findings):
                color = risk_colors.get(f["risk"], "#95a5a6")
                banner = (f.get("banner") or "")[:50] or "-"
                port_display = f"UDP/{f['port']}" if f.get("service") == "UDP" else f['port']
                action = _suggested_action(f, is_exploit=False)
                cvss = f.get("cvss_score", "-")
                ctrl = f.get("compliance_controls") or {}
                ctrl_str = ", ".join(f"{k}:{','.join(v)}" for k, v in ctrl.items()) if ctrl else "-"
                rows.append(
                    f"<tr><td>{h.host}</td><td>{device_str}</td><td>{port_display}</td><td>{f['service']}</td>"
                    f"<td style='color:{color};font-weight:bold'>{f['risk'].upper()}</td>"
                    f"<td>{cvss}</td><td>{f['notes']}</td><td>{banner}</td><td>{ctrl_str}</td><td>{action}</td></tr>"
                )

        html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Security Scan Report - {self.target}</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 2rem; background: #1a1a2e; color: #eee; }}
    h1 {{ color: #0f3460; }}
    .meta {{ color: #888; margin-bottom: 1.5rem; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #333; padding: 0.5rem 0.75rem; text-align: left; }}
    th {{ background: #16213e; color: #e94560; }}
    tr:nth-child(even) {{ background: #16213e; }}
    .summary {{ background: #0f3460; padding: 1rem; border-radius: 8px; margin-bottom: 1rem; }}
  </style>
</head>
<body>
  <h1>Security Scan Report</h1>
  <div class="meta">
    <p><strong>Target:</strong> {self.target} &nbsp;|&nbsp;
       <strong>Scan:</strong> {self.scan_type} &nbsp;|&nbsp;
       <strong>Date:</strong> {self.timestamp} &nbsp;|&nbsp;
       <strong>Hosts with findings:</strong> {len(self.hosts)}</p>
  </div>
  <div class="summary">
    <strong>Summary:</strong> {len(self.hosts)} host(s) with open ports or vulnerabilities.
    Risk scores: {', '.join(f"{_risk_score(h.findings, h.exploits):.1f}" for h in self.hosts)}.
    {f"Compliance: {self.compliance_profile}" if self.compliance_profile else ""}
  </div>
  {self._html_control_matrix()}
  <table>
    <thead><tr><th>Host</th><th>Device</th><th>Port</th><th>Service</th><th>Risk</th><th>CVSS</th><th>Notes</th><th>Banner</th><th>Controls</th><th>Suggested Action</th></tr></thead>
    <tbody>
      {"".join(rows)}
    </tbody>
  </table>
</body>
</html>"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

    def write_sarif(self, path: str) -> None:
        """Write report as SARIF (Static Analysis Results Interchange Format) for CI/CD."""
        results = []
        rule_ids = set()
        for h in self.hosts:
            for f in h.findings:
                rid = f"SYN-{f.get('port', '')}-{f.get('service', '')}"
                rule_ids.add(rid)
                results.append({
                    "ruleId": rid,
                    "level": "error" if f.get("risk") in ("critical", "high") else "warning",
                    "message": {"text": f"{f.get('notes', '')} - {f.get('service', '')} port {f.get('port', '')}"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": f"network://{h.host}"},
                            "region": {"startLine": 1},
                        }
                    }],
                    "properties": {
                        "cvss": f.get("cvss_score"),
                        "compliance": f.get("compliance_controls"),
                    },
                })
            for e in h.exploits:
                rid = f"SYN-EXPLOIT-{e.get('check', 'unknown')[:30]}"
                rule_ids.add(rid)
                results.append({
                    "ruleId": rid,
                    "level": "error",
                    "message": {"text": f"{e.get('check', '')}: {e.get('details', '')}"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": f"network://{h.host}"},
                            "region": {"startLine": 1},
                        }
                    }],
                    "properties": {"compliance": e.get("compliance_controls")},
                })
        rules = [{"id": rid, "name": rid, "shortDescription": {"text": rid}} for rid in sorted(rule_ids)]
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "SYN-REAPER",
                        "version": "1.0",
                        "informationUri": "https://github.com/syn-reaper",
                        "rules": rules,
                    }
                },
                "results": results,
            }],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2)
