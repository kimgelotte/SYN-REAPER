"""
Security Scanner - Network and port vulnerability scanner
WARNING: Authorized testing only. Unauthorized scanning may violate laws.
"""

import argparse
import os
import random
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

# Load .env if available (optional dependency)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


def _env_bool(key: str, default: bool = False) -> bool:
    """Parse boolean from environment (1, true, yes, on = True)."""
    val = os.environ.get(key, "").lower().strip()
    if not val:
        return default
    return val in ("1", "true", "yes", "on")

from scanner.network import discover_hosts, get_all_hosts, get_default_gateway, arp_discover_with_mac
from scanner.ports import (
    tcp_connect_scan,
    syn_scan,
    udp_scan,
    scan_ports,
    SCAPY_AVAILABLE,
    COMMON_PORTS,
    ROUTER_PORTS,
)
from scanner.vulnerability import check_port_vulnerability, VulnerabilityFinding
from scanner.fingerprint import fingerprint_host, FingerprintResult
from scanner.report import ScanReport
from scanner.exploit import run_exploit_checks, ExploitResult
from scanner.device import detect_device, DeviceInfo
from scanner.bruteforce import run_bruteforce, BruteResult
from scanner.issues import ScanIssue, _normalize_error
from scanner.ssl_check import run_ssl_checks, SSLFinding
from scanner.snmp import run_snmp_checks, SNMPFinding
from scanner.ssh_audit import run_ssh_audit, SSHAuditFinding
from scanner.version import get_version_finding, VersionFinding
from scanner.web_headers import run_web_header_checks, HeaderFinding
from scanner.injection import run_injection_probes, InjectionFinding
from scanner.container import run_container_checks, ContainerFinding
from scanner.web_probes import run_web_advanced_probes, WebProbeFinding
from scanner.wifi import scan_wifi_networks, WiFiNetwork
from scanner.obfuscate import set_obfuscate, random_delay
from scanner.post_exploit import run_post_exploit, PostExploitFinding


def format_finding(f: VulnerabilityFinding) -> str:
    """Format a vulnerability finding for display."""
    risk_markers = {"critical": "!!!", "high": "!!", "medium": "!", "low": ""}
    marker = risk_markers.get(f.risk, "")
    lines = [
        f"  [{f.port}] {f.service} - Risk: {f.risk.upper()} {marker}",
        f"      {f.notes}",
    ]
    if f.banner:
        display = f.banner[:100] + ("..." if len(f.banner) > 100 else "")
        lines.append(f"      Banner: {display}")
    return "\n".join(lines)


def format_fingerprint(r: FingerprintResult) -> str:
    """Format fingerprint result for display."""
    if r.success:
        return f"  OS: {r.os_guess} ({r.message})"
    return f"  OS: {r.message}"


def format_exploit(e: ExploitResult) -> str:
    """Format exploit result for display."""
    status = "EXPLOITABLE" if e.success else "failed"
    return f"  [{e.port}] {e.service} - {e.check}: {status} - {e.details}"


def format_device(d: DeviceInfo) -> str:
    """Format device info for display."""
    parts = [d.device_type]
    if d.vendor:
        parts.append(f"({d.vendor})")
    return f"  Device: {' '.join(parts)} [{d.confidence} confidence] - {d.details}"


def format_brute(b: BruteResult) -> str:
    """Format brute force result for display."""
    return f"  [{b.port}] {b.service}: {b.username}:{b.password} - CRACKED!"


def format_issue(i: ScanIssue) -> str:
    """Format scan issue for display."""
    loc = f" port {i.port}" if i.port else ""
    return f"  ! {i.phase}{loc}: {i.reason}"


def format_ssl_finding(f: SSLFinding) -> str:
    """Format SSL finding for display."""
    return f"  [{f.port}] SSL: {f.check} - {f.severity.upper()} - {f.message}"


def format_snmp_finding(f: SNMPFinding) -> str:
    """Format SNMP finding for display."""
    return f"  [UDP/{f.port}] SNMP community '{f.community}': {f.info or 'access granted'}"


def format_ssh_audit(f: SSHAuditFinding) -> str:
    """Format SSH audit finding for display."""
    return f"  [{f.port}] SSH: {f.category} - {f.severity.upper()} - {f.message}"


def format_version_finding(v: VersionFinding) -> str:
    """Format version/CVE finding for display."""
    cve_str = f" -> {v.guidance}" if v.cve_refs else f" -> {v.guidance}"
    return f"  [{v.port}] {v.service} {v.version}{cve_str}"


def format_header_finding(h: HeaderFinding) -> str:
    """Format HTTP header finding for display."""
    status = "OK" if h.present and "Missing" not in h.message else "MISSING" if not h.present else "WEAK"
    return f"  {h.header}: {status} - {h.message}"


def format_injection_finding(f: InjectionFinding) -> str:
    """Format SQL injection finding for display."""
    return f"  [{f.port}] Possible SQLi - {f.payload_name} -> {f.indicator}"


def format_container_finding(f: ContainerFinding) -> str:
    """Format container API finding for display."""
    return f"  [{f.port}] {f.service}: {f.check} - {f.severity.upper()} - {f.details}"


def format_web_probe_finding(f: WebProbeFinding) -> str:
    """Format web probe (XSS/path traversal) finding for display."""
    return f"  [{f.port}] {f.check}: {f.severity.upper()} - {f.details}"


def format_post_exploit(f: PostExploitFinding) -> str:
    """Format post-exploitation finding for display."""
    return f"  [{f.port}] {f.service} as {f.username} ({f.access_level}): {f.details}"


def format_wifi_network(w: WiFiNetwork) -> str:
    """Format WiFi network for display."""
    sig = f" {w.signal}%" if w.signal is not None else ""
    ch = f" ch{w.channel}" if w.channel is not None else ""
    return f"  {w.ssid or '(hidden)'}  {w.bssid}{sig}{ch}  {w.security}"


def run_scan(
    target: str,
    skip_discovery: bool = False,
    scan_all: bool = False,
    custom_ports: Optional[list[int]] = None,
    no_banner: bool = False,
    timeout: float = 1.0,
    scan_type: str = "connect",
    udp: bool = False,
    fingerprint: bool = False,
    report_path: Optional[str] = None,
    show_progress: bool = True,
    exploit: bool = False,
    bruteforce: bool = False,
    bruteforce_wordlist: Optional[str] = None,
    bruteforce_delay: float = 0.5,
    ssl_check: bool = False,
    ssh_audit: bool = False,
    web_deep: bool = False,
    injection: bool = False,
    rate_limit: Optional[float] = None,
    scope_file: Optional[str] = None,
    dry_run: bool = False,
    profile: Optional[str] = None,
    compliance_profile: Optional[str] = None,
    web_advanced: bool = False,
    write_report_after_each_host: bool = False,
    wifi: bool = False,
    include_router: bool = False,
    use_ai_wordlist: bool = False,
    obfuscate: bool = False,
    post_exploit: bool = False,
) -> None:
    """Run full scan: discover hosts, scan ports, check vulnerabilities."""
    set_obfuscate(obfuscate)
    if obfuscate:
        print("Obfuscation on: browser-like headers, randomized port order, reduced concurrency, pacing.\n")
    # Warning banner
    print("WARNING: Authorized testing only. Unauthorized scanning may violate laws.\n")

    if dry_run:
        if skip_discovery:
            hosts_preview = [target]
        elif scan_all and "/" in target:
            hosts_preview = get_all_hosts(target)
        else:
            hosts_preview = discover_hosts(target, timeout=int(timeout))
        print("DRY RUN: Would scan the following without executing:")
        for h in (hosts_preview or [target])[:20]:
            print(f"  - {h}")
        if len(hosts_preview or []) > 20:
            print(f"  ... and {len(hosts_preview) - 20} more")
        print("Use without --dry-run to run.")
        return

    # Apply profile overrides (profile sets baseline; explicit flags can add)
    if profile == "quick":
        exploit, bruteforce, ssl_check, ssh_audit, web_deep, injection, web_advanced = (
            False, False, False, False, False, False, False,
        )
    elif profile == "standard":
        exploit = exploit or True
        bruteforce = bruteforce or True
        injection = False
    elif profile == "deep":
        exploit, bruteforce, ssl_check, ssh_audit, web_deep, injection = True, True, True, True, True, True
    elif profile == "pentest":
        exploit, bruteforce, ssl_check, ssh_audit, web_deep, injection, web_advanced = (
            True, True, True, True, True, True, True,
        )
        post_exploit = post_exploit or True
    if skip_discovery:
        hosts = [target]
    elif scan_all and "/" in target:
        hosts = get_all_hosts(target)
        print(f"Scan-all mode: skipping ping, scanning {len(hosts)} IPs (ICMP may be blocked)...\n")
    else:
        hosts = discover_hosts(target, timeout=int(timeout))
    if not hosts:
        print(f"No hosts found for {target}")
        print("Tip: Use --scan-all (-A) to skip ping and scan all IPs in the range (ICMP is often blocked).")
        print("     Example: python main.py 192.168.1.0/24 --scan-all")
        return

    if scope_file:
        try:
            with open(scope_file, encoding="utf-8") as f:
                allowed = {line.strip() for line in f if line.strip() and not line.startswith("#")}
            if allowed:
                hosts = [h for h in hosts if h in allowed]
                if not hosts:
                    print("No hosts in scope file match. Exiting.")
                    return
        except FileNotFoundError:
            print(f"Scope file not found: {scope_file}")
            return

    gateway_ip: Optional[str] = None
    if include_router:
        gateway_ip = get_default_gateway()
        if gateway_ip:
            if gateway_ip not in hosts:
                hosts = [gateway_ip] + [h for h in hosts if h != gateway_ip]
            print(f"Including router (gateway) in pen test: {gateway_ip}")
        else:
            print("Include router requested but could not detect default gateway.")

    scan_name = {"connect": "TCP Connect", "syn": "SYN (half-open)"}.get(scan_type, "TCP Connect")
    if scan_type == "syn" and not SCAPY_AVAILABLE:
        print("Note: SYN scan requires scapy. Falling back to TCP Connect. Install: pip install scapy")
        scan_type = "connect"

    report = ScanReport(
        target=target,
        scan_type=scan_name,
        timestamp=datetime.now().isoformat(),
        compliance_profile=compliance_profile,
    ) if report_path else None

    if report and report_path and write_report_after_each_host and Path(report_path).suffix.lower() == ".json":
        report.write_json(report_path)  # initial write so UI can show target/metadata immediately

    # WiFi scan (uses system wireless adapter)
    if wifi:
        print("WiFi scan (nearby networks)...")
        try:
            wifi_networks = scan_wifi_networks(timeout=15)
            if wifi_networks:
                print(f"  Found {len(wifi_networks)} network(s):")
                for w in wifi_networks:
                    print(format_wifi_network(w))
                if report:
                    report.wifi_networks = [
                        {"ssid": w.ssid, "bssid": w.bssid, "signal": w.signal, "channel": w.channel, "security": w.security}
                        for w in wifi_networks
                    ]
                    if report_path and Path(report_path).suffix.lower() == ".json":
                        report.write_json(report_path)
            else:
                print("  No WiFi networks found (or adapter not available).")
        except Exception as e:
            print(f"  WiFi scan failed: {e}")

    total_hosts = len(hosts)
    print(f"Scanning {total_hosts} host(s) [{scan_name}]...\n")

    def make_progress_callback(host_idx: int, host_ip: str):
        def _cb(completed: int, total: int, open_ports: List[int]):
            pct = 100 * completed / total if total else 0
            found = f" ({len(open_ports)} open)" if open_ports else ""
            sys.stdout.write(f"\r  Host {host_idx}/{total_hosts}: {host_ip} - "
                             f"Ports {completed}/{total} ({pct:.1f}%){found}    ")
            sys.stdout.flush()
        return _cb

    for idx, host in enumerate(hosts, 1):
        if rate_limit and rate_limit > 0 and idx > 1:
            time.sleep(1.0 / rate_limit)
        if obfuscate and idx > 1:
            random_delay(0.5, 1.5)
        host_issues: List[ScanIssue] = []
        # Router/gateway gets extra ports (admin UI, TR-069, etc.)
        is_router_host = include_router and gateway_ip and host == gateway_ip
        base_ports = custom_ports or COMMON_PORTS
        ports_for_host = sorted(set(list(base_ports) + (ROUTER_PORTS if is_router_host else [])))
        if obfuscate:
            random.shuffle(ports_for_host)
        scan_workers = 12 if obfuscate else 100
        try:
            progress_cb = make_progress_callback(idx, host) if show_progress else None

            # TCP scan
            if scan_type == "syn":
                open_tcp = syn_scan(host, ports=ports_for_host, timeout=timeout,
                                   max_workers=min(scan_workers, 50), on_progress=progress_cb)
            else:
                open_tcp = tcp_connect_scan(host, ports=ports_for_host, timeout=timeout,
                                           max_workers=scan_workers, on_progress=progress_cb)
            if show_progress:
                sys.stdout.write("\r" + " " * 80 + "\r")  # Clear progress line
                sys.stdout.flush()

            # UDP scan
            open_udp: List[Tuple[int, str]] = []
            if udp:
                if show_progress:
                    sys.stdout.write(f"  Host {idx}/{total_hosts}: {host} - UDP scan...    \r")
                    sys.stdout.flush()
                open_udp = udp_scan(host, ports=ports_for_host, timeout=max(timeout, 2.0))
                if show_progress:
                    sys.stdout.write("\r" + " " * 80 + "\r")
                    sys.stdout.flush()

            if not open_tcp and not open_udp:
                if not scan_all:
                    print(f"\n{'='*50}\n--- {host} ---")
                    print("  No open ports found.")
                continue

            # Filter dead hosts: no TCP open, only UDP open|filtered (no response = likely no device)
            if not open_tcp and open_udp:
                udp_all_filtered = all(s == "open|filtered" for _, s in open_udp)
                if udp_all_filtered:
                    continue  # Skip - no real services, likely unused IP

            print(f"\n{'='*50}\n--- {host} ---")

            # Device detection
            banners_dict = {}
            for port in open_tcp:
                f = check_port_vulnerability(host, port, grab_banner_flag=not no_banner)
                if f.banner:
                    banners_dict[port] = f.banner
            device_info = detect_device(host, open_tcp, banners_dict, timeout)
            print(format_device(device_info))

            if open_tcp:
                print(f"  TCP open: {', '.join(map(str, open_tcp))}")
            if open_udp:
                udp_str = ", ".join(f"{p}({s})" for p, s in open_udp)
                print(f"  UDP open: {udp_str}")

            # Stack fingerprinting
            if fingerprint:
                print("\n  Stack fingerprint:")
                fp_port = 80 if 80 in open_tcp else (open_tcp[0] if open_tcp else 80)
                fp_result = fingerprint_host(host, port=fp_port, timeout=timeout)
                print(format_fingerprint(fp_result))

            # Vulnerability assessment + banner grabbing (reuse banners from device detection)
            print("\n  Vulnerability assessment:")
            findings_data = []
            version_findings: List[VersionFinding] = []
            for port in open_tcp:
                finding = check_port_vulnerability(host, port, grab_banner_flag=not no_banner)
                if port not in banners_dict and finding.banner:
                    banners_dict[port] = finding.banner
                print(format_finding(finding))
                vf = get_version_finding(host, port, finding.banner)
                if vf:
                    version_findings.append(vf)
                    print(format_version_finding(vf))
                vf_for_port = next((v for v in version_findings if v.port == port), None)
                cve_refs = vf_for_port.cve_refs if vf_for_port else None
                from scanner.cve_cvss import cvss_for_finding
                from scanner.compliance import COMPLIANCE_MAP
                cvss, _ = cvss_for_finding(finding.risk, cve_refs)
                controls = dict(COMPLIANCE_MAP.get(f"port:{port}", {}))
                findings_data.append({
                    "port": finding.port,
                    "service": finding.service,
                    "risk": finding.risk,
                    "notes": finding.notes,
                    "banner": finding.banner,
                    "remediation": finding.remediation,
                    "cve_refs": cve_refs,
                    "cvss_score": cvss,
                    "compliance_controls": controls or None,
                })
            for port, status in open_udp:
                print(f"  [UDP/{port}] {status} - Verify service manually")
                findings_data.append({
                    "port": port,
                    "service": "UDP",
                    "risk": "unknown",
                    "notes": status,
                    "banner": None,
                })

            # SSL/TLS checks
            ssl_ports = {443, 8443, 4433, 636}
            ssl_checks = []
            if ssl_check:
                for port in open_tcp:
                    if port in ssl_ports:
                        ssl_findings = run_ssl_checks(host, port, timeout=max(timeout, 5.0))
                        ssl_checks.extend(ssl_findings)
                if ssl_checks:
                    print("\n  SSL/TLS checks:")
                    for f in ssl_checks:
                        print(format_ssl_finding(f))

            # SSH weak algorithm audit
            ssh_audit_findings: List[SSHAuditFinding] = []
            if ssh_audit and 22 in open_tcp:
                ssh_audit_findings = run_ssh_audit(host, 22, timeout=max(timeout, 5.0))
                if ssh_audit_findings and not (len(ssh_audit_findings) == 1 and ssh_audit_findings[0].category == "error"):
                    print("\n  SSH audit:")
                    for f in ssh_audit_findings:
                        if f.category != "error":
                            print(format_ssh_audit(f))

            # SNMP enumeration (UDP 161 when --udp used)
            snmp_findings: List[SNMPFinding] = []
            if udp and any(p == 161 for p, _ in open_udp):
                snmp_findings = run_snmp_checks(host, 161, timeout=max(timeout, 2.0))
                if snmp_findings:
                    print("\n  SNMP enumeration (UDP 161):")
                    for f in snmp_findings:
                        print(format_snmp_finding(f))

            # HTTP security headers (when exploit/web checks enabled)
            header_findings: List[HeaderFinding] = []
            if exploit:
                web_ports = [p for p in open_tcp if p in (80, 443, 8080, 8443, 8000, 8888, 4433)]
                if web_ports:
                    header_findings = run_web_header_checks(host, web_ports, timeout=timeout)
                    missing = [h for h in header_findings if not h.present or "Missing" in h.message]
                    if missing:
                        print("\n  HTTP security headers:")
                        for h in missing[:6]:  # Show first 6
                            print(format_header_finding(h))

            # SQL injection probes (opt-in only)
            injection_findings: List[InjectionFinding] = []
            if injection and exploit:
                web_ports = [p for p in open_tcp if p in (80, 443, 8080, 8443, 8000, 8888, 4433)]
                if web_ports:
                    injection_findings = run_injection_probes(host, web_ports, timeout=timeout)
                    if injection_findings:
                        print("\n  SQL injection probes:")
                        for f in injection_findings:
                            print(format_injection_finding(f))

            # Container/cloud API checks
            container_findings: List[ContainerFinding] = []
            container_ports = [p for p in open_tcp if p in (2375, 2376, 2379, 6443)]
            if container_ports:
                container_findings = run_container_checks(host, container_ports, timeout=timeout)
                if container_findings:
                    print("\n  Container/Cloud APIs:")
                    for f in container_findings:
                        print(format_container_finding(f))

            # Web advanced (XSS / path traversal) - pentest-level probes
            web_probe_findings: List[WebProbeFinding] = []
            if web_advanced and exploit:
                web_ports = [p for p in open_tcp if p in (80, 443, 8080, 8443, 8000, 8888, 4433)]
                if web_ports:
                    web_probe_findings = run_web_advanced_probes(host, web_ports, timeout=timeout)
                    if web_probe_findings:
                        print("\n  Web penetration probes (XSS / path traversal):")
                        for f in web_probe_findings:
                            print(format_web_probe_finding(f))

            # Exploit attempts
            exploit_results: List[ExploitResult] = []
            if exploit:
                print("\n  Exploit attempts:")
                exploit_results = run_exploit_checks(host, open_tcp, timeout=timeout, web_deep=web_deep)
                if exploit_results:
                    for e in exploit_results:
                        print(format_exploit(e))
                else:
                    print("  No exploitable misconfigurations found.")

            # Brute force attempts
            brute_results: List[BruteResult] = []
            if bruteforce:
                print("\n  Brute force:")
                brute_results, brute_issues = run_bruteforce(
                    host, open_tcp,
                    wordlist_path=bruteforce_wordlist,
                    timeout=timeout,
                    delay=bruteforce_delay,
                    on_progress=lambda h, p, s, u, pw: (sys.stdout.write(f"\r    Trying {s} {u}:{pw}...    "), sys.stdout.flush()),
                    is_router=is_router_host,
                    use_ai_wordlist=use_ai_wordlist,
                )
                host_issues.extend(brute_issues)
                if show_progress and brute_results:
                    sys.stdout.write("\r" + " " * 60 + "\r")
                    sys.stdout.flush()
                if brute_results:
                    for b in brute_results:
                        print(format_brute(b))
                elif brute_issues:
                    print("  Brute force aborted:")
                    for i in brute_issues:
                        print(format_issue(i))
                else:
                    print("  No credentials found.")

            # Post-exploitation reconnaissance (after brute force cracks credentials)
            post_exploit_results: List[PostExploitFinding] = []
            if post_exploit and brute_results:
                successful_brutes = [b for b in brute_results if getattr(b, "success", True)]
                if successful_brutes:
                    print("\n  Post-exploitation recon:")
                    post_exploit_results = run_post_exploit(
                        host=host,
                        brute_results=brute_results,
                        open_ports=open_tcp,
                        on_progress=lambda msg: print(f"  {msg}"),
                    )
                    if post_exploit_results:
                        for pe in post_exploit_results:
                            print(format_post_exploit(pe))
                    else:
                        print("  No additional accessible services found.")

            fp_str = None
            if fingerprint:
                fp_str = fp_result.os_guess if fp_result.success else fp_result.message

            if report:
                from scanner.compliance import get_controls_dict_for_exploit
                def _exploit_entry(check: str, details: str) -> dict:
                    controls = get_controls_dict_for_exploit(check)
                    return {"check": check, "details": details, "compliance_controls": controls or None}
                exploit_entries = [_exploit_entry(e.check, e.details) for e in exploit_results]
                exploit_entries.extend([_exploit_entry("Brute", f"{b.username}:{b.password}") for b in brute_results])
                exploit_entries.extend([_exploit_entry(f"SSL: {f.check}", f"{f.severity}: {f.message}") for f in ssl_checks])
                exploit_entries.extend([_exploit_entry(f"SNMP: {f.community}", f.info or "access granted") for f in snmp_findings if f.success])
                exploit_entries.extend([_exploit_entry(f"SSH audit: {f.category}", f.message) for f in ssh_audit_findings if f.category not in ("error", "info")])
                exploit_entries.extend([_exploit_entry(f"Version: {v.service}", f"{v.version} - {v.guidance}") for v in version_findings])
                exploit_entries.extend([_exploit_entry(f"Header: {h.header}", h.message) for h in header_findings if not h.present])
                exploit_entries.extend([_exploit_entry("SQLi probe", f"{f.payload_name}: {f.indicator}") for f in injection_findings])
                exploit_entries.extend([_exploit_entry(f"Container: {f.service}", f.details) for f in container_findings])
                exploit_entries.extend([_exploit_entry(f"Web: {f.check}", f.details) for f in web_probe_findings])
                exploit_entries.extend([_exploit_entry(f"PostExploit: {pe.service}", f"{pe.username}@{pe.host}:{pe.port} ({pe.access_level}): {pe.details[:100]}") for pe in post_exploit_results])
                report.add_host(
                    host=host,
                    open_tcp=open_tcp,
                    open_udp=open_udp,
                    fingerprint=fp_str,
                    findings=findings_data,
                    exploits=exploit_entries,
                    device=device_info.device_type,
                    device_vendor=device_info.vendor,
                    issues=[{"phase": i.phase, "reason": i.reason, "port": i.port} for i in host_issues],
                )
                if write_report_after_each_host and report_path and Path(report_path).suffix.lower() == ".json":
                    report.write_json(report_path)

        except (ConnectionError, OSError, TimeoutError) as e:
            host_issues.append(ScanIssue("scan", _normalize_error(e), detail=str(e)))
            print(f"\n{'='*50}\n--- {host} ---")
            print(f"  ! Scan interrupted: {_normalize_error(e)}")
            if report:
                report.add_host(host=host, open_tcp=[], open_udp=[], fingerprint=None, findings=[],
                               exploits=[], device=None, device_vendor=None,
                               issues=[{"phase": "scan", "reason": _normalize_error(e), "port": None}])
                if write_report_after_each_host and report_path and Path(report_path).suffix.lower() == ".json":
                    report.write_json(report_path)

    if report and report_path:
        path = Path(report_path)
        suffix = path.suffix.lower()
        if suffix == ".json":
            report.write_json(report_path)
        elif suffix in (".html", ".htm"):
            report.write_html(report_path)
        elif suffix == ".sarif":
            report.write_sarif(report_path)
        else:
            report.write_txt(report_path)
        print(f"\nReport saved to: {report_path}")


def main():
    """Main entry point for the security scanner."""
    parser = argparse.ArgumentParser(
        description="Scan networks and ports for vulnerabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Scan types:
  connect  TCP Connect (full handshake) - default, no privileges
  syn      SYN (half-open) - stealth, requires scapy + root/admin
  udp      UDP scan - add --udp for UDP ports (slower)

Examples:
  python main.py 192.168.1.0/24              Scan subnet (TCP Connect)
  python main.py 192.168.1.1 --scan syn      SYN scan (needs scapy + admin)
  python main.py 10.0.0.1 --udp              Include UDP ports
  python main.py 127.0.0.1 -s -F             Skip discovery, fingerprint OS
  python main.py 192.168.1.0/24 --scan-all   Skip ping, scan all IPs (ICMP blocked)
  python main.py 192.168.1.0/24 -o report.html  Save results to HTML report
  python main.py 192.168.1.0/24 -A --all-ports -o report.html  Full network scan + report
        """,
    )
    parser.add_argument(
        "target",
        help="Target: IP address, hostname, or CIDR (e.g., 192.168.1.0/24)",
    )
    parser.add_argument(
        "--skip-discovery", "-s",
        action="store_true",
        help="Skip network discovery; treat target as single host",
    )
    parser.add_argument(
        "--scan-all", "-A",
        action="store_true",
        help="Skip ping; scan all IPs in CIDR (use when ICMP is blocked)",
    )
    parser.add_argument(
        "--ports", "-p",
        type=int,
        nargs="+",
        metavar="PORT",
        help="Specific ports to scan (default: common ports)",
    )
    parser.add_argument(
        "--scan", "-S",
        choices=["connect", "syn"],
        default=os.environ.get("SCAN_TYPE", "connect"),
        help="TCP scan type (default: connect or SCAN_TYPE from .env)",
    )
    parser.add_argument(
        "--udp", "-u",
        action="store_true",
        default=_env_bool("SCAN_UDP"),
        help="Include UDP port scan (default: SCAN_UDP from .env)",
    )
    parser.add_argument(
        "--fingerprint", "-F",
        action="store_true",
        default=_env_bool("SCAN_FINGERPRINT"),
        help="Perform stack fingerprinting (default: SCAN_FINGERPRINT from .env)",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Skip banner grabbing (faster)",
    )
    parser.add_argument(
        "--timeout", "-t",
        type=float,
        default=float(os.environ.get("SCAN_TIMEOUT", "1.0")),
        help="Timeout in seconds (default: 1.0 or SCAN_TIMEOUT from .env)",
    )
    parser.add_argument(
        "--report", "-o",
        metavar="FILE",
        help="Save report to file (.json, .html, .txt, or .sarif)",
    )
    parser.add_argument(
        "--compliance",
        choices=["cis", "pci-dss", "nist", "all"],
        metavar="PROFILE",
        default=os.environ.get("SCAN_COMPLIANCE") or None,
        help="Compliance profile (default: SCAN_COMPLIANCE from .env)",
    )
    parser.add_argument(
        "--all-ports",
        action="store_true",
        help="Scan all 65535 TCP ports (slow - use with -t 0.3 for speed)",
    )
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable progress updates in terminal",
    )
    parser.add_argument(
        "--exploit", "-e",
        action="store_true",
        default=_env_bool("SCAN_EXPLOIT"),
        help="Exploit checks (default: SCAN_EXPLOIT from .env)",
    )
    parser.add_argument(
        "--bruteforce", "-b",
        action="store_true",
        default=_env_bool("SCAN_BRUTEFORCE"),
        help="Brute force FTP/SSH/HTTP/MySQL (default: SCAN_BRUTEFORCE from .env)",
    )
    parser.add_argument(
        "--bruteforce-wordlist",
        metavar="FILE",
        help="Custom wordlist (user:pass per line)",
    )
    parser.add_argument(
        "--bruteforce-delay",
        type=float,
        default=0.5,
        help="Delay between attempts in seconds (default: 0.5)",
    )
    parser.add_argument(
        "--ai-bruteforce",
        action="store_true",
        default=_env_bool("SCAN_AI_BRUTEFORCE"),
        help="Use AI to suggest bruteforce credentials per port (falls back to wordlist if AI unavailable)",
    )
    parser.add_argument(
        "--ssl-check",
        action="store_true",
        default=_env_bool("SCAN_SSL_CHECK"),
        help="SSL/TLS and certificate checks (default: SCAN_SSL_CHECK from .env)",
    )
    parser.add_argument(
        "--ssh-audit",
        action="store_true",
        default=_env_bool("SCAN_SSH_AUDIT"),
        help="SSH weak algorithm audit (default: SCAN_SSH_AUDIT from .env)",
    )
    parser.add_argument(
        "--web-deep",
        action="store_true",
        default=_env_bool("SCAN_WEB_DEEP"),
        help="Extended web path discovery (default: SCAN_WEB_DEEP from .env)",
    )
    parser.add_argument(
        "--injection",
        action="store_true",
        default=_env_bool("SCAN_INJECTION"),
        help="SQL injection probes (default: SCAN_INJECTION from .env)",
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        metavar="N",
        help="Max requests per second (throttle between hosts)",
    )
    parser.add_argument(
        "--scope-file",
        metavar="FILE",
        help="Restrict targets to IPs/hostnames in file (one per line)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be scanned without executing",
    )
    parser.add_argument(
        "--profile",
        choices=["quick", "standard", "deep", "pentest"],
        default=os.environ.get("SCAN_PROFILE") or None,
        help="Scan profile: quick, standard, deep, or pentest (deep + web-advanced)",
    )
    parser.add_argument(
        "--web-advanced",
        action="store_true",
        default=_env_bool("SCAN_WEB_ADVANCED"),
        help="XSS reflection and path traversal probes (pentest-level)",
    )
    parser.add_argument(
        "--wifi", "-W",
        action="store_true",
        default=_env_bool("SCAN_WIFI"),
        help="Scan nearby WiFi networks (uses system wireless adapter)",
    )
    parser.add_argument(
        "--include-router",
        action="store_true",
        default=_env_bool("SCAN_INCLUDE_ROUTER"),
        help="Include default gateway (router) in pen test: extra ports, admin paths, default creds",
    )
    parser.add_argument(
        "--mac",
        metavar="MAC",
        help="Target by MAC address (target must be CIDR, e.g. 192.168.1.0/24). Uses ARP to resolve MAC to IP. E.g. aa:bb:cc:dd:ee:ff",
    )
    parser.add_argument(
        "--obfuscate",
        action="store_true",
        default=_env_bool("SCAN_OBFUSCATE"),
        help="Reduce blocking: browser-like User-Agents, random port order, lower concurrency, pacing (high-quality pen-test, slower)",
    )
    parser.add_argument(
        "--post-exploit",
        action="store_true",
        default=_env_bool("SCAN_POST_EXPLOIT"),
        help="Post-exploitation recon: enumerate SMB shares, FTP, SSH info, DB tables after brute force cracks credentials (auto-enabled with pentest profile)",
    )

    args = parser.parse_args()
    target = args.target
    skip_discovery = args.skip_discovery
    if args.mac:
        mac_raw = args.mac.strip().lower().replace("-", ":")
        if "/" not in target:
            parser.error("--mac requires target to be a subnet (CIDR), e.g. 192.168.1.0/24")
        ip_mac = arp_discover_with_mac(target, timeout=3)
        ip_for_mac = None
        for ip, mac in ip_mac:
            if mac_raw == mac.lower().replace("-", ":"):
                ip_for_mac = ip
                break
        if not ip_for_mac:
            sys.exit(f"MAC {args.mac} not found in {target}. Run without --mac to scan the subnet.")
        print(f"Resolved MAC {args.mac} -> {ip_for_mac}")
        target = ip_for_mac
        skip_discovery = True
    custom_ports = args.ports
    if args.all_ports and not custom_ports:
        custom_ports = list(range(1, 65536))
        if not args.report:
            print("Tip: Use -o report.html to save the full scan report")
    elif args.all_ports and custom_ports:
        custom_ports = list(range(1, 65536))
        print("Note: --all-ports overrides --ports")

    run_scan(
        target=target,
        skip_discovery=skip_discovery,
        scan_all=args.scan_all,
        custom_ports=custom_ports,
        no_banner=args.no_banner,
        timeout=args.timeout,
        scan_type=args.scan,
        udp=args.udp,
        fingerprint=args.fingerprint,
        report_path=args.report,
        show_progress=not args.no_progress,
        exploit=args.exploit,
        bruteforce=args.bruteforce,
        bruteforce_wordlist=args.bruteforce_wordlist,
        bruteforce_delay=args.bruteforce_delay,
        ssl_check=args.ssl_check,
        ssh_audit=args.ssh_audit,
        web_deep=args.web_deep,
        injection=args.injection,
        rate_limit=args.rate_limit,
        scope_file=args.scope_file,
        dry_run=args.dry_run,
        profile=args.profile,
        compliance_profile=args.compliance,
        web_advanced=args.web_advanced,
        wifi=args.wifi,
        include_router=args.include_router,
        use_ai_wordlist=args.ai_bruteforce,
        obfuscate=args.obfuscate,
        post_exploit=args.post_exploit,
    )


if __name__ == "__main__":
    main()
