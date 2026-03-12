"""Port scanning - TCP Connect, SYN (half-open), and UDP."""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Optional

try:
    from scapy.all import IP, TCP, UDP, ICMP, Raw, sr1
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Common ports to scan (top services + IoT/TV/phone)
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017,
    2375, 2376, 2379, 6443, 4433,
    # IoT, Smart TV, Phone
    554, 3000, 3001, 5555, 7000, 7100, 7676, 8000, 8008, 8009, 8060, 8061,
    8883, 10243, 55000, 62078,
]

# Router/gateway-specific ports (admin UI, TR-069, UPnP, vendor)
ROUTER_PORTS = [
    80, 443, 8080, 8008, 8443, 4433, 8888,  # Web admin
    22, 23,   # SSH, Telnet
    53,       # DNS (sometimes open on router)
    7547,     # TR-069 CWMP (ISP management)
    8291,     # MikroTik Winbox
    5000,     # UPnP / vendor
    161,      # SNMP (often default community)
]

# Common UDP ports that may respond to probes
COMMON_UDP_PORTS = [53, 67, 68, 69, 123, 161, 162, 500, 514, 520, 1194, 4500]

# Protocol-specific UDP probes (port -> probe bytes) for better response rate
UDP_PROBES = {
    53: bytes.fromhex("0000010000010000000000000377777700010001"),   # DNS query
    123: bytes.fromhex("1b" + "00" * 47),   # NTP client request
    161: bytes.fromhex("302602010104067075626c6963a0190201060201030400"),  # SNMP
}


# --- TCP Connect Scan ---

def tcp_connect_scan_port(host: str, port: int, timeout: float = 1.0) -> Optional[int]:
    """TCP Connect scan: full 3-way handshake. Returns port if open, else None."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return port if result == 0 else None
    except (socket.error, socket.timeout, OSError):
        return None


def tcp_connect_scan(
    host: str,
    ports: Optional[list[int]] = None,
    timeout: float = 1.0,
    max_workers: int = 100,
    on_progress: Optional[Callable[[int, int, list], None]] = None,
) -> list[int]:
    """TCP Connect scan - completes full 3-way handshake. Works without privileges."""
    ports = ports or COMMON_PORTS
    open_ports = []
    total = len(ports)
    last_reported = 0
    report_interval = max(1, total // 50)  # ~50 updates per host for large scans

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(tcp_connect_scan_port, host, p, timeout): p for p in ports}
        completed = 0
        for future in as_completed(futures):
            result = future.result()
            completed += 1
            if result is not None:
                open_ports.append(result)
            if on_progress and (completed - last_reported >= report_interval or completed == total):
                on_progress(completed, total, open_ports)
                last_reported = completed

    return sorted(open_ports)


# --- SYN Scan (Half-open) ---

def _syn_scan_port(host: str, port: int, timeout: float) -> Optional[int]:
    """Single port SYN scan. SYN-ACK = open, RST = closed, no response = filtered."""
    if not SCAPY_AVAILABLE:
        return None
    try:
        pkt = IP(dst=host) / TCP(dport=port, flags="S")
        ans = sr1(pkt, timeout=timeout, verbose=0)
        if ans is None:
            return None
        if ans.haslayer(TCP):
            flags = ans[TCP].flags
            if flags == 0x12:  # SYN-ACK
                return port
    except Exception:
        pass
    return None


def syn_scan(
    host: str,
    ports: Optional[list[int]] = None,
    timeout: float = 1.0,
    max_workers: int = 50,
    on_progress: Optional[Callable[[int, int, list], None]] = None,
) -> list[int]:
    """
    SYN (half-open) scan - sends SYN, does not complete handshake.
    Requires root/admin and scapy. Falls back to TCP Connect if scapy unavailable.
    """
    ports = ports or COMMON_PORTS

    if not SCAPY_AVAILABLE:
        return tcp_connect_scan(host, ports, timeout, max_workers, on_progress)

    open_ports = []
    total = len(ports)
    last_reported = 0
    report_interval = max(1, total // 50)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_syn_scan_port, host, p, timeout): p for p in ports}
        completed = 0
        for future in as_completed(futures):
            result = future.result()
            completed += 1
            if result is not None:
                open_ports.append(result)
            if on_progress and (completed - last_reported >= report_interval or completed == total):
                on_progress(completed, total, open_ports)
                last_reported = completed

    return sorted(open_ports)


# --- UDP Scan ---

def _udp_scan_port(host: str, port: int, timeout: float) -> Optional[tuple[int, str]]:
    """
    UDP scan: send probe, check for UDP response (open) or ICMP unreachable (closed).
    Returns (port, status) or None. Status: 'open', 'open|filtered', 'closed'.
    """
    if not SCAPY_AVAILABLE:
        return _udp_scan_port_fallback(host, port, timeout)

    try:
        probe = UDP_PROBES.get(port, b"\x00" * 32)
        pkt = IP(dst=host) / UDP(dport=port) / Raw(load=probe)
        ans = sr1(pkt, timeout=timeout, verbose=0)
        if ans is None:
            return (port, "open|filtered")
        if ans.haslayer(ICMP):
            if ans[ICMP].type == 3 and ans[ICMP].code == 3:  # Port Unreachable
                return None  # Closed
        if ans.haslayer(UDP):
            return (port, "open")
        return (port, "open|filtered")
    except Exception:
        return None


def _udp_scan_port_fallback(host: str, port: int, timeout: float) -> Optional[tuple[int, str]]:
    """UDP scan without scapy: send probe, check for UDP response only."""
    probe = UDP_PROBES.get(port, b"\x00" * 32)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(probe, (host, port))
        try:
            data, _ = sock.recvfrom(1024)
            sock.close()
            return (port, "open") if data else (port, "open|filtered")
        except socket.timeout:
            sock.close()
            return (port, "open|filtered")
    except (socket.error, OSError):
        return None


def udp_scan(
    host: str,
    ports: Optional[list[int]] = None,
    timeout: float = 2.0,
    max_workers: int = 50,
) -> list[tuple[int, str]]:
    """
    UDP scan - sends UDP probes. Open = response, closed = ICMP unreachable (scapy only).
    Without scapy: only detects ports that respond. Slower due to UDP timeouts.
    """
    ports = ports or COMMON_UDP_PORTS
    results = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_udp_scan_port, host, p, timeout): p for p in ports}
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                results.append(result)

    return sorted(results, key=lambda x: x[0])


# --- Convenience alias ---

def scan_ports(
    host: str,
    ports: Optional[list[int]] = None,
    timeout: float = 1.0,
    max_workers: int = 100,
    scan_type: str = "connect",
) -> list[int]:
    """
    Scan ports using specified method.
    scan_type: 'connect' | 'syn'
    Returns list of open ports (TCP only; for UDP use udp_scan).
    """
    if scan_type == "syn":
        return syn_scan(host, ports, timeout, max_workers)
    return tcp_connect_scan(host, ports, timeout, max_workers)
