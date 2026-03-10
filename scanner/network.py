"""Network host discovery."""

import ipaddress
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from scapy.all import ARP, Ether, srp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def arp_discover(network: str, timeout: int = 2) -> list[str]:
    """
    Discover live hosts using ARP who-has. Faster than ping when ICMP blocked.
    Requires scapy and admin/root privileges. Returns empty list on failure.
    """
    if not SCAPY_AVAILABLE:
        return []
    try:
        net = ipaddress.ip_network(network, strict=False)
        if net.num_addresses > 65536:
            return []  # Avoid huge subnets
        target = str(net.network_address)
        # ARP who-has for subnet
        arp = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(net))
        ans, _ = srp(arp, timeout=timeout, verbose=0)
        return sorted([r[1].psrc for r in ans if r[1].haslayer(ARP)], key=lambda x: ipaddress.ip_address(x))
    except (PermissionError, OSError, Exception):
        return []


def ping_host(host: str, timeout: int = 1) -> bool:
    """Check if a host is reachable via ICMP ping."""
    if sys.platform == "win32":
        cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout), host]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout + 2,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def discover_hosts(network: str, timeout: int = 1, max_workers: int = 50, use_arp: bool = True) -> list[str]:
    """
    Discover live hosts on a network. Uses ARP who-has when scapy available (faster when ICMP blocked),
    otherwise falls back to ping sweep.
    network: CIDR notation (e.g., 192.168.1.0/24) or single IP
    """
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError:
        return [network] if ping_host(network, timeout) else []

    # Single IP: ping only
    if net.num_addresses <= 2:
        return [network] if ping_host(network, timeout) else []

    # Subnet: try ARP first when available
    if use_arp and SCAPY_AVAILABLE:
        live = arp_discover(network, timeout=timeout)
        if live:
            return live
        # ARP failed (e.g. no admin) or empty - fall back to ping

    hosts = [str(ip) for ip in net.hosts()]
    live_hosts = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(ping_host, h, timeout): h for h in hosts}
        for future in as_completed(futures):
            if future.result():
                live_hosts.append(futures[future])

    return sorted(live_hosts, key=lambda x: ipaddress.ip_address(x))


def get_all_hosts(network: str) -> list[str]:
    """
    Get all host IPs in a CIDR range without ping.
    Use when ICMP is blocked or hosts don't respond to ping.
    """
    try:
        net = ipaddress.ip_network(network, strict=False)
        return sorted([str(ip) for ip in net.hosts()], key=lambda x: ipaddress.ip_address(x))
    except ValueError:
        return [network]
