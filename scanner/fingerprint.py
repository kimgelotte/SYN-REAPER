"""TCP/IP stack fingerprinting for OS detection."""

from dataclasses import dataclass
from typing import Optional

try:
    from scapy.all import IP, TCP, sr1
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# TTL -> typical initial TTL (OSes use 64, 128, 255)
def _normalize_ttl(ttl: int) -> int:
    if ttl <= 64:
        return 64
    if ttl <= 128:
        return 128
    return 255


# (TTL, Window) -> OS signature (simplified p0f-style)
# Window sizes vary; these are common defaults
OS_SIGNATURES = [
    (64, 5840, "Linux 2.4/2.6"),
    (64, 5720, "Linux 3.x"),
    (64, 65535, "FreeBSD"),
    (64, 65535, "OpenBSD"),
    (128, 65535, "Windows XP/2003"),
    (128, 8192, "Windows Vista/7/8/10/11"),
    (128, 64240, "Windows 10 (newer)"),
    (255, 4128, "Cisco IOS"),
    (64, 16384, "macOS"),
    (128, 65535, "Solaris"),
]


@dataclass
class FingerprintResult:
    """Stack fingerprint result."""
    host: str
    os_guess: Optional[str]
    ttl: Optional[int]
    window_size: Optional[int]
    raw_ttl: Optional[int]
    success: bool
    message: str


def fingerprint_host(host: str, port: int = 80, timeout: float = 2.0) -> FingerprintResult:
    """
    Perform TCP stack fingerprinting by sending SYN and analyzing SYN-ACK.
    Uses TTL and window size to guess OS. Requires scapy and root/admin.
    """
    if not SCAPY_AVAILABLE:
        return FingerprintResult(
            host=host,
            os_guess=None,
            ttl=None,
            window_size=None,
            raw_ttl=None,
            success=False,
            message="Scapy required for stack fingerprinting. Install: pip install scapy",
        )

    try:
        pkt = IP(dst=host) / TCP(dport=port, flags="S")
        ans = sr1(pkt, timeout=timeout, verbose=0)
        if ans is None:
            return FingerprintResult(
                host=host,
                os_guess=None,
                ttl=None,
                window_size=None,
                raw_ttl=None,
                success=False,
                message="No response (port filtered or host down)",
            )
        if not ans.haslayer(IP) or not ans.haslayer(TCP):
            return FingerprintResult(
                host=host,
                os_guess=None,
                ttl=None,
                window_size=None,
                raw_ttl=None,
                success=False,
                message="Unexpected response",
            )

        raw_ttl = ans[IP].ttl
        ttl = _normalize_ttl(raw_ttl)
        window = ans[TCP].window

        # Find best matching signature (exact TTL match, closest window)
        best_match = None
        best_score = -1
        for sig_ttl, sig_win, sig_os in OS_SIGNATURES:
            if ttl != sig_ttl:
                continue
            # Prefer exact window match
            if window == sig_win:
                best_match = sig_os
                break
            # Otherwise closest window
            diff = abs(window - sig_win)
            if best_score < 0 or diff < best_score:
                best_score = diff
                best_match = sig_os

        return FingerprintResult(
            host=host,
            os_guess=best_match or "Unknown",
            ttl=ttl,
            window_size=window,
            raw_ttl=raw_ttl,
            success=True,
            message=f"TTL={raw_ttl} (init ~{ttl}), Win={window}",
        )
    except Exception as e:
        return FingerprintResult(
            host=host,
            os_guess=None,
            ttl=None,
            window_size=None,
            raw_ttl=None,
            success=False,
            message=str(e),
        )
