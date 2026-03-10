"""
Scan issue tracking - Records reasons for incomplete scans, failures, or interruptions.
"""

from dataclasses import dataclass
from typing import List, Optional


@dataclass
class ScanIssue:
    """Record of a scan/bruteforce failure or interruption."""
    phase: str       # "scan", "bruteforce", "exploit", "fingerprint", "device"
    reason: str      # Human-readable reason
    port: Optional[int] = None
    service: Optional[str] = None
    detail: Optional[str] = None  # Raw exception or extra context


def _normalize_error(exc: Exception) -> str:
    """Convert exception to user-friendly reason."""
    msg = str(exc).lower()
    if "connection refused" in msg or "errno 111" in msg or "errno 10061" in msg:
        return "Connection refused (port closed or filtered)"
    if "connection reset" in msg or "errno 104" in msg or "errno 10054" in msg:
        return "Connection reset (host may have dropped connection)"
    if "timed out" in msg or "timeout" in msg:
        return "Timeout"
    if "no route" in msg or "host unreachable" in msg or "errno 113" in msg:
        return "Host unreachable"
    if "connection reset by peer" in msg:
        return "Connection reset by peer (possible rate limit or kicked off)"
    if "too many" in msg or "rate limit" in msg:
        return "Rate limited or too many attempts"
    if "permission denied" in msg or "access denied" in msg:
        return "Permission denied"
    if "no module" in msg or "import" in msg:
        return "Missing dependency"
    return str(exc)[:100] or type(exc).__name__
