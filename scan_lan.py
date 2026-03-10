#!/usr/bin/env python3
"""
Quick LAN scan - detects your subnet and scans all devices.
Run: python scan_lan.py
"""

import socket
import subprocess
import sys
from pathlib import Path

# Add project root
sys.path.insert(0, str(Path(__file__).parent))

from main import main as run_main


def get_local_subnet() -> str:
    """Detect local subnet from default route / primary interface."""
    try:
        # Get host's IP to determine subnet
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        # Assume /24 - use first 3 octets
        parts = ip.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except Exception:
        pass
    return "192.168.1.0/24"  # Fallback


if __name__ == "__main__":
    subnet = get_local_subnet()
    print(f"Scanning LAN: {subnet}")
    print("(Edit scan_lan.py to change subnet)\n")

    # Override sys.argv for main()
    sys.argv = [
        "main.py",
        subnet,
        "--scan-all",
        "--exploit",
        "-o", "report.html",
    ]
    run_main()
