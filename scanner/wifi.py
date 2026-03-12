"""
WiFi network discovery using the system wireless adapter.
Uses platform-specific commands: netsh (Windows), nmcli/iwlist (Linux), airport (macOS).
On Windows, triggers a fresh scan via WlanScan API before querying to avoid cached-only results.
Authorized testing only. Requires an available WiFi interface.
"""

import re
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class WiFiNetwork:
    """A discovered WiFi network."""
    ssid: str
    bssid: str
    signal: Optional[int]  # RSSI or percentage
    channel: Optional[int]
    security: str
    interface: Optional[str] = None


def _windows_trigger_refresh() -> bool:
    """
    Trigger a fresh WiFi scan on Windows so netsh returns more than cached/connected network.
    Uses WlanScan API (wlanapi.dll) if possible; otherwise opens network list to trigger scan.
    Returns True if a refresh was triggered, False otherwise.
    """
    if sys.platform != "win32":
        return False
    # Try 1: WlanScan via ctypes (no GUI, no admin required for scan)
    try:
        import ctypes
        from ctypes import wintypes

        wlanapi = ctypes.windll.wlanapi  # type: ignore[attr-defined]
        WLAN_API_VERSION = 2
        WLAN_NOTIFICATION_SOURCE_ACM = 0x00000008

        class GUID(ctypes.Structure):
            _fields_ = [
                ("Data1", wintypes.DWORD),
                ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD),
                ("Data4", ctypes.c_byte * 8),
            ]

        class WLAN_INTERFACE_INFO(ctypes.Structure):
            _fields_ = [
                ("InterfaceGuid", GUID),
                ("strInterfaceDescription", wintypes.WCHAR * 256),
                ("isState", wintypes.DWORD),
            ]

        WLAN_MAX_INTERFACES = 64
        class WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
            _fields_ = [
                ("dwNumberOfItems", wintypes.DWORD),
                ("dwIndex", wintypes.DWORD),
                ("InterfaceInfo", WLAN_INTERFACE_INFO * WLAN_MAX_INTERFACES),
            ]

        handle = wintypes.HANDLE()
        version = wintypes.DWORD()
        if wlanapi.WlanOpenHandle(WLAN_API_VERSION, None, ctypes.byref(version), ctypes.byref(handle)) != 0:
            raise OSError("WlanOpenHandle failed")
        try:
            iface_list = ctypes.POINTER(ctypes.c_void_p)()
            if wlanapi.WlanEnumInterfaces(handle, None, ctypes.byref(iface_list)) != 0:
                raise OSError("WlanEnumInterfaces failed")
            try:
                list_struct = ctypes.cast(iface_list, ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)).contents
                n = min(list_struct.dwNumberOfItems, WLAN_MAX_INTERFACES)
                for i in range(n):
                    iface = list_struct.InterfaceInfo[i]
                    if wlanapi.WlanScan(handle, ctypes.byref(iface.InterfaceGuid), None, None, None) == 0:
                        pass  # scan requested
                time.sleep(5)  # allow scan to complete
                return True
            finally:
                wlanapi.WlanFreeMemory(iface_list)
        finally:
            wlanapi.WlanCloseHandle(handle, None)
    except Exception:
        pass
    # Try 2: open network list UI (triggers scan); WiFi flyout may appear briefly
    try:
        subprocess.Popen(
            ["explorer.exe", "ms-availablenetworks:"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(5)
        return True
    except Exception:
        pass
    return False


def _windows_scan(timeout: int = 15) -> List[WiFiNetwork]:
    """Scan via netsh wlan show networks mode=bssid (Windows). Triggers refresh first so more networks appear."""
    result = []
    try:
        _windows_trigger_refresh()
        out = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True,
            timeout=timeout,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if out.returncode != 0:
            return []
        text = out.stdout or ""
        current: dict = {}
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("SSID ") and ":" in line:
                if current.get("bssid"):
                    result.append(WiFiNetwork(
                        ssid=current.get("ssid", ""),
                        bssid=current.get("bssid", ""),
                        signal=current.get("signal"),
                        channel=current.get("channel"),
                        security=current.get("security", "Unknown"),
                    ))
                idx = line.find(":")
                val = line[idx + 1:].strip()
                if val.startswith('"') and val.endswith('"'):
                    val = val[1:-1]
                current = {"ssid": val, "bssid": "", "signal": None, "channel": None, "security": "Unknown"}
            elif current and "BSSID " in line and ":" in line:
                if current.get("bssid"):
                    result.append(WiFiNetwork(
                        ssid=current.get("ssid", ""),
                        bssid=current.get("bssid", ""),
                        signal=current.get("signal"),
                        channel=current.get("channel"),
                        security=current.get("security", "Unknown"),
                    ))
                idx = line.find(":")
                current["bssid"] = line[idx + 1:].strip()
                current["signal"] = None
                current["channel"] = None
            elif current and line.startswith("Signal") and ":" in line:
                idx = line.find(":")
                sig = line[idx + 1:].strip().replace("%", "")
                try:
                    current["signal"] = int(sig)
                except ValueError:
                    pass
            elif current and line.startswith("Channel") and ":" in line:
                idx = line.find(":")
                try:
                    current["channel"] = int(line[idx + 1:].strip())
                except ValueError:
                    pass
            elif current and line.startswith("Authentication") and ":" in line:
                idx = line.find(":")
                current["security"] = line[idx + 1:].strip() or current.get("security", "Unknown")
        if current.get("bssid"):
            result.append(WiFiNetwork(
                ssid=current.get("ssid", ""),
                bssid=current.get("bssid", ""),
                signal=current.get("signal"),
                channel=current.get("channel"),
                security=current.get("security", "Unknown"),
            ))
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return result


def _linux_nmcli_scan(timeout: int = 15) -> List[WiFiNetwork]:
    """Scan via nmcli (NetworkManager). Preferred on Linux."""
    result = []
    try:
        out = subprocess.run(
            ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,SECURITY,CHAN", "dev", "wifi", "list"],
            capture_output=True,
            timeout=timeout,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if out.returncode != 0:
            return []
        for line in (out.stdout or "").strip().splitlines():
            parts = line.split(":")
            if len(parts) >= 4:
                ssid = parts[0].strip() or "(hidden)"
                bssid = (parts[1].strip() or "").upper()
                try:
                    signal = int(parts[2].strip()) if parts[2].strip() else None
                except ValueError:
                    signal = None
                security = parts[3].strip() if len(parts) > 3 else "Unknown"
                channel = None
                if len(parts) > 4 and parts[4].strip():
                    try:
                        channel = int(parts[4].strip())
                    except ValueError:
                        pass
                result.append(WiFiNetwork(
                    ssid=ssid,
                    bssid=bssid,
                    signal=signal,
                    channel=channel,
                    security=security or "Unknown",
                ))
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return result


def _linux_iwlist_scan(timeout: int = 20) -> List[WiFiNetwork]:
    """Scan via iwlist (wireless-tools). Fallback on Linux."""
    result = []
    try:
        # Find wireless interface
        out = subprocess.run(
            ["iwconfig"],
            capture_output=True,
            timeout=5,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if out.returncode != 0:
            return []
        iface = None
        for line in (out.stdout or "").splitlines():
            if "IEEE 802.11" in line and "no wireless" not in line.lower():
                iface = line.split()[0]
                break
        if not iface:
            return []
        out = subprocess.run(
            ["iwlist", iface, "scan"],
            capture_output=True,
            timeout=timeout,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if out.returncode != 0:
            return []
        text = out.stdout or ""
        current = {}
        for line in text.splitlines():
            line = line.strip()
            if "Cell " in line and "Address:" in line:
                if current:
                    result.append(WiFiNetwork(
                        ssid=current.get("ssid", "(hidden)"),
                        bssid=current.get("bssid", ""),
                        signal=current.get("signal"),
                        channel=current.get("channel"),
                        security=current.get("security", "WPA2" if current.get("enc") else "Open"),
                    ))
                current = {}
                idx = line.find("Address:")
                if idx >= 0:
                    current["bssid"] = line[idx + 8:].strip().upper()
            elif "ESSID:" in line:
                m = re.search(r'ESSID:"([^"]*)"', line)
                current["ssid"] = m.group(1) if m else "(hidden)"
            elif "Address:" in line and "bssid" not in current:
                current["bssid"] = line.split(":", 1)[1].strip().upper()
            elif "Quality=" in line:
                m = re.search(r"Quality=\d+/\d+\s+Signal level[=:](-?\d+)", line, re.I)
                if m:
                    current["signal"] = int(m.group(1))
            elif "Channel:" in line:
                try:
                    current["channel"] = int(line.split(":", 1)[1].strip())
                except ValueError:
                    pass
            elif "Encryption key:" in line:
                current["enc"] = "on" in line.lower()
            elif "IE:" in line and "WPA" in line:
                current["security"] = "WPA2"
            elif "IE:" in line and "WEP" in line:
                current["security"] = "WEP"
        if current:
            result.append(WiFiNetwork(
                ssid=current.get("ssid", "(hidden)"),
                bssid=current.get("bssid", ""),
                signal=current.get("signal"),
                channel=current.get("channel"),
                security=current.get("security", "WPA2" if current.get("enc") else "Open"),
            ))
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return result


def _macos_scan(timeout: int = 15) -> List[WiFiNetwork]:
    """Scan via airport -s (macOS)."""
    result = []
    try:
        # airport is at /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport
        out = subprocess.run(
            ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-s"],
            capture_output=True,
            timeout=timeout,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if out.returncode != 0:
            return []
        lines = (out.stdout or "").strip().splitlines()
        if not lines:
            return []
        # Header: SSID BSSID RSSI CHANNEL HT CC SECURITY
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 4:
                ssid = parts[0]
                bssid = (parts[1] or "").upper()
                try:
                    signal = int(parts[2]) if parts[2].lstrip("-").isdigit() else None
                except ValueError:
                    signal = None
                try:
                    channel = int(parts[3]) if parts[3].isdigit() else None
                except (ValueError, IndexError):
                    channel = None
                security = parts[-1] if len(parts) > 4 else "Unknown"
                result.append(WiFiNetwork(
                    ssid=ssid,
                    bssid=bssid,
                    signal=signal,
                    channel=channel,
                    security=security,
                ))
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return result


def scan_wifi_networks(timeout: int = 15) -> List[WiFiNetwork]:
    """
    Scan for nearby WiFi networks using the system wireless adapter.
    Returns a list of WiFiNetwork (SSID, BSSID, signal, channel, security).
    """
    if sys.platform == "win32":
        return _windows_scan(timeout=timeout)
    if sys.platform == "darwin":
        return _macos_scan(timeout=timeout)
    # Linux: try nmcli first, then iwlist
    out = _linux_nmcli_scan(timeout=timeout)
    if out:
        return out
    return _linux_iwlist_scan(timeout=timeout)
