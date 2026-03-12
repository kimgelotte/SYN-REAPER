"""
WiFi Connect Module - Auto-connect with cracked PSK, DHCP wait, subnet discovery.
Cross-platform: nmcli/wpa_supplicant on Linux, netsh on Windows.
WARNING: Authorized testing only.
"""

import platform
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass
from ipaddress import ip_interface
from pathlib import Path
from typing import Optional, Tuple

_IS_LINUX = platform.system() == "Linux"
_IS_WINDOWS = platform.system() == "Windows"
_IS_MAC = platform.system() == "Darwin"

_TEMP_PROFILE_NAME = "SYNREAPER_TEMP"


@dataclass
class ConnectionResult:
    connected: bool = False
    interface: str = ""
    ip: str = ""
    subnet: str = ""
    gateway: str = ""
    cidr: str = ""


def _run_cmd(cmd: list[str], timeout: int = 30) -> Tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return -2, "", "Command timed out"


def connect_to_wifi(ssid: str, psk: str, interface: Optional[str] = None) -> Tuple[bool, str]:
    """
    Connect to a WiFi network using the cracked PSK.
    Returns (connected, interface_name).
    """
    if _IS_LINUX:
        return _connect_linux(ssid, psk, interface)
    elif _IS_WINDOWS:
        return _connect_windows(ssid, psk, interface)
    elif _IS_MAC:
        return _connect_mac(ssid, psk)
    return False, f"Unsupported platform: {platform.system()}"


def _connect_linux(ssid: str, psk: str, interface: Optional[str] = None) -> Tuple[bool, str]:
    """Connect on Linux using nmcli or wpa_supplicant."""
    # Try nmcli first (NetworkManager)
    iface_arg = ["ifname", interface] if interface else []
    rc, out, err = _run_cmd(
        ["nmcli", "device", "wifi", "connect", ssid, "password", psk] + iface_arg,
        timeout=30,
    )
    if rc == 0 and "successfully" in out.lower():
        used_iface = interface or _detect_connected_interface_linux(ssid)
        print(f"  Connected to {ssid} via nmcli (interface: {used_iface})")
        return True, used_iface

    # Fallback: wpa_supplicant
    if interface:
        conf_content = f"""
network={{
    ssid="{ssid}"
    psk="{psk}"
    key_mgmt=WPA-PSK
}}
"""
        conf_file = Path(tempfile.gettempdir()) / "synreaper_wpa.conf"
        conf_file.write_text(conf_content)
        _run_cmd(["ip", "link", "set", interface, "up"])
        subprocess.Popen(
            ["wpa_supplicant", "-B", "-i", interface, "-c", str(conf_file)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(3)
        _run_cmd(["dhclient", interface], timeout=15)
        ip_info = _get_interface_ip_linux(interface)
        if ip_info and ip_info[0]:
            print(f"  Connected to {ssid} via wpa_supplicant (interface: {interface})")
            return True, interface

    return False, ""


def _detect_connected_interface_linux(ssid: str) -> str:
    """Find which interface is connected to the given SSID."""
    rc, out, _ = _run_cmd(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device"])
    if rc == 0:
        for line in out.splitlines():
            parts = line.split(":")
            if len(parts) >= 4 and "wifi" in parts[1].lower() and "connected" in parts[2].lower():
                return parts[0]
    rc, out, _ = _run_cmd(["iw", "dev"])
    if rc == 0:
        current = ""
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("Interface"):
                current = line.split()[-1]
            elif "ssid" in line.lower() and ssid.lower() in line.lower():
                return current
    return ""


def _connect_windows(ssid: str, psk: str, interface: Optional[str] = None) -> Tuple[bool, str]:
    """Connect on Windows using netsh."""
    profile_xml = f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{_TEMP_PROFILE_NAME}</name>
    <SSIDConfig>
        <SSID>
            <name>{ssid}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>manual</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>{psk}</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>"""

    xml_path = Path(tempfile.gettempdir()) / "synreaper_wifi.xml"
    xml_path.write_text(profile_xml)

    # Remove old profile if exists
    _run_cmd(["netsh", "wlan", "delete", "profile", f"name={_TEMP_PROFILE_NAME}"])
    # Add profile
    rc, out, err = _run_cmd(["netsh", "wlan", "add", "profile", f"filename={xml_path}"])
    if rc != 0:
        return False, f"Failed to add profile: {err}"

    # Connect
    iface_arg = [f"interface={interface}"] if interface else []
    rc, out, err = _run_cmd(
        ["netsh", "wlan", "connect", f"name={_TEMP_PROFILE_NAME}", f"ssid={ssid}"] + iface_arg,
        timeout=15,
    )
    time.sleep(5)

    # Check connection
    rc2, out2, _ = _run_cmd(["netsh", "wlan", "show", "interfaces"])
    if ssid.lower() in out2.lower() and "connected" in out2.lower():
        used_iface = interface or _detect_connected_interface_windows()
        print(f"  Connected to {ssid} via netsh (interface: {used_iface})")
        try:
            xml_path.unlink()
        except Exception:
            pass
        return True, used_iface

    try:
        xml_path.unlink()
    except Exception:
        pass
    return False, ""


def _detect_connected_interface_windows() -> str:
    """Get the name of the connected WiFi interface on Windows."""
    rc, out, _ = _run_cmd(["netsh", "wlan", "show", "interfaces"])
    if rc == 0:
        for line in out.splitlines():
            line = line.strip()
            if ":" in line:
                k, _, v = line.partition(":")
                if "name" in k.lower() and "profile" not in k.lower():
                    return v.strip()
    return ""


def _connect_mac(ssid: str, psk: str) -> Tuple[bool, str]:
    """Connect on macOS using networksetup."""
    rc, out, err = _run_cmd(
        ["networksetup", "-setairportnetwork", "en0", ssid, psk],
        timeout=15,
    )
    if rc == 0:
        print(f"  Connected to {ssid} via networksetup (en0)")
        return True, "en0"
    return False, ""


def wait_for_dhcp(interface: str, timeout: int = 30) -> Optional[Tuple[str, str, str]]:
    """
    Wait for the interface to get an IP via DHCP.
    Returns (ip, subnet_mask, gateway) or None on timeout.
    """
    start = time.time()
    while time.time() - start < timeout:
        if _IS_LINUX:
            result = _get_interface_ip_linux(interface)
        elif _IS_WINDOWS:
            result = _get_interface_ip_windows(interface)
        elif _IS_MAC:
            result = _get_interface_ip_mac(interface)
        else:
            return None

        if result and result[0] and not result[0].startswith("169.254"):
            return result
        time.sleep(2)
    return None


def _get_interface_ip_linux(interface: str) -> Optional[Tuple[str, str, str]]:
    """Get IP, subnet mask, gateway for an interface on Linux."""
    rc, out, _ = _run_cmd(["ip", "-4", "addr", "show", interface])
    ip_addr = ""
    prefix = ""
    if rc == 0:
        for line in out.splitlines():
            m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
            if m:
                ip_addr = m.group(1)
                prefix = m.group(2)
                break
    gateway = ""
    rc2, out2, _ = _run_cmd(["ip", "route", "show", "default"])
    if rc2 == 0:
        for line in out2.splitlines():
            if "via" in line and (interface in line or not interface):
                parts = line.split()
                idx = parts.index("via") if "via" in parts else -1
                if idx >= 0 and idx + 1 < len(parts):
                    gateway = parts[idx + 1]
                    break
    if ip_addr:
        mask = str(ip_interface(f"{ip_addr}/{prefix}").network.netmask) if prefix else "255.255.255.0"
        return (ip_addr, mask, gateway)
    return None


def _get_interface_ip_windows(interface: str) -> Optional[Tuple[str, str, str]]:
    """Get IP, subnet mask, gateway for an interface on Windows."""
    rc, out, _ = _run_cmd(["ipconfig"])
    if rc != 0:
        return None
    in_section = False
    ip_addr = ""
    mask = ""
    gateway = ""
    for line in out.splitlines():
        if interface.lower() in line.lower() or "wireless" in line.lower() or "wi-fi" in line.lower():
            in_section = True
            continue
        if in_section:
            if line.strip() == "":
                if ip_addr:
                    break
                in_section = False
                continue
            if "ipv4" in line.lower() or "ip address" in line.lower():
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if m:
                    ip_addr = m.group(1)
            elif "subnet" in line.lower() or "mask" in line.lower():
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if m:
                    mask = m.group(1)
            elif "gateway" in line.lower():
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if m:
                    gateway = m.group(1)
    if ip_addr:
        return (ip_addr, mask or "255.255.255.0", gateway)
    return None


def _get_interface_ip_mac(interface: str) -> Optional[Tuple[str, str, str]]:
    """Get IP info on macOS."""
    rc, out, _ = _run_cmd(["ifconfig", interface])
    ip_addr = ""
    mask = ""
    if rc == 0:
        for line in out.splitlines():
            m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(\S+)", line)
            if m:
                ip_addr = m.group(1)
                hex_mask = m.group(2)
                try:
                    mask_int = int(hex_mask, 16)
                    mask = f"{(mask_int >> 24) & 0xff}.{(mask_int >> 16) & 0xff}.{(mask_int >> 8) & 0xff}.{mask_int & 0xff}"
                except ValueError:
                    mask = hex_mask
    gateway = ""
    rc2, out2, _ = _run_cmd(["route", "-n", "get", "default"])
    if rc2 == 0:
        for line in out2.splitlines():
            if "gateway" in line.lower():
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if m:
                    gateway = m.group(1)
    if ip_addr:
        return (ip_addr, mask, gateway)
    return None


def get_target_subnet(interface: str) -> Optional[str]:
    """
    After DHCP, read gateway and subnet from the interface.
    Returns CIDR (e.g. '192.168.2.0/24') or None.
    """
    if _IS_LINUX:
        info = _get_interface_ip_linux(interface)
    elif _IS_WINDOWS:
        info = _get_interface_ip_windows(interface)
    elif _IS_MAC:
        info = _get_interface_ip_mac(interface)
    else:
        return None

    if not info or not info[0]:
        return None

    ip_addr, mask, gateway = info
    try:
        iface = ip_interface(f"{ip_addr}/{mask}")
        return str(iface.network)
    except Exception:
        try:
            iface = ip_interface(f"{ip_addr}/24")
            return str(iface.network)
        except Exception:
            return None


def disconnect_from_wifi(ssid: str, interface: Optional[str] = None) -> bool:
    """Disconnect and clean up temporary profiles."""
    if _IS_LINUX:
        rc, _, _ = _run_cmd(["nmcli", "device", "disconnect", interface or ""])
        if rc != 0 and interface:
            _run_cmd(["ip", "link", "set", interface, "down"])
        wpa_conf = Path(tempfile.gettempdir()) / "synreaper_wpa.conf"
        if wpa_conf.exists():
            try:
                wpa_conf.unlink()
            except Exception:
                pass
        return True
    elif _IS_WINDOWS:
        _run_cmd(["netsh", "wlan", "disconnect"])
        _run_cmd(["netsh", "wlan", "delete", "profile", f"name={_TEMP_PROFILE_NAME}"])
        return True
    elif _IS_MAC:
        _run_cmd(["networksetup", "-removepreferredwirelessnetwork", "en0", ssid])
        return True
    return False
