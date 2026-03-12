"""
Device type detection - Infer device type from ports, banners, and HTTP content.
"""

import re
import ssl
from dataclasses import dataclass
from typing import Optional
from urllib.request import Request, urlopen

from scanner.obfuscate import get_http_headers


@dataclass
class DeviceInfo:
    """Detected device information."""
    device_type: str
    vendor: Optional[str]
    model: Optional[str]
    confidence: str  # high, medium, low
    details: str


# Port signatures: (set of ports) -> (device_type, vendor_hint)
PORT_SIGNATURES = [
    # Windows
    ({135, 139, 445}, "Windows PC/Server", "Microsoft", "high"),
    ({135, 445}, "Windows PC/Server", "Microsoft", "high"),
    ({3389}, "Windows (RDP)", "Microsoft", "medium"),
    # Router / Gateway
    ({53, 80, 443}, "Router/Gateway", None, "medium"),
    ({53, 80, 8443}, "Router/Gateway", None, "medium"),
    ({80, 443, 8443}, "Router/Gateway", None, "low"),
    ({80, 8443}, "Router/Gateway", None, "low"),
    # Printer
    ({9100}, "Printer", None, "high"),
    ({515, 9100}, "Printer", None, "high"),
    ({631}, "Printer (IPP)", None, "high"),
    ({548}, "Apple Printer/Share", "Apple", "high"),
    # NAS
    ({5000, 5001}, "NAS", "Synology", "high"),
    ({8080, 8443}, "NAS/Embedded", None, "low"),
    # Database
    ({3306}, "Database Server", "MySQL", "medium"),
    ({5432}, "Database Server", "PostgreSQL", "medium"),
    ({27017}, "Database Server", "MongoDB", "medium"),
    ({6379}, "Cache/DB", "Redis", "medium"),
    # Linux/Server
    ({22, 80, 443}, "Linux Server", None, "low"),
    ({22, 80}, "Linux Server", None, "low"),
    # Smart TVs
    ({8008, 8009}, "Smart TV/Streaming", "Google (Chromecast)", "high"),
    ({8008}, "Smart TV/Streaming", "Chromecast", "medium"),
    ({8060, 8061}, "Smart TV/Streaming", "Roku", "high"),
    ({8060}, "Smart TV/Streaming", "Roku", "medium"),
    ({55000, 7676}, "Smart TV", "Samsung", "high"),
    ({10243}, "Smart TV", "LG webOS", "high"),
    ({3000, 3001}, "Smart TV/Streaming", "LG/Roku", "medium"),
    ({7000, 7100}, "Apple TV / AirPlay", "Apple", "high"),
    ({7000}, "Apple TV / AirPlay", "Apple", "medium"),
    # Smartphones / Tablets (when exposing services)
    ({5555}, "Android Device", "Android (ADB)", "high"),
    ({62078}, "iPhone/iPad", "Apple (Lockdown)", "high"),
    # IoT devices
    ({80, 8080}, "IoT Device", None, "medium"),
    ({80, 554}, "IP Camera", None, "high"),  # RTSP
    ({80, 8883}, "IoT Device", None, "medium"),  # MQTT
    ({8080}, "IoT/Embedded", None, "low"),
    ({8000, 8080}, "IoT/Embedded", None, "low"),
    ({80}, "IoT/Phone/TV", None, "low"),  # Generic - could be many things
]

# HTTP content keywords: (pattern, device_type, vendor?)
HTTP_SIGNATURES = [
    (r"router|gateway|modem", "Router/Gateway", None),
    (r"synology|diskstation", "NAS", "Synology"),
    (r"qnap", "NAS", "QNAP"),
    (r"netgear", "Router", "Netgear"),
    (r"tp-link|tplink", "Router", "TP-Link"),
    (r"asus", "Router", "Asus"),
    (r"linksys", "Router", "Linksys"),
    (r"d-link|dlink", "Router", "D-Link"),
    (r"ubiquiti|unifi", "Network Device", "Ubiquiti"),
    (r"hp.*print|laserjet|officejet", "Printer", "HP"),
    (r"epson", "Printer", "Epson"),
    (r"brother", "Printer", "Brother"),
    (r"canon.*print", "Printer", "Canon"),
    (r"cups|ipp.*print", "Printer", None),
    (r"phpmyadmin", "Web App", None),
    (r"wordpress", "Web Server", None),
    (r"apache|httpd", "Web Server", None),
    (r"nginx", "Web Server", None),
    # Smart TVs
    (r"roku|roku\.com", "Smart TV", "Roku"),
    (r"samsung.*tv|smart.?tv", "Smart TV", "Samsung"),
    (r"lg.*tv|webos", "Smart TV", "LG"),
    (r"chromecast|google.?cast", "Streaming Device", "Google"),
    (r"apple.?tv|airplay", "Apple TV", "Apple"),
    (r"vizio", "Smart TV", "Vizio"),
    (r"sony.*bravia|bravia", "Smart TV", "Sony"),
    # IoT / Smart Home
    (r"philips.?hue|hue.?bridge", "Smart Lighting", "Philips"),
    (r"smartthings|samsung.?iot", "IoT Hub", "Samsung"),
    (r"nest|google.?home", "Smart Home", "Google"),
    (r"echo|alexa|amazon.?fire", "Smart Speaker", "Amazon"),
    (r"ring|blink", "Smart Camera", None),
    (r"wyze", "Smart Camera", "Wyze"),
    (r"tp-link|kasa|tapo", "Smart Plug/IoT", "TP-Link"),
    (r"tuya|smart.?life", "IoT Device", "Tuya"),
    (r"esp32|esp8266|espressif", "IoT Device", "Espressif"),
    # Phones / Tablets (web interfaces)
    (r"android|adb", "Android Device", "Android"),
    (r"iphone|ipad|ios", "Apple Device", "Apple"),
]


def _fetch_http_content(host: str, port: int, timeout: float = 2.0) -> Optional[str]:
    """Fetch HTTP page content for analysis."""
    try:
        url = f"http://{host}:{port}/" if port != 80 else f"http://{host}/"
        req = Request(url, headers=get_http_headers())
        with urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="ignore").lower()
    except Exception:
        pass
    return None


def _fetch_https_content(host: str, port: int, timeout: float = 2.0) -> Optional[str]:
    """Fetch HTTPS page content."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        url = f"https://{host}:{port}/" if port != 443 else f"https://{host}/"
        req = Request(url, headers=get_http_headers())
        with urlopen(req, timeout=timeout, context=ctx) as r:
            return r.read().decode("utf-8", errors="ignore").lower()
    except Exception:
        pass
    return None


def detect_device(
    host: str,
    open_ports: list[int],
    banners: Optional[dict[int, str]] = None,
    timeout: float = 2.0,
) -> DeviceInfo:
    """
    Detect device type from open ports, banners, and HTTP content.
    banners: optional dict of port -> banner string
    """
    banners = banners or {}
    port_set = set(open_ports)
    best_match = None
    best_score = 0

    # Check port signatures (prefer more specific matches)
    for sig_ports, device_type, vendor, conf in PORT_SIGNATURES:
        if sig_ports <= port_set:
            score = len(sig_ports) * (3 if conf == "high" else 2 if conf == "medium" else 1)
            if score > best_score:
                best_score = score
                best_match = (device_type, vendor, conf)

    # Check HTTP/HTTPS content for better identification
    http_content = None
    for port in [80, 443, 8080, 8443, 8000]:
        if port in open_ports:
            if port in (443, 8443, 4433):
                http_content = _fetch_https_content(host, port, timeout)
            else:
                http_content = _fetch_http_content(host, port, timeout)
            if http_content:
                break

    if http_content:
        for pattern, device_type, vendor in HTTP_SIGNATURES:
            if re.search(pattern, http_content):
                return DeviceInfo(
                    device_type=device_type,
                    vendor=vendor,
                    model=None,
                    confidence="high",
                    details=f"Matched in HTTP content",
                )

    # Check banners for vendor hints
    for port, banner in banners.items():
        if banner:
            banner_lower = banner.lower()
            if "windows" in banner_lower or "microsoft" in banner_lower:
                return DeviceInfo("Windows", "Microsoft", None, "high", f"Banner: {banner[:60]}")
            if "synology" in banner_lower:
                return DeviceInfo("NAS", "Synology", None, "high", f"Banner: {banner[:60]}")
            if "apache" in banner_lower or "httpd" in banner_lower:
                if best_match and "Router" in best_match[0]:
                    return DeviceInfo("Router/Gateway", None, None, "medium", f"Banner: {banner[:60]}")

    if best_match:
        device_type, vendor, conf = best_match
        return DeviceInfo(
            device_type=device_type,
            vendor=vendor,
            model=None,
            confidence=conf,
            details=f"Port signature: {', '.join(map(str, sorted(port_set)))}",
        )

    # Fallback
    if open_ports:
        return DeviceInfo(
            device_type="Unknown",
            vendor=None,
            model=None,
            confidence="low",
            details=f"Open ports: {', '.join(map(str, sorted(open_ports)))}",
        )
    return DeviceInfo("Unknown", None, None, "low", "No open ports")
