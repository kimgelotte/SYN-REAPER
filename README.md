# SYN-REAPER

Network and port vulnerability scanner for authorized security testing. Discovers hosts, scans ports, checks for common vulnerabilities, and produces compliance-oriented reports.

---

<div align="center">

## ⚠️ WARNING

**AUTHORIZED TESTING ONLY**

Unauthorized scanning may violate computer crime laws (e.g. CFAA, Computer Misuse Act). Obtain written permission before scanning any network you do not own or control.

**Use at your own risk.** The authors are not responsible for misuse.

</div>

---

## Features

- **Network discovery** – ICMP ping or full CIDR enumeration (scan-all mode when ICMP is blocked)
- **Port scanning** – TCP Connect (default) or SYN (half-open) with optional UDP
- **Vulnerability checks** – Banner grabbing, service identification, risk assessment
- **Exploit probes** – Anonymous FTP, HTTP path discovery, Redis/MongoDB auth, SMB null session, EternalBlue
- **Security audits** – SSL/TLS, SSH algorithms, web headers, SNMP defaults
- **Brute force** – FTP, SSH, HTTP, MySQL (authorized testing only)
- **Device detection** – Network device fingerprinting
- **Compliance** – CIS, PCI-DSS, NIST 800-53 control mapping and matrix reports
- **CVE/CVSS** – Local CVE database and NVD API lookup for findings
- **Reports** – JSON, HTML, plain text, or SARIF (CI/CD integration)
- **Web interface** – Run scans from a browser and view results (check incoming security)
- **WiFi scan** – Discover nearby WiFi networks (SSID, BSSID, signal, channel, security) using the system wireless adapter
- **WiFi red team** – Full external attack chain: capture handshake, crack WiFi key, auto-connect, discover subnet, then run internal pen-test (see [WiFi Red Team](#wifi-red-team))
- **Post-exploitation** – After cracking credentials: enumerate SMB shares, FTP files, SSH info, MySQL/PostgreSQL databases, HTTP admin panels (report only, no data extraction)
- **AI agent** – Let the AI choose which hosts to scan, or `ATTACK_WIFI` to drive the full external WiFi attack chain autonomously (see [AI agent](#ai-agent-ai-runs-scans-and-exploits))

## Requirements

- Python 3.10+
- **SYN scan** requires [scapy](https://scapy.net/) and root/admin privileges

## Installation

```bash
git clone https://github.com/kimgelotte/SYN-REAPER.git
cd SYN-REAPER
pip install -r requirements.txt
```

**Optional dependencies:**

```bash
pip install pymysql   # MySQL brute force + exploit
pip install pysmb     # SMB null session (exploit)
pip install pymongo   # MongoDB no-auth check (exploit)
pip install psycopg2  # PostgreSQL brute force
pip install openai    # AI report analysis
pip install python-dotenv  # Load .env for settings
```

## Configuration (.env)

Copy `.env.example` to `.env` and customize. **Never commit `.env`** – it may contain API keys and scan preferences.

```bash
copy .env.example .env   # Windows
cp .env.example .env    # Linux/Mac
```

### Scan settings (main.py)

| Variable | Values | Description |
|----------|--------|-------------|
| `SCAN_PROFILE` | `quick`, `standard`, `deep`, `pentest` | Preset: quick (ports only), standard (+exploit+brute), deep (all), pentest (deep + web-advanced) |
| `SCAN_EXPLOIT` | `true`/`false` | Exploit checks (FTP, HTTP paths, Redis, SMB) |
| `SCAN_BRUTEFORCE` | `true`/`false` | Brute force FTP/SSH/HTTP/MySQL |
| `SCAN_SSL_CHECK` | `true`/`false` | SSL/TLS and certificate checks |
| `SCAN_SSH_AUDIT` | `true`/`false` | SSH weak algorithm audit |
| `SCAN_WEB_DEEP` | `true`/`false` | Extended web path discovery |
| `SCAN_INJECTION` | `true`/`false` | SQL injection probes (including time-based blind) |
| `SCAN_WEB_ADVANCED` | `true`/`false` | XSS reflection and path traversal probes (pentest-level) |
| `SCAN_POST_EXPLOIT` | `true`/`false` | Post-exploitation recon after brute force (auto with pentest profile) |
| `SCAN_AI_BRUTEFORCE` | `true`/`false` | Use AI to suggest bruteforce credentials per service |
| `SCAN_INCLUDE_ROUTER` | `true`/`false` | Include default gateway (router) in pen test |
| `SCAN_OBFUSCATE` | `true`/`false` | Browser-like User-Agents, random port order, pacing (reduces blocking) |
| `SCAN_WIFI` | `true`/`false` | Scan nearby WiFi networks (wireless adapter) |
| `SCAN_UDP` | `true`/`false` | Include UDP port scan |
| `SCAN_FINGERPRINT` | `true`/`false` | OS stack fingerprinting |
| `SCAN_TYPE` | `connect`, `syn` | TCP scan type |
| `SCAN_TIMEOUT` | `1.0` | Timeout in seconds |
| `SCAN_COMPLIANCE` | `cis`, `pci-dss`, `nist`, `all` | Compliance profile for reports |

### AI settings (analyze.py)

| Variable | Values | Description |
|----------|--------|-------------|
| `OPENAI_API_KEY` | `sk-...` | OpenAI API key (for cloud) |
| `OPENAI_API_BASE` | `http://localhost:11434/v1` | Self-hosted base URL (Ollama, etc.) |
| `AI_ANONYMIZE` | `true`/`false` | Force anonymization; unset = auto (external=yes, local=no) |
| `AI_MODEL` | `gpt-4o-mini`, `llama3.1` | Model name |

CLI flags override `.env` values.

### Do scans leave traces?

**Yes.** Scans are not stealthy and leave traces in several places.

| Where | What leaves a trace |
|-------|----------------------|
| **Target network / hosts** | **Port scans:** TCP Connect (default) does a full 3-way handshake per port, so connections appear in firewall/connection tables and logs. SYN scan (with Scapy) sends SYN packets that IDS/IPS (e.g. Snort, Suricata) can flag as port-scanning. **HTTP/HTTPS:** All web requests use the User-Agent `SYN-REAPER/1.0`, which appears in server access logs. **Auth attempts:** SSH, FTP, HTTP Basic, MySQL, etc. show up as failed/successful logins in auth logs. **Other:** ARP discovery, UDP probes, and path/exploit checks are visible to anyone capturing traffic or reading device logs. |
| **Your machine** | **Reports:** JSON/HTML/text/SARIF and (when using the web UI) `scans/last_scan.json`, `scans/last_scan.log`. **CLI:** If you run from a terminal, the command may remain in shell history. |

For authorized testing this is usually acceptable; for red-team or “low and slow” scenarios you would need different tooling and techniques. Use **`--obfuscate`** (or **Obfuscate** in the web UI) to reduce blocking: browser-like User-Agents, random port order, lower concurrency, and pacing for high-quality pen-tests that are less likely to be throttled or blocked.

## Web interface

Run the scanner from a browser to check your **incoming security** (what’s exposed from the network’s perspective):

```bash
pip install flask   # if not already installed
python web_app.py
```

Then open **http://127.0.0.1:5000**. Enter a target (e.g. your public IP or internal range like `192.168.1.0/24`), choose a profile (Quick / Standard / Deep / Pentest), and optionally enable **Scan all IPs** if ICMP is blocked. Click **Start scan** and open **View last results** to see findings when the scan finishes.

**Security:** The app binds to `127.0.0.1` by default. Do **not** expose it to the internet. Use only for authorized testing.

```bash
python web_app.py --host 127.0.0.1 --port 5000   # default
python web_app.py --port 8080                   # custom port
```

## Usage

```bash
python main.py <target> [options]
```

**Target:** IP address, hostname, or CIDR (e.g. `192.168.1.0/24`)

### Quick start

```bash
# Basic scan (uses .env defaults if set)
python main.py 192.168.1.0/24

# Save report
python main.py 192.168.1.0/24 -o report.html
```

### Common examples

```bash
# Scan subnet (TCP Connect, no privileges)
python main.py 192.168.1.0/24

# SYN scan (stealth, needs scapy + admin)
python main.py 192.168.1.1 --scan syn

# Include UDP ports
python main.py 10.0.0.1 --udp

# Skip discovery, single host
python main.py 127.0.0.1 -s

# Scan all IPs when ICMP is blocked
python main.py 192.168.1.0/24 --scan-all

# Save HTML report with compliance matrix
python main.py 192.168.1.0/24 -o report.html --compliance pci-dss

# Full scan with exploit checks and SARIF output
python main.py 192.168.1.0/24 -A -e -o results.sarif --compliance all
```

### Options

| Option | Description |
|--------|-------------|
| `-s`, `--skip-discovery` | Treat target as single host, skip discovery |
| `-A`, `--scan-all` | Skip ping; scan all IPs in CIDR |
| `-p`, `--ports` | Specific ports to scan |
| `-S`, `--scan` | `connect` or `syn` |
| `-u`, `--udp` | Include UDP port scan |
| `-F`, `--fingerprint` | OS stack fingerprinting |
| `--no-banner` | Skip banner grabbing (faster) |
| `-t`, `--timeout` | Timeout in seconds |
| `-o`, `--report` | Save report (.json, .html, .txt, .sarif) |
| `--compliance` | Profile: `cis`, `pci-dss`, `nist`, `all` |
| `--all-ports` | Scan all 65535 TCP ports |
| `-e`, `--exploit` | Run exploit checks |
| `-b`, `--bruteforce` | Brute force FTP/SSH/HTTP/MySQL |
| `--bruteforce-wordlist` | Custom wordlist file (`user:pass` per line) |
| `--bruteforce-delay` | Delay between attempts in seconds (default: 0.5) |
| `--ai-bruteforce` | Use AI to suggest bruteforce credentials per host/port (falls back to wordlist if AI unavailable) |
| `--ssl-check` | SSL/TLS and certificate checks |
| `--ssh-audit` | SSH weak algorithm audit |
| `--web-deep` | Extended web path discovery |
| `--injection` | SQL injection probes (error-based + time-based blind) |
| `--web-advanced` | XSS reflection and path traversal probes |
| `--wifi`, `-W` | Scan nearby WiFi networks (system wireless adapter) |
| `--include-router` | Include default gateway (router) in pen test: extra ports, admin paths, default creds |
| `--obfuscate` | Reduce blocking: browser-like User-Agents, random port order, lower concurrency, pacing (slower, high-quality pen-test) |
| `--post-exploit` | Post-exploitation recon after brute force (SMB/FTP/SSH/DB enum) |
| `--mac` | Target by MAC address (uses ARP to resolve; target must be CIDR, requires scapy) |
| `--rate-limit` | Delay between requests in seconds (throttle for production systems) |
| `--profile` | `quick`, `standard`, `deep`, or `pentest` |
| `--scope-file` | Restrict targets to IPs in file |
| `--dry-run` | Show what would be scanned |

### Bruteforce wordlist

Use `--bruteforce-wordlist` to supply a custom credential list. Put the file anywhere and pass its path:

```bash
python main.py 192.168.1.0/24 -b --bruteforce-wordlist wordlist.txt
```

**Format:** One `username:password` per line. Lines starting with `#` are ignored.

```
admin:password
root:toor
user:123456
```

Without a wordlist, the scanner uses a small built-in list of common weak credentials.

**AI bruteforce:** Use `--ai-bruteforce` (or enable **Use AI for bruteforce** in the web UI) to have the AI suggest username:password pairs per service (e.g. SSH, HTTP admin, router). The same OpenAI/Ollama setup as for report analysis is used; if the API is unavailable, the scanner falls back to the built-in wordlist. The AI agent always uses AI-suggested credentials when it runs scans.

### Scan profiles

- **quick** – Ports only
- **standard** – Ports + exploit + bruteforce
- **deep** – All checks (exploit, brute, SSL, SSH, web, injection)
- **pentest** – Deep + web-advanced (reflected XSS, path traversal, extended paths, time-based SQLi)

---

## Scanner modules

Each module runs automatically when enabled via flags or profile. This section describes what each does and how to use it.

### Network discovery (`network`)

**What it does:** Finds live hosts on a network before port scanning. Uses ICMP ping by default; uses ARP when scapy is available (faster, works when ICMP is blocked).

**How to use:** Runs automatically for CIDR targets. Use `-s` to skip (single host). Use `-A` to scan all IPs without ping (when ICMP is blocked).

```bash
python main.py 192.168.1.0/24        # Ping/ARP discovery
python main.py 192.168.1.0/24 -A     # No ping, scan all IPs
python main.py 192.168.1.1 -s        # Skip discovery, single host
```

---

### Port scanning (`ports`)

**What it does:** Discovers open TCP and UDP ports. TCP Connect (default) completes full handshake; SYN scan (half-open) is stealthier but requires scapy + admin.

**How to use:** `-S connect` (default) or `-S syn`. Add `-u` for UDP. Use `-p 80 443` for specific ports, `--all-ports` for full scan.

```bash
python main.py 192.168.1.1 -S syn    # SYN scan (needs scapy + admin)
python main.py 192.168.1.1 -u       # Include UDP (53, 161, etc.)
python main.py 192.168.1.1 -p 22 80 443
```

---

### Vulnerability checks (`vulnerability`)

**What it does:** Banner grabbing and service identification. Maps open ports to known risks (FTP, Telnet, SMB, Redis, etc.) with severity and remediation. Runs on every scan.

**How to use:** Always on. Use `--no-banner` to skip banner grabbing (faster, less detail).

---

### Version & CVE (`version`, `cve_cvss`)

**What it does:** Parses banners for version strings (OpenSSH, Apache, nginx, Redis, MySQL). Looks up known CVEs and CVSS scores from local DB or NVD API.

**How to use:** Runs automatically when banners are grabbed. Findings appear in reports with CVE references and CVSS.

---

### Exploit probes (`exploit`)

**What it does:** Safe, non-destructive checks: anonymous FTP, HTTP path discovery (admin, config, .git), Redis/MongoDB no-auth, SMB null session, MySQL empty root.

**How to use:** `-e` or `--exploit`, or `--profile standard` / `--profile deep`.

**Requires:** pysmb (SMB null session), pymongo (MongoDB), pymysql (MySQL).

```bash
python main.py 192.168.1.0/24 -e
python main.py 192.168.1.0/24 -e --web-deep   # Extended paths (GraphQL, backup, config, actuator, etc.)
```

---

### Brute force (`bruteforce`)

**What it does:** Tries common credentials on FTP, SSH, HTTP Basic, MySQL, PostgreSQL, RDP, Telnet. Uses built-in wordlist, custom file, or AI-suggested credentials per service.

**How to use:** `-b` or `--bruteforce`. Add `--bruteforce-wordlist path/to/file` for custom `user:pass` list. Add `--ai-bruteforce` to use the AI to suggest credentials per host/port (requires OpenAI or Ollama in `.env`).

```bash
python main.py 192.168.1.0/24 -b
python main.py 192.168.1.0/24 -b --bruteforce-wordlist creds.txt --bruteforce-delay 1.0
```

**Requires:** paramiko (SSH), pymysql (MySQL), psycopg2 (PostgreSQL).

---

### SSL/TLS checks (`ssl_check`)

**What it does:** Tests supported TLS versions (1.0, 1.1, 1.2, 1.3), weak ciphers (RC4, 3DES, NULL), and certificate validity (expiry, self-signed).

**How to use:** `--ssl-check`, or `--profile deep`.

```bash
python main.py 192.168.1.0/24 --ssl-check
```

**Requires:** cryptography.

---

### SSH audit (`ssh_audit`)

**What it does:** Detects weak SSH algorithms (KEX, cipher, MAC) per RFC 9142: diffie-hellman-group1-sha1, arcfour, 3des-cbc, hmac-sha1, etc.

**How to use:** `--ssh-audit`, or `--profile deep`.

```bash
python main.py 192.168.1.0/24 --ssh-audit
```

**Requires:** paramiko.

---

### Web headers (`web_headers`)

**What it does:** Checks HTTP/HTTPS for security headers: X-Frame-Options, X-Content-Type-Options, Content-Security-Policy, Strict-Transport-Security, X-XSS-Protection.

**How to use:** Runs with `-e` (exploit) on web ports. Part of exploit checks.

---

### SNMP checks (`snmp`)

**What it does:** Tests default SNMP community strings (public, private, admin, empty). Enumerates sysDescr if access granted.

**How to use:** Runs automatically when UDP port 161 is open. Requires `-u` for UDP scan.

```bash
python main.py 192.168.1.0/24 -u
```

**Requires:** pysnmp.

---

### SQL injection probes (`injection`)

**What it does:** Sends safe, non-destructive SQLi payloads to HTTP endpoints. Includes error-based probes (OR 1=1, UNION SELECT, etc.) and optional time-based blind probes (SLEEP/pg_sleep). Checks for error messages, reflection, or delayed responses.

**How to use:** `--injection` (requires `-e`). Only probes when both are set.

```bash
python main.py 192.168.1.0/24 -e --injection
```

---

### Web penetration probes (`web_probes`) – pentest-level

**What it does:** When `--web-advanced` or `--profile pentest` is set: checks for reflected XSS (payload reflection in response) and path traversal / LFI (e.g. `/etc/passwd`-style indicators). Safe, non-destructive; no script execution.

**How to use:** `--web-advanced`, or `--profile pentest`.

```bash
python main.py 192.168.1.0/24 --profile pentest
python main.py 192.168.1.0/24 -e --web-advanced
```

---

### WiFi scan (`wifi`)

**What it does:** Uses the system wireless adapter to discover nearby WiFi networks. Reports SSID, BSSID (MAC), signal strength, channel, and security type. Works on Windows (netsh), Linux (nmcli or iwlist), and macOS (airport).

**How to use:** `--wifi` or `-W`. Results are printed and included in JSON/HTML reports. In the web UI, enable "Scan WiFi networks" when starting a scan.

```bash
python main.py 192.168.1.0/24 --wifi
python main.py 192.168.1.0/24 -W -o report.json
```

**Note:** Requires a WiFi adapter and (on Linux) often `nmcli` (NetworkManager) or `iwlist` (wireless-tools). Authorized testing only.

---

### WiFi Red Team

Full external red-team WiFi penetration testing. Attack a WiFi network from the outside, crack its key, connect automatically, then run a complete internal pen-test on every device.

**Attack chain:**

1. **WiFi Recon** - Scan for nearby networks (already exists via `--wifi`)
2. **Handshake Capture** - Enable monitor mode, deauth clients, capture WPA 4-way handshake (Scapy)
3. **Crack Key** - Try built-in common WiFi passwords + AI-generated wordlist + hashcat/aircrack-ng
4. **Auto-Connect** - Connect with cracked PSK (nmcli/wpa_supplicant on Linux, netsh on Windows)
5. **Subnet Discovery** - Wait for DHCP, read gateway and subnet from the interface
6. **Internal Pen-Test** - Run `pentest` profile against the discovered subnet (scan all IPs, include router)
7. **Post-Exploitation** - Enumerate accessible services with cracked credentials
8. **Report** - WiFi key, connection info, all hosts, vulnerabilities, credentials, accessible services

**Web UI:** Go to **Scan WiFi** page, scan for networks, select one, and click **Attack this network**. The full chain runs automatically with live log output.

**AI agent:** Use `--wifi-attack` to let the AI drive the entire chain autonomously:

```bash
python ai_agent.py 192.168.1.0/24 --wifi-attack
```

The AI can issue `ATTACK_WIFI <bssid>` to attack a WiFi network, then seamlessly transition to scanning discovered hosts.

**Automatic fallback:** If monitor mode is unavailable (no compatible adapter, Windows without Npcap, Scapy not installed), the tool automatically falls back to **online brute-force** -- it tries connecting to the WiFi directly with each password from the wordlist (built-in + AI-generated + user-supplied). This is slower (~5-10s per attempt) but works on any OS with any standard WiFi card, no extra hardware needed. Monitor mode remains the preferred path when available.

**Requirements (full monitor-mode path):**
- **Linux recommended** for WiFi attack phase (monitor mode, raw packet injection)
- Monitor-mode capable WiFi adapter (e.g. Alfa AWUS036ACH)
- Root/admin privileges for monitor mode
- hashcat (GPU) or aircrack-ng (CPU) for key cracking
- Windows: Npcap + compatible adapter (limited support)

**Requirements (online brute-force fallback):**
- Any WiFi adapter (built-in laptop WiFi works)
- Any OS (Windows, Linux, macOS)
- No special privileges beyond WiFi connection rights

**Post-exploitation** (`--post-exploit`): After brute force cracks credentials, SYN-REAPER enumerates what's accessible:
- SMB shares (read/write permissions, sensitive files)
- FTP directory listings (flag .sql, .bak, .env, .key files)
- SSH: whoami, hostname, OS info, privilege level
- MySQL/PostgreSQL: databases, tables, flag credential-related tables
- HTTP admin panels: page title, firmware version, panel type

Post-exploit is auto-enabled with the `pentest` profile.

---

### Router / gateway pen test (`--include-router`)

**What it does:** Includes your default gateway (router) in the pen test so you can find ways in at the network level. The scanner will:

- **Discover the router** – Uses the system default route (e.g. from `ipconfig` / `ip route`) to get the gateway IP.
- **Extra ports on the router** – Scans router-specific ports: 80, 443, 8080, 8008, 8443, 7547 (TR-069), 8291 (MikroTik), 22, 23, 53, 161 (SNMP), etc.
- **Router admin paths** – Checks paths like `/router`, `/HNAP1/`, `/cgi-bin/`, `/cu.html`, `/userRpm/`, `/login.asp`, and other common vendor admin pages.
- **Default credentials** – Tries common router logins (admin/admin, admin/password, root/admin, support/support, etc.) on HTTP/HTTPS and Telnet.

**How to use:** `--include-router` or enable **Include router (gateway)** in the web UI when starting a pen test. The gateway is scanned first with the extended port list and router wordlist.

```bash
python main.py 192.168.2.0/24 --profile pentest --include-router -o report.html
```

---

### Container/cloud API (`container`)

**What it does:** Checks Docker (2375, 2376), Kubernetes (6443, 443), and etcd (2379) for unauthenticated API access.

**How to use:** Runs with `-e` when relevant ports are open.

---

### SMB EternalBlue (`smb_checks`)

**What it does:** Safe read-only check for MS17-010 (EternalBlue) vulnerability. No exploit execution.

**How to use:** Runs with `-e` when port 445 is open.

**Requires:** impacket.

---

### Device detection (`device`)

**What it does:** Infers device type from open ports and HTTP content (router, NAS, printer, Smart TV, IoT, Windows, etc.).

**How to use:** Runs automatically on every host.

---

### OS fingerprinting (`fingerprint`)

**What it does:** TCP stack fingerprinting (TTL, window size) to guess OS (Linux, Windows, Cisco, macOS, etc.).

**How to use:** `-F` or `--fingerprint`. Requires scapy + admin.

```bash
python main.py 192.168.1.1 -F
```

---

### Compliance mapping (`compliance`)

**What it does:** Maps findings to CIS, PCI-DSS, and NIST 800-53 controls. Produces control matrix in reports.

**How to use:** `--compliance cis`, `pci-dss`, `nist`, or `all`.

```bash
python main.py 192.168.1.0/24 -o report.html --compliance pci-dss
```

---

## AI report analysis

Generate an executive summary from a JSON report using an LLM. Uses `.env` for API settings.

### ⚠️ Privacy notice

When using **external APIs (OpenAI)**, reports are **anonymized by default** – IPs, CIDRs, and identifiers are removed before sending.

**`.env` override:** Set `AI_ANONYMIZE=true` to always anonymize (e.g. remote self-hosted), or `AI_ANONYMIZE=false` to never anonymize (local only). Unset = auto (external=yes, local=no).

```bash
# Create .env, add OPENAI_API_KEY
copy .env.example .env

# Analyze (OpenAI) - anonymization ON by default
python analyze.py report.json

# Self-hosted (Ollama) - anonymization OFF by default
python analyze.py report.json --base-url http://localhost:11434/v1 --model llama3.1

# Save as HTML
python analyze.py report.json -o summary.html
```

### AI Red Team (hacker view, Aikido-style)

Use the AI as a **red teamer**: it interprets the scan from an attacker’s perspective—attack chains, priority targets, and what to fix first.

**CLI:** Use the `--persona redteam` option:

```bash
python analyze.py report.json --persona redteam
python analyze.py report.json --persona redteam -o redteam.txt
```

**Web UI:** On the **Scan results** page, after a scan, an **“AI Red Team (hacker view)”** section appears. Click **“Get AI hacker analysis”** to run the same analysis in the browser (requires `OPENAI_API_KEY` or `OPENAI_API_BASE` in `.env`).

### AI agent (AI runs scans and exploits)

The **AI agent** discovers hosts, then decides which host to scan next and when to stop. For each chosen host it runs a **full scan** (ports, vulnerabilities, exploits, brute force). One merged report and a live log are produced.

**CLI:**

```bash
python ai_agent.py 192.168.1.0/24
python ai_agent.py 192.168.1.0/24 -o report.json --max-steps 20
python ai_agent.py 192.168.1.0/24 --wifi-attack    # AI drives WiFi attack chain
```

| Option | Description |
|--------|-------------|
| `target` | Target IP or CIDR (e.g. `192.168.1.0/24`) |
| `-o`, `--output` | Output report path (default: `scans/ai_agent_report.json`) |
| `--max-steps` | Max scan steps before stopping (default: 30) |
| `--wifi-attack` | Enable AI to attack external WiFi networks (scan, crack, connect, pen-test) |
| `--wifi-only` | Restrict AI to only the target WiFi network and its devices |
| `--no-router` | Do not add the default gateway to the host list |
| `--no-scan-all` | Use ping discovery only (default scans all IPs in CIDR) |
| `-A`, `--scan-all` | Discover all IPs without ping (default: enabled) |

**Web UI:** Home page → **"Let AI run the pen test"** → enter target → **"Start AI agent scan"** → live log. Requires `OPENAI_API_KEY` or `OPENAI_API_BASE` in `.env`.

**Targeting a router by MAC:** With scapy and ARP discovery, the AI sees each host’s MAC. You can tell it to target the router by MAC: the AI can reply `SCAN_MAC aa:bb:cc:dd:ee:ff` to run a full scan on that device. Direct CLI (no AI): `python main.py 192.168.1.0/24 --mac aa:bb:cc:dd:ee:ff` resolves the MAC to an IP and scans that host (requires scapy).

### Installing Ollama (self-hosted, no API key)

[Ollama](https://ollama.com) runs LLMs locally. No API key or internet required after setup.

**1. Download and install**

- **Windows:** [ollama.com/download](https://ollama.com/download) → run the installer
- **macOS:** `brew install ollama` or download from [ollama.com](https://ollama.com)
- **Linux:** `curl -fsSL https://ollama.com/install.sh | sh`

**2. Start Ollama**

- **Windows:** Ollama runs in the background after install. Open it from the Start menu if needed.
- **macOS/Linux:** `ollama serve` (or it may start automatically)

**3. Add Ollama to PATH (Windows)**

If `ollama` is not recognized in PowerShell:

```powershell
$env:Path += ";$env:LOCALAPPDATA\Programs\Ollama"
```

Or restart your terminal after installation.

**4. Pull a model**

```bash
ollama pull llama3.1
```

Other options: `mistral`, `qwen2.5`, `llama3.1:70b`. For pen-testing: `xploiter/the-xploiter` (see table below).

**5. Use with SYN-REAPER**

```bash
python analyze.py report.json --base-url http://localhost:11434/v1 --model llama3.1
```

Or add to `.env`:

```env
OPENAI_API_BASE=http://localhost:11434/v1
AI_MODEL=llama3.1
```

Then run: `python analyze.py report.json`

**Recommended models for pen-testing (Ollama)**

| Model | Pull command | Use case |
|-------|----------------|----------|
| **xploiter/the-xploiter** | `ollama pull xploiter/the-xploiter` | Red team / offensive security; attack-chain reasoning, exploit thinking (~9GB). |
| **qwen2.5:7b** or **qwen2.5:14b** | `ollama pull qwen2.5:7b` | Strong instruction-following and reasoning; good for AI agent and report analysis. |
| **llama3.1** | `ollama pull llama3.1` | General default; works well if you don’t need a security-specific model. |

Set in `.env`: `AI_MODEL=xploiter/the-xploiter` (or `qwen2.5:7b`, etc.).

### Other self-hosted options (LM Studio, vLLM)

| Tool | Base URL | Example models |
|------|----------|----------------|
| **Ollama** | `http://localhost:11434/v1` | `llama3.1`, `mistral`, `qwen2.5` |
| **LM Studio** | `http://localhost:1234/v1` | Depends on loaded model |
| **vLLM** | `http://localhost:8000/v1` | Depends on server config |

---

## Penetration testing expertise

SYN-REAPER supports deeper, assessment-grade checks for authorized penetration tests:

| Capability | How to enable |
|------------|----------------|
| **Full assessment** | `--profile pentest` (deep + web-advanced) |
| **Extended web paths** | `--web-deep` with `-e` (GraphQL, backup files, config leaks, security.txt) |
| **SQL injection** | `-e --injection` (error-based + time-based blind) |
| **XSS / path traversal** | `--web-advanced` (reflected XSS, LFI probes) |
| **SSL, SSH, headers** | `--ssl-check`, `--ssh-audit`; headers run with `-e` |
| **Brute force** | `-b` with optional `--bruteforce-wordlist` |
| **Obfuscation** | `--obfuscate`: browser-like User-Agents, random port order, pacing (reduces blocking; slower) |
| **Compliance mapping** | `--compliance all` for CIS, PCI-DSS, NIST in reports |

**Example – full pentest-style scan with report:**

```bash
python main.py 192.168.1.0/24 --profile pentest -o report.html --compliance all
# If the target throttles or blocks: add --obfuscate (and optionally --rate-limit 0.2)
```

Use `--rate-limit` to throttle requests when testing production systems.

---

## Report formats

| Extension | Format |
|-----------|--------|
| `.json` | Structured JSON |
| `.html` | HTML with control matrix |
| `.txt` | Plain text |
| `.sarif` | SARIF 2.1.0 for CI/CD |

## Compliance

Use `--compliance` to include a control matrix in reports:

- **cis** – CIS Controls
- **pci-dss** – PCI-DSS
- **nist** – NIST 800-53
- **all** – All frameworks

---

## License

MIT License. See [LICENSE](LICENSE) for details.

## Disclaimer

This tool is for **authorized security testing only**. Obtain written permission before scanning any network you do not own or control. Unauthorized access to computer systems is illegal. The authors assume no liability for misuse.
