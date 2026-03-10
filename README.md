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
| `SCAN_PROFILE` | `quick`, `standard`, `deep` | Preset: quick (ports only), standard (+exploit+brute), deep (all) |
| `SCAN_EXPLOIT` | `true`/`false` | Exploit checks (FTP, HTTP paths, Redis, SMB) |
| `SCAN_BRUTEFORCE` | `true`/`false` | Brute force FTP/SSH/HTTP/MySQL |
| `SCAN_SSL_CHECK` | `true`/`false` | SSL/TLS and certificate checks |
| `SCAN_SSH_AUDIT` | `true`/`false` | SSH weak algorithm audit |
| `SCAN_WEB_DEEP` | `true`/`false` | Extended web path discovery |
| `SCAN_INJECTION` | `true`/`false` | SQL injection probes |
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
| `--ssl-check` | SSL/TLS and certificate checks |
| `--ssh-audit` | SSH weak algorithm audit |
| `--web-deep` | Extended web path discovery |
| `--injection` | Basic SQL injection probes |
| `--profile` | `quick`, `standard`, or `deep` |
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

### Scan profiles

- **quick** – Ports only
- **standard** – Ports + exploit + bruteforce
- **deep** – All checks (exploit, brute, SSL, SSH, web, injection)

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
python main.py 192.168.1.0/24 -e --web-deep   # Extended paths (swagger, actuator, etc.)
```

---

### Brute force (`bruteforce`)

**What it does:** Tries common credentials on FTP, SSH, HTTP Basic, MySQL, PostgreSQL, RDP, Telnet. Uses built-in wordlist or custom file.

**How to use:** `-b` or `--bruteforce`. Add `--bruteforce-wordlist path/to/file` for custom `user:pass` list.

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

**What it does:** Sends safe, non-destructive SQLi payloads to HTTP endpoints. Checks for error messages or indicators of SQL injection.

**How to use:** `--injection` (requires `-e`). Only probes when both are set.

```bash
python main.py 192.168.1.0/24 -e --injection
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

Other options: `mistral`, `qwen2.5`, `llama3.1:70b` (larger, higher quality).

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

### Other self-hosted options (LM Studio, vLLM)

| Tool | Base URL | Example models |
|------|----------|----------------|
| **Ollama** | `http://localhost:11434/v1` | `llama3.1`, `mistral`, `qwen2.5` |
| **LM Studio** | `http://localhost:1234/v1` | Depends on loaded model |
| **vLLM** | `http://localhost:8000/v1` | Depends on server config |

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

[Specify your license, e.g. MIT, GPL-3.0]

## Disclaimer

This tool is for **authorized security testing only**. Obtain written permission before scanning any network you do not own or control. Unauthorized access to computer systems is illegal. The authors assume no liability for misuse.
