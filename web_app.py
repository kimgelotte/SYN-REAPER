"""
Web interface for SYN-REAPER - run scans and view results.
WARNING: For authorized testing only. Run on localhost or trusted network only.
"""

import json
import os
import threading
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template_string, request, url_for

# Optional: suppress scan stdout in background (set to True to quiet)
QUIET_SCAN = os.environ.get("SYNREAPER_QUIET_SCAN", "").lower() in ("1", "true", "yes")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "change-me-in-production")
app.config["MAX_CONTENT_LENGTH"] = 1024

# Scan state (thread-safe via lock)
_scan_lock = threading.Lock()
_scan_state = {
    "running": False,
    "target": None,
    "profile": None,
    "scan_all": False,
    "wifi": False,
    "error": None,
    "report_path": None,
    "started_at": None,
}

SCANS_DIR = Path(__file__).resolve().parent / "scans"
REPORT_FILENAME = "last_scan.json"
LOG_FILENAME = "last_scan.log"


class _LogTee:
    """Writes to a file and flushes after each write so the log page can read in real time."""

    def __init__(self, file_handle):
        self._file = file_handle

    def write(self, data):
        self._file.write(data)
        self._file.flush()

    def flush(self):
        self._file.flush()

    def writable(self):
        return True


def _ensure_scans_dir():
    SCANS_DIR.mkdir(parents=True, exist_ok=True)


def _subnet_from_gateway(gateway: str):
    """Derive a /24 subnet from gateway IP (e.g. 192.168.1.1 -> 192.168.1.0/24)."""
    try:
        from ipaddress import ip_interface
        return str(ip_interface(f"{gateway}/24").network)
    except Exception:
        return None


def _run_scan_thread(target: str, profile: str, scan_all: bool, wifi: bool, include_router: bool,
                     skip_discovery: bool,
                     exploit: bool, bruteforce: bool, use_ai_wordlist: bool, obfuscate: bool,
                     ssl_check: bool, ssh_audit: bool,
                     web_deep: bool, injection: bool, web_advanced: bool):
    """Run the scanner in a background thread; stdout is teed to the log file for real-time view."""
    global _scan_state
    import sys

    _ensure_scans_dir()
    report_path = str(SCANS_DIR / REPORT_FILENAME)
    log_path = SCANS_DIR / LOG_FILENAME

    with _scan_lock:
        _scan_state["running"] = True
        _scan_state["target"] = target
        _scan_state["profile"] = profile
        _scan_state["scan_all"] = scan_all
        _scan_state["wifi"] = wifi
        _scan_state["error"] = None
        _scan_state["report_path"] = report_path
        _scan_state["started_at"] = __import__("datetime").datetime.now().isoformat()

    log_file = None
    old_stdout = sys.stdout
    try:
        log_file = open(log_path, "w", encoding="utf-8")
        log_file.write(f"=== Pen test started at {_scan_state['started_at']} ===\n")
        log_file.write(f"Target: {target}  Profile: {profile}\n\n")
        log_file.flush()
        sys.stdout = _LogTee(log_file)

        from main import run_scan
        run_scan(
            target=target,
            skip_discovery=skip_discovery,
            scan_all=scan_all,
            report_path=report_path,
            show_progress=False,
            profile=profile,
            exploit=exploit,
            bruteforce=bruteforce,
            ssl_check=ssl_check,
            ssh_audit=ssh_audit,
            web_deep=web_deep,
            injection=injection,
            web_advanced=web_advanced,
            write_report_after_each_host=True,
            wifi=wifi,
            include_router=include_router,
            use_ai_wordlist=use_ai_wordlist,
            obfuscate=obfuscate,
        )

        with _scan_lock:
            if not Path(report_path).exists() or Path(report_path).stat().st_size == 0:
                _scan_state["error"] = "No hosts found or no results. Try enabling 'Scan all IPs' if ICMP is blocked."
    except Exception as e:
        with _scan_lock:
            _scan_state["error"] = str(e)
        if log_file:
            try:
                log_file.write(f"\n! Scan error: {e}\n")
                log_file.flush()
            except Exception:
                pass
    finally:
        sys.stdout = old_stdout
        if log_file:
            try:
                log_file.write("\n=== Scan finished ===\n")
                log_file.close()
            except Exception:
                pass
        with _scan_lock:
            _scan_state["running"] = False


def _run_wifi_only_thread():
    """Run WiFi scan only (no target); write progress to log file for real-time view."""
    global _scan_state
    _ensure_scans_dir()
    report_path = str(SCANS_DIR / REPORT_FILENAME)
    log_path = SCANS_DIR / LOG_FILENAME
    dt = __import__("datetime").datetime

    with _scan_lock:
        _scan_state["running"] = True
        _scan_state["target"] = "WiFi scan (no target)"
        _scan_state["error"] = None
        _scan_state["report_path"] = report_path
        _scan_state["started_at"] = dt.now().isoformat()

    log_file = None
    try:
        log_file = open(log_path, "w", encoding="utf-8")
        log_file.write(f"=== WiFi scan started at {_scan_state['started_at']} ===\n\n")
        log_file.flush()

        log_file.write("Scanning for nearby WiFi networks...\n")
        log_file.flush()
        from scanner.wifi import scan_wifi_networks
        wifi_networks = scan_wifi_networks(timeout=15)

        log_file.write(f"Found {len(wifi_networks)} network(s):\n")
        for w in wifi_networks:
            sig = f" {w.signal}%" if w.signal is not None else ""
            ch = f" ch{w.channel}" if w.channel is not None else ""
            log_file.write(f"  {w.ssid or '(hidden)'}  {w.bssid}{sig}{ch}  {w.security or ''}\n")
        log_file.write("\n=== WiFi scan finished ===\n")
        log_file.flush()

        report = {
            "target": "WiFi scan",
            "scan_type": "WiFi only",
            "timestamp": dt.now().isoformat(),
            "compliance_profile": None,
            "hosts": [],
            "wifi_networks": [
                {"ssid": w.ssid, "bssid": w.bssid, "signal": w.signal, "channel": w.channel, "security": w.security}
                for w in wifi_networks
            ],
        }
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
    except Exception as e:
        with _scan_lock:
            _scan_state["error"] = str(e)
        if log_file:
            try:
                log_file.write(f"\n! Error: {e}\n")
                log_file.flush()
            except Exception:
                pass
    finally:
        if log_file:
            try:
                log_file.close()
            except Exception:
                pass
        with _scan_lock:
            _scan_state["running"] = False


def _run_wifi_redteam_thread(bssid: str, ssid: str, use_ai: bool = True, wordlist_path: str = None, interface: str = None):
    """Run the full WiFi red-team attack chain; stdout teed to log file."""
    global _scan_state
    import sys

    _ensure_scans_dir()
    report_path = str(SCANS_DIR / REPORT_FILENAME)
    log_path = SCANS_DIR / LOG_FILENAME

    with _scan_lock:
        _scan_state["running"] = True
        _scan_state["target"] = f"WiFi Red Team: {ssid} ({bssid})"
        _scan_state["error"] = None
        _scan_state["report_path"] = report_path
        _scan_state["started_at"] = __import__("datetime").datetime.now().isoformat()

    log_file = None
    old_stdout = sys.stdout
    try:
        log_file = open(log_path, "w", encoding="utf-8")
        log_file.write(f"=== WiFi Red Team attack started at {_scan_state['started_at']} ===\n")
        log_file.write(f"Target: {ssid} ({bssid})\n\n")
        log_file.flush()
        sys.stdout = _LogTee(log_file)

        from scanner.wifi_redteam import run_wifi_redteam
        result = run_wifi_redteam(
            target_bssid=bssid,
            target_ssid=ssid,
            interface=interface or None,
            use_ai=use_ai,
            wordlist_path=wordlist_path or None,
            report_path=report_path,
        )

        if result.error and not result.wifi_key:
            with _scan_lock:
                _scan_state["error"] = result.error
    except Exception as e:
        with _scan_lock:
            _scan_state["error"] = str(e)
        if log_file:
            try:
                log_file.write(f"\n! Error: {e}\n")
                log_file.flush()
            except Exception:
                pass
    finally:
        sys.stdout = old_stdout
        if log_file:
            try:
                log_file.write("\n=== WiFi Red Team finished ===\n")
                log_file.close()
            except Exception:
                pass
        with _scan_lock:
            _scan_state["running"] = False


def _run_ai_agent_thread(target: str, max_steps: int = 30, scope_wifi_only: bool = False, target_was_empty: bool = False):
    """Run the AI agent (AI chooses which hosts to scan); stdout teed to log file."""
    global _scan_state
    import sys

    _ensure_scans_dir()
    report_path = str(SCANS_DIR / REPORT_FILENAME)
    log_path = SCANS_DIR / LOG_FILENAME

    with _scan_lock:
        _scan_state["running"] = True
        _scan_state["target"] = f"AI agent: {target}"
        _scan_state["error"] = None
        _scan_state["report_path"] = report_path
        _scan_state["started_at"] = __import__("datetime").datetime.now().isoformat()

    log_file = None
    old_stdout = sys.stdout
    try:
        log_file = open(log_path, "w", encoding="utf-8")
        log_file.write(f"=== AI agent scan started at {_scan_state['started_at']} ===\nTarget: {target}\n")
        if target_was_empty:
            log_file.write("(Target was empty; using local subnet from default gateway. To scan another network, enter its CIDR in the target field.)\n")
        log_file.write("\n")
        log_file.flush()
        sys.stdout = _LogTee(log_file)

        from ai_agent import run_ai_agent
        run_ai_agent(
            target=target,
            scan_all=True,
            report_path=report_path,
            max_steps=max_steps,
            include_router=not scope_wifi_only,
            scope_wifi_only=scope_wifi_only,
        )
    except Exception as e:
        with _scan_lock:
            _scan_state["error"] = str(e)
        if log_file:
            try:
                log_file.write(f"\n! Error: {e}\n")
                log_file.flush()
            except Exception:
                pass
    finally:
        sys.stdout = old_stdout
        if log_file:
            try:
                log_file.write("\n=== AI agent finished ===\n")
                log_file.close()
            except Exception:
                pass
        with _scan_lock:
            _scan_state["running"] = False


INDEX_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SYN-REAPER – Security Scanner</title>
  <style>
    :root {
      --bg: #0B0C10;
      --surface: #1F2833;
      --border: #2a3544;
      --text: #C5C6C7;
      --muted: #8b959e;
      --accent: #66FCF1;
      --teal: #45A29E;
      --danger: #e74c3c;
      --warn: #45A29E;
      --success: #45A29E;
    }
    * { box-sizing: border-box; }
    body {
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: var(--bg);
      color: var(--text);
      margin: 0;
      padding: 1.5rem;
      line-height: 1.5;
    }
    .container { max-width: 720px; margin: 0 auto; }
    h1 { font-size: 1.5rem; margin-bottom: 0.25rem; }
    .subtitle { color: var(--muted); font-size: 0.9rem; margin-bottom: 1.5rem; }
    .warning {
      background: rgba(231,76,60,0.12);
      border: 1px solid var(--danger);
      color: #f5a5a0;
      padding: 0.75rem 1rem;
      border-radius: 6px;
      margin-bottom: 1.5rem;
      font-size: 0.9rem;
    }
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.25rem;
      margin-bottom: 1rem;
    }
    .card-option { margin-bottom: 1.5rem; }
    .card-title { font-size: 1.1rem; margin: 0 0 0.5rem 0; color: var(--accent); }
    .card-desc { color: var(--muted); font-size: 0.9rem; margin: 0 0 0.75rem 0; }
    label { display: block; margin-bottom: 0.35rem; color: var(--muted); font-size: 0.85rem; }
    input[type="text"], select {
      width: 100%;
      padding: 0.5rem 0.75rem;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text);
      font-size: 1rem;
    }
    input:focus, select:focus { outline: none; border-color: var(--accent); }
    .row { display: flex; gap: 1rem; flex-wrap: wrap; align-items: flex-end; }
    .row .field { flex: 1; min-width: 200px; }
    .checkboxes { display: flex; flex-wrap: wrap; gap: 1rem; margin-top: 1rem; }
    .checkboxes label { display: flex; align-items: center; gap: 0.5rem; cursor: pointer; }
    .checkboxes input { width: auto; }
    .btn {
      padding: 0.6rem 1.25rem;
      border-radius: 6px;
      border: none;
      font-size: 0.95rem;
      cursor: pointer;
      font-weight: 500;
    }
    .btn-primary {
      background: var(--accent);
      color: var(--bg);
    }
    .btn-primary:hover { filter: brightness(1.08); color: var(--bg); }
    .btn-primary:disabled { opacity: 0.6; cursor: not-allowed; }
    .btn-secondary {
      background: var(--surface);
      color: var(--accent);
      border: 1px solid var(--border);
    }
    .btn-secondary:hover { background: var(--border); }
    .status {
      padding: 0.75rem 1rem;
      border-radius: 6px;
      margin-bottom: 1rem;
      font-size: 0.9rem;
    }
    .status.running { background: rgba(102,252,241,0.12); border: 1px solid var(--accent); color: var(--accent); }
    .status.error { background: rgba(231,76,60,0.12); border: 1px solid var(--danger); color: #f5a5a0; }
    .status.done { background: rgba(69,162,158,0.2); border: 1px solid var(--success); color: #66FCF1; }
    a { color: var(--accent); text-decoration: none; }
    a:hover { text-decoration: underline; }
    .mt { margin-top: 1rem; }
  </style>
</head>
<body>
  <div class="container">
    <h1>SYN-REAPER</h1>
    <p class="subtitle">Network &amp; port vulnerability scanner – check your incoming security</p>
    <div class="warning">
      <strong>Authorized testing only.</strong> Only scan networks you own or have permission to test.
      Unauthorized scanning may be illegal.
    </div>

    {% if scan_running %}
    <div class="status running">
      Scan in progress: <strong>{{ scan_target }}</strong>. This can take several minutes.
      <a href="{{ url_for('results') }}">Refresh results</a>
    </div>
    {% endif %}
    {% if scan_error %}
    <div class="status error">{{ scan_error }}</div>
    {% endif %}

    <div class="card card-option">
      <h2 class="card-title">1. Scan local network and devices</h2>
      <p class="card-desc">Pen-test devices on your connected network (computers, phones, DB, etc.): find open ports, services, and vulnerabilities.</p>
      <form method="post" action="{{ url_for('start_scan') }}">
        <div class="row">
          <div class="field">
            <label for="target">Target (IP or CIDR)</label>
            <input type="text" id="target" name="target" placeholder="e.g. 192.168.1.0/24 or leave empty to scan whole subnet"
                   value="{{ request.form.get('target', scan_target or '') }}">
          </div>
        </div>
        <div class="row mt">
          <div class="field">
            <label for="profile">Profile</label>
            <select id="profile" name="profile">
              <option value="quick" {{ 'selected' if (request.form.get('profile') or profile) == 'quick' else '' }}>Quick (ports only)</option>
              <option value="standard" {{ 'selected' if (request.form.get('profile') or profile) == 'standard' else '' }}>Standard (+ exploit + brute)</option>
              <option value="deep" {{ 'selected' if (request.form.get('profile') or profile) == 'deep' else '' }}>Deep (all checks)</option>
              <option value="pentest" {{ 'selected' if (request.form.get('profile') or profile) == 'pentest' else '' }}>Pentest (deep + XSS/LFI)</option>
            </select>
          </div>
        </div>
        <div class="checkboxes">
          <label><input type="checkbox" name="scan_all" value="1" {{ 'checked' if scan_all else '' }}> Scan all IPs (no ping – use when ICMP blocked)</label>
          <label><input type="checkbox" name="include_router" value="1"> Include router (gateway) – pen test admin UI, default creds</label>
          <label><input type="checkbox" name="use_ai_wordlist" value="1"> Use AI for bruteforce (suggest credentials per service)</label>
          <label><input type="checkbox" name="obfuscate" value="1"> Obfuscate (browser-like traffic, less likely to be blocked)</label>
        </div>
        <div class="mt">
          <button type="submit" class="btn btn-primary" {{ 'disabled' if scan_running else '' }}>
            {{ 'Scanning…' if scan_running else 'Start scan' }}
          </button>
        </div>
      </form>
    </div>

    <div class="card card-option">
      <h2 class="card-title">2. Scan external WiFis and pen-test them</h2>
      <p class="card-desc">Discover nearby WiFi networks, choose one, and run a penetration test (e.g. handshakes, brute force, router checks).</p>
      <a href="{{ url_for('wifi_scan_page') }}" class="btn btn-primary">Go to Scan WiFi →</a>
    </div>

    <div class="card card-option">
      <h2 class="card-title">Let AI run the pen test</h2>
      <p class="card-desc">The AI agent discovers hosts, then chooses which to scan (full scan + exploits + brute) and when to stop. Requires OpenAI or Ollama in .env.</p>
      <form method="post" action="{{ url_for('start_ai_agent') }}">
        <div class="row">
          <div class="field">
            <label for="ai_target">Target (IP or CIDR)</label>
            <input type="text" id="ai_target" name="target" placeholder="e.g. 192.168.1.0/24 — leave empty for local network (default gateway subnet)">
            <p class="meta" style="margin-top:0.35rem;">Leave empty to use your <strong>local</strong> network (subnet of your default gateway). To scan another network (e.g. guest WiFi, external), enter that network’s CIDR here.</p>
          </div>
        </div>
        <div class="mt">
          <button type="submit" class="btn btn-primary" {{ 'disabled' if scan_running else '' }}>
            {{ 'Scanning…' if scan_running else 'Start AI agent scan' }}
          </button>
        </div>
      </form>
    </div>

    <p class="subtitle" style="margin-top:1.5rem;">
      <a href="{{ url_for('results') }}">View last results</a>
    </p>
  </div>
</body>
</html>
"""

LOG_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Scan log – SYN-REAPER</title>
  <style>
    :root {
      --bg: #0B0C10;
      --surface: #1F2833;
      --border: #2a3544;
      --text: #C5C6C7;
      --muted: #8b959e;
      --accent: #66FCF1;
      --danger: #e74c3c;
      --success: #45A29E;
    }
    body { font-family: 'Consolas', 'Monaco', monospace; background: var(--bg); color: var(--text); margin: 0; padding: 1rem 1.5rem; font-size: 0.875rem; line-height: 1.5; }
    .container { max-width: 960px; margin: 0 auto; }
    h1 { font-size: 1.25rem; margin-bottom: 0.5rem; }
    .nav { margin-bottom: 1rem; }
    .nav a { color: var(--accent); text-decoration: none; margin-right: 1rem; }
    .nav a:hover { text-decoration: underline; }
    .status { padding: 0.5rem 0.75rem; border-radius: 6px; margin-bottom: 0.75rem; font-size: 0.85rem; }
    .status.running { background: rgba(102,252,241,0.12); border: 1px solid var(--accent); color: var(--accent); }
    .status.done { background: rgba(69,162,158,0.2); border: 1px solid var(--success); color: var(--accent); }
    .log-box {
      background: #0d1117;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 1rem;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
      max-height: 75vh;
      overflow-y: auto;
    }
    .pulse { animation: pulse 1.2s ease-in-out infinite; }
    @keyframes pulse { 50% { opacity: 0.6; } }
  </style>
</head>
<body>
  <div class="container">
    <div class="nav">
      <a href="{{ url_for('index') }}">← Scanner</a>
      <a href="{{ url_for('results') }}">View results</a>
    </div>
    <h1>Scan log</h1>
    <div id="status" class="status running pulse">Starting…</div>
    <div id="log-box" class="log-box"></div>
  </div>
  <script>
    const logBox = document.getElementById('log-box');
    const statusEl = document.getElementById('status');
    const API = '{{ url_for("api_log") }}';

    function poll() {
      fetch(API)
        .then(r => r.json())
        .then(function(data) {
          logBox.textContent = data.content || '';
          if (data.running) {
            statusEl.className = 'status running pulse';
            statusEl.textContent = 'Scan in progress…';
          } else {
            statusEl.className = 'status done';
            statusEl.textContent = data.error ? 'Error: ' + data.error : 'Scan finished.';
          }
          logBox.scrollTop = logBox.scrollHeight;
        })
        .catch(function() { statusEl.textContent = 'Could not load log.'; });
    }
    poll();
    const interval = setInterval(function() {
      fetch(API).then(r => r.json()).then(function(data) {
        logBox.textContent = data.content || '';
        logBox.scrollTop = logBox.scrollHeight;
        if (!data.running) {
          clearInterval(interval);
          statusEl.className = 'status done';
          statusEl.textContent = data.error ? 'Error: ' + data.error : 'Scan finished.';
        }
      }).catch(function() {});
    }, 600);
  </script>
</body>
</html>
"""

WIFI_SCAN_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Scan WiFi - SYN-REAPER</title>
  <style>
    :root {
      --bg: #0B0C10;
      --surface: #1F2833;
      --border: #2a3544;
      --text: #C5C6C7;
      --muted: #8b959e;
      --accent: #66FCF1;
      --teal: #45A29E;
      --danger: #e74c3c;
    }
    body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 1.5rem; line-height: 1.5; }
    .container { max-width: 720px; margin: 0 auto; }
    h1 { font-size: 1.35rem; margin-bottom: 0.25rem; }
    .subtitle { color: var(--muted); font-size: 0.9rem; margin-bottom: 1rem; }
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.25rem;
      margin-bottom: 1.25rem;
    }
    .card h2 { font-size: 1.05rem; margin: 0 0 0.5rem 0; color: var(--accent); }
    label { display: block; margin-bottom: 0.35rem; color: var(--muted); font-size: 0.85rem; }
    input[type="text"], select {
      width: 100%;
      max-width: 400px;
      padding: 0.5rem 0.75rem;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text);
      font-size: 1rem;
    }
    .btn {
      padding: 0.6rem 1.25rem;
      border-radius: 6px;
      border: none;
      font-size: 0.95rem;
      cursor: pointer;
      font-weight: 500;
      text-decoration: none;
      display: inline-block;
    }
    .btn-primary { background: var(--accent); color: var(--bg); }
    .btn-primary:hover { filter: brightness(1.08); }
    .btn-primary:disabled { opacity: 0.6; cursor: not-allowed; }
    .btn-secondary { background: var(--surface); color: var(--accent); border: 1px solid var(--border); margin-left: 0.5rem; }
    a { color: var(--accent); }
    .wifi-list { font-size: 0.9rem; }
    .wifi-row { padding: 0.5rem 0; border-bottom: 1px solid var(--border); }
    .wifi-row:last-child { border-bottom: none; }
    .empty-msg { color: var(--muted); font-style: italic; padding: 1rem 0; }
    .mt { margin-top: 1rem; }
    .status.error { padding: 0.5rem 0.75rem; border-radius: 6px; font-size: 0.9rem; background: rgba(231,76,60,0.12); border: 1px solid var(--danger); color: #f5a5a0; }
  </style>
</head>
<body>
  <div class="container">
    <a href="{{ url_for('index') }}">&#8592; Back to scanner</a>
    <h1>Scan WiFi</h1>
    <p class="subtitle">Scan for nearby networks, then attack one from the outside (full red-team chain).</p>

    <div class="card">
      <h2>1. Scan for networks</h2>
      <p class="subtitle" style="margin-bottom:0.75rem;">Find all WiFis in your vicinity using your wireless adapter.</p>
      <form method="post" action="{{ url_for('scan_wifi_only') }}" style="display:inline;">
        <button type="submit" class="btn btn-primary" id="btn-scan" {{ 'disabled' if scan_running else '' }}>
          {{ 'Scanning...' if scan_running else 'Scan for networks' }}
        </button>
      </form>
      <div id="scan-status" class="subtitle" style="margin-top:0.5rem; min-height:1.25rem;"></div>
    </div>

    <div class="card">
      <h2>2. Networks in your vicinity</h2>
      <div id="wifi-list" class="wifi-list">
        <div class="empty-msg" id="wifi-empty">Run a scan above first.</div>
        <div id="wifi-rows" style="display:none;"></div>
      </div>
    </div>

    <div class="card" id="redteam-card">
      <h2>3. Attack a WiFi network (full red-team chain)</h2>
      <p class="subtitle" style="margin-bottom:0.75rem;">Select a network. We will <strong>capture the handshake, crack the key, connect automatically, discover the subnet, and run a full pen-test</strong> on every device &#8212; truly from the outside.</p>
      <form method="post" action="{{ url_for('start_wifi_redteam') }}" id="redteam-form">
        <div class="mt">
          <label for="redteam-wifi-select">Network to attack</label>
          <select id="redteam-wifi-select" name="wifi_network" required style="display:block; max-width:400px;">
            <option value="">&#8212; Choose a network &#8212;</option>
          </select>
          <input type="hidden" name="ssid" id="hidden-ssid" value="">
        </div>
        <div class="mt">
          <label for="wifi-interface">WiFi interface (leave empty for auto-detect)</label>
          <input type="text" id="wifi-interface" name="interface" placeholder="Auto-detect" style="max-width:300px;">
        </div>
        <div class="mt">
          <label><input type="checkbox" name="use_ai" value="1" checked> Use AI for wordlist generation (increases crack success)</label>
        </div>
        <div class="mt">
          <label for="wordlist-path">Extra wordlist path (optional)</label>
          <input type="text" id="wordlist-path" name="wordlist_path" placeholder="/path/to/wordlist.txt">
        </div>
        <div class="mt">
          <button type="submit" class="btn btn-primary" id="btn-redteam" disabled>Attack this network</button>
          <span class="subtitle" style="display:block; margin-top:0.35rem;">Full chain: handshake capture &#8594; crack key &#8594; auto-connect &#8594; scan all devices &#8594; exploit &#8594; report. Requires monitor-mode adapter (Linux recommended).</span>
        </div>
      </form>
    </div>

    <div class="card" id="pentest-card">
      <h2>4. Manual pen-test (already on the network)</h2>
      {% if target_required %}
      <div class="status error" style="margin-bottom:0.75rem;">
        <strong>Enter the target subnet.</strong> We need the network range (e.g. 192.168.2.0/24) for the WiFi you want to attack.
      </div>
      {% endif %}
      <p class="subtitle" style="margin-bottom:0.75rem;">If you are already connected to the target network, enter its subnet to run a full pen-test.</p>
      <form method="post" action="{{ url_for('start_scan') }}" id="pentest-form">
        <div class="mt">
          <label for="pentest-target">Target (IP or CIDR)</label>
          <input type="text" id="pentest-target" name="target" placeholder="e.g. 192.168.2.0/24" required>
        </div>
        <div class="mt">
          <label><input type="checkbox" name="scan_all" value="1" checked> Scan all IPs in range</label>
        </div>
        <div class="mt">
          <label><input type="checkbox" name="include_router" value="1" checked> Include router (gateway)</label>
        </div>
        <div class="mt">
          <label><input type="checkbox" name="use_ai_wordlist" value="1"> Use AI for bruteforce</label>
        </div>
        <div class="mt">
          <label><input type="checkbox" name="obfuscate" value="1"> Obfuscate</label>
        </div>
        <div class="mt">
          <label for="pentest-profile">Profile</label>
          <select id="pentest-profile" name="profile">
            <option value="pentest" selected>Pentest (full)</option>
            <option value="deep">Deep</option>
            <option value="standard">Standard</option>
          </select>
        </div>
        <div class="mt">
          <button type="submit" class="btn btn-primary" id="btn-pentest" disabled>Start pen-test</button>
        </div>
      </form>
    </div>
  </div>
  <script>
    var API = '{{ url_for("api_status") }}';
    var wifiEmpty = document.getElementById('wifi-empty');
    var wifiRows = document.getElementById('wifi-rows');
    var redteamSelect = document.getElementById('redteam-wifi-select');
    var hiddenSsid = document.getElementById('hidden-ssid');
    var btnPentest = document.getElementById('btn-pentest');
    var btnRedteam = document.getElementById('btn-redteam');
    var btnScan = document.getElementById('btn-scan');
    var scanStatus = document.getElementById('scan-status');
    var lastWifiJson = '';
    var wifiNetworkData = [];

    if (redteamSelect && hiddenSsid) {
      redteamSelect.addEventListener('change', function() {
        var bssid = redteamSelect.value;
        var ssid = '';
        for (var i = 0; i < wifiNetworkData.length; i++) {
          if (wifiNetworkData[i].bssid === bssid) { ssid = wifiNetworkData[i].ssid || ''; break; }
        }
        hiddenSsid.value = ssid;
      });
    }

    function refresh() {
      fetch(API).then(function(r) { return r.json(); }).then(function(data) {
        if (data.running) {
          scanStatus.textContent = 'Scanning for networks...';
          if (btnScan) btnScan.disabled = true;
        } else {
          scanStatus.textContent = '';
          if (btnScan) btnScan.disabled = false;
        }
        var networks = data.report && data.report.wifi_networks && data.report.wifi_networks.length ? data.report.wifi_networks : null;
        var wifiJson = networks ? JSON.stringify(networks) : '';
        if (wifiJson !== lastWifiJson) {
          lastWifiJson = wifiJson;
          wifiNetworkData = networks || [];
          var prevRedteam = redteamSelect ? redteamSelect.value : '';
          if (networks) {
            wifiEmpty.style.display = 'none';
            wifiRows.style.display = 'block';
            wifiRows.innerHTML = networks.map(function(w) {
              var sig = w.signal != null ? ' ' + w.signal + '%' : '';
              var ch = w.channel != null ? ' ch' + w.channel : '';
              return '<div class="wifi-row">' + (w.ssid || '(hidden)') + ' &nbsp; ' + (w.bssid || '') + sig + ch + ' &nbsp; ' + (w.security || '') + '</div>';
            }).join('');
            var opts = '<option value="">-- Choose a network --</option>' +
              networks.map(function(w) {
                var label = (w.ssid || '(hidden)') + ' -- ' + (w.bssid || '') + (w.security ? ' (' + w.security + ')' : '');
                return '<option value="' + (w.bssid || '') + '">' + label.replace(/</g, '&lt;') + '</option>';
              }).join('');
            if (redteamSelect) {
              redteamSelect.innerHTML = opts;
              if (prevRedteam && [].slice.call(redteamSelect.options).some(function(o) { return o.value === prevRedteam; })) {
                redteamSelect.value = prevRedteam;
              }
            }
          } else {
            wifiEmpty.style.display = 'block';
            wifiRows.style.display = 'none';
            if (redteamSelect) redteamSelect.innerHTML = '<option value="">-- Choose a network --</option>';
          }
        }
        var hasNetworks = !!wifiNetworkData.length;
        if (btnRedteam) btnRedteam.disabled = !hasNetworks || !!data.running;
        if (btnPentest) btnPentest.disabled = !!data.running;
      }).catch(function() {});
    }
    refresh();
    setInterval(refresh, 2000);
  </script>
</body>
</html>
"""

RESULTS_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Scan results – SYN-REAPER</title>
  <style>
    :root {
      --bg: #0B0C10;
      --surface: #1F2833;
      --border: #2a3544;
      --text: #C5C6C7;
      --muted: #8b959e;
      --accent: #66FCF1;
      --teal: #45A29E;
      --danger: #e74c3c;
      --warn: #45A29E;
      --success: #45A29E;
    }
    body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 1.5rem; }
    .container { max-width: 960px; margin: 0 auto; }
    h1 { font-size: 1.35rem; }
    a { color: var(--accent); }
    .meta { color: var(--muted); font-size: 0.9rem; margin-bottom: 1.5rem; }
    .status-bar {
      padding: 0.75rem 1rem;
      border-radius: 6px;
      margin-bottom: 1rem;
      font-size: 0.9rem;
    }
    .status-bar.running { background: rgba(102,252,241,0.12); border: 1px solid var(--accent); color: var(--accent); }
    .status-bar.error { background: rgba(231,76,60,0.12); border: 1px solid var(--danger); color: #f5a5a0; }
    .status-bar.done { background: rgba(69,162,158,0.2); border: 1px solid var(--success); color: #66FCF1; }
    .host {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1rem 1.25rem;
      margin-bottom: 1rem;
    }
    .host h2 { font-size: 1.1rem; margin: 0 0 0.5rem 0; }
    .host .device { color: var(--muted); font-size: 0.9rem; margin-bottom: 0.5rem; }
    .ports { font-size: 0.9rem; margin-bottom: 0.75rem; }
    .finding, .exploit {
      font-size: 0.85rem;
      padding: 0.4rem 0;
      border-bottom: 1px solid var(--border);
    }
    .finding:last-child, .exploit:last-child { border-bottom: none; }
    .risk-high, .risk-critical { color: #f5a5a0; }
    .risk-medium { color: var(--warn); }
    .risk-low { color: var(--muted); }
    .section-title { font-weight: 600; margin-top: 0.75rem; margin-bottom: 0.35rem; }
    .empty { color: var(--muted); font-style: italic; }
    .back { display: inline-block; margin-bottom: 1rem; }
    .wifi-row { font-size: 0.9rem; padding: 0.4rem 0; border-bottom: 1px solid var(--border); }
    .wifi-row:last-child { border-bottom: none; }
    .btn { padding: 0.6rem 1.25rem; border-radius: 6px; border: none; font-size: 0.95rem; cursor: pointer; font-weight: 500; background: var(--accent); color: var(--bg); }
    .btn:hover { filter: brightness(1.08); }
    .pulse { animation: pulse 1.5s ease-in-out infinite; }
    @keyframes pulse { 50% { opacity: 0.7; } }
  </style>
</head>
<body>
  <div class="container">
    <a href="{{ url_for('index') }}" class="back">← Back to scanner</a>
    <a href="{{ url_for('log_page') }}" style="margin-left:1rem;">View log</a>
    <h1>Scan results</h1>
    <div id="status-bar" class="status-bar"></div>
    <p id="meta" class="meta"></p>
    <div id="wifi-redteam-section" class="host" style="display:none; margin-bottom:1rem; border-color:var(--accent);">
      <h2 style="font-size:1.1rem; margin-bottom:0.5rem; color:var(--accent);">WiFi Red Team Results</h2>
      <div id="wifi-redteam-content" style="font-size:0.9rem; line-height:1.8;"></div>
    </div>
    <div id="post-exploit-section" class="host" style="display:none; margin-bottom:1rem;">
      <h2 style="font-size:1.1rem; margin-bottom:0.5rem;">Post-Exploitation Findings</h2>
      <div id="post-exploit-content" style="font-size:0.9rem;"></div>
    </div>
    <div id="ai-reportback-section" class="host" style="display:none; margin-bottom:1rem;">
      <h2 style="font-size:1.1rem; margin-bottom:0.5rem;">AI report back</h2>
      <p class="meta" style="margin-bottom:0.5rem;">Autonomous agent summary of what it found and what to fix.</p>
      <div id="ai-reportback-content" style="white-space:pre-wrap; font-size:0.9rem; line-height:1.5;"></div>
    </div>
    <div id="wifi-section" style="display:none;">
      <h2 style="font-size:1.1rem; margin-bottom:0.5rem;">WiFi networks</h2>
      <div id="wifi-networks"></div>
      <div id="pentest-section" style="display:none; margin-top:1rem; padding:1rem; background:var(--surface); border:1px solid var(--border); border-radius:8px;">
        <h3 style="font-size:1rem; margin:0 0 0.5rem 0;">Attack a selected network</h3>
        <p class="meta" style="margin-bottom:0.75rem;">Choose a network and enter its subnet. We’ll discover all hosts, scan ports, run exploits and brute force, and gather everything we can to find ways in.</p>
        <form method="post" action="{{ url_for('start_scan') }}" id="pentest-form">
          <div style="margin-bottom:0.75rem;">
            <label for="pentest-wifi-select" style="display:block; color:var(--muted); font-size:0.85rem; margin-bottom:0.25rem;">Network to attack</label>
            <select id="pentest-wifi-select" name="wifi_network" style="width:100%; max-width:400px; padding:0.5rem; background:var(--bg); border:1px solid var(--border); border-radius:6px; color:var(--text);"></select>
          </div>
          <div style="margin-bottom:0.75rem;">
            <label for="pentest-target" style="display:block; color:var(--muted); font-size:0.85rem; margin-bottom:0.25rem;">Target (IP or CIDR) — subnet of the selected WiFi (e.g. 192.168.2.0/24)</label>
            <input type="text" id="pentest-target" name="target" placeholder="e.g. 192.168.2.0/24" style="width:100%; max-width:400px; padding:0.5rem; background:var(--bg); border:1px solid var(--border); border-radius:6px; color:var(--text);">
          </div>
          <div style="margin-bottom:0.75rem;">
            <label for="pentest-profile" style="display:block; color:var(--muted); font-size:0.85rem; margin-bottom:0.25rem;">Profile</label>
            <select id="pentest-profile" name="profile" style="padding:0.5rem; background:var(--bg); border:1px solid var(--border); border-radius:6px; color:var(--text);">
              <option value="standard">Standard</option>
              <option value="deep">Deep</option>
              <option value="pentest" selected>Pentest (full: ports, exploits, brute, SSL, web, XSS/LFI)</option>
            </select>
          </div>
          <div style="margin-bottom:0.75rem;">
            <label style="display:flex; align-items:center; gap:0.5rem; cursor:pointer;">
              <input type="checkbox" name="scan_all" value="1" checked> Scan all IPs in range (essential for another WiFi; finds every host)
            </label>
          </div>
          <div style="margin-bottom:0.75rem;">
            <label style="display:flex; align-items:center; gap:0.5rem; cursor:pointer;">
              <input type="checkbox" name="include_router" value="1" checked> Include router (gateway) — find ways in via admin UI, default creds, TR-069, etc.
            </label>
          </div>
          <div style="margin-bottom:0.75rem;">
            <label style="display:flex; align-items:center; gap:0.5rem; cursor:pointer;">
              <input type="checkbox" name="use_ai_wordlist" value="1"> Use AI for bruteforce (suggest credentials per service)
            </label>
          </div>
          <div style="margin-bottom:0.75rem;">
            <label style="display:flex; align-items:center; gap:0.5rem; cursor:pointer;">
              <input type="checkbox" name="obfuscate" value="1"> Obfuscate (browser-like traffic, less likely to be blocked)
            </label>
          </div>
          <button type="submit" class="btn btn-primary" id="pentest-submit">Start pen test</button>
        </form>
      </div>
    </div>
    <div id="hosts"></div>
    <div id="ai-redteam-section" class="host" style="display:none; margin-top:1.5rem;">
      <h2 style="font-size:1.1rem; margin-bottom:0.5rem;">AI Red Team (hacker view)</h2>
      <p class="meta" style="margin-bottom:0.75rem;">Like Aikido-style AI pentesting: the AI acts as an attacker and tells you what it would do, which attack chains it sees, and what to fix first.</p>
      <button type="button" class="btn" id="ai-redteam-btn">Get AI hacker analysis</button>
      <div id="ai-redteam-status" class="meta" style="margin-top:0.5rem;"></div>
      <div id="ai-redteam-content" style="margin-top:0.75rem; white-space:pre-wrap; font-size:0.9rem; line-height:1.5;"></div>
    </div>
    <p id="no-results" class="meta" style="display:none;">No results yet. Run a scan from the <a href="{{ url_for('index') }}">home page</a>.</p>
  </div>
  <script>
    const API = '{{ url_for("api_status") }}';
    const POLL_MS = 1500;

    function renderHost(h) {
      let udp = (h.open_udp || []).map(u => u.port).join(', ');
      let html = '<div class="host"><h2>' + escapeHtml(h.host) + '</h2>';
      html += '<div class="device">' + escapeHtml(h.device || 'Unknown') + (h.device_vendor ? ' (' + escapeHtml(h.device_vendor) + ')' : '') + '</div>';
      html += '<div class="ports">TCP: ' + (h.open_tcp && h.open_tcp.length ? h.open_tcp.join(', ') : 'none') + (udp ? ' · UDP: ' + udp : '') + '</div>';
      if (h.findings && h.findings.length) {
        html += '<div class="section-title">Findings</div>';
        h.findings.forEach(f => {
          html += '<div class="finding risk-' + (f.risk || '') + '">[' + (f.port || '') + '] ' + escapeHtml(f.service || '') + ' – ' + (f.risk || '') + ': ' + escapeHtml(f.notes || '');
          if (f.banner) html += '<br><span class="empty">Banner: ' + escapeHtml(String(f.banner).slice(0, 80)) + '</span>';
          html += '</div>';
        });
      }
      if (h.exploits && h.exploits.length) {
        html += '<div class="section-title">Exploits / issues</div>';
        h.exploits.forEach(e => {
          html += '<div class="exploit">' + escapeHtml(e.check || '') + ': ' + escapeHtml(e.details || '') + '</div>';
        });
      }
      if (!(h.findings && h.findings.length) && !(h.exploits && h.exploits.length)) {
        html += '<div class="empty">No findings reported for this host.</div>';
      }
      html += '</div>';
      return html;
    }

    function escapeHtml(s) {
      const div = document.createElement('div');
      div.textContent = s;
      return div.innerHTML;
    }

    function update(data) {
      const statusEl = document.getElementById('status-bar');
      const metaEl = document.getElementById('meta');
      const hostsEl = document.getElementById('hosts');
      const noResultsEl = document.getElementById('no-results');

      if (data.error) {
        statusEl.className = 'status-bar error';
        statusEl.textContent = data.error;
        statusEl.style.display = 'block';
      } else if (data.running) {
        statusEl.className = 'status-bar running pulse';
        const n = data.report && data.report.hosts ? data.report.hosts.length : 0;
        statusEl.innerHTML = 'Scanning <strong>' + escapeHtml(data.target || '') + '</strong> … ' + n + ' host(s) completed. Updates in real time.';
        statusEl.style.display = 'block';
      } else if (data.report && ((data.report.hosts && data.report.hosts.length) || (data.report.wifi_networks && data.report.wifi_networks.length))) {
        statusEl.className = 'status-bar done';
        var msg = 'Scan complete.';
        if (data.report.hosts && data.report.hosts.length) msg += ' ' + data.report.hosts.length + ' host(s) scanned.';
        if (data.report.wifi_networks && data.report.wifi_networks.length) msg += ' ' + data.report.wifi_networks.length + ' WiFi network(s) found.';
        statusEl.textContent = msg;
        statusEl.style.display = 'block';
      } else {
        statusEl.style.display = 'none';
      }

      var wifiSection = document.getElementById('wifi-section');
      var wifiNetworksEl = document.getElementById('wifi-networks');
      var pentestSection = document.getElementById('pentest-section');
      var pentestSelect = document.getElementById('pentest-wifi-select');
      var pentestTarget = document.getElementById('pentest-target');
      if (data.report && data.report.wifi_networks && data.report.wifi_networks.length) {
        wifiSection.style.display = 'block';
        wifiNetworksEl.innerHTML = data.report.wifi_networks.map(function(w) {
          var sig = w.signal != null ? ' ' + w.signal + '%' : '';
          var ch = w.channel != null ? ' ch' + w.channel : '';
          return '<div class="wifi-row">' + escapeHtml(w.ssid || '(hidden)') + ' &nbsp; ' +
            escapeHtml(w.bssid) + sig + ch + ' &nbsp; ' + escapeHtml(w.security || '') + '</div>';
        }).join('');
        pentestSection.style.display = 'block';
        pentestSelect.innerHTML = '<option value="">-- Choose network --</option>' +
          data.report.wifi_networks.map(function(w, i) {
            var label = (w.ssid || '(hidden)') + ' — ' + (w.bssid || '') + (w.security ? ' (' + w.security + ')' : '');
            return '<option value="' + escapeHtml(w.bssid || '') + '">' + escapeHtml(label) + '</option>';
          }).join('');
        if (!pentestTarget.value) pentestTarget.placeholder = 'e.g. 192.168.2.0/24 (subnet for the selected network)';
        var pentestSubmit = document.getElementById('pentest-submit');
        if (pentestSubmit) pentestSubmit.disabled = !!data.running;
      } else {
        wifiSection.style.display = 'none';
        if (pentestSection) pentestSection.style.display = 'none';
      }

      if (data.report && data.report.hosts && data.report.hosts.length) {
        metaEl.textContent = 'Target: ' + (data.report.target || '') + ' · ' + (data.report.scan_type || '') + ' · ' + (data.report.timestamp || '');
        metaEl.style.display = 'block';
        hostsEl.innerHTML = data.report.hosts.map(renderHost).join('');
        hostsEl.style.display = 'block';
        noResultsEl.style.display = 'none';
      } else {
        metaEl.style.display = 'none';
        hostsEl.innerHTML = '';
        hostsEl.style.display = 'none';
        if (!data.running && !data.error) noResultsEl.style.display = 'block';
      }
      var redteamSection = document.getElementById('wifi-redteam-section');
      var redteamContent = document.getElementById('wifi-redteam-content');
      if (redteamSection && redteamContent && data.report && data.report.wifi) {
        var w = data.report.wifi;
        var html = '';
        if (w.ssid) html += '<div><strong>Target:</strong> ' + escapeHtml(w.ssid) + ' (' + escapeHtml(w.bssid || '') + ')</div>';
        if (w.key) html += '<div><strong>WiFi Key:</strong> <code style="background:#0d1117;padding:2px 8px;border-radius:4px;color:var(--accent);">' + escapeHtml(w.key) + '</code></div>';
        if (w.connected) html += '<div><strong>Connected:</strong> Yes (IP: ' + escapeHtml(w.ip || '') + ')</div>';
        if (w.subnet) html += '<div><strong>Subnet:</strong> ' + escapeHtml(w.subnet) + '</div>';
        if (w.gateway) html += '<div><strong>Gateway:</strong> ' + escapeHtml(w.gateway) + '</div>';
        if (w.crack_method) html += '<div><strong>Crack Method:</strong> ' + escapeHtml(w.crack_method) + (w.crack_duration ? ' (' + w.crack_duration.toFixed(1) + 's)' : '') + '</div>';
        redteamSection.style.display = html ? 'block' : 'none';
        redteamContent.innerHTML = html;
      } else if (redteamSection) {
        redteamSection.style.display = 'none';
      }
      var postExSection = document.getElementById('post-exploit-section');
      var postExContent = document.getElementById('post-exploit-content');
      if (postExSection && postExContent && data.report && data.report.post_exploit && data.report.post_exploit.length) {
        postExSection.style.display = 'block';
        postExContent.innerHTML = data.report.post_exploit.map(function(pe) {
          return '<div class="exploit">[' + pe.port + '] ' + escapeHtml(pe.service || '') + ' as ' + escapeHtml(pe.username || '') + ' (' + escapeHtml(pe.access_level || '') + '): ' + escapeHtml(pe.details || '') + '</div>';
        }).join('');
      } else if (postExSection) {
        postExSection.style.display = 'none';
      }
      var aiSection = document.getElementById('ai-redteam-section');
      if (aiSection) aiSection.style.display = (data.report && (data.report.hosts && data.report.hosts.length || data.report.wifi_networks && data.report.wifi_networks.length)) ? 'block' : 'none';
      var aiReportback = document.getElementById('ai-reportback-section');
      var aiReportbackContent = document.getElementById('ai-reportback-content');
      if (aiReportback && aiReportbackContent && data.report && data.report.ai_summary) {
        aiReportback.style.display = 'block';
        aiReportbackContent.textContent = data.report.ai_summary;
      } else if (aiReportback) {
        aiReportback.style.display = 'none';
      }
    }

    function poll() {
      fetch(API)
        .then(r => r.json())
        .then(update)
        .catch(() => {});
    }

    poll();
    const interval = setInterval(() => {
      fetch(API)
        .then(r => r.json())
        .then(data => {
          update(data);
          if (!data.running && !data.error) clearInterval(interval);
        })
        .catch(() => {});
    }, POLL_MS);

    var aiBtn = document.getElementById('ai-redteam-btn');
    var aiStatus = document.getElementById('ai-redteam-status');
    var aiContent = document.getElementById('ai-redteam-content');
    if (aiBtn && aiStatus && aiContent) {
      aiBtn.addEventListener('click', function() {
        aiBtn.disabled = true;
        aiStatus.textContent = 'Asking AI (red team view)...';
        aiContent.textContent = '';
        fetch('{{ url_for("api_ai_redteam") }}', { method: 'POST', headers: { 'Content-Type': 'application/json' } })
          .then(function(r) { return r.json(); })
          .then(function(data) {
            aiBtn.disabled = false;
            if (data.error) {
              aiStatus.textContent = '';
              aiContent.textContent = 'Error: ' + data.error;
              aiContent.style.color = 'var(--danger, #e74c3c)';
            } else {
              aiStatus.textContent = '';
              aiContent.textContent = data.content || '';
              aiContent.style.color = '';
            }
          })
          .catch(function(err) {
            aiBtn.disabled = false;
            aiStatus.textContent = '';
            aiContent.textContent = 'Request failed: ' + (err && err.message ? err.message : 'unknown');
            aiContent.style.color = 'var(--danger, #e74c3c)';
          });
      });
    }
  </script>
</body>
</html>
"""


@app.route("/")
def index():
    with _scan_lock:
        return render_template_string(
            INDEX_HTML,
            scan_running=_scan_state["running"],
            scan_target=_scan_state["target"] or "",
            profile=_scan_state["profile"] or "standard",
            scan_all=_scan_state["scan_all"],
            scan_error=_scan_state["error"],
            wifi_scan=_scan_state.get("wifi") or False,
        )


@app.route("/wifi")
def wifi_scan_page():
    """Scan WiFi subpage: scan for networks, then choose one to pen-test."""
    with _scan_lock:
        scan_running = _scan_state["running"]
    target_required = request.args.get("target_required") == "1"
    return render_template_string(WIFI_SCAN_HTML, scan_running=scan_running, target_required=target_required)


@app.route("/scan-wifi", methods=["POST"])
def scan_wifi_only():
    """Run WiFi scan only; stay on Scan WiFi page so the list appears when done."""
    with _scan_lock:
        if _scan_state["running"]:
            return redirect(url_for("wifi_scan_page"))
    thread = threading.Thread(target=_run_wifi_only_thread, daemon=True)
    thread.start()
    return redirect(url_for("wifi_scan_page"))


@app.route("/wifi-redteam", methods=["POST"])
def start_wifi_redteam():
    """Start the full WiFi red-team attack chain: handshake -> crack -> connect -> scan."""
    bssid = (request.form.get("wifi_network") or "").strip()
    ssid = (request.form.get("ssid") or "").strip()
    interface = (request.form.get("interface") or "").strip() or None
    use_ai = request.form.get("use_ai") == "1"
    wordlist_path = (request.form.get("wordlist_path") or "").strip() or None

    if not bssid:
        return redirect(url_for("wifi_scan_page"))

    if not ssid:
        report_path = SCANS_DIR / REPORT_FILENAME
        if report_path.exists():
            try:
                with open(report_path, encoding="utf-8") as f:
                    report = json.load(f)
                for w in report.get("wifi_networks", []):
                    if w.get("bssid", "").lower() == bssid.lower():
                        ssid = w.get("ssid", "")
                        break
            except Exception:
                pass
        if not ssid:
            ssid = bssid

    with _scan_lock:
        if _scan_state["running"]:
            return redirect(url_for("wifi_scan_page"))
        _scan_state["error"] = None

    thread = threading.Thread(
        target=_run_wifi_redteam_thread,
        args=(bssid, ssid, use_ai, wordlist_path, interface),
        daemon=True,
    )
    thread.start()
    return redirect(url_for("log_page"))


@app.route("/log")
def log_page():
    """Real-time scan log page."""
    return render_template_string(LOG_HTML)


@app.route("/api/log")
def api_log():
    """Return current log file content for real-time log view."""
    with _scan_lock:
        running = _scan_state["running"]
        error = _scan_state.get("error")
    log_path = SCANS_DIR / LOG_FILENAME
    content = ""
    if log_path.exists():
        try:
            with open(log_path, encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception:
            pass
    return jsonify({"running": running, "content": content, "error": error})


@app.route("/scan", methods=["POST"])
def start_scan():
    target = (request.form.get("target") or "").strip()
    include_router = request.form.get("include_router") == "1"
    skip_discovery = False
    if not target:
        from scanner.network import get_default_gateway
        gateway = get_default_gateway() or ""
        if include_router and gateway:
            # Router-only: scan just the gateway
            target = gateway
            skip_discovery = True
        elif gateway:
            # "Search everything": use whole subnet derived from gateway (e.g. 192.168.1.0/24)
            target = _subnet_from_gateway(gateway) or ""
    if not target:
        return redirect(url_for("index"))
    profile = request.form.get("profile") or "standard"
    scan_all = request.form.get("scan_all") == "1"
    wifi = request.form.get("wifi") == "1"
    exploit = profile in ("standard", "deep", "pentest")
    bruteforce = profile in ("standard", "deep", "pentest")
    use_ai_wordlist = request.form.get("use_ai_wordlist") == "1"
    obfuscate = request.form.get("obfuscate") == "1"
    ssl_check = profile in ("deep", "pentest")
    ssh_audit = profile in ("deep", "pentest")
    web_deep = profile in ("deep", "pentest")
    injection = profile in ("deep", "pentest")
    web_advanced = profile == "pentest"

    with _scan_lock:
        if _scan_state["running"]:
            return redirect(url_for("index"))
        _scan_state["error"] = None  # clear previous error

    thread = threading.Thread(
        target=_run_scan_thread,
        args=(target, profile, scan_all, wifi, include_router, skip_discovery, exploit, bruteforce, use_ai_wordlist, obfuscate, ssl_check, ssh_audit, web_deep, injection, web_advanced),
        daemon=True,
    )
    thread.start()
    return redirect(url_for("log_page"))


@app.route("/scan-ai-agent", methods=["POST"])
def start_ai_agent():
    """Start AI agent scan (AI chooses hosts and runs full scans + exploits); redirect to log."""
    target = (request.form.get("target") or "").strip()
    scope_wifi_only = request.form.get("scope") == "wifi"
    # When attacking a selected WiFi, we must have a target (that network's subnet). Do not default to local.
    if scope_wifi_only and not target:
        return redirect(url_for("wifi_scan_page", target_required=1))
    target_was_empty = not target
    if not target:
        from scanner.network import get_default_gateway
        gw = get_default_gateway()
        target = (_subnet_from_gateway(gw) if gw else None) or ""
    if not target:
        return redirect(url_for("index"))
    try:
        max_steps = min(50, max(5, int(request.form.get("max_steps") or "30")))
    except ValueError:
        max_steps = 30
    with _scan_lock:
        if _scan_state["running"]:
            return redirect(url_for("index"))
        _scan_state["error"] = None
    thread = threading.Thread(target=_run_ai_agent_thread, args=(target, max_steps, scope_wifi_only, target_was_empty), daemon=True)
    thread.start()
    return redirect(url_for("log_page"))


@app.route("/api/status")
def api_status():
    """JSON endpoint for real-time poll: running, target, error, report (partial or full)."""
    with _scan_lock:
        running = _scan_state["running"]
        target = _scan_state["target"]
        error = _scan_state["error"]
        report_path = _scan_state["report_path"]

    report = None
    if report_path and Path(report_path).exists():
        try:
            with open(report_path, encoding="utf-8") as f:
                report = json.load(f)
        except Exception:
            pass

    return jsonify({
        "running": running,
        "target": target or "",
        "error": error,
        "report": report,
    })


@app.route("/api/ai-redteam", methods=["POST"])
def api_ai_redteam():
    """Run AI red-team analysis on the last report (attacker view, like Aikido). Returns JSON { content } or { error }."""
    report_path = SCANS_DIR / REPORT_FILENAME
    if not report_path.exists() or report_path.stat().st_size == 0:
        return jsonify({"error": "No report found. Run a scan first."}), 400
    try:
        with open(report_path, encoding="utf-8") as f:
            report = json.load(f)
    except Exception as e:
        return jsonify({"error": f"Invalid report: {e}"}), 400
    try:
        from analyze import analyze_redteam_safe
        content, err = analyze_redteam_safe(report, anonymize=os.environ.get("AI_ANONYMIZE", "1").lower() in ("1", "true", "yes"))
        if err:
            return jsonify({"error": err}), 503
        return jsonify({"content": content or ""})
    except ImportError:
        return jsonify({"error": "AI analysis requires: pip install openai"}), 503
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/results")
def results():
    """Results page: content is updated in real time via polling /api/status."""
    return render_template_string(RESULTS_HTML)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="SYN-REAPER web interface")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="Port (default: 5000)")
    parser.add_argument("--debug", action="store_true", help="Flask debug mode")
    args = parser.parse_args()
    _ensure_scans_dir()
    print(f"SYN-REAPER web UI: http://{args.host}:{args.port}")
    print("Authorized testing only. Do not expose to the internet.")
    app.run(host=args.host, port=args.port, debug=args.debug, use_reloader=False)


if __name__ == "__main__":
    main()
