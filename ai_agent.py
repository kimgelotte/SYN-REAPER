"""
AI agent that runs scans and exploits: the AI chooses which host to scan next and when to stop.
Requires: pip install openai. Set OPENAI_API_KEY or OPENAI_API_BASE (e.g. Ollama) in .env.

Usage:
  python ai_agent.py 192.168.1.0/24
  python ai_agent.py 192.168.1.0/24 --scan-all -o report.json
  python ai_agent.py 192.168.1.1 --max-steps 5
"""

import json
import os
import re
import sys
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Discovery and scan
from scanner.network import (
    get_all_hosts,
    discover_hosts,
    get_default_gateway,
    arp_discover_with_mac,
)
from main import run_scan


def _normalize_mac(mac: str) -> str:
    """Normalize MAC to lowercase colon-separated."""
    s = str(mac).strip().lower().replace("-", ":")
    return s


def _get_hosts(target: str, scan_all: bool) -> list[str]:
    """Return list of host IPs for the target (single IP or CIDR)."""
    if "/" not in target and target.count(".") == 3:
        return [target]
    if scan_all:
        return get_all_hosts(target)
    return discover_hosts(target, timeout=2) or get_all_hosts(target)


def _get_hosts_with_mac(target: str, scan_all: bool) -> tuple[list[str], dict[str, str]]:
    """
    Return (host_ips, mac_to_ip). If ARP with MAC is available and target is CIDR,
    mac_to_ip maps normalized MAC -> IP. Otherwise mac_to_ip is empty.
    """
    if "/" not in target and target.count(".") == 3:
        return [target], {}
    if scan_all:
        hosts = get_all_hosts(target)
        # Optionally run ARP to get MACs even in scan-all (so AI can target by MAC)
        ip_mac = arp_discover_with_mac(target, timeout=2) if "/" in target else []
        mac_to_ip = {_normalize_mac(m): ip for ip, m in ip_mac}
        if ip_mac:
            # Merge: prefer ARP-discovered IPs, add any from get_all_hosts not in ARP
            arp_ips = {ip for ip, _ in ip_mac}
            for ip in hosts:
                if ip not in arp_ips:
                    arp_ips.add(ip)
            hosts = sorted(arp_ips, key=lambda x: (len(x), x))
        return hosts, mac_to_ip
    ip_mac = arp_discover_with_mac(target, timeout=2) if "/" in target else []
    if ip_mac:
        hosts = [ip for ip, _ in ip_mac]
        mac_to_ip = {_normalize_mac(m): ip for ip, m in ip_mac}
        return hosts, mac_to_ip
    hosts = discover_hosts(target, timeout=2) or get_all_hosts(target)
    return hosts, {}


def _call_llm(prompt: str, system: str, max_tokens: int = 128) -> str:
    """Call OpenAI-compatible API; return raw response text. Raises on missing config or API error."""
    try:
        from openai import OpenAI
    except ImportError:
        sys.exit("Install openai: python -m pip install openai")

    base_url = os.environ.get("OPENAI_API_BASE") or os.environ.get("OPENAI_BASE_URL")
    api_key = os.environ.get("OPENAI_API_KEY")
    if base_url and not api_key:
        api_key = "ollama"
    if not base_url and not api_key:
        sys.exit("Set OPENAI_API_KEY or OPENAI_API_BASE in .env")

    if os.environ.get("AI_MODEL"):
        model = os.environ.get("AI_MODEL")
    elif base_url and ("11434" in str(base_url) or "localhost" in str(base_url).lower()):
        model = "llama3.1"
    else:
        model = "gpt-4o-mini"
    client = OpenAI(api_key=api_key, base_url=base_url) if base_url else OpenAI(api_key=api_key)
    r = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ],
        max_tokens=max_tokens,
        temperature=0.2,
    )
    return (r.choices[0].message.content or "").strip()


def _summarize_host(host_data: dict) -> str:
    """Richer one-line summary so the AI can reason about what was found."""
    host = host_data.get("host", "?")
    tcp = host_data.get("open_tcp") or []
    findings = host_data.get("findings") or []
    exploits = host_data.get("exploits") or []
    parts = [f"TCP {tcp[:8]}{'...' if len(tcp) > 8 else ''}"]
    if findings:
        by_risk = {}
        for f in findings:
            r = f.get("risk") or "medium"
            by_risk[r] = by_risk.get(r, 0) + 1
        if by_risk:
            risk_str = ",".join(f"{r}:{n}" for r, n in sorted(by_risk.items(), key=lambda x: -(["critical", "high", "medium", "low"].index(x[0]) if x[0] in ("critical", "high", "medium", "low") else 0)))
            parts.append(f"findings({risk_str})")
    if exploits:
        part_strs = []
        for e in (exploits or [])[:5]:
            det = (e.get("details") or "")[:40]
            if "CRACKED" in det or "password" in det.lower():
                part_strs.append("creds!")
            else:
                part_strs.append((e.get("check") or "?")[:15])
        parts.append("exploits:" + ";".join(part_strs))
    return " | ".join(parts)


def _parse_action(
    response: str,
    allowed_ips: set[str],
    mac_to_ip: dict[str, str] | None = None,
    wifi_networks: list | None = None,
) -> tuple[str, str | None]:
    """Parse AI response into ('scan', ip), ('attack_wifi', bssid), or ('done', None). Returns ('error', msg) on parse failure."""
    mac_to_ip = mac_to_ip or {}
    resp_upper = response.upper().strip()
    if "DONE" in resp_upper or "FINISH" in resp_upper or "STOP" in resp_upper:
        return "done", None
    # ATTACK_WIFI <bssid>
    wifi_match = re.search(
        r"ATTACK[_\s]?WIFI\s+(([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2})",
        response,
        re.I,
    )
    if wifi_match:
        bssid = wifi_match.group(1).strip().lower()
        if wifi_networks:
            for w in wifi_networks:
                wb = (w.get("bssid") or getattr(w, "bssid", "") or "").lower()
                if wb == bssid:
                    return "attack_wifi", bssid
            return "error", f"BSSID {bssid} not in scanned WiFi list"
        return "attack_wifi", bssid
    # SCAN_MAC aa:bb:cc:dd:ee:ff (or aa-bb-cc-dd-ee-ff)
    mac_match = re.search(
        r"SCAN[_\s]?MAC\s+(([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2})",
        response,
        re.I,
    )
    if mac_match:
        raw = mac_match.group(1).strip()
        mac = _normalize_mac(raw)
        if mac in mac_to_ip:
            ip = mac_to_ip[mac]
            if ip in allowed_ips:
                return "scan", ip
            return "error", f"MAC {mac} resolved to {ip} not in list"
        return "error", f"MAC {raw} not found in discovered hosts"
    # SCAN <ip>
    match = re.search(r"SCAN\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", response, re.I)
    if match:
        ip = match.group(1)
        if ip in allowed_ips:
            return "scan", ip
        return "error", f"IP {ip} not in allowed list"
    for ip in allowed_ips:
        if ip in response:
            return "scan", ip
    return "error", "Reply with: SCAN <ip>, SCAN_MAC <mac>, ATTACK_WIFI <bssid>, or DONE"


def run_ai_agent(
    target: str,
    scan_all: bool = True,
    report_path: str | Path | None = None,
    max_steps: int = 30,
    include_router: bool = True,
    scope_wifi_only: bool = False,
    wifi_attack: bool = False,
) -> dict:
    """
    Run the AI agent: discover hosts, then loop where the AI chooses the next host to scan
    (full scan + exploits + brute). Merges results into one report. Returns final report dict.
    When scope_wifi_only is True, the AI is restricted to only the WiFi network and devices
    in the target list (no other networks or IPs).
    """
    report_path = Path(report_path) if report_path else Path("scans") / "ai_agent_report.json"
    report_path = report_path.resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)

    print("AI agent: discovering hosts...")
    hosts, mac_to_ip = _get_hosts_with_mac(target, scan_all)
    if not hosts:
        print("No hosts found. Try --scan-all if ICMP is blocked.")
        from datetime import datetime
        minimal = {"target": target, "scan_type": "AI agent", "timestamp": datetime.now().isoformat(), "hosts": [], "ai_summary": "No hosts discovered. Enable --scan-all if ICMP is blocked."}
        if scope_wifi_only:
            minimal["scope"] = "WiFi network only"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        if report_path.suffix.lower() == ".json":
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(minimal, f, indent=2)
            print(f"Report saved to: {report_path}")
        return minimal

    # When scope is WiFi-only, do not add current default gateway (it may be another network)
    if scope_wifi_only:
        include_router = False
    gateway = get_default_gateway() if include_router else None
    if gateway and gateway not in hosts:
        hosts = [gateway] + [h for h in hosts if h != gateway]
        print(f"Including router: {gateway}")

    ip_to_mac = {ip: mac for mac, ip in mac_to_ip.items()}
    if mac_to_ip:
        print(f"Resolved {len(mac_to_ip)} host(s) with MAC addresses (you can target by MAC).")

    allowed_ips = set(hosts)
    scanned: dict[str, str] = {}
    report_hosts: list[dict] = []
    report_meta = {"target": target, "scan_type": "AI agent", "timestamp": ""}
    if scope_wifi_only:
        report_meta["scope"] = "WiFi network only"

    # WiFi scanning for AI-driven WiFi attacks
    wifi_networks = []
    if wifi_attack:
        print("AI agent: scanning for nearby WiFi networks...")
        try:
            from scanner.wifi import scan_wifi_networks
            wifi_networks_raw = scan_wifi_networks(timeout=15)
            wifi_networks = [
                {"ssid": w.ssid, "bssid": w.bssid, "signal": w.signal, "channel": w.channel, "security": w.security}
                for w in wifi_networks_raw
            ]
            if wifi_networks:
                print(f"  Found {len(wifi_networks)} WiFi network(s):")
                for w in wifi_networks:
                    sig = f" {w['signal']}%" if w.get("signal") is not None else ""
                    ch = f" ch{w['channel']}" if w.get("channel") is not None else ""
                    print(f"    {w['ssid'] or '(hidden)'}  {w['bssid']}{sig}{ch}  {w.get('security', '')}")
            else:
                print("  No WiFi networks found.")
        except Exception as e:
            print(f"  WiFi scan failed: {e}")

    scope_rule = (
        "STRICT SCOPE: You may ONLY attack the WiFi network and its devices listed below. "
        "Only output SCAN <ip> or SCAN_MAC <mac> for hosts in the list. Do not suggest or scan any other networks or IPs. "
        if scope_wifi_only
        else ""
    )
    wifi_rule = (
        "You can also attack external WiFi networks using ATTACK_WIFI <bssid>. This will capture the handshake, crack the key, connect, and scan the internal network automatically. "
        if wifi_attack and wifi_networks
        else ""
    )
    system = f"""You are an autonomous penetration testing agent. {scope_rule}{wifi_rule}
You decide which host to scan next based on the results so far.
Use the scan results to prioritize: unscanned hosts first; then hosts that looked interesting (e.g. many findings, credentials found, router).
When you have enough to report (e.g. you've covered the main targets or found critical issues), say DONE.
Reply with exactly one line:
- SCAN <ip>   : full scan (ports, exploits, brute force) on that IP.
- SCAN_MAC <mac> : full scan on the host with this MAC (e.g. router: aa:bb:cc:dd:ee:ff).
{('- ATTACK_WIFI <bssid> : attack an external WiFi network (capture handshake, crack key, connect, scan).' + chr(10)) if wifi_attack and wifi_networks else ''}- DONE       : stop; you will then receive the full report and summarize findings.
Only output one of the commands above. Nothing else."""

    def _host_line(ip: str) -> str:
        mac_str = f" (MAC: {ip_to_mac[ip]})" if ip in ip_to_mac else ""
        if ip in scanned:
            return f"  {ip}{mac_str}: scanned - {scanned[ip]}"
        return f"  {ip}{mac_str}: not scanned yet"

    wifi_redteam_results = []

    step = 0
    while step < max_steps:
        step += 1
        lines = [f"Target: {target}", f"Hosts ({len(hosts)}):", ""]
        for ip in hosts:
            lines.append(_host_line(ip))
        if wifi_attack and wifi_networks:
            lines.append("")
            lines.append(f"WiFi Networks ({len(wifi_networks)}):")
            for w in wifi_networks:
                attacked = any(r.get("bssid") == w["bssid"] for r in wifi_redteam_results)
                status = "attacked" if attacked else "not attacked"
                lines.append(f"  {w.get('ssid', '(hidden)')} ({w['bssid']}) {w.get('security', '')} - {status}")
        lines.append("")
        actions = "SCAN <ip>, SCAN_MAC <mac>"
        if wifi_attack and wifi_networks:
            actions += ", ATTACK_WIFI <bssid>"
        lines.append(f"Decide based on the results above. Reply: {actions}, or DONE")

        prompt = "\n".join(lines)
        try:
            response = _call_llm(prompt, system)
        except Exception as e:
            print(f"AI error: {e}")
            break

        action, arg = _parse_action(response, allowed_ips, mac_to_ip, wifi_networks if wifi_attack else None)
        if action == "error":
            print(f"AI said: {response[:80]}... -> {arg}")
            continue
        if action == "done":
            print("AI decided to stop.")
            break

        if action == "attack_wifi":
            bssid = arg
            target_ssid = ""
            for w in wifi_networks:
                if w.get("bssid", "").lower() == bssid.lower():
                    target_ssid = w.get("ssid", "")
                    break
            print(f"\n[{step}/{max_steps}] AI chose to attack WiFi: {target_ssid} ({bssid})")
            try:
                from scanner.wifi_redteam import run_wifi_redteam
                wifi_report_path = str(report_path.parent / f"_ai_wifi_{bssid.replace(':', '')}.json")
                result = run_wifi_redteam(
                    target_bssid=bssid,
                    target_ssid=target_ssid,
                    use_ai=True,
                    report_path=wifi_report_path,
                )
                wifi_result_dict = {
                    "bssid": bssid, "ssid": target_ssid,
                    "key": result.wifi_key, "connected": result.connected,
                    "subnet": result.subnet, "error": result.error,
                }
                wifi_redteam_results.append(wifi_result_dict)
                if result.scan_report:
                    for h in result.scan_report.get("hosts", []):
                        report_hosts.append(h)
                        ip = h.get("host", "")
                        scanned[ip] = _summarize_host(h)
                        if ip not in allowed_ips:
                            hosts.append(ip)
                            allowed_ips.add(ip)
                if result.wifi_key:
                    scanned[bssid] = f"WiFi cracked: key={result.wifi_key}, subnet={result.subnet}"
                else:
                    scanned[bssid] = f"WiFi attack: {result.error or 'key not found'}"
            except Exception as e:
                print(f"WiFi attack failed: {e}")
                scanned[bssid] = f"WiFi attack error: {e}"
                wifi_redteam_results.append({"bssid": bssid, "ssid": target_ssid, "error": str(e)})
            continue

        # SCAN arg (ip)
        ip = arg
        print(f"\n[{step}/{max_steps}] AI chose to scan {ip} (full scan + exploits + brute)...")
        temp_report = report_path.parent / f"_ai_agent_{ip.replace('.', '_')}.json"
        try:
            run_scan(
                target=ip,
                skip_discovery=True,
                scan_all=False,
                report_path=str(temp_report),
                show_progress=True,
                profile="pentest",
                exploit=True,
                bruteforce=True,
                use_ai_wordlist=True,
                ssl_check=True,
                ssh_audit=True,
                web_deep=True,
                injection=True,
                web_advanced=True,
                include_router=(ip == gateway),
                write_report_after_each_host=True,
            )
        except Exception as e:
            print(f"Scan failed: {e}")
            scanned[ip] = f"error: {e}"
            continue

        if temp_report.exists():
            try:
                with open(temp_report, encoding="utf-8") as f:
                    data = json.load(f)
                host_list = data.get("hosts") or []
                for h in host_list:
                    report_hosts.append(h)
                    scanned[h.get("host", ip)] = _summarize_host(h)
                temp_report.unlink(missing_ok=True)
            except Exception as e:
                print(f"Could not read temp report: {e}")
                scanned[ip] = "scan ran; report read failed"

    # Build final report (always write to file so UI has something)
    from datetime import datetime
    report_meta["timestamp"] = datetime.now().isoformat()
    report_meta["hosts"] = report_hosts
    if wifi_redteam_results:
        report_meta["wifi_attacks"] = wifi_redteam_results
        for wr in wifi_redteam_results:
            if wr.get("key"):
                report_meta.setdefault("wifi", {})
                report_meta["wifi"]["ssid"] = wr.get("ssid", "")
                report_meta["wifi"]["bssid"] = wr.get("bssid", "")
                report_meta["wifi"]["key"] = wr["key"]
                report_meta["wifi"]["connected"] = wr.get("connected", False)
                report_meta["wifi"]["subnet"] = wr.get("subnet", "")
                break
    report = dict(report_meta)

    # Autonomous "report back": AI summarizes what it found (optional; don't block report write)
    if report_hosts:
        print("\nAI agent: summarizing findings (report back)...")
        try:
            condensed = []
            for h in report_hosts:
                line = f"{h.get('host', '?')}: " + _summarize_host(h)
                expl = (h.get("exploits") or [])
                for e in expl[:3]:
                    line += f" | {e.get('check', '')}: {str(e.get('details', ''))[:50]}"
                condensed.append(line)
            report_back_prompt = (
                "You just ran an autonomous penetration test. Here is what was found:\n\n"
                + "\n".join(condensed[:30])
                + "\n\nSummarize in 1 short paragraph: (1) What you found – key hosts and risks. "
                "(2) Top 3–5 things the user should fix first. (3) Any credentials or critical issues. Be concise and actionable."
            )
            report_back_system = (
                "You are a penetration tester reporting to the client. "
                "Summarize the scan results clearly: what you found, what to fix first, and any critical issues."
            )
            ai_summary = _call_llm(report_back_prompt, report_back_system, max_tokens=1024)
            report["ai_summary"] = ai_summary
            print("\n" + "=" * 50)
            print("AI REPORT BACK")
            print("=" * 50)
            print(ai_summary)
            print("=" * 50)
        except Exception as e:
            print(f"AI report-back failed: {e}")
            report["ai_summary"] = f"(Summary failed: {e})"
    else:
        report["ai_summary"] = "No hosts were scanned (AI stopped with no scans or no hosts in scope)."

    try:
        if report_path.suffix.lower() == ".json":
            report_path.parent.mkdir(parents=True, exist_ok=True)
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            print(f"\nReport saved to: {report_path}")
    except Exception as e:
        print(f"Failed to write report: {e}")

    return report


def main():
    import argparse
    p = argparse.ArgumentParser(description="AI agent: AI chooses which hosts to scan and runs full scans + exploits")
    p.add_argument("target", help="Target: IP or CIDR (e.g. 192.168.1.0/24)")
    p.add_argument("--scan-all", "-A", action="store_true", default=True,
                   help="Discover all IPs in CIDR without ping (default: True)")
    p.add_argument("--no-scan-all", action="store_true", help="Use ping discovery only")
    p.add_argument("-o", "--output", type=Path, default=Path("scans") / "ai_agent_report.json",
                   help="Output report path")
    p.add_argument("--max-steps", type=int, default=30, help="Max scan steps (default: 30)")
    p.add_argument("--no-router", action="store_true", help="Do not add default gateway to list")
    p.add_argument("--wifi-only", action="store_true", help="Restrict AI to only this network (WiFi scope); do not add gateway from other interfaces")
    p.add_argument("--wifi-attack", action="store_true", help="Enable AI to attack external WiFi networks (scan, crack, connect, pen-test)")
    args = p.parse_args()

    run_ai_agent(
        target=args.target,
        scan_all=not args.no_scan_all,
        report_path=args.output,
        max_steps=args.max_steps,
        include_router=not args.no_router,
        scope_wifi_only=args.wifi_only,
        wifi_attack=args.wifi_attack,
    )


if __name__ == "__main__":
    main()
