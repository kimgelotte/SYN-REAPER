"""
AI-powered report analysis - Generate executive summary from SYN-REAPER JSON reports.
Requires: pip install openai

Settings: Use .env (copy from .env.example) or environment variables.
External APIs (OpenAI): Anonymization is ON by default - no IPs, hostnames, or keys sent.
Self-hosted (Ollama): Anonymization is OFF by default.
"""

import argparse
import html
import json
import os
import re
import sys
from pathlib import Path

# Load .env if available (optional dependency)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


def _anonymize_report(data: dict) -> dict:
    """Replace IPs and CIDRs with placeholders for privacy. No keys or identifiers sent."""
    data = json.loads(json.dumps(data))  # deep copy
    ip_to_label: dict[str, str] = {}
    cidr_to_label: dict[str, str] = {}
    label_counter = [0]

    def _next_label() -> str:
        label_counter[0] += 1
        return f"host{label_counter[0]}"

    def _next_net() -> str:
        label_counter[0] += 1
        return f"network{label_counter[0]}"

    def _replace_ip(match: re.Match) -> str:
        ip = match.group(0)
        if ip not in ip_to_label:
            ip_to_label[ip] = _next_label()
        return ip_to_label[ip]

    def _replace_cidr(match: re.Match) -> str:
        cidr = match.group(0)
        if cidr not in cidr_to_label:
            cidr_to_label[cidr] = _next_net()
        return cidr_to_label[cidr]

    cidr_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b")
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    json_str = json.dumps(data)
    json_str = cidr_pattern.sub(_replace_cidr, json_str)
    json_str = ip_pattern.sub(_replace_ip, json_str)
    return json.loads(json_str)


def _summary_to_html(summary: str, report: dict) -> str:
    """Wrap summary in a simple HTML document."""
    escaped = html.escape(summary)
    paragraphs = [f"<p>{p.replace(chr(10), '<br>')}</p>" for p in escaped.split("\n\n") if p.strip()]
    body = "\n".join(paragraphs) if paragraphs else f"<p>{escaped.replace(chr(10), '<br>')}</p>"
    target = report.get("target", "Unknown")
    timestamp = report.get("timestamp", "")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>AI Summary - {target}</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 800px; margin: 2rem auto; padding: 0 1rem; line-height: 1.6; }}
    h1 {{ font-size: 1.25rem; color: #333; }}
    .meta {{ color: #666; font-size: 0.9rem; margin-bottom: 1.5rem; }}
    .summary {{ background: #f5f5f5; padding: 1rem; border-radius: 6px; }}
  </style>
</head>
<body>
  <h1>AI Executive Summary</h1>
  <p class="meta">Target: {target} &bull; Scan: {report.get("scan_type", "")} &bull; {timestamp}</p>
  <div class="summary">{body}</div>
</body>
</html>"""


def _build_prompt(report: dict, max_chars: int = 12000) -> str:
    """Build a condensed representation of the report for the LLM."""
    report_str = json.dumps(report, indent=2)
    if len(report_str) > max_chars:
        report_str = report_str[:max_chars] + "\n... (truncated)"
    return report_str


EXECUTIVE_SYSTEM_PROMPT = """You are a security analyst. Analyze this vulnerability scan report and provide:
1. EXECUTIVE SUMMARY: 2-3 sentences on overall risk and key concerns.
2. TOP 5 PRIORITIES: Most critical findings to address first (host/port, finding, why it matters).
3. NEXT STEPS: 3-5 concrete recommended actions.

Be concise. Use plain language for non-technical readers. Focus on business impact."""

def _default_model(base_url: str | None) -> str:
    """Default model: Ollama/local often use llama3.1; OpenAI uses gpt-4o-mini."""
    if os.environ.get("AI_MODEL"):
        return os.environ.get("AI_MODEL", "gpt-4o-mini")
    if base_url and ("11434" in str(base_url) or "localhost" in str(base_url).lower()):
        return "llama3.1"
    return "gpt-4o-mini"


RED_TEAM_SYSTEM_PROMPT = """You are an expert penetration tester / red teamer. Think like an attacker. Analyze this vulnerability scan report from a hacker's perspective.

Provide:
1. ATTACKER VIEW: In 2-4 sentences, what does an attacker see here? What's the most attractive entry point and why?
2. ATTACK CHAINS: What would you try first? List 3-5 concrete attack steps (e.g. "Brute force router admin → pivot to LAN", "Exploit X on port Y → credential access"). Be specific to the hosts and services in the report.
3. PRIORITY TARGETS: Which host(s) and service(s) would you prioritize and why (e.g. default creds, known CVEs, missing auth)?
4. FIX FROM ATTACKER'S EYES: What would make you give up or move on? Give 3-5 defensive actions that directly block the attacks you described.

Write in direct, red-team language. Be practical and specific. No generic advice—tie every point to findings in the report."""


def _call_openai(
    report: dict,
    system_prompt: str,
    anonymize: bool | None,
    model: str,
    base_url: str | None,
    api_key: str | None,
) -> str:
    """Common OpenAI call with given system prompt."""
    try:
        from openai import OpenAI
    except ImportError:
        sys.exit("Install openai: python -m pip install openai")

    base_url = base_url or os.environ.get("OPENAI_API_BASE") or os.environ.get("OPENAI_BASE_URL")
    api_key = api_key or os.environ.get("OPENAI_API_KEY")

    if not base_url and not api_key:
        sys.exit("Set OPENAI_API_KEY (for OpenAI) or OPENAI_API_BASE (for self-hosted) in .env or environment")
    if base_url and not api_key:
        api_key = "ollama"

    env_anon = os.environ.get("AI_ANONYMIZE", "").lower().strip()
    if anonymize is not None:
        should_anonymize = anonymize
    elif env_anon in ("1", "true", "yes", "on"):
        should_anonymize = True
    elif env_anon in ("0", "false", "no", "off"):
        should_anonymize = False
    else:
        is_external = base_url is None or "openai.com" in (base_url or "")
        should_anonymize = is_external
    if should_anonymize:
        report = _anonymize_report(report)
        print("Anonymizing report (IPs/CIDRs removed) before sending to API.", file=sys.stderr)

    report_snippet = _build_prompt(report)
    user_prompt = f"""Analyze this SYN-REAPER security scan report:\n\n{report_snippet}"""

    client = OpenAI(api_key=api_key, base_url=base_url) if base_url else OpenAI(api_key=api_key)
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        max_tokens=1024,
        temperature=0.3,
    )
    return response.choices[0].message.content or ""


def analyze_with_openai(
    report: dict,
    anonymize: bool | None = None,
    model: str = "gpt-4o-mini",
    base_url: str | None = None,
    api_key: str | None = None,
    persona: str = "executive",
) -> str:
    """Send report to OpenAI-compatible API. persona: 'executive' (summary) or 'redteam' (attacker view)."""
    prompt = RED_TEAM_SYSTEM_PROMPT if persona == "redteam" else EXECUTIVE_SYSTEM_PROMPT
    return _call_openai(report, prompt, anonymize, model, base_url, api_key)


def analyze_redteam_safe(
    report: dict,
    model: str | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
    anonymize: bool = True,
) -> tuple[str | None, str | None]:
    """
    Red-team analysis for programmatic use (e.g. web UI). Never sys.exit.
    Returns (content, None) on success or (None, error_message) on failure.
    """
    try:
        from openai import OpenAI
    except ImportError:
        return None, "Install openai: pip install openai"

    base_url = base_url or os.environ.get("OPENAI_API_BASE") or os.environ.get("OPENAI_BASE_URL")
    api_key = api_key or os.environ.get("OPENAI_API_KEY")
    if base_url and not api_key:
        api_key = "ollama"
    if not base_url and not api_key:
        return None, "Set OPENAI_API_KEY or OPENAI_API_BASE in .env"

    if model is None:
        model = _default_model(base_url)

    if anonymize:
        report = _anonymize_report(report)
    report_snippet = _build_prompt(report)
    user_prompt = f"Analyze this SYN-REAPER security scan report:\n\n{report_snippet}"

    try:
        client = OpenAI(api_key=api_key, base_url=base_url) if base_url else OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": RED_TEAM_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            max_tokens=1024,
            temperature=0.3,
        )
        return (response.choices[0].message.content or ""), None
    except Exception as e:
        return None, str(e)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate AI executive summary from SYN-REAPER JSON report",
    )
    parser.add_argument(
        "report",
        type=Path,
        help="Path to JSON report file",
    )
    anon_group = parser.add_mutually_exclusive_group()
    anon_group.add_argument(
        "--anonymize",
        action="store_true",
        help="Anonymize IPs/CIDRs before sending (default for external APIs)",
    )
    anon_group.add_argument(
        "--no-anonymize",
        action="store_true",
        help="Disable anonymization (use only with self-hosted/trusted API)",
    )
    parser.add_argument(
        "--persona",
        choices=("executive", "redteam"),
        default="executive",
        help="executive = summary for stakeholders; redteam = attacker view, attack chains (default: executive)",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Model name (default: from AI_MODEL or auto for Ollama=llama3.1, OpenAI=gpt-4o-mini)",
    )
    parser.add_argument(
        "--base-url",
        metavar="URL",
        help="API base URL for self-hosted (e.g. http://localhost:11434/v1 for Ollama)",
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        metavar="FILE",
        help="Write summary to file (.txt or .html)",
    )
    args = parser.parse_args()

    if not args.report.exists():
        sys.exit(f"Report not found: {args.report}")

    with open(args.report, encoding="utf-8") as f:
        report = json.load(f)

    anonymize = True if args.anonymize else (False if args.no_anonymize else None)
    base_url = args.base_url or os.environ.get("OPENAI_API_BASE") or os.environ.get("OPENAI_BASE_URL")
    model = args.model or os.environ.get("AI_MODEL") or _default_model(base_url)
    print("Analyzing report...", file=sys.stderr)
    summary = analyze_with_openai(
        report,
        anonymize=anonymize,
        model=model,
        base_url=args.base_url,
        persona=args.persona,
    )

    if args.output:
        if args.output.suffix.lower() in (".html", ".htm"):
            html = _summary_to_html(summary, report)
            args.output.write_text(html, encoding="utf-8")
        else:
            args.output.write_text(summary, encoding="utf-8")
        print(f"Summary written to {args.output}", file=sys.stderr)
    else:
        print(summary)


if __name__ == "__main__":
    main()
