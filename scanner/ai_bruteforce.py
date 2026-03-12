"""
AI-generated bruteforce credentials. Asks the LLM for username:password pairs to try
for a given host/port/service. Requires openai and .env (OPENAI_API_KEY or OPENAI_API_BASE).
"""

import os
from typing import List, Tuple

# Lazy import openai in get_ai_bruteforce_credentials


def get_ai_bruteforce_credentials(
    host: str,
    port: int,
    service: str,
    is_router: bool = False,
    max_pairs: int = 30,
) -> List[Tuple[str, str]]:
    """
    Ask the AI for username:password pairs to try for this host/port/service.
    Returns list of (username, password). On API error or parse failure, returns [].
    """
    try:
        from openai import OpenAI
    except ImportError:
        return []

    base_url = os.environ.get("OPENAI_API_BASE") or os.environ.get("OPENAI_BASE_URL")
    api_key = os.environ.get("OPENAI_API_KEY")
    if base_url and not api_key:
        api_key = "ollama"
    if not base_url and not api_key:
        return []

    model = os.environ.get("AI_MODEL")
    if not model and base_url and ("11434" in str(base_url) or "localhost" in str(base_url).lower()):
        model = "llama3.1"
    if not model:
        model = "gpt-4o-mini"

    system = (
        "You suggest username and password pairs for brute-force login attempts (authorized testing only). "
        "Reply with one pair per line, format 'username:password' or 'username password'. "
        "No explanation, only lines. Use common weak credentials, default router/device logins, and service-specific defaults."
    )
    user = (
        f"Suggest up to {max_pairs} username:password pairs to try for {service} on port {port} (host {host}). "
    )
    if is_router:
        user += "Include router/gateway default logins (admin, root, support, ISP defaults). "
    user += "One pair per line, format username:password. Nothing else."

    try:
        client = OpenAI(api_key=api_key, base_url=base_url) if base_url else OpenAI(api_key=api_key)
        r = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            max_tokens=1024,
            temperature=0.3,
        )
        text = (r.choices[0].message.content or "").strip()
    except Exception:
        return []

    # Parse lines: "user:pass" or "user pass"
    pairs: List[Tuple[str, str]] = []
    seen = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            parts = line.split(":", 1)
            u, p = (parts[0].strip(), parts[1].strip())
        else:
            parts = line.split(None, 1)
            if len(parts) >= 2:
                u, p = parts[0].strip(), parts[1].strip()
            else:
                continue
        if not u and not p:
            continue
        key = (u or "", p or "")
        if key not in seen:
            seen.add(key)
            pairs.append((u or "", p or ""))
        if len(pairs) >= max_pairs:
            break
    return pairs
