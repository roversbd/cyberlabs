import json
import logging
import re

import httpx

from ..config import settings

log = logging.getLogger("cyberlabs.lab_generator")

SYSTEM_PROMPT = """You are a lab generator for a bug-bounty learning platform called CyberLabs.

You generate a SMALL, intentionally-vulnerable web application that a student can attack
from localhost. Rules:

1. Language MUST be Python 3 with Flask. Single `app.py` file. Optionally a `requirements.txt`
   (only if you need more than flask).
2. The app must contain the vulnerability the user requests, implemented simply and clearly
   (it is a teaching lab). DO NOT write secure code and DO NOT add accidental extra severe
   vulns. One clear vulnerability per lab.
3. The app must listen on host 0.0.0.0 and the port you declare. It runs in a sandboxed
   container with no internet and limited RAM/CPU, so do not use heavy frameworks,
   databases you cannot start easily (prefer sqlite / in-memory), or network calls.
4. The app MUST include a hidden success route: the flag is only reachable by exploiting the
   intended vulnerability. Simpler is better. The flag string is this exact literal:
   `CYBERLABS_FLAG_PLACEHOLDER`  (the server will substitute it).
   Examples: a `/flag` that only the admin session can fetch; a route whose value appears only
   when a stored-XSS payload executes; an endpoint requiring the dumped password to earn a cookie.
5. Keep the app under ~120 lines. Make the bug obvious to a beginner (comments like
   "VULNERABLE" are forbidden — students must spot it themselves, but keep it clearly a lab).
6. Must return ONLY valid JSON, no markdown fences, no prose. Schema:
{
  "name": "short lab title",
  "description": "one sentence, what the student will attack",
  "port": 5000,
  "files": {"app.py": "<full source>", "requirements.txt": "<optional>"}
}
"""


class AIError(Exception):
    pass


def _strip_fences(text: str) -> str:
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    return text.strip()


def generate_lab(prompt: str) -> dict:
    """Calls the OpenAI-compatible API. Returns parsed {name,description,port,files}."""
    if not settings.ai_api_key:
        raise AIError(
            "No AI provider configured: set AI_API_KEY (and optionally AI_BASE_URL) in backend/.env. "
            "Default labs still work without it."
        )

    headers = {
        "Authorization": f"Bearer {settings.ai_api_key}",
        "Content-Type": "application/json",
    }
    body = {
        "model": settings.ai_model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Vulnerability/lab requested: {prompt}"},
        ],
        "temperature": 0.4,
        **({"response_format": {"type": "json_object"}} if "openai" in settings.ai_base_url or "api.openai" in settings.ai_base_url else {}),
    }

    try:
        r = httpx.post(
            f"{settings.ai_base_url.rstrip('/')}/chat/completions",
            headers=headers,
            json=body,
            timeout=settings.ai_timeout_seconds,
        )
        r.raise_for_status()
        content = r.json()["choices"][0]["message"]["content"]
    except httpx.HTTPStatusError as e:
        raise AIError(f"AI provider returned {e.response.status_code}: {e.response.text[:300]}") from e
    except (httpx.HTTPError, KeyError, IndexError) as e:
        raise AIError(f"AI call failed: {e}") from e

    data = json.loads(_strip_fences(content)) if _strip_fences(content).startswith("{") else None
    if data is None:
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise AIError(f"AI returned invalid JSON: {e}") from e

    files = data.get("files") or {}
    if not files or "app.py" not in files:
        raise AIError("AI response missing app.py")

    port = int(data.get("port", 5000))
    if not (1 <= port <= 65535):
        raise AIError(f"Invalid port from AI: {port}")

    return {
        "name": str(data.get("name", "AI Lab"))[:160],
        "description": str(data.get("description", prompt))[:2000],
        "port": port,
        "files": files,
    }