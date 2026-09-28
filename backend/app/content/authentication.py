"""Authentication module content: theory + labs."""

from __future__ import annotations

from .auth_theory import AUTH_THEORY_LESSONS, LEARNING_MAP
from .auth_labs_mfa_reset import MFA_RESET_LABS
from .auth_labs_login import enumeration_labs

AUTH_LABS: list[dict] = [*enumeration_labs(), *MFA_RESET_LABS]


def _strip_front_matter(lessons: list[dict]) -> list[dict]:
    """The first PortSwigger lab lives in its own module; avoid duplicating it."""
    seen: set[str] = set()
    out: list[dict] = []
    for item in lessons:
        if item["slug"] in seen:
            continue
        seen.add(item["slug"])
        out.append(item)
    return out


AUTH_TOPIC: dict = {
    "slug": "authentication",
    "name": "Authentication",
    "icon": "\U0001f510",
    "color": "#e05252",
    "tagline": "Proving who someone is — and every way that proof fails.",
    "description": (
        "Authentication is the gate. Everything downstream assumes the gate held, which is "
        "why attackers start here and why almost every authorisation bug is easier to "
        "exploit when authentication is weak.\n\n"
        "This module covers the full identity-establishment surface: credentials and "
        "enumeration, brute force, registration, password policy and comparison, login "
        "workflow state, password reset and recovery, multi-factor authentication, one-time "
        "passwords, magic links, account lifecycle, and security questions. It is scoped "
        "strictly to proving identity — session management, access control, and the "
        "cryptography of OAuth/OIDC/JWT are separate modules.\n\n"
        "Every lab runs an isolated, intentionally vulnerable application in its own "
        "container, and exposes exactly the one weakness it teaches."
    ),
    "sort_order": 1,
    "learning_map": LEARNING_MAP,
    "vulns": [*AUTH_THEORY_LESSONS, *_strip_front_matter(AUTH_LABS)],
}
