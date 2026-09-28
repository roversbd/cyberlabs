"""Shared helpers for authoring CyberLabs content.

Keeping the builders in one place means a new lab only has to supply the parts
that actually differ from the default, and the page structure stays identical
across every lesson.
"""

from __future__ import annotations

import json

DIFFICULTY_XP = {"apprentice": 100, "practitioner": 250, "expert": 500}

DIFFICULTY_ORDER = ["apprentice", "practitioner", "expert"]


def _bullets(items) -> str:
    return "\n".join(f"- {i}" for i in items)


def lesson(
    slug: str,
    name: str,
    *,
    difficulty: str = "apprentice",
    category: str = "Fundamentals",
    summary: str,
    theory: str,
    scenario: str = "",
    objectives: list[str] | None = None,
    hints: list[str] | None = None,
    solution: str = "",
    methodology: str = "",
    credentials: str = "",
    endpoints: str = "",
    behaviour: str = "",
    success: str = "",
    remediation: str = "",
    detection: str = "",
    references: list[str] | None = None,
    lab_family: str = "",
    lab_variant: str = "",
    sort_order: int | None = None,
    xp: int | None = None,
) -> dict:
    """Build one Vulnerability payload.

    `sort_order` doubles as the learner's catalogue number, so labs are numbered
    to match the requested list. Theory modules pass a negative value to sort
    ahead of the labs without consuming catalogue numbers.

    `solution` is stored server-side and is deliberately NOT part of the normal
    /api/vulns response - the UI has to POST to /vulns/{id}/solution to get it,
    which makes the reveal an explicit learner action.
    """
    obj = list(objectives or [])
    if success and success not in obj:
        obj.append(success)

    payload = {
        "slug": slug,
        "name": name,
        "difficulty": difficulty,
        "category": category,
        "xp": xp if xp is not None else DIFFICULTY_XP.get(difficulty, 100),
        "summary": summary,
        "theory": theory.strip() + "\n",
        "scenario": scenario,
        "objectives": _bullets(obj),
        "hints": json.dumps(list(hints or []), ensure_ascii=False, indent=2),
        "solution": solution,
        "methodology": methodology,
        "starting_credentials": credentials,
        "endpoints": endpoints,
        "application_behaviour": behaviour,
        "success_condition": success,
        "remediation": remediation,
        "detection": detection,
        "references": _bullets(references or []),
        "default_lab_slug": lab_family,
        "lab_variant": lab_variant,
        "lab_objective": success,
    }
    if sort_order is not None:
        payload["sort_order"] = sort_order
    return payload
