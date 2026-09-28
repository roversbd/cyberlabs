"""Seeds topics + vulnerability content into the DB.

Content lives in ``app/content/``. The only module currently defined is the
standalone Authentication module (``content/authentication.py``); add further
topic dicts to ``TOPICS`` there when you author them.

Adding or editing a lesson
--------------------------
Seeding is an **upsert keyed on slug**, so you can add a batch of lessons and
restart without wiping progress. The first run creates the database; later runs
update the content in place.

    ./scripts/dev.sh restart

If you change the *shape* of a table (a new column), the existing database file
does not get the column, so delete it and let startup recreate it::

    ./scripts/dev.sh stop && rm -f data/cyberlabs.db && ./scripts/dev.sh start

Lesson shape
------------
Use ``app.content.builder.lesson()``. It supplies the defaults and the fixed
page structure, so a lesson only has to state what is actually different::

    lesson(
        "auth-example",
        "Example weakness",
        difficulty="apprentice",       # apprentice | practitioner | expert
        category="Credentials & Enumeration",
        summary="One line for the card.",
        theory="...markdown...",
        scenario="Who you are and what you have.",
        objectives=["...", "..."],
        hints=["nudge", "nudger", "nearly there", "almost"],
        solution="...walkthrough...",
        methodology="How a tester approaches it.",
        credentials="Accounts and passwords.",
        endpoints="GET / - POST /login",
        behaviour="What the app does differently.",
        success="What you must achieve.",
        remediation="...",
        detection="...",
        references=["https://..."],
        lab_family="auth_login",       # folder under labs/default/
        lab_variant="enum_response",   # LAB_VARIANT for that app
        sort_order=1,
    )

``solution`` is stored server-side and is *not* part of the normal
``/api/vulns`` payload. The lesson page POSTs to ``/api/vulns/{id}/solution``
only when the learner asks for the walkthrough, so the answer is never
preloaded into the page.

Lab apps
--------
``lab_family`` names a folder under ``labs/default/``. One folder is one app;
``lab_variant`` selects which single weakness it exposes for a given run, via
the ``LAB_VARIANT`` environment variable injected by ``lab_runner``. That keeps
the container intentionally vulnerable in exactly one way. Register the port in
``lab_runner.DEFAULT_PORTS``.
"""

from __future__ import annotations

# --- content goes below this line -------------------------------------------------

from .content.authentication import AUTH_TOPIC

TOPICS: list[dict] = [AUTH_TOPIC]

# ---------------------------------------------------------------------------------

# Lesson fields copied straight onto the Vulnerability row.
_LESSON_FIELDS = (
    "slug",
    "name",
    "difficulty",
    "category",
    "xp",
    "summary",
    "theory",
    "scenario",
    "objectives",
    "hints",
    "solution",
    "methodology",
    "starting_credentials",
    "endpoints",
    "application_behaviour",
    "success_condition",
    "remediation",
    "detection",
    "references",
    "default_lab_slug",
    "lab_variant",
    "lab_objective",
    "sort_order",
)


def seed_topics(db) -> None:
    """Create or update every topic/lesson in TOPICS. Idempotent."""
    from .models import Topic, Vulnerability

    existing = {t.slug: t for t in db.query(Topic).all()}

    for t in TOPICS:
        topic = existing.get(t["slug"])
        if topic is None:
            topic = Topic(slug=t["slug"])
            db.add(topic)
        topic.name = t["name"]
        topic.tagline = t.get("tagline", "")
        topic.description = t.get("description", "")
        topic.learning_map = t.get("learning_map", "")
        topic.icon = t.get("icon", "📦")
        topic.color = t.get("color", "#0f0")
        topic.sort_order = t.get("sort_order", 0)
        db.flush()

        current = {v.slug: v for v in topic.vulns}
        seen: set[str] = set()

        for i, v in enumerate(t.get("vulns", [])):
            slug = v["slug"]
            if slug in seen:
                raise ValueError(f"duplicate lesson slug in topic {t['slug']}: {slug}")
            seen.add(slug)

            row = current.get(slug)
            if row is None:
                row = Vulnerability(topic_id=topic.id, slug=slug)
                db.add(row)
            for field in _LESSON_FIELDS:
                if field in v:
                    setattr(row, field, v[field])
            if "sort_order" not in v:
                row.sort_order = i + 1

        # Drop lessons that were removed from the content file so the catalogue
        # always matches what is on disk. Progress rows cascade.
        for slug, row in current.items():
            if slug not in seen:
                db.delete(row)

    db.commit()
