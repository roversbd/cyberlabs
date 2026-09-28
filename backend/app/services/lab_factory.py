import asyncio
import logging
import shutil
from pathlib import Path

from ..config import settings
from ..models import Lab, Vulnerability
from . import lab_generator, lab_runner

log = logging.getLogger("cyberlabs.lab_factory")

RESERVED_PLACEHOLDER = "CYBERLABS_FLAG_PLACEHOLDER"


def _build_context_for_default(lab: Lab) -> Path:
    """Copy the repo's default-lab source into a per-lab build dir."""
    src = settings.labs_dir / "default" / lab.source_dir if lab.source_dir else None
    if not src or not src.exists():
        raise RuntimeError(f"default lab source missing: {src}")
    ctx = settings.generated_dir / "build" / f"lab-{lab.id}"
    if ctx.exists():
        shutil.rmtree(ctx)
    ctx.mkdir(parents=True, exist_ok=True)
    for item in src.iterdir():
        if item.name.startswith("."):
            continue
        dst = ctx / item.name
        if item.is_dir():
            shutil.copytree(item, dst)
        else:
            shutil.copy2(item, dst)
    return ctx


def _build_context_for_ai(lab: Lab, generated: dict) -> Path:
    ctx = settings.generated_dir / f"lab-{lab.id}"
    if ctx.exists():
        shutil.rmtree(ctx)
    ctx.mkdir(parents=True, exist_ok=True)
    for relpath, content in generated["files"].items():
        safe = Path(relpath).name  # flatten: no path traversal in writes
        (ctx / safe).write_text(content, encoding="utf-8")
    return ctx


def _inject_flag(app_source: str, lab_id: int) -> str:
    import secrets

    flag = f"FLAG{{lab{lab_id}_{secrets.token_hex(4)}}}"
    return app_source.replace(RESERVED_PLACEHOLDER, flag)


def create_default_lab(db, vuln: Vulnerability) -> Lab:
    _check_capacity(db)
    lab = Lab(
        name=f"Default Lab: {vuln.name}",
        description=vuln.lab_objective or f"Practice {vuln.name}",
        source="default",
        vuln_slug=vuln.slug,
        source_dir=vuln.default_lab_slug,
        lab_variant=vuln.lab_variant or "default",
        status="queued",
    )
    db.add(lab)
    db.commit()
    db.refresh(lab)
    return lab


def create_ai_lab(db, prompt: str, vuln_slug: str, name_hint: str = "") -> Lab:
    _check_capacity(db)
    lab = Lab(
        name=name_hint or f"AI Lab · {prompt[:60]}",
        description=prompt,
        source="ai",
        vuln_slug=vuln_slug,
        prompt=prompt,
        status="queued",
    )
    db.add(lab)
    db.commit()
    db.refresh(lab)
    return lab


def _check_capacity(db) -> None:
    active = (
        db.query(Lab)
        .filter(Lab.status.in_(["queued", "building", "running"]))
        .count()
    )
    if active >= settings.max_concurrent_labs:
        raise RuntimeError(
            f"Lab limit reached ({settings.max_concurrent_labs} active). "
            "Stop an existing lab before creating a new one."
        )


async def spawn_by_id(lab_id: int) -> None:
    """Drive a lab through build -> run -> healthy using its own DB session.

    The request-scoped session from the creating endpoint is closed as soon as
    the response is sent, so the background task must open its own.
    """
    from ..database import SessionLocal

    db = SessionLocal()
    try:
        lab = db.get(Lab, lab_id)
        if lab is not None:
            await spawn(db, lab)
    finally:
        db.close()


async def spawn(db, lab: Lab) -> None:
    """Drives a lab through build -> run -> healthy. Runs in a background task."""
    lab_id = lab.id
    lab.status = "building"
    lab.error = ""
    db.commit()
    try:
        if lab.source == "default":
            container_port = lab_runner.DEFAULT_PORTS.get(lab.source_dir, 5000)
            ctx = _build_context_for_default(lab)
            variant = lab.lab_variant or "default"
        else:
            generated = await asyncio.to_thread(lab_generator.generate_lab, lab.prompt)
            container_port = generated["port"]
            ctx = _build_context_for_ai(lab, generated)
            variant = "default"
            if generated.get("name"):
                lab.name = generated["name"]
            if generated.get("description"):
                lab.description = generated["description"]
            db.commit()

        # Substitute the flag placeholder into all source files.
        import secrets

        flag = f"FLAG{{lab{lab_id}_{secrets.token_hex(4)}}}"
        for f in ctx.glob("**/*.py"):
            text = f.read_text(encoding="utf-8")
            if RESERVED_PLACEHOLDER in text:
                f.write_text(text.replace(RESERVED_PLACEHOLDER, flag), encoding="utf-8")

        lab_runner._write_dockerfile(ctx, container_port)
        image_tag = f"{settings.image_prefix}/lab-{lab_id}:latest"

        await asyncio.to_thread(lab_runner.build_image, ctx, image_tag)
        container_id, port, host_ip = await asyncio.to_thread(
            lab_runner.run_container, image_tag, container_port, lab_id, variant
        )

        healthy = await lab_runner.wait_healthy(lab_id, port, host_ip)
        if not healthy:
            lab_runner.teardown_container(container_id)
            raise RuntimeError("Lab started but did not answer HTTP within 30s")

        from datetime import datetime, timezone

        lab.status = "running"
        lab.port = port
        lab.host = host_ip
        lab.container_id = container_id
        lab.image_tag = image_tag
        lab.started_at = datetime.now(timezone.utc)
        lab.error = ""
        db.commit()
        # Build the URL from locals: commit expires ORM attributes, and reading
        # them from async context would trigger a lazy load (MissingGreenlet).
        log.info("lab %s live at http://%s:%s", lab_id, host_ip, port)
    except Exception as e:  # noqa: BLE001
        log.exception("spawn failed for lab %s", lab_id)
        lab.status = "error"
        lab.error = str(e)[:2000]
        lab_runner.teardown_container(lab.container_id)
        db.commit()


def teardown(db, lab: Lab, reason: str = "user stopped") -> None:
    lab_runner.teardown_container(lab.container_id)
    lab.status = "stopped"
    lab.error = reason if reason != "user stopped" else ""
    lab.port = 0
    lab.started_at = None
    db.commit()