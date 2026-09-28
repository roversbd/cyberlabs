import asyncio
import logging
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path

import docker
from docker.errors import APIError, BuildError, DockerException, NotFound

from ..config import settings
from ..models import Lab

log = logging.getLogger("cyberlabs.lab_runner")

# Container port per lab folder under labs/default/<slug>/. Add an entry when you
# add a new prebuilt lab; without one the lab falls back to port 5000.
DEFAULT_PORTS: dict[str, int] = {
    "auth_login": 8091,
    "auth_mfa": 8092,
    "auth_reset": 8093,
}

DOCKERFILE_HEAD = """FROM python:3.11-slim

RUN useradd -m -u 1000 labuser
WORKDIR /app
"""

# Emitted only when the lab actually ships a requirements.txt. A COPY whose glob
# matches nothing fails the build outright ("no source files were specified"),
# which happens before the `if [ -f requirements.txt ]` shell guard can help.
DOCKERFILE_WITH_DEPS = """
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
"""

DOCKERFILE_NO_DEPS = """
RUN pip install --no-cache-dir flask
"""

DOCKERFILE_TAIL = """
COPY . /app

USER labuser
EXPOSE {port}

CMD ["python", "app.py"]
"""

_client = None


def get_client() -> docker.DockerClient:
    global _client
    if _client is None:
        _client = docker.from_env()
    return _client


def _active_labs(db) -> int:
    from ..database import SessionLocal

    s = SessionLocal()
    try:
        return (
            s.query(Lab)
            .filter(Lab.status.in_(["queued", "building", "running"]))
            .count()
        )
    finally:
        s.close()


def _write_dockerfile(source_dir: Path, container_port: int) -> None:
    has_reqs = (source_dir / "requirements.txt").is_file()
    parts = [
        DOCKERFILE_HEAD,
        DOCKERFILE_WITH_DEPS if has_reqs else DOCKERFILE_NO_DEPS,
        DOCKERFILE_TAIL.format(port=container_port),
    ]
    (source_dir / "Dockerfile").write_text("".join(parts), encoding="utf-8")


def _ensure_network() -> None:
    """Internal bridge: containers get NO internet egress, only each other."""
    client = get_client()
    try:
        client.networks.get(settings.network_name)
    except NotFound:
        client.networks.create(
            settings.network_name,
            driver="bridge",
            internal=True,
            labels={"cyberlabs.component": "network"},
        )


def build_image(source_dir: Path, image_tag: str) -> None:
    client = get_client()
    _ensure_network()
    log.info("building image %s from %s", image_tag, source_dir)
    try:
        result = client.images.build(
            path=str(source_dir),
            tag=image_tag,
            rm=True,
            timeout=settings.build_timeout_seconds,
            # NB: the docker SDK spells this "platform" (singular), not "platforms".
            platform=settings.build_platform,
        )
        # images.build() returns either an Image (fully cached, stream already
        # consumed) or a (Image, log-generator) tuple. BuildError is raised by
        # the SDK itself when a chunk contains "error".
        logs = result[1] if isinstance(result, tuple) else ()
        for chunk in logs:
            raw = chunk.get("stream") or chunk.get("error") or ""
            if raw:
                log.debug("build: %s", raw.strip())
    except BuildError as e:
        raise RuntimeError(f"docker build failed: {e}") from e
    except APIError as e:
        raise RuntimeError(f"docker api error during build: {e}") from e


def run_container(
    image_tag: str, container_port: int, lab_id: int, lab_variant: str = "default"
) -> tuple[str, int, str]:
    """Runs the container sandboxed. Returns (container_id, port, reachable_ip).

    Labs live on an *internal* bridge network so they have no internet egress.
    Docker does not create port-publishing NAT rules for internal networks, so
    `-p` would silently do nothing; the host reaches the lab on the container's
    bridge IP instead.
    """
    client = get_client()
    _ensure_network()
    container = client.containers.run(
        image=image_tag,
        name=f"cyberlabs-lab-{lab_id}",
        detach=True,
        mem_limit=settings.mem_limit,
        nano_cpus=settings.cpu_nano,
        pids_limit=settings.pids_limit,
        cap_drop=["ALL"],
        security_opt=["no-new-privileges:true"],
        read_only=True,
        tmpfs={"/tmp": "rw,noexec,nosuid,size=64m"},
        network=settings.network_name,
        environment={
            "LAB_ID": str(lab_id),
            "FLAG": f"FLAG{{lab{lab_id}_{secrets.token_hex(4)}}}",
            # Selects which single weakness this lab app should expose.
            "LAB_VARIANT": lab_variant,
        },
        labels={"cyberlabs.lab_id": str(lab_id), "cyberlabs.component": "lab"},
        oom_kill_disable=False,
    )
    container.reload()
    networks = container.attrs.get("NetworkSettings", {}).get("Networks", {})
    ip = (networks.get(settings.network_name) or {}).get("IPAddress", "")
    if not ip:
        container.remove(force=True)
        raise RuntimeError(f"container got no IP on network {settings.network_name}")
    return container.id, container_port, ip


async def wait_healthy(lab_id: int, port: int, host: str, timeout_s: int = 30) -> bool:
    import httpx

    url = f"http://{host}:{port}/"
    deadline = asyncio.get_running_loop().time() + timeout_s
    async with httpx.AsyncClient(timeout=2.0, verify=False) as client:
        while asyncio.get_running_loop().time() < deadline:
            try:
                r = await client.get(url)
                if r.status_code < 500:
                    return True
            except Exception:  # noqa: BLE001
                pass
            await asyncio.sleep(0.8)
    return False


def teardown_container(container_id: str) -> None:
    if not container_id:
        return
    client = get_client()
    try:
        c = client.containers.get(container_id)
        c.remove(force=True)
    except NotFound:
        pass
    except DockerException as e:
        log.warning("teardown error: %s", e)


def clean_stale_containers() -> None:
    """On startup: rip out any containers/images from a crashed session."""
    client = get_client()
    try:
        for c in client.containers.list(all=True, filters={"label": "cyberlabs.component=lab"}):
            c.remove(force=True)
    except (APIError, DockerException):
        pass


def _as_utc(dt: datetime | None) -> datetime | None:
    """SQLite drops tzinfo on read, so a value written as aware comes back naive.
    Normalize before doing arithmetic or the comparison raises TypeError."""
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


async def monitor_ttl(db) -> None:
    """Background loop killing labs older than TTL and clearing stopped rows."""
    from ..database import SessionLocal

    while True:
        await asyncio.sleep(30)
        s = SessionLocal()
        try:
            now = datetime.now(timezone.utc)
            for lab in s.query(Lab).filter(Lab.status == "running").all():
                started = _as_utc(lab.started_at)
                if started and (now - started).total_seconds() >= settings.lab_ttl_minutes * 60:
                    log.info("TTL expired for lab %s, tearing down", lab.id)
                    teardown_container(lab.container_id)
                    lab.status = "stopped"
                    lab.error = f"auto-stopped after {settings.lab_ttl_minutes} min TTL"
            s.commit()
        except Exception as e:  # noqa: BLE001
            log.warning("ttl monitor error: %s", e)
        finally:
            s.close()


def current_image_tags() -> set[str]:
    client = get_client()
    tags: set[str] = set()
    try:
        for img in client.images.list(filters={"label": "cyberlabs.lab_id"}):
            tags.update(img.tags)
    except (APIError, DockerException):
        pass
    return tags


def sanitize_image_name(name: str) -> str:
    return re.sub(r"[^a-z0-9_.-]", "-", name.lower())[:60].strip("-")