import asyncio
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from .config import settings
from .database import Base, SessionLocal, engine
from .routers import labs as labs_router
from .routers import progress as progress_router
from .routers import topics as topics_router
from .schemas import DashboardStats
from .services.lab_runner import clean_stale_containers, monitor_ttl

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("cyberlabs.app")


def create_app() -> FastAPI:
    Base.metadata.create_all(bind=engine)

    # idempotent seeds
    with SessionLocal() as s:
        seed_safe(s)

    app = FastAPI(title=settings.app_name, version="1.0.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(topics_router.router)
    app.include_router(labs_router.router)
    app.include_router(progress_router.router)

    @app.get("/api/stats", response_model=DashboardStats)
    def stats():
        from . import models

        with SessionLocal() as s:
            total_topics = s.query(models.Topic).count()
            total_vulns = s.query(models.Vulnerability).count()
            learned = s.query(models.Progress).filter(models.Progress.completed.is_(True)).count()
            wins = s.query(models.Progress).filter(models.Progress.lab_wins > 0).count()
            active = s.query(models.Lab).filter(models.Lab.status.in_(["queued", "building", "running"])).count()
            pts = (
                s.query(models.Vulnerability)
                .join(models.Progress, models.Progress.vuln_id == models.Vulnerability.id)
                .filter(models.Progress.completed.is_(True))
                .all()
            )
            xp = sum(v.xp for v in pts)
        return DashboardStats(
            total_topics=total_topics,
            total_vulns=total_vulns,
            learned=learned,
            wins=wins,
            active_labs=active,
            xp_total=xp,
        )

    @app.on_event("startup")
    async def startup():
        clean_stale_containers()
        asyncio.create_task(monitor_ttl(None))

    return app


def seed_safe(s: Session) -> None:
    from .seed import seed_topics

    seed_topics(s)


app = create_app()