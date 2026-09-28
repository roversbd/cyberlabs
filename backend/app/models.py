from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Topic(Base):
    __tablename__ = "topics"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    slug: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(120))
    tagline: Mapped[str] = mapped_column(String(300), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    learning_map: Mapped[str] = mapped_column(Text, default="")
    icon: Mapped[str] = mapped_column(String(16), default="🛡️")
    color: Mapped[str] = mapped_column(String(16), default="#0f0")
    sort_order: Mapped[int] = mapped_column(Integer, default=0)

    vulns: Mapped[list["Vulnerability"]] = relationship(
        back_populates="topic", cascade="all, delete-orphan", order_by="Vulnerability.sort_order"
    )

    # NOTE: these are deliberately *not* named total_vulns / completed_vulns.
    # TopicOut has fields with those names and validates from ORM attributes, so
    # same-named methods would be read as the field value and fail int coercion.
    def count_vulns(self) -> int:
        return len(self.vulns)

    def count_completed(self, db) -> int:
        from .models import Progress  # local import to avoid cycle

        ids = [v.id for v in self.vulns]
        if not ids:
            return 0
        return (
            db.query(Progress.id)
            .filter(Progress.vuln_id.in_(ids), Progress.completed.is_(True))
            .count()
        )


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    topic_id: Mapped[int] = mapped_column(ForeignKey("topics.id"), index=True)
    slug: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(120))
    # apprentice | practitioner | expert
    difficulty: Mapped[str] = mapped_column(String(16), default="apprentice")
    xp: Mapped[int] = mapped_column(Integer, default=100)
    summary: Mapped[str] = mapped_column(String(400), default="")
    theory: Mapped[str] = mapped_column(Text, default="")
    category: Mapped[str] = mapped_column(String(80), default="")
    scenario: Mapped[str] = mapped_column(Text, default="")
    objectives: Mapped[str] = mapped_column(Text, default="")  # newline separated
    methodology: Mapped[str] = mapped_column(Text, default="")
    starting_credentials: Mapped[str] = mapped_column(Text, default="")
    endpoints: Mapped[str] = mapped_column(Text, default="")
    application_behaviour: Mapped[str] = mapped_column(Text, default="")
    success_condition: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    detection: Mapped[str] = mapped_column(Text, default="")
    references: Mapped[str] = mapped_column(Text, default="")
    # JSON list of progressively more specific hints (4 entries)
    hints: Mapped[str] = mapped_column(Text, default="[]")
    # Full walkthrough, only ever sent to the client after an explicit request
    solution: Mapped[str] = mapped_column(Text, default="")
    default_lab_slug: Mapped[str] = mapped_column(String(80), default="")  # key into labs/default/
    # Which behaviour of that app to activate (one app, many single-vuln variants)
    lab_variant: Mapped[str] = mapped_column(String(80), default="")
    lab_objective: Mapped[str] = mapped_column(String(500), default="")
    sort_order: Mapped[int] = mapped_column(Integer, default=0)

    topic: Mapped["Topic"] = relationship(back_populates="vulns")

    @property
    def topic_slug(self) -> str:
        return self.topic.slug if self.topic else ""


class Lab(Base):
    __tablename__ = "labs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(160), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(32), default="ai")  # "default" | "ai"
    vuln_slug: Mapped[str] = mapped_column(String(80), default="")
    prompt: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(
        String(24), default="queued"
    )  # queued | building | running | error | stopped
    error: Mapped[str] = mapped_column(Text, default="")
    port: Mapped[int] = mapped_column(Integer, default=0)
    host: Mapped[str] = mapped_column(String(80), default="")
    container_id: Mapped[str] = mapped_column(String(80), default="")
    image_tag: Mapped[str] = mapped_column(String(120), default="")
    source_dir: Mapped[str] = mapped_column(String(400), default="")
    lab_variant: Mapped[str] = mapped_column(String(80), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    @property
    def url(self) -> str:
        if not self.port:
            return ""
        return f"http://{self.host or '127.0.0.1'}:{self.port}"

    @property
    def ttl_minutes(self) -> int:
        from .config import settings

        return settings.lab_ttl_minutes


class Progress(Base):
    __tablename__ = "progress"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    vuln_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id"), index=True)
    completed: Mapped[bool] = mapped_column(default=False)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    lab_wins: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)