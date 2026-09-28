from datetime import datetime
import json

from pydantic import BaseModel, ConfigDict, field_validator


class VulnerabilityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    topic_id: int = 0
    topic_slug: str = ""
    slug: str
    name: str
    difficulty: str
    xp: int
    summary: str
    theory: str
    category: str = ""
    scenario: str = ""
    objectives: list[str] = []
    hints: list[str] = []
    methodology: str = ""
    starting_credentials: str = ""
    endpoints: str = ""
    application_behaviour: str = ""
    success_condition: str = ""
    remediation: str = ""
    detection: str = ""
    references: str = ""
    default_lab_slug: str
    lab_variant: str = ""
    lab_objective: str
    sort_order: int

    @field_validator("objectives", mode="before")
    @classmethod
    def _split_objectives(cls, v):
        if isinstance(v, str):
            return [ln.strip(" -*\t") for ln in v.splitlines() if ln.strip()]
        return v or []

    @field_validator("hints", mode="before")
    @classmethod
    def _parse_hints(cls, v):
        if isinstance(v, str):
            try:
                parsed = json.loads(v) if v.strip() else []
            except json.JSONDecodeError:
                parsed = []
            return [str(h) for h in parsed]
        return v or []


class SolutionOut(BaseModel):
    """Returned only when the learner explicitly asks to reveal the solution."""

    vuln_id: int
    solution: str


class TopicOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    slug: str
    name: str
    tagline: str
    description: str
    learning_map: str = ""
    icon: str
    color: str
    sort_order: int
    total_vulns: int = 0
    completed_vulns: int = 0
    vulns: list[VulnerabilityOut] = []


class LabOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str
    source: str
    vuln_slug: str
    prompt: str
    status: str
    error: str
    port: int
    host: str = ""
    container_id: str
    lab_variant: str = ""
    url: str
    ttl_minutes: int = 0
    created_at: datetime
    started_at: datetime | None


class ProgressOut(BaseModel):
    vuln_id: int
    completed: bool
    attempts: int
    lab_wins: int


class AiLabRequest(BaseModel):
    prompt: str
    vuln_slug: str = ""


class DefaultLabRequest(BaseModel):
    vuln_slug: str


class ProgressUpdate(BaseModel):
    completed: bool | None = None
    attempts_delta: int = 0
    lab_win: bool = False


class DashboardStats(BaseModel):
    total_topics: int
    total_vulns: int
    learned: int
    wins: int
    active_labs: int
    xp_total: int