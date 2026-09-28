from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import models
from ..database import get_db
from ..schemas import SolutionOut, TopicOut, VulnerabilityOut

router = APIRouter(prefix="/api", tags=["topics"])


@router.get("/topics", response_model=list[TopicOut])
def list_topics(db: Session = Depends(get_db)):
    topics = db.query(models.Topic).order_by(models.Topic.sort_order).all()
    out = []
    for t in topics:
        item = TopicOut.model_validate(t)
        item.total_vulns = t.count_vulns()
        item.completed_vulns = t.count_completed(db)
        item.vulns = [VulnerabilityOut.model_validate(v) for v in t.vulns]
        out.append(item)
    return out


@router.get("/topics/{slug}", response_model=TopicOut)
def get_topic(slug: str, db: Session = Depends(get_db)):
    t = db.query(models.Topic).filter(models.Topic.slug == slug).first()
    if not t:
        raise HTTPException(404, "topic not found")
    item = TopicOut.model_validate(t)
    item.total_vulns = t.count_vulns()
    item.completed_vulns = t.count_completed(db)
    item.vulns = [VulnerabilityOut.model_validate(v) for v in t.vulns]
    return item


@router.get("/vulns/{vuln_id}", response_model=VulnerabilityOut)
def get_vuln(vuln_id: int, db: Session = Depends(get_db)):
    v = db.query(models.Vulnerability).filter(models.Vulnerability.id == vuln_id).first()
    if not v:
        raise HTTPException(404, "vulnerability not found")
    return v


@router.post("/vulns/{vuln_id}/solution", response_model=SolutionOut)
def reveal_solution(vuln_id: int, db: Session = Depends(get_db)):
    """Walkthrough. Kept off the normal vuln endpoint so it can only be fetched
    on an explicit action, never preloaded into the lesson page."""
    v = db.query(models.Vulnerability).filter(models.Vulnerability.id == vuln_id).first()
    if not v:
        raise HTTPException(404, "vulnerability not found")
    return SolutionOut(vuln_id=v.id, solution=v.solution)
