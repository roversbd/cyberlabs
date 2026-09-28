from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import models
from ..database import get_db
from ..schemas import ProgressOut, ProgressUpdate

router = APIRouter(prefix="/api/progress", tags=["progress"])


def _get_or_create(db: Session, vuln_id: int) -> models.Progress:
    p = db.query(models.Progress).filter(models.Progress.vuln_id == vuln_id).first()
    if not p:
        p = models.Progress(vuln_id=vuln_id)
        db.add(p)
        db.flush()
    return p


@router.get("/{vuln_id}", response_model=ProgressOut)
def get_progress(vuln_id: int, db: Session = Depends(get_db)):
    if not db.get(models.Vulnerability, vuln_id):
        raise HTTPException(404, "vulnerability not found")
    p = _get_or_create(db, vuln_id)
    db.commit()
    return ProgressOut(
        vuln_id=vuln_id,
        completed=p.completed,
        attempts=p.attempts,
        lab_wins=p.lab_wins,
    )


@router.post("/{vuln_id}", response_model=ProgressOut)
def update_progress(vuln_id: int, data: ProgressUpdate, db: Session = Depends(get_db)):
    if not db.get(models.Vulnerability, vuln_id):
        raise HTTPException(404, "vulnerability not found")
    p = _get_or_create(db, vuln_id)
    if data.completed is not None:
        p.completed = data.completed
    p.attempts = max(0, p.attempts + data.attempts_delta)
    if data.lab_win:
        p.lab_wins += 1
        p.completed = True
    db.commit()
    return ProgressOut(
        vuln_id=vuln_id,
        completed=p.completed,
        attempts=p.attempts,
        lab_wins=p.lab_wins,
    )