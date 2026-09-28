from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import models
from ..database import get_db
from ..schemas import AiLabRequest, DefaultLabRequest, LabOut
from ..services import lab_factory

router = APIRouter(prefix="/api/labs", tags=["labs"])


def _to_out(lab) -> LabOut:
    return LabOut.model_validate(lab)


@router.get("", response_model=list[LabOut])
def list_labs(db: Session = Depends(get_db)):
    labs = db.query(models.Lab).order_by(models.Lab.id.desc()).limit(50).all()
    return [_to_out(l) for l in labs]


@router.get("/{lab_id}", response_model=LabOut)
def get_lab(lab_id: int, db: Session = Depends(get_db)):
    lab = db.get(models.Lab, lab_id)
    if not lab:
        raise HTTPException(404, "lab not found")
    return lab


@router.post("/default", response_model=LabOut)
def create_default_lab(req: DefaultLabRequest, background: BackgroundTasks, db: Session = Depends(get_db)):
    vuln = db.query(models.Vulnerability).filter(models.Vulnerability.slug == req.vuln_slug).first()
    if not vuln or not vuln.default_lab_slug:
        raise HTTPException(404, "no default lab for this vulnerability")
    try:
        lab = lab_factory.create_default_lab(db, vuln)
    except RuntimeError as e:
        raise HTTPException(409, str(e)) from e
    background.add_task(lab_factory.spawn_by_id, lab.id)
    return lab


@router.post("/ai", response_model=LabOut)
def create_ai_lab(req: AiLabRequest, background: BackgroundTasks, db: Session = Depends(get_db)):
    prompt = (req.prompt or "").strip()
    if len(prompt) < 5:
        raise HTTPException(422, "describe the lab you want (e.g. 'SQL injection in a search box')")
    try:
        lab = lab_factory.create_ai_lab(db, prompt, req.vuln_slug)
    except RuntimeError as e:
        raise HTTPException(409, str(e)) from e
    background.add_task(lab_factory.spawn_by_id, lab.id)
    return lab


@router.delete("/{lab_id}", response_model=LabOut)
def delete_lab(lab_id: int, db: Session = Depends(get_db)):
    lab = db.get(models.Lab, lab_id)
    if not lab:
        raise HTTPException(404, "lab not found")
    lab_factory.teardown(db, lab)
    return lab