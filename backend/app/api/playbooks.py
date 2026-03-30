from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Dict, Optional
from app.db.database import get_db
from app.models.integrations import Playbook
from app.models.ads_framework import User
from app.core.security import get_current_user
from app.services.playbook_engine import playbook_engine

router = APIRouter(prefix="/playbooks", tags=["playbooks"])

class PlaybookCreate(BaseModel):
    name: str
    description: Optional[str] = None
    trigger_conditions: Dict
    steps: List[Dict]
    requires_approval: bool = False

@router.post("/")
async def create_playbook(
    playbook: PlaybookCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    db_playbook = Playbook(
        name=playbook.name,
        description=playbook.description,
        trigger_conditions=playbook.trigger_conditions,
        steps=playbook.steps,
        requires_approval=playbook.requires_approval,
        created_by=current_user.id
    )
    db.add(db_playbook)
    db.commit()
    db.refresh(db_playbook)
    return {"id": str(db_playbook.id), "name": db_playbook.name, "status": "created"}

@router.get("/")
async def list_playbooks(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    playbooks = db.query(Playbook).all()
    return [{"id": str(p.id), "name": p.name, "is_active": p.is_active, "execution_count": p.execution_count} for p in playbooks]

@router.post("/{playbook_id}/execute/{alert_id}")
async def execute_playbook(
    playbook_id: str,
    alert_id: str,
    current_user: User = Depends(get_current_user)
):
    result = await playbook_engine.execute_playbook(playbook_id, alert_id)
    return result
