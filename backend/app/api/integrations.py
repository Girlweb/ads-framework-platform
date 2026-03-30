from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Dict
from pydantic import BaseModel

from app.db.database import get_db
from app.models.integrations import Integration, Alert
from app.models.ads_framework import User
from app.core.security import get_current_user

router = APIRouter(prefix="/integrations", tags=["integrations"])

class IntegrationCreate(BaseModel):
    name: str
    integration_type: str
    connector_class: str
    config: Dict

@router.post("/")
async def create_integration(
    integration: IntegrationCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        db_integration = Integration(
            name=integration.name,
            integration_type=integration.integration_type,
            connector_class=integration.connector_class,
            config=integration.config,
            created_by=current_user.id
        )
        db.add(db_integration)
        db.commit()
        db.refresh(db_integration)
        return {"id": str(db_integration.id), "name": db_integration.name, "type": db_integration.integration_type, "status": "created"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

@router.get("/")
async def list_integrations(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    integrations = db.query(Integration).all()
    return [{"id": str(i.id), "name": i.name, "type": i.integration_type, "is_active": i.is_active} for i in integrations]

@router.get("/alerts/")
async def list_alerts(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    alerts = db.query(Alert).offset(skip).limit(limit).all()
    return [{"id": str(a.id), "title": a.title, "severity": a.severity, "status": a.status} for a in alerts]
