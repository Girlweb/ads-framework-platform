from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from app.db.database import get_db
from app.models.integrations import Alert
from app.models.ads_framework import User
from app.core.security import get_current_user
from app.services.alert_ingestion import alert_ingestion_service

router = APIRouter(prefix="/alerts", tags=["alerts"])

class AlertCreate(BaseModel):
    title: str
    severity: str
    description: Optional[str] = None
    mitre_tactics: Optional[list] = []
    mitre_techniques: Optional[list] = []

@router.post("/ingest")
async def ingest_alert(
    alert: AlertCreate,
    current_user: User = Depends(get_current_user)
):
    result = await alert_ingestion_service.ingest_single_alert(alert.dict())
    return result

@router.post("/simulate")
async def simulate_alerts(
    count: int = 5,
    current_user: User = Depends(get_current_user)
):
    results = await alert_ingestion_service.simulate_alert_stream(count)
    return {"alerts_generated": len(results), "alerts": results}

@router.get("/")
async def list_alerts(
    skip: int = 0,
    limit: int = 100,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(Alert)
    if severity:
        query = query.filter(Alert.severity == severity)
    if status:
        query = query.filter(Alert.status == status)
    alerts = query.order_by(Alert.created_at.desc()).offset(skip).limit(limit).all()
    return [
        {
            "id": str(a.id),
            "title": a.title,
            "severity": a.severity,
            "status": a.status,
            "mitre_tactics": a.mitre_tactics,
            "created_at": a.created_at.isoformat() if a.created_at else None
        }
        for a in alerts
    ]

@router.get("/stats")
async def alert_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    total = db.query(Alert).count()
    critical = db.query(Alert).filter(Alert.severity == "critical").count()
    high = db.query(Alert).filter(Alert.severity == "high").count()
    medium = db.query(Alert).filter(Alert.severity == "medium").count()
    new = db.query(Alert).filter(Alert.status == "new").count()
    investigated = db.query(Alert).filter(Alert.status == "investigated").count()
    return {
        "total": total,
        "by_severity": {"critical": critical, "high": high, "medium": medium},
        "by_status": {"new": new, "investigated": investigated}
    }
