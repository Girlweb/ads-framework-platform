from fastapi import APIRouter, Depends
from app.models.ads_framework import User
from app.core.security import get_current_user
from app.services.threat_intelligence import threat_intel_service

router = APIRouter(prefix="/threat-intel", tags=["threat-intelligence"])

@router.post("/enrich/{alert_id}")
async def enrich_alert(
    alert_id: str,
    current_user: User = Depends(get_current_user)
):
    result = await threat_intel_service.enrich_alert(alert_id)
    return result

@router.post("/enrich-all")
async def enrich_all_alerts(
    current_user: User = Depends(get_current_user)
):
    result = await threat_intel_service.enrich_all_pending()
    return result
