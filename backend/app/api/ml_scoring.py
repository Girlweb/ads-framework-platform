from fastapi import APIRouter, Depends
from app.models.ads_framework import User
from app.core.security import get_current_user
from app.services.ml_scoring import ml_scorer

router = APIRouter(prefix="/ml", tags=["ml-scoring"])

@router.post("/score/{alert_id}")
async def score_alert(
    alert_id: str,
    current_user: User = Depends(get_current_user)
):
    return await ml_scorer.score_alert(alert_id)

@router.get("/prioritized")
async def get_prioritized_alerts(
    current_user: User = Depends(get_current_user)
):
    return await ml_scorer.score_all_alerts()
