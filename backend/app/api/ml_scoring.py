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

@router.get("/model-score/{alert_id}")
async def score_with_model(
    alert_id: str,
    current_user: User = Depends(get_current_user)
):
    return await ml_scorer.score_alert_with_model(alert_id)

@router.get("/model-prioritized")
async def get_model_prioritized_alerts(
    current_user: User = Depends(get_current_user)
):
    from app.db.database import SessionLocal
    from app.models.integrations import Alert
    db = SessionLocal()
    try:
        alerts = db.query(Alert).all()
        results = []
        for alert in alerts:
            result = await ml_scorer.score_alert_with_model(str(alert.id))
            results.append(result)
        results.sort(key=lambda x: x.get("rule_based_score", 0), reverse=True)
        return {"total": len(results), "alerts": results}
    finally:
        db.close()
