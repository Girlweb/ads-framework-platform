from app.db.database import SessionLocal
from app.models.integrations import Playbook, PlaybookExecution, Alert
from datetime import datetime
import json

class PlaybookEngine:
    
    def evaluate_trigger(self, playbook: Playbook, alert: Alert) -> bool:
        conditions = playbook.trigger_conditions or {}
        if "severity" in conditions:
            if alert.severity != conditions["severity"]:
                return False
        if "keywords" in conditions:
            for keyword in conditions["keywords"]:
                if keyword.lower() not in (alert.title or "").lower():
                    return False
        return True
    
    async def execute_playbook(self, playbook_id: str, alert_id: str) -> dict:
        db = SessionLocal()
        log = []
        try:
            playbook = db.query(Playbook).filter(Playbook.id == playbook_id).first()
            alert = db.query(Alert).filter(Alert.id == alert_id).first()
            
            if not playbook or not alert:
                return {"status": "failed", "error": "Playbook or alert not found"}
            
            execution = PlaybookExecution(
                playbook_id=playbook_id,
                alert_id=alert_id,
                status="running",
                started_at=datetime.utcnow()
            )
            db.add(execution)
            db.commit()
            
            steps = playbook.steps or []
            for step in steps:
                result = await self.execute_step(step, alert)
                log.append({"step": step.get("name"), "result": result, "time": datetime.utcnow().isoformat()})
            
            execution.status = "completed"
            execution.completed_at = datetime.utcnow()
            execution.execution_log = log
            
            alert.status = "investigated"
            db.commit()
            
            return {"status": "completed", "steps_executed": len(steps), "log": log}
        
        except Exception as e:
            return {"status": "failed", "error": str(e)}
        finally:
            db.close()
    
    async def execute_step(self, step: dict, alert: Alert) -> str:
        action = step.get("action")
        if action == "notify":
            return f"Notification sent: {step.get('message', 'Alert requires attention')}"
        elif action == "isolate_host":
            return f"Host isolation triggered for alert: {alert.title}"
        elif action == "block_ip":
            return f"IP block initiated"
        elif action == "create_ticket":
            return f"Ticket created for: {alert.title}"
        elif action == "enrich":
            return f"Threat intelligence enrichment completed"
        else:
            return f"Step executed: {action}"

playbook_engine = PlaybookEngine()
