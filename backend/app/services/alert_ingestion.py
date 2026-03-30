from app.db.database import SessionLocal
from app.models.integrations import Alert, Playbook
from app.services.playbook_engine import playbook_engine
from datetime import datetime
import uuid
import asyncio

SAMPLE_ALERTS = [
    {"title": "Phishing email with malicious attachment", "severity": "high", "description": "User received email with .exe attachment from unknown sender", "mitre_tactics": ["TA0001"], "mitre_techniques": ["T1566.001"]},
    {"title": "Brute force login attempt detected", "severity": "medium", "description": "Multiple failed login attempts from IP 192.168.1.105", "mitre_tactics": ["TA0006"], "mitre_techniques": ["T1110"]},
    {"title": "Lateral movement via PsExec", "severity": "critical", "description": "PsExec usage detected moving between internal hosts", "mitre_tactics": ["TA0008"], "mitre_techniques": ["T1570"]},
    {"title": "Suspicious PowerShell execution", "severity": "high", "description": "Encoded PowerShell command executed on workstation", "mitre_tactics": ["TA0002"], "mitre_techniques": ["T1059.001"]},
    {"title": "Data exfiltration over DNS", "severity": "critical", "description": "Unusual DNS query volume detected suggesting data exfiltration", "mitre_tactics": ["TA0010"], "mitre_techniques": ["T1048.003"]},
    {"title": "Ransomware file encryption activity", "severity": "critical", "description": "Mass file renaming with unknown extension detected", "mitre_tactics": ["TA0040"], "mitre_techniques": ["T1486"]},
    {"title": "New admin account created", "severity": "medium", "description": "Unexpected privileged account creation outside change window", "mitre_tactics": ["TA0003"], "mitre_techniques": ["T1136.001"]},
    {"title": "C2 beacon to known malicious IP", "severity": "high", "description": "Outbound connection to known C2 server detected", "mitre_tactics": ["TA0011"], "mitre_techniques": ["T1071.001"]}
]

class AlertIngestionService:
    
    async def ingest_single_alert(self, alert_data: dict) -> dict:
        db = SessionLocal()
        try:
            alert = Alert(
                id=uuid.uuid4(),
                title=alert_data.get("title"),
                severity=alert_data.get("severity"),
                description=alert_data.get("description"),
                status="new",
                raw_data=alert_data,
                normalized_data=alert_data,
                mitre_tactics=alert_data.get("mitre_tactics", []),
                mitre_techniques=alert_data.get("mitre_techniques", []),
                created_at=datetime.utcnow()
            )
            db.add(alert)
            db.commit()
            db.refresh(alert)

            triggered = await self.check_playbook_triggers(str(alert.id), alert, db)
            
            return {
                "alert_id": str(alert.id),
                "title": alert.title,
                "severity": alert.severity,
                "status": "ingested",
                "playbook_triggered": triggered
            }
        finally:
            db.close()
    
    async def check_playbook_triggers(self, alert_id: str, alert: Alert, db) -> bool:
        playbooks = db.query(Playbook).filter(Playbook.is_active == True).all()
        for playbook in playbooks:
            if playbook_engine.evaluate_trigger(playbook, alert):
                asyncio.create_task(
                    playbook_engine.execute_playbook(str(playbook.id), alert_id)
                )
                return True
        return False
    
    async def simulate_alert_stream(self, count: int = 5) -> list:
        results = []
        import random
        for i in range(count):
            alert_data = random.choice(SAMPLE_ALERTS).copy()
            result = await self.ingest_single_alert(alert_data)
            results.append(result)
            await asyncio.sleep(0.1)
        return results

alert_ingestion_service = AlertIngestionService()
