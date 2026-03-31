from app.db.database import SessionLocal
from app.models.integrations import Alert
import numpy as np

class MLAlertScorer:

    def __init__(self):
        self.severity_weights = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25}
        self.status_weights = {"new": 1.0, "investigating": 0.5, "investigated": 0.1}
        self.high_risk_techniques = {
            "T1486": 1.0, "T1570": 0.9, "T1048": 0.85,
            "T1059.001": 0.75, "T1071": 0.8, "T1110": 0.5,
            "T1566": 0.7, "T1136": 0.6
        }
        self.keyword_weights = {
            "ransomware": 1.0, "lateral movement": 0.9,
            "exfiltration": 0.85, "c2 beacon": 0.85,
            "privilege escalation": 0.8, "credential": 0.7,
            "phishing": 0.65, "brute force": 0.5,
            "powershell": 0.6, "suspicious": 0.3
        }

    def extract_features(self, alert: Alert) -> dict:
        features = {}
        features["severity_score"] = self.severity_weights.get(alert.severity, 0.25)
        features["status_score"] = self.status_weights.get(alert.status, 1.0)
        features["has_enrichment"] = 1.0 if alert.enrichment_data else 0.0
        features["threat_intel_score"] = (alert.threat_score or 0) / 100.0
        technique_score = 0.0
        techniques = alert.mitre_techniques or []
        for technique in techniques:
            for tech_id, weight in self.high_risk_techniques.items():
                if tech_id in str(technique):
                    technique_score = max(technique_score, weight)
        features["technique_score"] = technique_score
        title = (alert.title or "").lower()
        description = (alert.description or "").lower()
        combined_text = f"{title} {description}"
        keyword_score = 0.0
        matched_keywords = []
        for keyword, weight in self.keyword_weights.items():
            if keyword in combined_text:
                keyword_score = max(keyword_score, weight)
                matched_keywords.append(keyword)
        features["keyword_score"] = keyword_score
        features["matched_keywords"] = matched_keywords
        return features

    def calculate_priority_score(self, features: dict) -> float:
        weights = {
            "severity_score": 0.30,
            "threat_intel_score": 0.25,
            "technique_score": 0.20,
            "keyword_score": 0.15,
            "status_score": 0.10
        }
        score = sum(features.get(k, 0) * w for k, w in weights.items())
        return round(score * 100, 2)

    def get_priority_label(self, score: float) -> str:
        if score >= 80: return "P1 - CRITICAL"
        elif score >= 60: return "P2 - HIGH"
        elif score >= 40: return "P3 - MEDIUM"
        elif score >= 20: return "P4 - LOW"
        else: return "P5 - INFORMATIONAL"

    def get_analyst_guidance(self, features: dict, score: float) -> list:
        guidance = []
        if score >= 80:
            guidance.append("IMMEDIATE ACTION: Respond within 15 minutes")
        elif score >= 60:
            guidance.append("URGENT: Respond within 1 hour")
        elif score >= 40:
            guidance.append("STANDARD: Respond within 4 hours")
        else:
            guidance.append("ROUTINE: Respond within 24 hours")
        keywords = features.get("matched_keywords", [])
        if "ransomware" in keywords:
            guidance.append("Isolate affected systems immediately")
        if "lateral movement" in keywords:
            guidance.append("Check for compromised accounts across network")
        if "c2 beacon" in keywords:
            guidance.append("Block C2 IP at firewall and investigate infected host")
        if "phishing" in keywords:
            guidance.append("Check if user clicked link or opened attachment")
        return guidance

    async def score_alert(self, alert_id: str) -> dict:
        db = SessionLocal()
        try:
            alert = db.query(Alert).filter(Alert.id == alert_id).first()
            if not alert:
                return {"error": "Alert not found"}
            features = self.extract_features(alert)
            priority_score = self.calculate_priority_score(features)
            priority_label = self.get_priority_label(priority_score)
            guidance = self.get_analyst_guidance(features, priority_score)
            return {
                "alert_id": alert_id,
                "title": alert.title,
                "ml_priority_score": priority_score,
                "priority_label": priority_label,
                "analyst_guidance": guidance,
                "features_used": {
                    "severity": alert.severity,
                    "threat_intel_score": features["threat_intel_score"],
                    "technique_score": features["technique_score"],
                    "keyword_score": features["keyword_score"],
                    "matched_keywords": features["matched_keywords"]
                }
            }
        finally:
            db.close()

    async def score_all_alerts(self) -> dict:
        db = SessionLocal()
        try:
            alerts = db.query(Alert).all()
            results = []
            for alert in alerts:
                result = await self.score_alert(str(alert.id))
                results.append(result)
            results.sort(key=lambda x: x.get("ml_priority_score", 0), reverse=True)
            return {
                "total_scored": len(results),
                "prioritized_alerts": results
            }
        finally:
            db.close()

ml_scorer = MLAlertScorer()
