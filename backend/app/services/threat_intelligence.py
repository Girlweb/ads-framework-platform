from app.db.database import SessionLocal
from app.models.integrations import Alert
import re
import httpx
import asyncio
import os

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"

KNOWN_MALICIOUS_IPS = [
    "185.220.101.1", "194.165.16.11", "45.153.160.2",
    "91.108.4.0", "192.42.116.0", "198.96.155.3"
]

KNOWN_MALICIOUS_DOMAINS = [
    "malware-c2.evil", "phishing-site.tk", "ransomware-pay.onion",
    "steal-creds.xyz", "botnet-controller.ru"
]

KNOWN_MALICIOUS_HASHES = [
    "d41d8cd98f00b204e9800998ecf8427e",
    "5d41402abc4b2a76b9719d911017c592"
]

class ThreatIntelligenceService:

    def extract_indicators(self, text: str) -> dict:
        indicators = {"ips": [], "domains": [], "hashes": []}
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        domain_pattern = r'\b[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}\b'
        hash_pattern = r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b'
        indicators["ips"] = list(set(re.findall(ip_pattern, text)))
        indicators["domains"] = list(set(re.findall(domain_pattern, text)))
        indicators["hashes"] = list(set(re.findall(hash_pattern, text)))
        return indicators

    async def check_virustotal_ip(self, ip: str) -> dict:
        if not VIRUSTOTAL_API_KEY:
            return {"ip": ip, "source": "local", "malicious": ip in KNOWN_MALICIOUS_IPS}
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{VIRUSTOTAL_BASE_URL}/ip_addresses/{ip}",
                    headers={"x-apikey": VIRUSTOTAL_API_KEY},
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious_count = stats.get("malicious", 0)
                    suspicious_count = stats.get("suspicious", 0)
                    return {
                        "ip": ip,
                        "source": "virustotal",
                        "malicious": malicious_count > 0,
                        "malicious_engines": malicious_count,
                        "suspicious_engines": suspicious_count,
                        "total_engines": sum(stats.values())
                    }
                return {"ip": ip, "source": "virustotal", "malicious": False, "error": f"Status {response.status_code}"}
        except Exception as e:
            return {"ip": ip, "source": "error", "malicious": False, "error": str(e)}

    async def check_virustotal_domain(self, domain: str) -> dict:
        if not VIRUSTOTAL_API_KEY:
            return {"domain": domain, "source": "local", "malicious": domain in KNOWN_MALICIOUS_DOMAINS}
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{VIRUSTOTAL_BASE_URL}/domains/{domain}",
                    headers={"x-apikey": VIRUSTOTAL_API_KEY},
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious_count = stats.get("malicious", 0)
                    return {
                        "domain": domain,
                        "source": "virustotal",
                        "malicious": malicious_count > 0,
                        "malicious_engines": malicious_count,
                        "total_engines": sum(stats.values())
                    }
                return {"domain": domain, "source": "virustotal", "malicious": False}
        except Exception as e:
            return {"domain": domain, "source": "error", "malicious": False, "error": str(e)}

    async def check_virustotal_hash(self, file_hash: str) -> dict:
        if not VIRUSTOTAL_API_KEY:
            return {"hash": file_hash, "source": "local", "malicious": file_hash in KNOWN_MALICIOUS_HASHES}
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{VIRUSTOTAL_BASE_URL}/files/{file_hash}",
                    headers={"x-apikey": VIRUSTOTAL_API_KEY},
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious_count = stats.get("malicious", 0)
                    return {
                        "hash": file_hash,
                        "source": "virustotal",
                        "malicious": malicious_count > 0,
                        "malicious_engines": malicious_count,
                        "total_engines": sum(stats.values())
                    }
                return {"hash": file_hash, "source": "virustotal", "malicious": False}
        except Exception as e:
            return {"hash": file_hash, "source": "error", "malicious": False, "error": str(e)}

    def check_local_intel(self, indicators: dict) -> dict:
        results = {"malicious_ips": [], "malicious_domains": [], "malicious_hashes": [], "threat_score": 0}
        for ip in indicators.get("ips", []):
            if ip in KNOWN_MALICIOUS_IPS:
                results["malicious_ips"].append(ip)
                results["threat_score"] += 30
        for domain in indicators.get("domains", []):
            if domain in KNOWN_MALICIOUS_DOMAINS:
                results["malicious_domains"].append(domain)
                results["threat_score"] += 25
        for hash_val in indicators.get("hashes", []):
            if hash_val in KNOWN_MALICIOUS_HASHES:
                results["malicious_hashes"].append(hash_val)
                results["threat_score"] += 40
        return results

    def calculate_threat_score(self, alert_data: dict) -> int:
        score = 0
        severity_scores = {"critical": 40, "high": 30, "medium": 20, "low": 10}
        score += severity_scores.get(alert_data.get("severity", "low"), 10)
        high_risk_techniques = ["T1486", "T1570", "T1048", "T1059.001", "T1071"]
        techniques = alert_data.get("mitre_techniques", [])
        for technique in techniques:
            for high_risk in high_risk_techniques:
                if high_risk in technique:
                    score += 15
        title = alert_data.get("title", "").lower()
        keywords = ["ransomware", "exfiltration", "lateral movement", "c2", "beacon"]
        for keyword in keywords:
            if keyword in title:
                score += 10
        return min(score, 100)

    async def enrich_alert(self, alert_id: str) -> dict:
        db = SessionLocal()
        try:
            alert = db.query(Alert).filter(Alert.id == alert_id).first()
            if not alert:
                return {"error": "Alert not found"}

            text_to_analyze = f"{alert.title} {alert.description}"
            indicators = self.extract_indicators(text_to_analyze)

            # Run VirusTotal checks in parallel
            vt_results = {"ips": [], "domains": [], "hashes": []}
            
            ip_tasks = [self.check_virustotal_ip(ip) for ip in indicators["ips"][:3]]
            domain_tasks = [self.check_virustotal_domain(d) for d in indicators["domains"][:3]]
            hash_tasks = [self.check_virustotal_hash(h) for h in indicators["hashes"][:3]]

            if ip_tasks:
                vt_results["ips"] = await asyncio.gather(*ip_tasks)
            if domain_tasks:
                vt_results["domains"] = await asyncio.gather(*domain_tasks)
            if hash_tasks:
                vt_results["hashes"] = await asyncio.gather(*hash_tasks)

            # Calculate VT threat score bonus
            vt_score_bonus = 0
            for ip_result in vt_results["ips"]:
                if ip_result.get("malicious"):
                    vt_score_bonus += 25
            for domain_result in vt_results["domains"]:
                if domain_result.get("malicious"):
                    vt_score_bonus += 20

            intel_results = self.check_local_intel(indicators)
            alert_data = {
                "severity": alert.severity,
                "mitre_techniques": alert.mitre_techniques or [],
                "title": alert.title
            }
            threat_score = self.calculate_threat_score(alert_data)
            threat_score = min(threat_score + intel_results["threat_score"] + vt_score_bonus, 100)

            enrichment = {
                "indicators_found": indicators,
                "virustotal_results": vt_results,
                "local_intel": intel_results,
                "threat_score": threat_score,
                "risk_level": self.score_to_risk(threat_score),
                "recommendations": self.get_recommendations(alert_data, intel_results)
            }
            alert.enrichment_data = enrichment
            alert.threat_score = threat_score
            db.commit()
            return {"alert_id": alert_id, "enrichment": enrichment}
        finally:
            db.close()

    async def enrich_all_pending(self) -> dict:
        db = SessionLocal()
        try:
            alerts = db.query(Alert).all()
            results = []
            for alert in alerts:
                result = await self.enrich_alert(str(alert.id))
                enrichment = result.get("enrichment", {})
                results.append({
                    "alert_id": str(alert.id),
                    "title": alert.title,
                    "threat_score": enrichment.get("threat_score"),
                    "risk_level": enrichment.get("risk_level"),
                    "virustotal_checked": len(enrichment.get("virustotal_results", {}).get("ips", [])) > 0
                })
            return {"enriched": len(results), "results": results}
        finally:
            db.close()

    def score_to_risk(self, score: int) -> str:
        if score >= 80: return "CRITICAL"
        elif score >= 60: return "HIGH"
        elif score >= 40: return "MEDIUM"
        else: return "LOW"

    def get_recommendations(self, alert_data: dict, intel_results: dict) -> list:
        recommendations = []
        if alert_data.get("severity") == "critical":
            recommendations.append("Immediate isolation of affected systems required")
            recommendations.append("Escalate to Tier 3 analyst immediately")
        if intel_results.get("malicious_ips"):
            recommendations.append(f"Block malicious IPs at firewall: {intel_results['malicious_ips']}")
        if "ransomware" in alert_data.get("title", "").lower():
            recommendations.append("Disconnect affected hosts from network immediately")
            recommendations.append("Check backup integrity before any recovery")
        if "lateral" in alert_data.get("title", "").lower():
            recommendations.append("Review all accounts with recent privilege escalation")
            recommendations.append("Check for new scheduled tasks and services")
        if not recommendations:
            recommendations.append("Monitor for additional indicators")
            recommendations.append("Review related alerts in the last 24 hours")
        return recommendations

threat_intel_service = ThreatIntelligenceService()
