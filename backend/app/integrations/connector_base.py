from abc import ABC, abstractmethod
from typing import Dict, Any, List
import httpx
import asyncio

class BaseConnector(ABC):
    """Base class for all security tool integrations"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.api_url = config.get('api_url')
        self.api_key = config.get('api_key')
        self.timeout = config.get('timeout', 30)
    
    @abstractmethod
    async def authenticate(self) -> bool:
        """Authenticate with the security tool"""
        pass
    
    @abstractmethod
    async def fetch_alerts(self, filters: Dict = None) -> List[Dict]:
        """Fetch alerts from the security tool"""
        pass
    
    @abstractmethod
    async def execute_action(self, action: str, params: Dict) -> Dict:
        """Execute an action on the security tool"""
        pass
    
    @abstractmethod
    async def validate_connection(self) -> bool:
        """Test connection to security tool"""
        pass
    
    async def normalize_alert(self, raw_alert: Dict) -> Dict:
        """Convert tool-specific alert to standard format"""
        return {
            "severity": self._map_severity(raw_alert.get("severity")),
            "title": raw_alert.get("title", "Untitled Alert"),
            "description": raw_alert.get("description", ""),
            "indicators": self._extract_indicators(raw_alert),
            "timestamp": raw_alert.get("timestamp")
        }
    
    def _map_severity(self, original_severity: str) -> str:
        """Map tool-specific severity to standard levels"""
        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "informational": "low"
        }
        return severity_map.get(original_severity.lower(), "medium")
    
    def _extract_indicators(self, alert: Dict) -> Dict:
        """Extract IOCs from alert"""
        return {
            "ips": [],
            "domains": [],
            "hashes": [],
            "urls": []
        }
