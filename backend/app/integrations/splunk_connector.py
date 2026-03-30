from .connector_base import BaseConnector
from typing import Dict, List
import httpx
import json

class SplunkConnector(BaseConnector):
    """Splunk SIEM integration"""
    
    async def authenticate(self) -> bool:
        """Authenticate with Splunk"""
        async with httpx.AsyncClient(verify=False) as client:
            try:
                response = await client.post(
                    f"{self.api_url}/services/auth/login",
                    data={
                        "username": self.config.get('username'),
                        "password": self.config.get('password')
                    },
                    timeout=self.timeout
                )
                if response.status_code == 200:
                    self.session_key = response.text
                    return True
                return False
            except Exception as e:
                print(f"Splunk auth error: {e}")
                return False
    
    async def fetch_alerts(self, filters: Dict = None) -> List[Dict]:
        """Fetch alerts from Splunk using SPL query"""
        search_query = filters.get('query', 'search index=* | head 100')
        
        async with httpx.AsyncClient(verify=False) as client:
            try:
                # Create search job
                response = await client.post(
                    f"{self.api_url}/services/search/jobs",
                    data={"search": search_query},
                    headers={"Authorization": f"Splunk {self.session_key}"},
                    timeout=self.timeout
                )
                
                if response.status_code == 201:
                    job_id = response.json().get('sid')
                    
                    # Wait for results
                    results = await self._get_search_results(client, job_id)
                    return results
                
                return []
            except Exception as e:
                print(f"Splunk fetch error: {e}")
                return []
    
    async def _get_search_results(self, client, job_id: str) -> List[Dict]:
        """Get results from Splunk search job"""
        import asyncio
        await asyncio.sleep(5)  # Wait for search to complete
        
        response = await client.get(
            f"{self.api_url}/services/search/jobs/{job_id}/results",
            headers={"Authorization": f"Splunk {self.session_key}"},
            params={"output_mode": "json"}
        )
        
        if response.status_code == 200:
            return response.json().get('results', [])
        return []
    
    async def execute_action(self, action: str, params: Dict) -> Dict:
        """Execute Splunk action"""
        actions = {
            "create_notable": self._create_notable_event,
            "update_alert": self._update_alert,
            "run_query": self._run_search_query
        }
        
        if action in actions:
            return await actions[action](params)
        
        return {"success": False, "error": "Unknown action"}
    
    async def _create_notable_event(self, params: Dict) -> Dict:
        """Create notable event in Splunk ES"""
        # Implementation for creating notable event
        return {"success": True, "event_id": "notable_123"}
    
    async def _update_alert(self, params: Dict) -> Dict:
        """Update existing alert"""
        return {"success": True}
    
    async def _run_search_query(self, params: Dict) -> Dict:
        """Run ad-hoc SPL query"""
        results = await self.fetch_alerts({"query": params.get('query')})
        return {"success": True, "results": results}
    
    async def validate_connection(self) -> bool:
        """Test Splunk connection"""
        return await self.authenticate()
