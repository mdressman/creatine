"""PromptIntel feed client for fetching IoPC indicators."""

import httpx
from typing import Optional, List, Tuple

from .models import IoPC


PROMPTINTEL_API_URL = "https://api.promptintel.novahunting.ai/api/v1"


class PromptIntelFeedClient:
    """Client for fetching IoPC feed from PromptIntel API."""
    
    def __init__(self, api_key: str, verbose: bool = False):
        self.api_key = api_key
        self.verbose = verbose
        self._client = httpx.Client(
            base_url=PROMPTINTEL_API_URL,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            timeout=30.0,
        )
    
    def fetch_prompts(
        self,
        page: int = 1,
        limit: int = 100,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        search: Optional[str] = None,
    ) -> Tuple[List[IoPC], int]:
        """
        Fetch IoPC indicators from the PromptIntel feed.
        
        Returns:
            Tuple of (list of IoPC indicators, total count)
        """
        params = {"page": page, "limit": limit}
        if severity:
            params["severity"] = severity
        if category:
            params["category"] = category
        if search:
            params["search"] = search
        
        if self.verbose:
            print(f">>> GET {PROMPTINTEL_API_URL}/prompts?{params}")
        
        response = self._client.get("/prompts", params=params)
        
        if self.verbose:
            print(f"<<< Status: {response.status_code}")
        
        response.raise_for_status()
        data = response.json()
        
        # Handle response - can be {"data": [...]} or just [...]
        items = data.get("data", data) if isinstance(data, dict) else data
        
        if self.verbose:
            print(f"<<< Found {len(items)} indicators")
        
        indicators = []
        for item in items:
            pattern = item.get("prompt", "")
            categories = item.get("categories", [])
            threats = item.get("threats", [])
            
            indicators.append(IoPC(
                id=item.get("id", ""),
                prompt=pattern,
                risk_score=item.get("severity", "medium"),
                tags=categories + threats,
                description=item.get("title", "") or item.get("impact_description", ""),
                pattern=pattern,
                category=categories[0] if categories else "unknown",
            ))
        
        total = len(items)
        if isinstance(data, dict) and "total" in data:
            total = data["total"]
        
        return indicators, total
    
    def fetch_all(self, max_pages: int = 10, **kwargs) -> List[IoPC]:
        """Fetch all indicators with pagination."""
        all_indicators = []
        page = 1
        
        while page <= max_pages:
            indicators, total = self.fetch_prompts(page=page, **kwargs)
            all_indicators.extend(indicators)
            
            if len(all_indicators) >= total or not indicators:
                break
            page += 1
        
        return all_indicators
    
    def close(self):
        self._client.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        self.close()
