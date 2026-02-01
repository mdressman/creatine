"""PromptIntel API client for threat intelligence on adversarial prompts."""

import httpx
from dataclasses import dataclass
from typing import Optional


@dataclass
class ThreatAnalysis:
    """Result of analyzing a prompt for threats."""
    is_threat: bool
    risk_score: str  # Low, Medium, High, Critical
    attack_types: list[str]
    details: dict


@dataclass 
class IoPC:
    """Indicator of Prompt Compromise."""
    id: str
    prompt: str
    risk_score: str
    tags: list[str]
    description: str


class PromptIntelClient:
    """Client for the PromptIntel API - threat intelligence for adversarial prompts."""
    
    BASE_URL = "https://api.promptintel.novahunting.ai/v1"
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self._client = httpx.AsyncClient(
            base_url=self.BASE_URL,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            timeout=30.0,
        )
    
    async def analyze_prompt(self, prompt: str) -> ThreatAnalysis:
        """
        Analyze a prompt for potential threats (jailbreaks, injections, etc).
        
        Args:
            prompt: The prompt text to analyze
            
        Returns:
            ThreatAnalysis with risk assessment and attack types detected
        """
        response = await self._client.post(
            "/analyze",
            json={"prompt": prompt},
        )
        response.raise_for_status()
        data = response.json()
        
        return ThreatAnalysis(
            is_threat=data.get("is_threat", False),
            risk_score=data.get("risk_score", "Low"),
            attack_types=data.get("attack_types", []),
            details=data.get("details", {}),
        )
    
    async def get_iopc_feed(
        self,
        risk_score: Optional[str] = None,
        tag: Optional[str] = None,
        limit: int = 10,
    ) -> list[IoPC]:
        """
        Query the IoPC (Indicators of Prompt Compromise) feed.
        
        Args:
            risk_score: Filter by risk level (Low, Medium, High, Critical)
            tag: Filter by attack type (jailbreak, prompt_injection, data_exfiltration)
            limit: Max number of results
            
        Returns:
            List of IoPC indicators matching the criteria
        """
        params = {"limit": limit}
        if risk_score:
            params["risk_score"] = risk_score
        if tag:
            params["tag"] = tag
        
        response = await self._client.get("/prompts", params=params)
        response.raise_for_status()
        data = response.json()
        
        return [
            IoPC(
                id=item.get("id", ""),
                prompt=item.get("prompt", ""),
                risk_score=item.get("risk_score", ""),
                tags=item.get("tags", []),
                description=item.get("description", ""),
            )
            for item in data.get("prompts", [])
        ]
    
    async def search_similar(self, prompt: str, threshold: float = 0.8) -> list[IoPC]:
        """
        Search for known malicious prompts similar to the given prompt.
        
        Args:
            prompt: The prompt to find similar threats for
            threshold: Similarity threshold (0-1)
            
        Returns:
            List of similar known malicious prompts
        """
        response = await self._client.post(
            "/search",
            json={"prompt": prompt, "threshold": threshold},
        )
        response.raise_for_status()
        data = response.json()
        
        return [
            IoPC(
                id=item.get("id", ""),
                prompt=item.get("prompt", ""),
                risk_score=item.get("risk_score", ""),
                tags=item.get("tags", []),
                description=item.get("description", ""),
            )
            for item in data.get("matches", [])
        ]
    
    async def close(self):
        """Close the HTTP client."""
        await self._client.aclose()
