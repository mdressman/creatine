"""PromptIntel - Local prompt threat detection using Nova pattern matching."""

import httpx
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from nova import NovaMatcher, NovaParser


# Path to default rules file
DEFAULT_RULES_PATH = Path(__file__).parent / "rules" / "default.nov"
FEED_RULES_PATH = Path(__file__).parent / "rules" / "feed_generated.nov"

# PromptIntel API
PROMPTINTEL_API_URL = "https://api.promptintel.novahunting.ai/api/v1"


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
    pattern: str = ""
    category: str = ""


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
    ) -> tuple[list[IoPC], int]:
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
            # Extract pattern from prompt field
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
        
        # Total is len if not paginated response
        total = len(items)
        if isinstance(data, dict) and "total" in data:
            total = data["total"]
        
        return indicators, total
    
    def fetch_all(self, max_pages: int = 10, **kwargs) -> list[IoPC]:
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


class PromptIntelClient:
    """Local prompt threat detection using Nova pattern matching."""
    
    SEVERITY_ORDER = ["low", "medium", "high", "critical"]
    
    def __init__(
        self, 
        api_key: str = "", 
        verbose: bool = False, 
        rules_path: Path = None,
        include_feed_rules: bool = True,
    ):
        """
        Initialize the detector.
        
        Args:
            api_key: Ignored (kept for API compatibility)
            verbose: Print detailed match info
            rules_path: Path to .nov rules file (uses default if not provided)
            include_feed_rules: Whether to also load feed-generated rules
        """
        self.verbose = verbose
        self._matchers: list[NovaMatcher] = []
        self._rules_loaded: list[str] = []
        
        # Load default rules
        rules_file = rules_path or DEFAULT_RULES_PATH
        if rules_file.exists():
            self.load_rules_file(rules_file)
            self._rules_loaded.append(str(rules_file))
        elif verbose:
            print(f"Warning: Rules file not found: {rules_file}")
        
        # Also load feed-generated rules if requested and they exist
        if include_feed_rules and FEED_RULES_PATH.exists() and FEED_RULES_PATH != rules_file:
            if verbose:
                print(f"Loading feed rules from: {FEED_RULES_PATH}")
            self.load_rules_file(FEED_RULES_PATH)
            self._rules_loaded.append(str(FEED_RULES_PATH))
    
    @property
    def rules_info(self) -> str:
        """Return info about loaded rules."""
        return f"{len(self._matchers)} rules from {len(self._rules_loaded)} files"
    
    def _split_rules(self, rules_text: str) -> list[str]:
        """Split a rules file into individual rule blocks."""
        rules = []
        current_rule = []
        brace_count = 0
        
        for line in rules_text.split('\n'):
            current_rule.append(line)
            brace_count += line.count('{') - line.count('}')
            
            if brace_count == 0 and current_rule:
                rule_text = '\n'.join(current_rule).strip()
                if rule_text.startswith('rule '):
                    rules.append(rule_text)
                current_rule = []
        
        return rules
    
    async def analyze_prompt(self, prompt: str) -> ThreatAnalysis:
        """
        Analyze a prompt for potential threats using Nova pattern matching.
        
        Args:
            prompt: The prompt text to analyze
            
        Returns:
            ThreatAnalysis with risk assessment and attack types detected
        """
        matches = []
        attack_types = []
        max_severity = "low"
        
        for matcher in self._matchers:
            result = matcher.check_prompt(prompt)
            
            if result.get("matched"):
                meta = result.get("meta", {})
                severity = meta.get("severity", "medium").lower()
                attack_type = meta.get("attack_type", "unknown")
                
                matches.append({
                    "rule": result.get("rule_name"),
                    "severity": severity,
                    "attack_type": attack_type,
                    "keywords": result.get("matching_keywords", {}),
                    "debug": result.get("debug", {}),
                })
                
                if attack_type not in attack_types:
                    attack_types.append(attack_type)
                
                # Track highest severity
                if self.SEVERITY_ORDER.index(severity) > self.SEVERITY_ORDER.index(max_severity):
                    max_severity = severity
        
        is_threat = len(matches) > 0
        
        if self.verbose:
            print(f"\n>>> Analyzing prompt: {prompt[:80]}...")
            print(f"<<< Threat: {is_threat}, Severity: {max_severity.title()}")
            if matches:
                for m in matches:
                    print(f"    Rule: {m['rule']}, Type: {m['attack_type']}")
                    print(f"    Keywords matched: {list(m['keywords'].keys())}")
        
        return ThreatAnalysis(
            is_threat=is_threat,
            risk_score=max_severity.title() if is_threat else "Low",
            attack_types=attack_types,
            details={"matches": matches, "prompt_length": len(prompt)},
        )
    
    async def get_iopc_feed(self, risk_score: str = None, tag: str = None, limit: int = 10) -> list[IoPC]:
        """Not implemented for local detection."""
        return []
    
    async def search_similar(self, prompt: str, threshold: float = 0.8) -> list[IoPC]:
        """Not implemented for local detection."""
        return []
    
    async def close(self):
        """No-op for local detection."""
        pass
    
    def load_rules_file(self, path: Path) -> None:
        """Load additional rules from a .nov file."""
        rules_text = path.read_text()
        parser = NovaParser()
        
        for rule_block in self._split_rules(rules_text):
            if rule_block.strip():
                try:
                    parsed = parser.parse(rule_block)
                    self._matchers.append(NovaMatcher(parsed))
                except Exception as e:
                    if self.verbose:
                        print(f"Warning: Failed to parse rule from {path}: {e}")
