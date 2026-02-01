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


def generate_nova_rules(indicators: list[IoPC], rule_prefix: str = "Feed") -> str:
    """
    Generate Nova rules from IoPC indicators (simple keyword extraction).
    
    For smarter AI-powered rule generation, use generate_nova_rules_with_ai().
    """
    # Group by category
    by_category: dict[str, list[IoPC]] = {}
    for iopc in indicators:
        cat = iopc.category or "unknown"
        cat = re.sub(r'[^a-zA-Z0-9]', '_', cat).title()
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append(iopc)
    
    rules = []
    
    for category, items in by_category.items():
        # Extract unique patterns/keywords from prompts
        keywords = []
        seen_patterns = set()
        
        for i, item in enumerate(items[:30]):  # Limit keywords per rule
            prompt = item.pattern or item.prompt
            if not prompt:
                continue
            
            # Extract short key phrases (under 60 chars)
            # Look for quoted strings, specific phrases
            for match in re.findall(r'"([^"]{5,50})"', prompt):
                if match not in seen_patterns:
                    seen_patterns.add(match)
                    clean = match.replace('"', '\\"').strip()
                    var_name = f"$k{len(keywords)}"
                    keywords.append(f'        {var_name} = "{clean}"')
                    if len(keywords) >= 15:
                        break
            
            # Also extract threat-indicator phrases
            threat_phrases = [
                "ignore previous", "ignore all", "disregard", "forget your",
                "new instructions", "override", "bypass", "jailbreak",
                "pretend you", "act as", "you are now", "developer mode",
                "DAN", "do anything now", "no restrictions", "unfiltered"
            ]
            prompt_lower = prompt.lower()
            for phrase in threat_phrases:
                if phrase in prompt_lower and phrase not in seen_patterns:
                    seen_patterns.add(phrase)
                    var_name = f"$t{len(keywords)}"
                    keywords.append(f'        {var_name} = "{phrase}"')
            
            if len(keywords) >= 15:
                break
        
        if not keywords:
            continue
        
        # Determine severity based on indicators
        severities = [i.risk_score.lower() for i in items if i.risk_score]
        if "critical" in severities:
            severity = "critical"
        elif "high" in severities:
            severity = "high"
        elif "medium" in severities:
            severity = "medium"
        else:
            severity = "low"
        
        # Map category to attack type
        attack_type = "unknown"
        cat_lower = category.lower()
        if "inject" in cat_lower:
            attack_type = "prompt_injection"
        elif "jailbreak" in cat_lower or "bypass" in cat_lower:
            attack_type = "jailbreak"
        elif "exfil" in cat_lower or "leak" in cat_lower:
            attack_type = "data_exfiltration"
        elif "obfusc" in cat_lower or "encod" in cat_lower:
            attack_type = "obfuscation"
        elif "manipul" in cat_lower:
            attack_type = "prompt_injection"
        
        # Build condition (OR all keywords)
        keyword_vars = [k.split('=')[0].strip() for k in keywords]
        condition = " or ".join([f"keywords.{v.strip()}" for v in keyword_vars])
        
        rule = f"""rule {rule_prefix}_{category} {{
    meta:
        description = "Auto-generated from PromptIntel feed: {category}"
        severity = "{severity}"
        attack_type = "{attack_type}"
        indicator_count = "{len(items)}"
    keywords:
{chr(10).join(keywords)}
    condition:
        {condition}
}}"""
        rules.append(rule)
    
    return "\n\n".join(rules)


RULE_GENERATION_PROMPT = """You are a security researcher specializing in LLM prompt injection and jailbreak detection.

Analyze the following adversarial prompts and create Nova detection rules. Nova rules use YARA-like syntax for pattern matching.

## Nova Rule Syntax:
```
rule RuleName {{
    meta:
        description = "What this rule detects"
        severity = "critical|high|medium|low"
        attack_type = "prompt_injection|jailbreak|data_exfiltration|obfuscation"
    keywords:
        $var1 = "exact phrase to match"
        $var2 = "another phrase"
    condition:
        keywords.$var1 or keywords.$var2
}}
```

## Guidelines:
1. Identify the ATTACK TECHNIQUE, not just specific words
2. Extract generalizable patterns that would catch similar attacks
3. Focus on:
   - Instruction override patterns ("ignore", "disregard", "forget")
   - Role manipulation ("you are now", "pretend", "act as")
   - Context injection (fake system messages, delimiters)
   - Authority claims ("admin mode", "developer mode", "debug")
   - Encoding/obfuscation hints ("base64", "rot13", "decode")
4. Create MULTIPLE rules for different attack categories
5. Use lowercase for keywords to catch case variations
6. Keep keywords short (3-50 chars) but distinctive
7. Avoid overly generic terms that would cause false positives

## Adversarial Prompts to Analyze:
{prompts}

## Your Task:
Create 5-10 well-crafted Nova rules that would detect these and similar attack patterns.
Output ONLY the Nova rules, no explanations. Each rule should be complete and valid."""


async def generate_nova_rules_with_ai(
    indicators: list[IoPC],
    verbose: bool = False
) -> str:
    """
    Use AI to analyze IoPC indicators and generate sophisticated Nova rules.
    
    Requires Azure OpenAI credentials in environment.
    """
    import os
    from azure.identity import DefaultAzureCredential, get_bearer_token_provider
    from openai import AzureOpenAI
    
    # Check required env vars
    endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
    deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT_NAME")
    
    if not endpoint or endpoint == "https://your-resource-name.openai.azure.com/":
        raise ValueError(
            "Azure OpenAI not configured. Set AZURE_OPENAI_ENDPOINT and "
            "AZURE_OPENAI_DEPLOYMENT_NAME in .env file."
        )
    
    # Set up Azure OpenAI client
    token_provider = get_bearer_token_provider(
        DefaultAzureCredential(),
        "https://cognitiveservices.azure.com/.default"
    )
    
    client = AzureOpenAI(
        azure_endpoint=endpoint,
        azure_ad_token_provider=token_provider,
        api_version=os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-15-preview"),
    )
    
    # Prepare prompts for analysis (batch to avoid token limits)
    all_rules = []
    batch_size = 10
    
    for i in range(0, len(indicators), batch_size):
        batch = indicators[i:i + batch_size]
        
        prompts_text = "\n\n---\n\n".join([
            f"**{iopc.description or 'Untitled'}** (Severity: {iopc.risk_score}, Category: {iopc.category})\n```\n{iopc.prompt[:1500]}\n```"
            for iopc in batch
        ])
        
        prompt = RULE_GENERATION_PROMPT.format(prompts=prompts_text)
        
        if verbose:
            print(f"Analyzing batch {i // batch_size + 1} ({len(batch)} indicators)...")
        
        try:
            response = client.chat.completions.create(
                model=deployment,
                messages=[
                    {"role": "system", "content": "You are an expert security researcher. Output ONLY valid Nova rules, no explanations or markdown."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
            )
            rules_text = response.choices[0].message.content
            
            # Extract just the rules (in case AI added explanations)
            if "rule " in rules_text:
                all_rules.append(rules_text)
                
        except Exception as e:
            if verbose:
                print(f"Error analyzing batch: {e}")
            continue
    
    # Combine all rules
    combined = "\n\n".join(all_rules)
    
    # Clean up: ensure valid rule syntax
    # Remove any markdown code blocks
    combined = re.sub(r'```\w*\n?', '', combined)
    combined = combined.strip()
    
    return combined


async def sync_feed_rules_with_ai(
    api_key: str,
    output_path: Path = None,
    verbose: bool = False
) -> Path:
    """
    Fetch IoPC feed and use AI to generate sophisticated Nova rules.
    """
    output_path = output_path or FEED_RULES_PATH
    
    client = PromptIntelFeedClient(api_key, verbose=verbose)
    try:
        if verbose:
            print("Fetching IoPC feed from PromptIntel...")
        
        indicators = client.fetch_all()
        
        if verbose:
            print(f"Retrieved {len(indicators)} indicators")
            print("Using AI to analyze and generate rules...")
        
        if not indicators:
            raise ValueError("No indicators retrieved from feed")
        
        rules = await generate_nova_rules_with_ai(indicators, verbose=verbose)
        
        if not rules or "rule " not in rules:
            raise ValueError("AI failed to generate valid rules")
        
        # Ensure directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rules)
        
        if verbose:
            rule_count = rules.count("rule ")
            print(f"Generated {rule_count} AI-crafted rules")
            print(f"Saved to: {output_path}")
        
        return output_path
    finally:
        client.close()


def sync_feed_rules(api_key: str, output_path: Path = None, verbose: bool = False) -> Path:
    """
    Fetch latest IoPC feed and generate Nova rules.
    
    Returns:
        Path to the generated rules file
    """
    output_path = output_path or FEED_RULES_PATH
    
    client = PromptIntelFeedClient(api_key, verbose=verbose)
    try:
        if verbose:
            print("Fetching IoPC feed from PromptIntel...")
        
        indicators = client.fetch_all()
        
        if verbose:
            print(f"Retrieved {len(indicators)} indicators")
        
        if not indicators:
            raise ValueError("No indicators retrieved from feed")
        
        rules = generate_nova_rules(indicators)
        
        # Ensure directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rules)
        
        if verbose:
            print(f"Generated rules saved to: {output_path}")
        
        return output_path
    finally:
        client.close()


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
