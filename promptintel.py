"""PromptIntel - Local prompt threat detection using Nova pattern matching."""

from dataclasses import dataclass
from pathlib import Path
from nova import NovaMatcher, NovaParser


# Default rules for detecting prompt injection and jailbreak attempts
DEFAULT_RULES = """
rule PromptInjection {
    meta:
        description = "Detects prompt injection attempts"
        severity = "high"
        attack_type = "prompt_injection"
    keywords:
        $ignore1 = "ignore previous instructions"
        $ignore2 = "ignore all previous"
        $ignore3 = "disregard previous"
        $ignore4 = "forget previous"
        $override = "new instructions"
        $system = "[system]"
        $inst = "[INST]"
    condition:
        keywords.$ignore1 or keywords.$ignore2 or keywords.$ignore3 or keywords.$ignore4 or keywords.$override or keywords.$system or keywords.$inst
}

rule JailbreakDAN {
    meta:
        description = "Detects DAN-style jailbreak attempts"
        severity = "critical"
        attack_type = "jailbreak"
    keywords:
        $dan = "DAN"
        $anything_now = "Do Anything Now"
        $no_restrictions = "without restrictions"
        $no_rules = "no rules"
        $no_guidelines = "no ethical guidelines"
        $unfiltered = "unfiltered"
    condition:
        keywords.$dan or keywords.$anything_now or keywords.$no_restrictions or keywords.$no_rules or keywords.$no_guidelines or keywords.$unfiltered
}

rule JailbreakRoleplay {
    meta:
        description = "Detects roleplay-based jailbreaks"
        severity = "high"
        attack_type = "jailbreak"
    keywords:
        $pretend = "pretend you are"
        $act_as = "act as"
        $roleplay = "roleplay as"
        $you_are_now = "you are now"
        $evil_ai = "evil AI"
        $freedom_gpt = "FreedomGPT"
        $developer_mode = "developer mode"
    condition:
        keywords.$pretend or keywords.$act_as or keywords.$roleplay or keywords.$you_are_now or keywords.$evil_ai or keywords.$freedom_gpt or keywords.$developer_mode
}

rule DataExfiltration {
    meta:
        description = "Detects attempts to extract system information"
        severity = "high"
        attack_type = "data_exfiltration"
    keywords:
        $system_prompt = "system prompt"
        $output_prompt = "output your prompt"
        $show_instructions = "show your instructions"
        $reveal = "reveal your"
        $initial_prompt = "initial prompt"
        $hidden_prompt = "hidden prompt"
    condition:
        keywords.$system_prompt or keywords.$output_prompt or keywords.$show_instructions or keywords.$reveal or keywords.$initial_prompt or keywords.$hidden_prompt
}

rule Obfuscation {
    meta:
        description = "Detects obfuscated malicious prompts"
        severity = "medium"
        attack_type = "obfuscation"
    keywords:
        $rot13 = "ROT13"
        $base64 = "base64"
        $decode = "decode"
        $encoded = "encoded"
        $hex = "hex"
    condition:
        keywords.$rot13 or keywords.$base64 or keywords.$decode or keywords.$encoded or keywords.$hex
}

rule CommandInjection {
    meta:
        description = "Detects command execution attempts"
        severity = "critical"
        attack_type = "prompt_injection"
    keywords:
        $execute = "execute:"
        $run = "run command"
        $terminal = "act as a terminal"
        $shell = "shell command"
        $cat = "cat /etc"
        $sudo = "sudo"
    condition:
        keywords.$execute or keywords.$run or keywords.$terminal or keywords.$shell or keywords.$cat or keywords.$sudo
}

rule HypotheticalJailbreak {
    meta:
        description = "Detects hypothetical scenario jailbreaks"
        severity = "medium"
        attack_type = "jailbreak"
    keywords:
        $hypothetically = "hypothetically"
        $in_theory = "in theory"
        $for_research = "for research"
        $educational = "educational purposes"
        $fiction = "write a story"
        $imagine = "imagine you"
    condition:
        keywords.$hypothetically or keywords.$in_theory or keywords.$for_research or keywords.$educational or keywords.$fiction or keywords.$imagine
}
"""


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
    """Local prompt threat detection using Nova pattern matching."""
    
    SEVERITY_ORDER = ["low", "medium", "high", "critical"]
    
    def __init__(self, api_key: str = "", verbose: bool = False, rules: str = None):
        """
        Initialize the detector.
        
        Args:
            api_key: Ignored (kept for API compatibility)
            verbose: Print detailed match info
            rules: Custom Nova rules (uses defaults if not provided)
        """
        self.verbose = verbose
        self._matchers: list[NovaMatcher] = []
        
        rules_text = rules or DEFAULT_RULES
        parser = NovaParser()
        
        # Parse and create matchers for each rule
        for rule_block in self._split_rules(rules_text):
            if rule_block.strip():
                try:
                    parsed = parser.parse(rule_block)
                    self._matchers.append(NovaMatcher(parsed))
                except Exception as e:
                    if verbose:
                        print(f"Warning: Failed to parse rule: {e}")
    
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
