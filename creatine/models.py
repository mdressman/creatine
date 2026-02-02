"""Data models for Creatine prompt security detection."""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum


class DetectionTier(Enum):
    """Detection tier used for final verdict."""
    KEYWORDS = 1
    SEMANTICS = 2
    LLM = 3


class EscalationReason(Enum):
    """Reason for escalating to next detection tier."""
    NONE = "none"
    SUSPICIOUS_PATTERNS = "suspicious_patterns"
    UNCERTAIN_CONFIDENCE = "uncertain_confidence"
    PARTIAL_MATCH = "partial_match"
    LENGTH_THRESHOLD = "length_threshold"
    ENCODING_DETECTED = "encoding_detected"


@dataclass
class ThreatAnalysis:
    """Result of analyzing a prompt for threats."""
    is_threat: bool
    risk_score: str  # Low, Medium, High, Critical
    attack_types: List[str]
    details: Dict[str, Any]


@dataclass 
class IoPC:
    """Indicator of Prompt Compromise."""
    id: str
    prompt: str
    risk_score: str
    tags: List[str]
    description: str
    pattern: str = ""
    category: str = ""


@dataclass
class AdaptiveResult:
    """Result from adaptive detection."""
    is_threat: bool
    confidence: float  # 0.0 to 1.0
    risk_score: str  # Low, Medium, High, Critical
    attack_types: List[str]
    tier_used: DetectionTier
    escalation_path: List[tuple]  # List of (DetectionTier, EscalationReason)
    timing: Dict[str, float]  # Time spent in each tier
    details: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def total_time_ms(self) -> float:
        """Total detection time in milliseconds."""
        return sum(self.timing.values())
    
    @property
    def cost_saved(self) -> str:
        """Describe cost savings from adaptive approach."""
        if self.tier_used == DetectionTier.KEYWORDS:
            return "~99% (avoided semantic & LLM)"
        elif self.tier_used == DetectionTier.SEMANTICS:
            return "~95% (avoided LLM)"
        return "0% (full analysis needed)"


@dataclass
class AdaptiveConfig:
    """Configuration for adaptive detection thresholds."""
    # Confidence thresholds for short-circuiting
    high_confidence_threshold: float = 0.85
    low_confidence_threshold: float = 0.3
    
    # Suspicious patterns that trigger escalation
    suspicious_keywords: List[str] = field(default_factory=lambda: [
        "ignore", "bypass", "override", "pretend", "roleplay",
        "hypothetical", "simulate", "instead", "forget", "new rules",
        "system prompt", "instruction", "disregard", "administrator",
    ])
    
    # Length threshold - longer prompts are more suspicious
    length_escalation_threshold: int = 500
    
    # Encoding patterns that suggest obfuscation
    encoding_patterns: List[str] = field(default_factory=lambda: [
        "base64", "\\x", "\\u", "%", "&#", "eval(", "exec(",
    ])
    
    # Maximum time budget (ms)
    max_time_budget_ms: float = 10000
    
    # Whether to always run all tiers (for comparison/testing)
    force_full_analysis: bool = False
