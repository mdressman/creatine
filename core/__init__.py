"""Creatine - Prompt security detection platform.

A multi-tier detection system for prompt injection and jailbreak attacks
using Nova pattern matching, semantic similarity, and LLM analysis.

Quick Start:
    from core import AdaptiveDetector
    
    detector = AdaptiveDetector()
    result = await detector.analyze("Your prompt here")
    print(f"Threat: {result.is_threat}, Tier: {result.tier_used.name}")
"""

from .models import (
    ThreatAnalysis,
    AdaptiveResult,
    AdaptiveConfig,
    DetectionTier,
    EscalationReason,
    IoPC,
)
from .detector import ThreatDetector
from .adaptive import AdaptiveDetector
from .feed import PromptIntelFeedClient
from .evaluators import AzureEntraLLMEvaluator

__version__ = "0.2.0"

__all__ = [
    # Core classes
    "ThreatDetector",
    "AdaptiveDetector",
    "PromptIntelFeedClient",
    "AzureEntraLLMEvaluator",
    # Models
    "ThreatAnalysis",
    "AdaptiveResult", 
    "AdaptiveConfig",
    "DetectionTier",
    "EscalationReason",
    "IoPC",
]