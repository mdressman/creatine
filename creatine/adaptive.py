"""
Adaptive Detection - Intelligent tiered prompt security analysis.

Automatically escalates from fast/cheap methods to thorough/expensive ones
based on threat signals, optimizing for both accuracy and cost.

Tiers:
  1. Keywords (Tier 1): ~1ms, free - catches obvious attacks
  2. Semantics (Tier 2): ~25ms, low cost - catches obfuscated attacks
  3. LLM (Tier 3): ~6s, higher cost - catches sophisticated attacks
"""

import asyncio
import re
import time
from typing import Optional, Dict, Any, List, Tuple

from .models import (
    ThreatAnalysis, AdaptiveResult, AdaptiveConfig,
    DetectionTier, EscalationReason
)
from .detector import ThreatDetector


class AdaptiveDetector:
    """
    Intelligent multi-tier prompt security detector.
    
    Automatically escalates from fast to thorough analysis based on
    threat signals, optimizing for both accuracy and cost.
    
    Example:
        detector = AdaptiveDetector()
        result = await detector.analyze("Ignore previous instructions...")
        print(f"Threat: {result.is_threat} (Tier: {result.tier_used.name})")
    """
    
    def __init__(
        self,
        config: Optional[AdaptiveConfig] = None,
        verbose: bool = False,
    ):
        """
        Initialize the adaptive detector.
        
        Args:
            config: Adaptive detection configuration
            verbose: Print detailed analysis info
        """
        self.config = config or AdaptiveConfig()
        self.verbose = verbose
        
        # Lazy-initialized tier clients
        self._tier1_client: Optional[ThreatDetector] = None
        self._tier2_client: Optional[ThreatDetector] = None
        self._tier3_client: Optional[ThreatDetector] = None
        
        # Stats tracking
        self._stats = {
            "total_analyzed": 0,
            "tier1_stops": 0,
            "tier2_stops": 0,
            "tier3_stops": 0,
            "total_time_ms": 0,
        }
    
    def _init_tier1(self) -> ThreatDetector:
        """Initialize Tier 1: Keywords only."""
        if self._tier1_client is None:
            self._tier1_client = ThreatDetector(
                verbose=self.verbose,
                include_feed_rules=False,
                enable_llm=False,
                enable_semantics=False,
                quiet=True,  # Suppress init messages, AdaptiveDetector handles output
            )
        return self._tier1_client
    
    def _init_tier2(self) -> ThreatDetector:
        """Initialize Tier 2: Keywords + Semantics."""
        if self._tier2_client is None:
            self._tier2_client = ThreatDetector(
                verbose=self.verbose,
                include_feed_rules=False,
                enable_llm=False,
                enable_semantics=True,
                quiet=True,
            )
        return self._tier2_client
    
    def _init_tier3(self) -> ThreatDetector:
        """Initialize Tier 3: Full LLM analysis."""
        if self._tier3_client is None:
            self._tier3_client = ThreatDetector(
                verbose=self.verbose,
                include_feed_rules=False,
                enable_llm=True,
                enable_semantics=True,
                quiet=True,
            )
        return self._tier3_client
    
    def _check_suspicious_signals(self, text: str) -> Tuple[bool, List[EscalationReason]]:
        """Check for suspicious signals that warrant escalation."""
        reasons = []
        text_lower = text.lower()
        
        # Check for suspicious keywords
        matches = [kw for kw in self.config.suspicious_keywords if kw in text_lower]
        if matches:
            reasons.append(EscalationReason.SUSPICIOUS_PATTERNS)
            if self.verbose:
                print(f"  Suspicious patterns detected: {matches[:3]}...")
        
        # Check length
        if len(text) > self.config.length_escalation_threshold:
            reasons.append(EscalationReason.LENGTH_THRESHOLD)
            if self.verbose:
                print(f"  Long prompt ({len(text)} chars)")
        
        # Check for encoding/obfuscation
        for pattern in self.config.encoding_patterns:
            if pattern in text:
                reasons.append(EscalationReason.ENCODING_DETECTED)
                if self.verbose:
                    print(f"  Encoding pattern detected: {pattern}")
                break
        
        # Check for leetspeak
        if re.search(r'[a-z][0-9][a-z]|[0-9][a-z][0-9]', text_lower):
            if EscalationReason.ENCODING_DETECTED not in reasons:
                reasons.append(EscalationReason.ENCODING_DETECTED)
                if self.verbose:
                    print(f"  Leetspeak obfuscation detected")
        
        # Check for unicode homoglyphs
        non_ascii = sum(1 for c in text if ord(c) > 127 and c.isalpha())
        if non_ascii > 2:
            if EscalationReason.ENCODING_DETECTED not in reasons:
                reasons.append(EscalationReason.ENCODING_DETECTED)
                if self.verbose:
                    print(f"  Unicode homoglyphs detected ({non_ascii} non-ASCII)")
        
        return len(reasons) > 0, reasons
    
    def _calculate_confidence(self, result: ThreatAnalysis) -> float:
        """Calculate confidence score from a ThreatAnalysis result."""
        if not result.is_threat:
            matches = result.details.get("matches", [])
            return 0.9 if not matches else 0.5
        
        matches = result.details.get("matches", [])
        num_matches = len(matches)
        
        if num_matches >= 3:
            base = 0.95
        elif num_matches >= 2:
            base = 0.85
        else:
            base = 0.7
        
        boost = {"Critical": 0.1, "High": 0.05, "Medium": 0.0, "Low": -0.05}
        return min(1.0, base + boost.get(result.risk_score, 0))
    
    async def analyze(self, prompt: str) -> AdaptiveResult:
        """
        Analyze a prompt using adaptive tiered detection.
        
        Args:
            prompt: The prompt text to analyze
            
        Returns:
            AdaptiveResult with threat assessment and tier info
        """
        timing = {}
        escalation_path = []
        current_tier = DetectionTier.KEYWORDS
        final_result: Optional[ThreatAnalysis] = None
        confidence = 0.0
        
        self._stats["total_analyzed"] += 1
        
        if self.verbose:
            print(f"\n{'='*60}")
            print(f"Adaptive Analysis: {prompt[:60]}...")
            print(f"{'='*60}")
        
        # ===== TIER 1: Keywords =====
        if self.verbose:
            print(f"\n[Tier 1: Keywords]")
        
        start = time.perf_counter()
        tier1 = self._init_tier1()
        result = await tier1.analyze(prompt)
        elapsed = (time.perf_counter() - start) * 1000
        timing["tier1_ms"] = elapsed
        
        confidence = self._calculate_confidence(result)
        
        if self.verbose:
            print(f"  Result: {'THREAT' if result.is_threat else 'CLEAN'}")
            print(f"  Confidence: {confidence:.2f}, Time: {elapsed:.1f}ms")
        
        # Decision: Stop or escalate?
        if result.is_threat and confidence >= self.config.high_confidence_threshold:
            if self.verbose:
                print(f"  → HIGH CONFIDENCE THREAT - stopping at Tier 1")
            final_result = result
            self._stats["tier1_stops"] += 1
        elif not result.is_threat and confidence >= self.config.high_confidence_threshold:
            suspicious, reasons = self._check_suspicious_signals(prompt)
            if not suspicious and not self.config.force_full_analysis:
                if self.verbose:
                    print(f"  → HIGH CONFIDENCE CLEAN - stopping at Tier 1")
                final_result = result
                self._stats["tier1_stops"] += 1
            else:
                escalation_path.append((DetectionTier.KEYWORDS, reasons[0] if reasons else EscalationReason.UNCERTAIN_CONFIDENCE))
        else:
            suspicious, reasons = self._check_suspicious_signals(prompt)
            reason = reasons[0] if reasons else EscalationReason.UNCERTAIN_CONFIDENCE
            escalation_path.append((DetectionTier.KEYWORDS, reason))
        
        # ===== TIER 2: Semantics =====
        if final_result is None:
            current_tier = DetectionTier.SEMANTICS
            
            if self.verbose:
                print(f"\n[Tier 2: Semantics]")
            
            start = time.perf_counter()
            tier2 = self._init_tier2()
            result = await tier2.analyze(prompt)
            elapsed = (time.perf_counter() - start) * 1000
            timing["tier2_ms"] = elapsed
            
            confidence = self._calculate_confidence(result)
            
            if self.verbose:
                print(f"  Result: {'THREAT' if result.is_threat else 'CLEAN'}")
                print(f"  Confidence: {confidence:.2f}, Time: {elapsed:.1f}ms")
            
            total_time = sum(timing.values())
            time_remaining = self.config.max_time_budget_ms - total_time
            
            if result.is_threat and confidence >= self.config.high_confidence_threshold:
                if self.verbose:
                    print(f"  → HIGH CONFIDENCE THREAT - stopping at Tier 2")
                final_result = result
                self._stats["tier2_stops"] += 1
            elif confidence >= self.config.high_confidence_threshold and not self.config.force_full_analysis:
                if self.verbose:
                    print(f"  → HIGH CONFIDENCE CLEAN - stopping at Tier 2")
                final_result = result
                self._stats["tier2_stops"] += 1
            elif time_remaining < 5000 and not self.config.force_full_analysis:
                if self.verbose:
                    print(f"  → TIME BUDGET LOW - stopping at Tier 2")
                final_result = result
                self._stats["tier2_stops"] += 1
            else:
                escalation_path.append((DetectionTier.SEMANTICS, EscalationReason.UNCERTAIN_CONFIDENCE))
        
        # ===== TIER 3: LLM =====
        if final_result is None:
            current_tier = DetectionTier.LLM
            
            if self.verbose:
                print(f"\n[Tier 3: LLM Analysis]")
            
            start = time.perf_counter()
            tier3 = self._init_tier3()
            result = await tier3.analyze(prompt)
            elapsed = (time.perf_counter() - start) * 1000
            timing["tier3_ms"] = elapsed
            
            confidence = self._calculate_confidence(result)
            
            if self.verbose:
                print(f"  Result: {'THREAT' if result.is_threat else 'CLEAN'}")
                print(f"  Confidence: {confidence:.2f}, Time: {elapsed:.1f}ms")
                print(f"  → FINAL VERDICT from LLM")
            
            final_result = result
            self._stats["tier3_stops"] += 1
        
        total_time = sum(timing.values())
        self._stats["total_time_ms"] += total_time
        
        adaptive_result = AdaptiveResult(
            is_threat=final_result.is_threat,
            confidence=confidence,
            risk_score=final_result.risk_score,
            attack_types=final_result.attack_types,
            tier_used=current_tier,
            escalation_path=escalation_path,
            timing=timing,
            details=final_result.details,
        )
        
        if self.verbose:
            print(f"\n{'='*60}")
            print(f"FINAL: {'🚨 THREAT' if adaptive_result.is_threat else '✅ CLEAN'}")
            print(f"Tier: {adaptive_result.tier_used.name}, Time: {adaptive_result.total_time_ms:.1f}ms")
            print(f"Cost saved: {adaptive_result.cost_saved}")
            print(f"{'='*60}\n")
        
        return adaptive_result
    
    async def analyze_batch(
        self, 
        prompts: List[str],
        max_concurrency: int = 5,
    ) -> List[AdaptiveResult]:
        """Analyze multiple prompts with controlled concurrency."""
        semaphore = asyncio.Semaphore(max_concurrency)
        
        async def analyze_one(prompt: str) -> AdaptiveResult:
            async with semaphore:
                return await self.analyze(prompt)
        
        return await asyncio.gather(*[analyze_one(p) for p in prompts])
    
    def get_stats(self) -> Dict[str, Any]:
        """Get detection statistics."""
        total = self._stats["total_analyzed"]
        if total == 0:
            return self._stats
        
        return {
            **self._stats,
            "tier1_stop_rate": self._stats["tier1_stops"] / total,
            "tier2_stop_rate": self._stats["tier2_stops"] / total,
            "tier3_stop_rate": self._stats["tier3_stops"] / total,
            "avg_time_ms": self._stats["total_time_ms"] / total,
        }
    
    def reset_stats(self):
        """Reset statistics."""
        self._stats = {
            "total_analyzed": 0,
            "tier1_stops": 0,
            "tier2_stops": 0,
            "tier3_stops": 0,
            "total_time_ms": 0,
        }
