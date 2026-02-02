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
    
    # Default log directory
    DEFAULT_LOG_DIR = "logs"
    
    def __init__(
        self,
        config: Optional[AdaptiveConfig] = None,
        verbose: bool = False,
        log_file: Optional[str] = None,
        enable_logging: bool = True,
    ):
        """
        Initialize the adaptive detector.
        
        Args:
            config: Adaptive detection configuration
            verbose: Print detailed analysis info
            log_file: Custom log file path (default: auto-generated daily log)
            enable_logging: Enable detection logging (default: True)
        """
        self.config = config or AdaptiveConfig()
        self.verbose = verbose
        self.enable_logging = enable_logging
        
        # Set up logging
        if enable_logging:
            self.log_file = log_file or self._get_default_log_file()
        else:
            self.log_file = None
        
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
    
    def _get_default_log_file(self) -> str:
        """Get default log file path with daily rotation."""
        from datetime import datetime
        from pathlib import Path
        
        # Create logs directory if needed
        log_dir = Path(self.DEFAULT_LOG_DIR)
        log_dir.mkdir(exist_ok=True)
        
        # Daily log file: logs/detections_2026-02-02.jsonl
        date_str = datetime.utcnow().strftime("%Y-%m-%d")
        return str(log_dir / f"detections_{date_str}.jsonl")
    
    def _log_detection(
        self, 
        prompt: str, 
        result: "AdaptiveResult",
        forensics: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log detection result to JSONL file for learning pipeline."""
        if not self.log_file:
            return
        
        import json
        from datetime import datetime
        
        log_entry = {
            "prompt": prompt,
            "is_threat": result.is_threat,
            "tier_used": result.tier_used.name,
            "confidence": result.confidence,
            "risk_score": result.risk_score,
            "attack_types": result.attack_types,
            "escalation_reasons": [str(r[1].name) for r in result.escalation_path] if result.escalation_path else [],
            "timing_ms": result.timing,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
        
        # Add forensics data if available
        if forensics:
            log_entry["forensics"] = {
                "severity": forensics.get("severity"),
                "risk_score": forensics.get("risk_score"),
                "techniques": forensics.get("techniques", []),
                "recommendations": forensics.get("recommendations", []),
            }
        
        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
        except Exception as e:
            if self.verbose:
                print(f"  Warning: Failed to log detection: {e}")
    
    def _init_tier1(self) -> ThreatDetector:
        """Initialize Tier 1: Keywords only."""
        if self._tier1_client is None:
            self._tier1_client = ThreatDetector(
                verbose=False,  # AdaptiveDetector handles verbose output
                include_feed_rules=False,
                enable_llm=False,
                enable_semantics=False,
                quiet=True,
            )
        return self._tier1_client
    
    def _init_tier2(self) -> ThreatDetector:
        """Initialize Tier 2: Keywords + Semantics."""
        if self._tier2_client is None:
            self._tier2_client = ThreatDetector(
                verbose=False,
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
                verbose=False,
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
    
    def _decode_leetspeak(self, text: str) -> str:
        """Decode common leetspeak substitutions to help keyword detection."""
        leetspeak_map = {
            '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's',
            '6': 'g', '7': 't', '8': 'b', '9': 'g', '@': 'a',
            '$': 's', '!': 'i', '+': 't', '|': 'l',
        }
        decoded = []
        for char in text:
            decoded.append(leetspeak_map.get(char, char))
        return ''.join(decoded)
    
    def _try_decode_base64(self, text: str) -> Optional[str]:
        """Try to decode base64 encoded text."""
        import base64
        # Check if it looks like base64 (alphanumeric + /+ and = padding)
        clean = text.strip()
        if not re.match(r'^[A-Za-z0-9+/]+=*$', clean):
            return None
        if len(clean) < 8:  # Too short to be meaningful base64
            return None
        try:
            decoded = base64.b64decode(clean).decode('utf-8')
            # Only return if it looks like readable text
            if decoded.isprintable() and len(decoded) > 3:
                return decoded
        except Exception:
            pass
        return None
    
    def _decode_rot13(self, text: str) -> str:
        """Decode ROT13 encoded text."""
        import codecs
        return codecs.decode(text, 'rot_13')
    
    def _is_meaningful_english(self, text: str, threshold: float = 0.4) -> bool:
        """
        Check if text appears to be meaningful English (vs gibberish).
        
        Uses a simple heuristic: what percentage of words are common English words?
        If above threshold, it's likely intentionally encoded meaningful text.
        """
        # Common English words (~500 most frequent + security-relevant terms)
        common_words = {
            # Top 100 most common
            'the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'i',
            'it', 'for', 'not', 'on', 'with', 'he', 'as', 'you', 'do', 'at',
            'this', 'but', 'his', 'by', 'from', 'they', 'we', 'say', 'her', 'she',
            'or', 'an', 'will', 'my', 'one', 'all', 'would', 'there', 'their', 'what',
            'so', 'up', 'out', 'if', 'about', 'who', 'get', 'which', 'go', 'me',
            'when', 'make', 'can', 'like', 'time', 'no', 'just', 'him', 'know', 'take',
            'people', 'into', 'year', 'your', 'good', 'some', 'could', 'them', 'see', 'other',
            'than', 'then', 'now', 'look', 'only', 'come', 'its', 'over', 'think', 'also',
            'back', 'after', 'use', 'two', 'how', 'our', 'work', 'first', 'well', 'way',
            'even', 'new', 'want', 'because', 'any', 'these', 'give', 'day', 'most', 'us',
            # Common verbs
            'is', 'are', 'was', 'were', 'been', 'has', 'had', 'did', 'does',
            'tell', 'ask', 'show', 'try', 'leave', 'call', 'keep', 'let', 'begin', 'seem',
            'help', 'talk', 'turn', 'start', 'might', 'should', 'need', 'feel', 'must',
            'put', 'run', 'move', 'live', 'believe', 'hold', 'bring', 'happen', 'write', 'read',
            'provide', 'sit', 'stand', 'lose', 'pay', 'meet', 'include', 'continue', 'set', 'learn',
            'change', 'lead', 'understand', 'watch', 'follow', 'stop', 'create', 'speak', 'allow', 'add',
            'spend', 'grow', 'open', 'walk', 'win', 'offer', 'remember', 'love', 'consider', 'appear',
            'buy', 'wait', 'serve', 'die', 'send', 'expect', 'build', 'stay', 'fall', 'cut',
            'reach', 'kill', 'remain', 'suggest', 'raise', 'pass', 'sell', 'require', 'report', 'decide',
            # Common adjectives
            'good', 'new', 'first', 'last', 'long', 'great', 'little', 'own', 'other', 'old',
            'right', 'big', 'high', 'different', 'small', 'large', 'next', 'early', 'young', 'important',
            'few', 'public', 'bad', 'same', 'able', 'quick', 'brown', 'lazy', 'fast', 'slow',
            # Common nouns
            'man', 'woman', 'child', 'world', 'life', 'hand', 'part', 'place', 'case', 'week',
            'company', 'system', 'program', 'question', 'government', 'number', 'night', 'point', 'home', 'water',
            'room', 'mother', 'area', 'money', 'story', 'fact', 'month', 'lot', 'study', 'book',
            'eye', 'job', 'word', 'business', 'issue', 'side', 'kind', 'head', 'house', 'service',
            'friend', 'father', 'power', 'hour', 'game', 'line', 'end', 'member', 'law', 'car',
            'city', 'community', 'name', 'president', 'team', 'minute', 'idea', 'kid', 'body', 'information',
            'dog', 'cat', 'fox', 'bird', 'fish', 'tree', 'flower', 'poem', 'song', 'color',
            # Common adverbs/prepositions
            'each', 'find', 'down', 'still', 'here', 'why', 'where', 'while', 'through', 'very',
            'much', 'before', 'too', 'mean', 'never', 'always', 'every', 'under', 'again', 'however',
            # Security/tech relevant
            'please', 'system', 'prompt', 'ignore', 'previous', 'instructions', 'forget', 'pretend', 'act', 'role',
            'secret', 'password', 'code', 'message', 'decode', 'encrypt', 'hidden', 'bypass', 'override', 'admin',
            'user', 'data', 'file', 'access', 'command', 'execute', 'reveal', 'show', 'tell', 'give',
            'hack', 'bomb', 'weapon', 'attack', 'exploit', 'inject', 'script', 'output', 'input', 'text',
        }
        
        # Extract words (letters only)
        words = re.findall(r'[a-zA-Z]+', text.lower())
        
        if len(words) < 3:
            return False  # Too short to judge
        
        # Count how many are common English words
        common_count = sum(1 for w in words if w in common_words)
        ratio = common_count / len(words)
        
        return ratio >= threshold
    
    def _try_decode_rot13(self, text: str) -> Optional[str]:
        """
        Try to decode ROT13 if the text looks like it might be encoded.
        
        If text mentions ROT13/cipher/decode, extract and decode portions.
        Flag as suspicious if decoded text is meaningful English - the act
        of obfuscating ANY message to an LLM is itself suspicious.
        """
        text_lower = text.lower()
        
        # Trigger words that suggest intentional encoding
        encoding_hints = ['rot13', 'rot-13', 'rot 13', 'cipher', 'decode', 'encoded', 'decrypt']
        
        if not any(hint in text_lower for hint in encoding_hints):
            return None
        
        # Try to find quoted/encoded portions
        patterns = [
            r"['\"]([^'\"]{5,})['\"]",  # Quoted strings (min 5 chars)
            r":\s*['\"]?([a-zA-Z][a-zA-Z\s]{4,})['\"]?",  # After colon
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                decoded = self._decode_rot13(match)
                # If decoded is meaningful English, it was intentionally obfuscated
                if self._is_meaningful_english(decoded, threshold=0.4):
                    if self.verbose:
                        print(f"  ROT13 decoded to meaningful text: '{decoded[:50]}...'")
                    return decoded
        
        return None
    
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
        
        # If no threat found, check for leetspeak and try decoded version
        decoded_prompt = None
        if not result.is_threat and re.search(r'[a-z][0-9][a-z]|[0-9][a-z][0-9]', prompt.lower()):
            decoded_prompt = self._decode_leetspeak(prompt)
            if decoded_prompt != prompt:
                if self.verbose:
                    print(f"  Leetspeak detected, trying decoded: '{decoded_prompt[:40]}...'")
                decoded_result = await tier1.analyze(decoded_prompt)
                if decoded_result.is_threat:
                    result = decoded_result
        
        elapsed = (time.perf_counter() - start) * 1000
        timing["tier1_ms"] = elapsed
        
        confidence = self._calculate_confidence(result)
        
        if self.verbose:
            print(f"  Result: {'THREAT' if result.is_threat else 'CLEAN'}, Confidence: {confidence:.2f}, Time: {elapsed:.1f}ms")
        
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
            
            # Check if obfuscation was detected in Tier 1
            obfuscation_detected = any(
                reason == EscalationReason.ENCODING_DETECTED 
                for _, reason in escalation_path
            )
            
            # Analyze original prompt
            result = await tier2.analyze(prompt)
            
            # If obfuscation was detected and original didn't match, try decoding
            if not result.is_threat and obfuscation_detected:
                # Try leetspeak decoding
                decoded_prompt = self._decode_leetspeak(prompt)
                if decoded_prompt != prompt:
                    if self.verbose:
                        print(f"  Trying leetspeak decode: '{decoded_prompt[:40]}...'")
                    decoded_result = await tier2.analyze(decoded_prompt)
                    if decoded_result.is_threat:
                        result = decoded_result
                
                # Try base64 decoding if still no match
                if not result.is_threat:
                    base64_decoded = self._try_decode_base64(prompt)
                    if base64_decoded:
                        if self.verbose:
                            print(f"  Trying base64 decode: '{base64_decoded[:40]}...'")
                        decoded_result = await tier2.analyze(base64_decoded)
                        if decoded_result.is_threat:
                            result = decoded_result
                
                # Try ROT13 decoding if still no match
                if not result.is_threat:
                    rot13_decoded = self._try_decode_rot13(prompt)
                    if rot13_decoded and rot13_decoded != prompt:
                        if self.verbose:
                            print(f"  Trying ROT13 decode: '{rot13_decoded[:40]}...'")
                        decoded_result = await tier2.analyze(rot13_decoded)
                        if decoded_result.is_threat:
                            result = decoded_result
            
            elapsed = (time.perf_counter() - start) * 1000
            timing["tier2_ms"] = elapsed
            
            confidence = self._calculate_confidence(result)
            
            if self.verbose:
                print(f"  Result: {'THREAT' if result.is_threat else 'CLEAN'}, Confidence: {confidence:.2f}, Time: {elapsed:.1f}ms")
            
            total_time = sum(timing.values())
            time_remaining = self.config.max_time_budget_ms - total_time
            
            if result.is_threat and confidence >= self.config.high_confidence_threshold:
                if self.verbose:
                    print(f"  → HIGH CONFIDENCE THREAT - stopping at Tier 2")
                final_result = result
                self._stats["tier2_stops"] += 1
            elif result.is_threat:
                # Threat detected with lower confidence - still report as threat
                # Don't escalate to LLM which might clear a valid detection
                if self.verbose:
                    print(f"  → THREAT DETECTED - stopping at Tier 2")
                final_result = result
                self._stats["tier2_stops"] += 1
            elif obfuscation_detected and not result.is_threat and not self.config.force_full_analysis:
                # Obfuscation detected but even decoded didn't match - try LLM
                if self.verbose:
                    print(f"  → OBFUSCATION DETECTED - escalating to LLM for reliable analysis")
                escalation_path.append((DetectionTier.SEMANTICS, EscalationReason.ENCODING_DETECTED))
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
                print(f"  Result: {'THREAT' if result.is_threat else 'CLEAN'}, Confidence: {confidence:.2f}, Time: {elapsed:.1f}ms")
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
        
        # Log for learning pipeline (without forensics - use log_with_forensics for that)
        self._log_detection(prompt, adaptive_result)
        
        if self.verbose:
            print(f"\n{'='*60}")
            print(f"FINAL: {'🚨 THREAT' if adaptive_result.is_threat else '✅ CLEAN'}")
            print(f"Tier: {adaptive_result.tier_used.name}, Time: {adaptive_result.total_time_ms:.1f}ms")
            print(f"Cost saved: {adaptive_result.cost_saved}")
            print(f"{'='*60}\n")
        
        return adaptive_result
    
    def log_with_forensics(self, prompt: str, result: "AdaptiveResult", forensics_report) -> None:
        """
        Update the log entry with forensics data.
        
        Call this after running forensics analysis to enrich the log entry.
        This overwrites the last log entry for this prompt with forensics data.
        """
        if not self.log_file:
            return
        
        # Convert forensics report to dict
        forensics_data = None
        if forensics_report:
            forensics_data = {
                "severity": getattr(forensics_report, 'severity', None),
                "risk_score": getattr(forensics_report, 'risk_score', None),
                "techniques": [
                    {"name": t.name, "category": t.category, "confidence": t.confidence}
                    for t in getattr(forensics_report, 'techniques', [])[:5]
                ],
                "recommendations": getattr(forensics_report, 'recommendations', [])[:3],
            }
        
        # Re-log with forensics (we accept the duplicate - learning pipeline dedupes)
        self._log_detection(prompt, result, forensics=forensics_data)
    
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
