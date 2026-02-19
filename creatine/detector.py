"""Core threat detector using Nova pattern matching."""

import os
import sys
import io
import warnings
from contextlib import contextmanager
from pathlib import Path
from typing import Optional, List

from nova import NovaMatcher, NovaParser

from .models import ThreatAnalysis
from .evaluators import AzureEntraLLMEvaluator, create_semantic_evaluator


# Default paths for rule files
RULES_DIR = Path(__file__).parent / "rules"
DEFAULT_RULES_PATH = RULES_DIR / "default.nov"
ADVANCED_RULES_PATH = RULES_DIR / "advanced.nov"
FEED_RULES_PATH = RULES_DIR / "feed_generated.nov"
COMMUNITY_RULES_DIR = RULES_DIR / "community"

# Default community rules repo
NOVA_RULES_REPO = "https://github.com/Nova-Hunting/nova-rules.git"


@contextmanager
def suppress_output():
    """Temporarily suppress stdout, stderr, and warnings."""
    old_stdout = sys.stdout
    old_stderr = sys.stderr
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        # Also suppress HuggingFace tokenizers warning
        os.environ["TOKENIZERS_PARALLELISM"] = "false"
        try:
            yield
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr


class ThreatDetector:
    """
    Local prompt threat detection using Nova pattern matching.
    
    Supports three evaluation modes:
    - Keywords: Fast pattern matching (~1ms)
    - Semantics: Embedding similarity matching (~25ms)
    - LLM: Full LLM-based analysis (~6s)
    """
    
    SEVERITY_ORDER = ["low", "medium", "high", "critical"]
    
    def __init__(
        self, 
        verbose: bool = False, 
        rules_path: Optional[Path] = None,
        include_feed_rules: bool = True,
        include_community_rules: bool = True,
        enable_llm: bool = False,
        enable_semantics: bool = False,
        quiet: bool = False,
    ):
        """
        Initialize the detector.
        
        Args:
            verbose: Print detailed match info
            rules_path: Path to .nov rules file (uses default if not provided)
            include_feed_rules: Whether to also load feed-generated rules
            include_community_rules: Whether to load community rules from nova-rules repo
            enable_llm: Enable LLM-based rule evaluation (requires Azure OpenAI)
            enable_semantics: Enable semantic similarity matching
            quiet: Suppress initialization messages (still shows analysis output if verbose)
        """
        self.verbose = verbose
        self.quiet = quiet
        self._matchers: List[NovaMatcher] = []
        self._rules_loaded: List[str] = []
        self._enable_llm = enable_llm
        self._enable_semantics = enable_semantics
        
        # Initialize evaluators if enabled
        self._llm_evaluator = None
        self._semantic_evaluator = None
        
        if enable_llm:
            try:
                self._llm_evaluator = AzureEntraLLMEvaluator()
                if verbose and not quiet:
                    print("LLM evaluator initialized (Azure OpenAI with Entra auth)")
            except Exception as e:
                if verbose and not quiet:
                    print(f"Warning: Failed to initialize LLM evaluator: {e}")
        
        if enable_semantics:
            try:
                self._semantic_evaluator = create_semantic_evaluator()
                if verbose and not quiet:
                    print("Semantic evaluator initialized")
            except Exception as e:
                if verbose and not quiet:
                    print(f"Warning: Failed to initialize semantic evaluator: {e}")
        
        # Load default rules
        rules_file = rules_path or DEFAULT_RULES_PATH
        if rules_file.exists():
            self.load_rules_file(rules_file)
            self._rules_loaded.append(str(rules_file))
        elif verbose and not quiet:
            print(f"Warning: Rules file not found: {rules_file}")
        
        # Also load feed-generated rules if requested and they exist
        if include_feed_rules and FEED_RULES_PATH.exists() and FEED_RULES_PATH != rules_file:
            if verbose and not quiet:
                print(f"Loading feed rules from: {FEED_RULES_PATH}")
            self.load_rules_file(FEED_RULES_PATH)
            self._rules_loaded.append(str(FEED_RULES_PATH))
        
        # Load advanced rules if semantic/LLM evaluation is enabled
        if (enable_llm or enable_semantics) and ADVANCED_RULES_PATH.exists():
            if verbose and not quiet:
                print(f"Loading advanced rules from: {ADVANCED_RULES_PATH}")
            self.load_rules_file(ADVANCED_RULES_PATH)
            self._rules_loaded.append(str(ADVANCED_RULES_PATH))
        
        # Load community rules (from nova-rules repo) if available
        if include_community_rules and COMMUNITY_RULES_DIR.exists():
            count = self.load_rules_directory(COMMUNITY_RULES_DIR)
            if count > 0 and verbose and not quiet:
                print(f"Loaded {count} community rule files from: {COMMUNITY_RULES_DIR}")
    
    @property
    def rules_info(self) -> str:
        """Return info about loaded rules."""
        return f"{len(self._matchers)} rules from {len(self._rules_loaded)} files"
    
    def _split_rules(self, rules_text: str) -> List[str]:
        """Split a rules file into individual rule blocks."""
        rules = []
        current_rule = []
        brace_count = 0
        entered_braces = False
        
        for line in rules_text.split('\n'):
            current_rule.append(line)
            brace_count += line.count('{') - line.count('}')
            if brace_count > 0:
                entered_braces = True
            
            if brace_count == 0 and entered_braces and current_rule:
                rule_text = '\n'.join(current_rule).strip()
                if rule_text.startswith('rule '):
                    rules.append(rule_text)
                current_rule = []
                entered_braces = False
        
        return rules
    
    async def analyze(self, prompt: str) -> ThreatAnalysis:
        """
        Analyze a prompt for potential threats.
        
        Args:
            prompt: The prompt text to analyze
            
        Returns:
            ThreatAnalysis with risk assessment and attack types detected
        """
        import concurrent.futures
        
        matches = []
        attack_types = []
        max_severity = "low"
        
        # Run all matchers in parallel for better performance with LLM rules
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(m.check_prompt, prompt): m for m in self._matchers}
            results = []
            for future in concurrent.futures.as_completed(futures):
                try:
                    results.append(future.result())
                except Exception:
                    pass  # Skip failed rules
        
        for result in results:
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
    
    def load_rules_file(self, path: Path) -> None:
        """Load additional rules from a .nov file."""
        rules_text = path.read_text()
        parser = NovaParser()
        
        for rule_block in self._split_rules(rules_text):
            if rule_block.strip():
                try:
                    parsed = parser.parse(rule_block)
                    # Suppress Nova's noisy output during matcher creation
                    with suppress_output():
                        matcher = NovaMatcher(
                            parsed,
                            llm_evaluator=self._llm_evaluator,
                            semantic_evaluator=self._semantic_evaluator,
                            create_llm_evaluator=False,
                        )
                    self._matchers.append(matcher)
                except Exception as e:
                    if self.verbose:
                        print(f"Warning: Failed to parse rule from {path}: {e}")
    
    def load_rules_directory(self, directory: Path) -> int:
        """Load all .nov rule files from a directory (recursively).
        
        Returns the number of rule files loaded.
        """
        count = 0
        for nov_file in sorted(directory.rglob("*.nov")):
            try:
                self.load_rules_file(nov_file)
                self._rules_loaded.append(str(nov_file))
                count += 1
            except Exception as e:
                if self.verbose:
                    print(f"Warning: Failed to load {nov_file}: {e}")
        return count
    
    async def close(self):
        """Clean up resources."""
        pass


# Alias for backward compatibility
PromptIntelClient = ThreatDetector
