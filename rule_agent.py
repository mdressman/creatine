"""Rule Generation Agent - AI-powered Nova rule creation with iterative optimization.

This agent ingests data from multiple sources, generates Nova rules using AI,
and iteratively optimizes for precision and recall using test feedback.
"""

import asyncio
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional, Callable

from dotenv import load_dotenv
from azure.identity import DefaultAzureCredential, get_bearer_token_provider
from openai import AzureOpenAI

from dataset import Dataset, DatasetRegistry, TestPrompt, AttackType
from promptintel import (
    PromptIntelFeedClient, IoPC, FEED_RULES_PATH, DEFAULT_RULES_PATH,
    PromptIntelClient
)
from test_harness import TestHarness, TestReport

load_dotenv()


@dataclass
class DataSource:
    """A source of adversarial prompt data."""
    name: str
    source_type: str  # "promptintel", "huggingface", "file", "custom"
    config: dict = field(default_factory=dict)


@dataclass
class RuleCandidate:
    """A candidate rule being evaluated."""
    rule_text: str
    rule_name: str
    source: str
    iteration: int
    metrics: dict = field(default_factory=dict)


@dataclass
class OptimizationResult:
    """Result of an optimization run."""
    iterations: int
    initial_metrics: dict
    final_metrics: dict
    rules_generated: int
    rules_kept: int
    improvement: dict
    history: list = field(default_factory=list)
    output_file: str = ""


RULE_GENERATION_SYSTEM_PROMPT = """You are an expert security researcher specializing in LLM prompt injection and jailbreak detection.

Your task is to create Nova detection rules that identify adversarial prompts. Nova uses YARA-like syntax:

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

Guidelines:
1. Focus on ATTACK TECHNIQUES, not specific words
2. Extract GENERALIZABLE patterns that catch similar attacks
3. Use lowercase keywords to catch case variations
4. Keep keywords 3-50 chars, distinctive but not overly generic
5. Combine keywords logically (use AND for precision, OR for recall)
6. Consider: instruction override, role manipulation, context injection, authority claims, encoding hints

Output ONLY valid Nova rules, no explanations or markdown."""


OPTIMIZATION_PROMPT = """Based on test results, improve the Nova rules.

Current Performance:
- Precision: {precision:.2%} (of detected threats, how many were actually malicious)
- Recall: {recall:.2%} (of malicious prompts, how many were detected)
- False Positives: {false_positives} (benign prompts incorrectly flagged)
- False Negatives: {false_negatives} (malicious prompts missed)

{feedback}

Current Rules:
```
{current_rules}
```

{sample_errors}

Your task:
1. If precision is low (many false positives): Make keywords MORE SPECIFIC or use AND conditions
2. If recall is low (many false negatives): Add NEW keywords or use OR conditions
3. Remove rules that cause false positives without catching real threats
4. Add rules to catch the missed attack patterns shown above

Output improved Nova rules. Keep rules that work well, fix or remove problematic ones."""


class RuleGenerationAgent:
    """Agent that generates and optimizes Nova detection rules."""
    
    def __init__(
        self,
        output_dir: Path = None,
        verbose: bool = False,
    ):
        self.output_dir = output_dir or Path(__file__).parent / "rules"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.verbose = verbose
        
        # Initialize Azure OpenAI
        endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
        deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT_NAME")
        
        if not endpoint or "your-resource" in endpoint:
            raise ValueError("Azure OpenAI not configured. Set AZURE_OPENAI_ENDPOINT and AZURE_OPENAI_DEPLOYMENT_NAME")
        
        token_provider = get_bearer_token_provider(
            DefaultAzureCredential(),
            "https://cognitiveservices.azure.com/.default"
        )
        
        self.client = AzureOpenAI(
            azure_endpoint=endpoint,
            azure_ad_token_provider=token_provider,
            api_version=os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-15-preview"),
        )
        self.deployment = deployment
        
        # Data sources
        self.data_sources: list[DataSource] = []
        self.indicators: list[IoPC] = []
        
        # Test infrastructure
        self.registry = DatasetRegistry()
        
    def add_data_source(self, source: DataSource) -> None:
        """Add a data source for rule generation."""
        self.data_sources.append(source)
        if self.verbose:
            print(f"Added data source: {source.name} ({source.source_type})")
    
    def add_promptintel_source(self, api_key: str = None) -> None:
        """Add PromptIntel feed as a data source."""
        key = api_key or os.getenv("PROMPTINTEL_API_KEY")
        self.add_data_source(DataSource(
            name="PromptIntel Feed",
            source_type="promptintel",
            config={"api_key": key}
        ))
    
    def add_huggingface_source(self, dataset_name: str, **kwargs) -> None:
        """Add a HuggingFace dataset as a data source."""
        self.add_data_source(DataSource(
            name=f"HuggingFace: {dataset_name}",
            source_type="huggingface",
            config={"dataset": dataset_name, **kwargs}
        ))
    
    def add_file_source(self, path: Path, format: str = "json") -> None:
        """Add a local file as a data source."""
        self.add_data_source(DataSource(
            name=f"File: {path.name}",
            source_type="file",
            config={"path": str(path), "format": format}
        ))
    
    def add_custom_prompts(self, prompts: list[str], category: str = "custom") -> None:
        """Add custom prompts directly."""
        for i, prompt in enumerate(prompts):
            self.indicators.append(IoPC(
                id=f"custom_{category}_{i}",
                prompt=prompt,
                risk_score="medium",
                tags=[category],
                description=f"Custom prompt: {category}",
                pattern=prompt,
                category=category,
            ))
        if self.verbose:
            print(f"Added {len(prompts)} custom prompts in category '{category}'")
    
    async def fetch_all_sources(self) -> list[IoPC]:
        """Fetch data from all configured sources."""
        all_indicators = list(self.indicators)  # Start with any custom prompts
        
        for source in self.data_sources:
            if self.verbose:
                print(f"Fetching from {source.name}...")
            
            try:
                if source.source_type == "promptintel":
                    indicators = await self._fetch_promptintel(source)
                    all_indicators.extend(indicators)
                    
                elif source.source_type == "huggingface":
                    indicators = await self._fetch_huggingface(source)
                    all_indicators.extend(indicators)
                    
                elif source.source_type == "file":
                    indicators = await self._fetch_file(source)
                    all_indicators.extend(indicators)
                    
            except Exception as e:
                if self.verbose:
                    print(f"  Error fetching {source.name}: {e}")
        
        if self.verbose:
            print(f"Total indicators collected: {len(all_indicators)}")
        
        return all_indicators
    
    async def _fetch_promptintel(self, source: DataSource) -> list[IoPC]:
        """Fetch from PromptIntel API."""
        client = PromptIntelFeedClient(
            source.config.get("api_key", ""),
            verbose=self.verbose
        )
        try:
            indicators = client.fetch_all()
            if self.verbose:
                print(f"  Fetched {len(indicators)} indicators from PromptIntel")
            return indicators
        finally:
            client.close()
    
    async def _fetch_huggingface(self, source: DataSource) -> list[IoPC]:
        """Fetch from HuggingFace dataset."""
        from dataset import load_from_huggingface
        
        dataset = load_from_huggingface(
            source.config["dataset"],
            split=source.config.get("split", "train"),
            prompt_field=source.config.get("prompt_field", "prompt"),
            label_field=source.config.get("label_field", "label"),
        )
        
        indicators = []
        for prompt in dataset.prompts:
            if prompt.is_malicious:
                indicators.append(IoPC(
                    id=f"hf_{len(indicators)}",
                    prompt=prompt.prompt,
                    risk_score="medium",
                    tags=[prompt.attack_type.value],
                    description="From HuggingFace dataset",
                    pattern=prompt.prompt,
                    category=prompt.attack_type.value,
                ))
        
        if self.verbose:
            print(f"  Fetched {len(indicators)} malicious prompts from HuggingFace")
        return indicators
    
    async def _fetch_file(self, source: DataSource) -> list[IoPC]:
        """Fetch from local file."""
        path = Path(source.config["path"])
        format = source.config.get("format", "json")
        
        indicators = []
        
        if format == "json":
            data = json.loads(path.read_text())
            if isinstance(data, list):
                for i, item in enumerate(data):
                    prompt = item.get("prompt") or item.get("text") or str(item)
                    indicators.append(IoPC(
                        id=f"file_{i}",
                        prompt=prompt,
                        risk_score=item.get("severity", "medium"),
                        tags=item.get("tags", []),
                        description=item.get("description", ""),
                        pattern=prompt,
                        category=item.get("category", "unknown"),
                    ))
        
        if self.verbose:
            print(f"  Loaded {len(indicators)} indicators from file")
        return indicators
    
    def _call_llm(self, system: str, user: str, temperature: float = 0.3) -> str:
        """Call Azure OpenAI."""
        response = self.client.chat.completions.create(
            model=self.deployment,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user}
            ],
            temperature=temperature,
        )
        return response.choices[0].message.content
    
    async def generate_initial_rules(self, indicators: list[IoPC], batch_size: int = 15) -> str:
        """Generate initial rules from indicators."""
        all_rules = []
        
        for i in range(0, len(indicators), batch_size):
            batch = indicators[i:i + batch_size]
            
            prompts_text = "\n\n---\n\n".join([
                f"**{iopc.description or 'Attack'}** (Severity: {iopc.risk_score}, Category: {iopc.category})\n```\n{iopc.prompt[:1200]}\n```"
                for iopc in batch
            ])
            
            user_prompt = f"""Analyze these adversarial prompts and create Nova detection rules:

{prompts_text}

Create 3-5 rules that detect these and similar attack patterns."""
            
            if self.verbose:
                print(f"  Generating rules for batch {i // batch_size + 1}...")
            
            try:
                rules_text = self._call_llm(RULE_GENERATION_SYSTEM_PROMPT, user_prompt)
                if "rule " in rules_text:
                    # Clean markdown
                    rules_text = re.sub(r'```\w*\n?', '', rules_text)
                    all_rules.append(rules_text.strip())
            except Exception as e:
                if self.verbose:
                    print(f"    Error: {e}")
        
        return "\n\n".join(all_rules)
    
    async def test_rules(
        self,
        rules_text: str,
        test_dataset: str,
    ) -> TestReport:
        """Test rules against a dataset."""
        # Write rules to temp file
        temp_rules = self.output_dir / "temp_rules.nov"
        temp_rules.write_text(rules_text)
        
        # Create client with only these rules
        client = PromptIntelClient(
            verbose=False,
            rules_path=temp_rules,
            include_feed_rules=False,
        )
        
        harness = TestHarness(client, self.registry)
        dataset = self.registry.get(test_dataset)
        
        if not dataset:
            raise ValueError(f"Test dataset not found: {test_dataset}")
        
        report = await harness.run_dataset(dataset, concurrency=10)
        await client.close()
        
        return report
    
    async def optimize_rules(
        self,
        initial_rules: str,
        test_dataset: str,
        target_precision: float = 0.90,
        target_recall: float = 0.80,
        max_iterations: int = 5,
        progress_callback: Callable = None,
    ) -> tuple[str, OptimizationResult]:
        """Iteratively optimize rules for precision and recall."""
        
        current_rules = initial_rules
        history = []
        
        # Initial test
        if self.verbose:
            print("Testing initial rules...")
        
        report = await self.test_rules(current_rules, test_dataset)
        initial_metrics = {
            "precision": report.precision,
            "recall": report.recall,
            "f1": report.f1_score,
            "accuracy": report.accuracy,
            "true_positives": report.true_positives,
            "false_positives": report.false_positives,
            "false_negatives": report.false_negatives,
        }
        history.append({"iteration": 0, "metrics": initial_metrics.copy()})
        
        if self.verbose:
            print(f"  Initial: P={report.precision:.2%} R={report.recall:.2%} F1={report.f1_score:.2%}")
        
        if progress_callback:
            progress_callback(0, max_iterations, initial_metrics)
        
        # Optimization loop
        for iteration in range(1, max_iterations + 1):
            # Check if we've met targets
            if report.precision >= target_precision and report.recall >= target_recall:
                if self.verbose:
                    print(f"  Targets met at iteration {iteration - 1}!")
                break
            
            # Determine optimization focus
            feedback = []
            if report.precision < target_precision:
                feedback.append(f"PRIORITY: Improve precision (target: {target_precision:.0%}). Reduce false positives.")
            if report.recall < target_recall:
                feedback.append(f"PRIORITY: Improve recall (target: {target_recall:.0%}). Catch more attacks.")
            
            # Get sample errors for context
            sample_errors = await self._get_sample_errors(current_rules, test_dataset)
            
            # Generate improved rules
            if self.verbose:
                print(f"  Iteration {iteration}: Optimizing...")
            
            optimization_prompt = OPTIMIZATION_PROMPT.format(
                precision=report.precision,
                recall=report.recall,
                false_positives=report.false_positives,
                false_negatives=report.false_negatives,
                feedback="\n".join(feedback),
                current_rules=current_rules[:8000],  # Limit size
                sample_errors=sample_errors,
            )
            
            try:
                improved_rules = self._call_llm(
                    RULE_GENERATION_SYSTEM_PROMPT,
                    optimization_prompt,
                    temperature=0.4,
                )
                
                # Clean and validate
                improved_rules = re.sub(r'```\w*\n?', '', improved_rules).strip()
                
                if "rule " not in improved_rules:
                    if self.verbose:
                        print("    No valid rules generated, keeping current")
                    continue
                
                # Test improved rules
                new_report = await self.test_rules(improved_rules, test_dataset)
                
                new_metrics = {
                    "precision": new_report.precision,
                    "recall": new_report.recall,
                    "f1": new_report.f1_score,
                    "accuracy": new_report.accuracy,
                    "true_positives": new_report.true_positives,
                    "false_positives": new_report.false_positives,
                    "false_negatives": new_report.false_negatives,
                }
                
                # Accept if F1 improved or both precision and recall improved
                f1_improved = new_report.f1_score > report.f1_score
                both_improved = (new_report.precision >= report.precision and 
                               new_report.recall >= report.recall)
                
                if f1_improved or both_improved:
                    current_rules = improved_rules
                    report = new_report
                    if self.verbose:
                        print(f"    Improved: P={report.precision:.2%} R={report.recall:.2%} F1={report.f1_score:.2%}")
                else:
                    if self.verbose:
                        print(f"    No improvement (P={new_report.precision:.2%} R={new_report.recall:.2%}), keeping previous")
                
                history.append({"iteration": iteration, "metrics": new_metrics})
                
                if progress_callback:
                    progress_callback(iteration, max_iterations, new_metrics)
                    
            except Exception as e:
                if self.verbose:
                    print(f"    Error in iteration {iteration}: {e}")
        
        # Final metrics
        final_metrics = {
            "precision": report.precision,
            "recall": report.recall,
            "f1": report.f1_score,
            "accuracy": report.accuracy,
        }
        
        # Calculate improvement
        improvement = {
            "precision": final_metrics["precision"] - initial_metrics["precision"],
            "recall": final_metrics["recall"] - initial_metrics["recall"],
            "f1": final_metrics["f1"] - initial_metrics["f1"],
        }
        
        result = OptimizationResult(
            iterations=len(history) - 1,
            initial_metrics=initial_metrics,
            final_metrics=final_metrics,
            rules_generated=current_rules.count("rule "),
            rules_kept=current_rules.count("rule "),
            improvement=improvement,
            history=history,
        )
        
        return current_rules, result
    
    async def _get_sample_errors(self, rules_text: str, test_dataset: str, max_samples: int = 5) -> str:
        """Get sample false positives and false negatives for optimization context."""
        temp_rules = self.output_dir / "temp_rules.nov"
        temp_rules.write_text(rules_text)
        
        client = PromptIntelClient(
            verbose=False,
            rules_path=temp_rules,
            include_feed_rules=False,
        )
        
        harness = TestHarness(client, self.registry)
        dataset = self.registry.get(test_dataset)
        report = await harness.run_dataset(dataset, concurrency=10)
        await client.close()
        
        samples = []
        
        # Sample false negatives (missed attacks)
        fn_count = 0
        for result in report.results:
            if result.prompt.is_malicious and not result.detected_as_threat:
                if fn_count < max_samples:
                    samples.append(f"MISSED ATTACK ({result.prompt.attack_type.value}):\n{result.prompt.prompt[:300]}")
                    fn_count += 1
        
        # Sample false positives (benign flagged as threat)
        fp_count = 0
        for result in report.results:
            if not result.prompt.is_malicious and result.detected_as_threat:
                if fp_count < max_samples:
                    samples.append(f"FALSE POSITIVE (benign prompt flagged):\n{result.prompt.prompt[:300]}")
                    fp_count += 1
        
        if samples:
            return "Sample Errors:\n" + "\n\n".join(samples)
        return ""
    
    async def run(
        self,
        test_dataset: Optional[str] = None,
        output_file: str = "optimized_rules.nov",
        target_precision: float = 0.90,
        target_recall: float = 0.80,
        max_iterations: int = 5,
    ) -> OptimizationResult:
        """
        Full pipeline: fetch data, generate rules, optimize, save.
        
        Args:
            test_dataset: Name of dataset to test against (None = skip optimization)
            output_file: Output filename for optimized rules
            target_precision: Target precision (default 90%)
            target_recall: Target recall (default 80%)
            max_iterations: Max optimization iterations
            
        Returns:
            OptimizationResult with metrics and history
        """
        if self.verbose:
            print("=" * 60)
            print("Rule Generation Agent - Starting")
            print("=" * 60)
        
        # Fetch all data
        if self.verbose:
            print("\n[1/4] Fetching data from sources...")
        indicators = await self.fetch_all_sources()
        
        if not indicators:
            raise ValueError("No indicators found from any source")
        
        # Generate initial rules
        if self.verbose:
            print(f"\n[2/4] Generating initial rules from {len(indicators)} indicators...")
        initial_rules = await self.generate_initial_rules(indicators)
        
        initial_count = initial_rules.count("rule ")
        if self.verbose:
            print(f"  Generated {initial_count} initial rules")
        
        # Skip optimization if no test dataset provided
        if not test_dataset:
            if self.verbose:
                print("\n[3/4] Skipping optimization (no test dataset provided)")
                print(f"\n[4/4] Saving rules...")
            
            output_path = self.output_dir / output_file
            output_path.write_text(initial_rules)
            
            if self.verbose:
                print(f"  Saved to: {output_path}")
            
            result = OptimizationResult(
                iterations=0,
                initial_metrics={"precision": 0, "recall": 0, "f1": 0},
                final_metrics={"precision": 0, "recall": 0, "f1": 0},
                rules_generated=initial_count,
                rules_kept=initial_count,
                improvement={"precision": 0, "recall": 0, "f1": 0},
                history=[],
            )
            result.output_file = output_file
            return result
        
        # Optimize
        if self.verbose:
            print(f"\n[3/4] Optimizing rules (target: P≥{target_precision:.0%}, R≥{target_recall:.0%})...")
        
        def progress(iteration, total, metrics):
            if self.verbose:
                print(f"  [{iteration}/{total}] P={metrics['precision']:.2%} R={metrics['recall']:.2%} F1={metrics['f1']:.2%}")
        
        optimized_rules, result = await self.optimize_rules(
            initial_rules,
            test_dataset,
            target_precision=target_precision,
            target_recall=target_recall,
            max_iterations=max_iterations,
            progress_callback=progress,
        )
        
        # Save
        if self.verbose:
            print(f"\n[4/4] Saving optimized rules...")
        
        output_path = self.output_dir / output_file
        output_path.write_text(optimized_rules)
        result.output_file = output_file
        
        if self.verbose:
            print(f"  Saved to: {output_path}")
            print("\n" + "=" * 60)
            print("OPTIMIZATION COMPLETE")
            print("=" * 60)
            print(f"Iterations: {result.iterations}")
            print(f"Rules: {result.rules_generated}")
            print(f"\nMetrics:")
            print(f"  Precision: {result.initial_metrics['precision']:.2%} → {result.final_metrics['precision']:.2%} ({result.improvement['precision']:+.2%})")
            print(f"  Recall:    {result.initial_metrics['recall']:.2%} → {result.final_metrics['recall']:.2%} ({result.improvement['recall']:+.2%})")
            print(f"  F1 Score:  {result.initial_metrics['f1']:.2%} → {result.final_metrics['f1']:.2%} ({result.improvement['f1']:+.2%})")
        
        return result


async def main():
    """Example usage of the Rule Generation Agent."""
    agent = RuleGenerationAgent(verbose=True)
    
    # Add data sources
    agent.add_promptintel_source()
    
    # Run optimization
    result = await agent.run(
        test_dataset="common_jailbreaks",
        output_file="agent_optimized.nov",
        target_precision=0.95,
        target_recall=0.90,
        max_iterations=3,
    )
    
    print(f"\nFinal F1: {result.final_metrics['f1']:.2%}")


if __name__ == "__main__":
    asyncio.run(main())


def generate_simple_rules(indicators: list, rule_prefix: str = "Feed") -> str:
    """
    Generate Nova rules from IoPC indicators using simple keyword extraction.
    
    This is the non-AI version for basic rule generation.
    
    Args:
        indicators: List of IoPC indicators
        rule_prefix: Prefix for rule names
        
    Returns:
        Nova rule text
    """
    # Group by category
    by_category: dict[str, list] = {}
    for iopc in indicators:
        cat = getattr(iopc, 'category', None) or "unknown"
        cat = re.sub(r'[^a-zA-Z0-9]', '_', cat).title()
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append(iopc)
    
    rules = []
    
    for category, items in by_category.items():
        # Extract unique patterns/keywords from prompts
        keywords = []
        seen_patterns = set()
        
        for item in items[:30]:  # Limit keywords per rule
            prompt = getattr(item, 'pattern', '') or getattr(item, 'prompt', '')
            if not prompt:
                continue
            
            # Extract short key phrases (under 60 chars) - look for quoted strings
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
        severities = [getattr(i, 'risk_score', 'medium').lower() for i in items if getattr(i, 'risk_score', None)]
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
