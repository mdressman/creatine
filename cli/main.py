"""Creatine CLI - Command-line interface for prompt security detection."""

import asyncio
import argparse
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


def get_registry():
    """Get dataset registry."""
    from testing import DatasetRegistry
    return DatasetRegistry(Path(__file__).parent.parent / "datasets")


# =============================================================================
# Detection Commands
# =============================================================================

def cmd_detect(args):
    """Run detection on a prompt."""
    from creatine import AdaptiveDetector, ThreatDetector, AdaptiveConfig
    
    async def run():
        if args.mode == "adaptive":
            # Adaptive mode - escalates through tiers as needed
            config = AdaptiveConfig(
                high_confidence_threshold=args.confidence_threshold or 0.85,
            )
            detector = AdaptiveDetector(config=config, verbose=args.verbose)
            result = await detector.analyze(args.prompt)
            
            status = "🚨 THREAT" if result.is_threat else "✅ SAFE"
            print(f"{status} | {result.risk_score} | {result.confidence:.0%} confidence | Tier: {result.tier_used.name} | {result.total_time_ms:.0f}ms")
            
            if result.attack_types:
                print(f"   Attack types: {', '.join(result.attack_types)}")
            if args.verbose:
                print(f"   Cost saved: {result.cost_saved}")
        else:
            # Full mode - runs all three tiers
            detector = ThreatDetector(
                verbose=args.verbose,
                enable_semantics=True,
                enable_llm=True,
            )
            result = await detector.analyze(args.prompt)
            
            status = "🚨 THREAT" if result.is_threat else "✅ SAFE"
            print(f"{status} | {result.risk_score} | {result.confidence:.0%} confidence | {result.response_time_ms:.0f}ms")
            
            if result.attack_types:
                print(f"   Attack types: {', '.join(result.attack_types)}")
    
    asyncio.run(run())


def cmd_detect_pipeline(args):
    """Run detection pipeline (detect → forensics if threat)."""
    from agents import create_detection_pipeline
    
    async def run():
        pipeline = create_detection_pipeline(include_forensics=True)
        
        print(f"Running detection pipeline...")
        print(f"Prompt: {args.prompt[:60]}{'...' if len(args.prompt) > 60 else ''}")
        print()
        
        result = await pipeline.run(args.prompt)
        
        # Display detection result
        final = result.final_result
        if final:
            is_threat = final.get("is_threat", False) if isinstance(final, dict) else getattr(final, 'is_threat', False)
            status = "🚨 THREAT" if is_threat else "✅ SAFE"
            risk = final.get("risk_score", "Unknown") if isinstance(final, dict) else getattr(final, 'risk_score', 'Unknown')
            tier = final.get("tier_used", "Unknown") if isinstance(final, dict) else getattr(final, 'tier_used', 'Unknown')
            print(f"{status} | Risk: {risk} | Tier: {tier}")
        
        # Check for forensics errors
        metadata = result.metadata if hasattr(result, 'metadata') else {}
        stage_errors = metadata.get("stage_errors", {}) if metadata else {}
        if "forensics" in stage_errors:
            error = str(stage_errors["forensics"])
            if "content_filter" in error.lower() or "content management policy" in error.lower():
                print(f"\nℹ Forensics blocked by Azure Content Safety")
            else:
                print(f"\nForensics error: {error[:80]}...")
        
        print(f"\nPipeline: {' → '.join(result.execution_path)}")
        print(f"Total time: {result.total_time_ms:.0f}ms")
    
    try:
        asyncio.run(run())
    except Exception as e:
        print(f"Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()


def cmd_detect_ensemble(args):
    """Run ensemble detection (parallel voting across multiple LLM models)."""
    from agents import create_ensemble_detector
    
    async def run():
        ensemble = create_ensemble_detector()
        
        model_names = [a.name for a in ensemble.agents]
        print(f"Running ensemble detection with {len(model_names)} model(s)...")
        print(f"Models: {', '.join(model_names)}")
        print(f"Prompt: {args.prompt[:60]}{'...' if len(args.prompt) > 60 else ''}")
        print()
        
        result = await ensemble.run(args.prompt)
        
        final = result.final_result
        if final:
            is_threat = final.get("is_threat", False) if isinstance(final, dict) else False
            votes = final.get("votes", {}) if isinstance(final, dict) else {}
            confidence = final.get("confidence", 0) if isinstance(final, dict) else 0
            status = "🚨 THREAT" if is_threat else "✅ SAFE"
            print(f"{status}")
            if votes:
                print(f"Votes: {votes} ({confidence:.0%} consensus)")
        
        print(f"\nTotal time: {result.total_time_ms:.0f}ms (parallel execution)")
    
    try:
        asyncio.run(run())
    except Exception as e:
        print(f"Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()


# =============================================================================
# Test Commands
# =============================================================================

def cmd_test(args):
    """Run tests on a dataset."""
    from creatine import ThreatDetector, AdaptiveDetector
    from testing import TestHarness, print_progress
    
    registry = get_registry()
    
    if args.compare:
        asyncio.run(run_comparison_test(args, registry))
        return
    
    if args.mode == "adaptive":
        # Use adaptive detector for testing
        async def run_adaptive():
            from creatine import AdaptiveDetector
            detector = AdaptiveDetector(verbose=args.verbose)
            
            dataset = registry.get(args.name)
            if not dataset:
                print(f"Dataset not found: {args.name}")
                return
            
            print(f"Testing {len(dataset)} prompts with Adaptive detection...")
            
            correct = 0
            tier_counts = {1: 0, 2: 0, 3: 0}
            total_time = 0
            
            for i, prompt in enumerate(dataset.prompts):
                result = await detector.analyze(prompt.prompt)
                
                is_correct = (result.is_threat == prompt.is_malicious)
                if is_correct:
                    correct += 1
                
                tier_counts[result.tier_used.value] += 1
                total_time += result.total_time_ms
                
                if not args.quiet and (i + 1) % 10 == 0:
                    pct = (i + 1) / len(dataset) * 100
                    print(f"  Progress: {i+1}/{len(dataset)} ({pct:.0f}%)", end="\r")
            
            print()
            stats = detector.get_stats()
            accuracy = correct / len(dataset)
            
            print(f"\n{'='*60}")
            print(f"ADAPTIVE DETECTION RESULTS")
            print(f"{'='*60}")
            print(f"Accuracy: {accuracy:.1%} ({correct}/{len(dataset)})")
            print(f"Total Time: {total_time:.1f}ms")
            print(f"Avg Time: {stats['avg_time_ms']:.1f}ms per prompt")
            print()
            print(f"Tier Distribution:")
            print(f"  Tier 1 (Keywords):  {tier_counts[1]:3d} ({stats['tier1_stop_rate']:.1%})")
            print(f"  Tier 2 (Semantics): {tier_counts[2]:3d} ({stats['tier2_stop_rate']:.1%})")
            print(f"  Tier 3 (LLM):       {tier_counts[3]:3d} ({stats['tier3_stop_rate']:.1%})")
            print(f"{'='*60}")
        
        asyncio.run(run_adaptive())
        return
    
    # Full mode - use ThreatDetector with all tiers
    detector = ThreatDetector(
        verbose=args.verbose,
        include_feed_rules=not args.default_only,
        enable_llm=True,
        enable_semantics=True,
    )
    
    harness = TestHarness(detector, registry)
    
    async def run():
        if args.name == "all":
            reports = await harness.run_all(
                concurrency=args.concurrency,
                progress_callback=print_progress if not args.quiet else None,
                verbose=args.verbose,
            )
            print("\n")
            for name, report in reports.items():
                print(report.summary())
        else:
            dataset = registry.get(args.name)
            if not dataset:
                print(f"Dataset not found: {args.name}")
                return
            
            print(f"Testing {len(dataset)} prompts from '{args.name}' with Full detection...")
            report = await harness.run_dataset(
                dataset,
                concurrency=args.concurrency,
                progress_callback=print_progress if not args.quiet else None,
                verbose=args.verbose,
            )
            print("\n" + report.summary())
            
            if args.save:
                path = harness.save_report(report)
                print(f"Report saved to: {path}")
    
    asyncio.run(run())


async def run_comparison_test(args, registry):
    """Compare Adaptive vs Full detection modes."""
    from creatine import ThreatDetector, AdaptiveDetector
    from testing import TestHarness, print_progress
    
    dataset = registry.get(args.name)
    if not dataset:
        print(f"Dataset not found: {args.name}")
        return
    
    print(f"=== Detection Mode Comparison: {args.name} ({len(dataset)} prompts) ===\n")
    
    # Mode 1: Adaptive
    print("[1/2] Running ADAPTIVE detection...")
    adaptive = AdaptiveDetector(verbose=False)
    adaptive_correct = 0
    adaptive_time = 0
    tier_counts = {1: 0, 2: 0, 3: 0}
    
    for i, prompt in enumerate(dataset.prompts):
        result = await adaptive.analyze(prompt.prompt)
        if result.is_threat == prompt.is_malicious:
            adaptive_correct += 1
        tier_counts[result.tier_used.value] += 1
        adaptive_time += result.total_time_ms
        if (i + 1) % 10 == 0:
            print(f"  Progress: {i+1}/{len(dataset)}", end="\r")
    
    adaptive_accuracy = adaptive_correct / len(dataset)
    adaptive_stats = adaptive.get_stats()
    
    # Mode 2: Full
    print("\n\n[2/2] Running FULL detection (all tiers)...")
    detector = ThreatDetector(verbose=False, enable_semantics=True, enable_llm=True)
    harness = TestHarness(detector, registry)
    full_report = await harness.run_dataset(
        dataset, concurrency=args.concurrency,
        progress_callback=print_progress if not args.quiet else None,
    )
    
    # Print comparison
    print("\n\n")
    print("=" * 70)
    print("                    DETECTION MODE COMPARISON")
    print("=" * 70)
    print(f"{'Metric':<25} {'Adaptive':>20} {'Full':>20}")
    print("-" * 70)
    print(f"{'Accuracy':<25} {adaptive_accuracy:>19.1%} {full_report.accuracy:>19.1%}")
    print(f"{'Total Time':<25} {adaptive_time:>17.0f}ms {full_report.total_test_time_ms:>17.0f}ms")
    print(f"{'Avg Time/Prompt':<25} {adaptive_stats['avg_time_ms']:>17.1f}ms {full_report.avg_response_time_ms:>17.1f}ms")
    print("-" * 70)
    print(f"\nAdaptive Tier Distribution:")
    print(f"  Tier 1 (Keywords):  {tier_counts[1]:3d} ({adaptive_stats['tier1_stop_rate']:.1%})")
    print(f"  Tier 2 (Semantics): {tier_counts[2]:3d} ({adaptive_stats['tier2_stop_rate']:.1%})")
    print(f"  Tier 3 (LLM):       {tier_counts[3]:3d} ({adaptive_stats['tier3_stop_rate']:.1%})")
    print("=" * 70)


# =============================================================================
# Dataset Commands
# =============================================================================

def cmd_list(args):
    """List available datasets."""
    registry = get_registry()
    datasets = registry.list_datasets()
    
    if not datasets:
        print("No datasets found.")
        return
    
    print("Available datasets:")
    for name in datasets:
        dataset = registry.get(name)
        if dataset:
            malicious = len([p for p in dataset.prompts if p.is_malicious])
            benign = len(dataset) - malicious
            print(f"  • {name}: {len(dataset)} prompts ({malicious} malicious, {benign} benign)")


def cmd_info(args):
    """Show dataset info."""
    registry = get_registry()
    dataset = registry.get(args.name)
    
    if not dataset:
        print(f"Dataset not found: {args.name}")
        return
    
    print(f"Dataset: {dataset.name}")
    print(f"Description: {dataset.description}")
    print(f"Total prompts: {len(dataset)}")
    
    malicious = len([p for p in dataset.prompts if p.is_malicious])
    print(f"Malicious: {malicious}, Benign: {len(dataset) - malicious}")


def cmd_sample(args):
    """Show sample prompts."""
    registry = get_registry()
    dataset = registry.get(args.name)
    
    if not dataset:
        print(f"Dataset not found: {args.name}")
        return
    
    samples = dataset.sample(args.count)
    for i, prompt in enumerate(samples, 1):
        status = "🔴 Malicious" if prompt.is_malicious else "🟢 Benign"
        print(f"\n[{i}] {status}")
        print(f"    {prompt.prompt[:200]}{'...' if len(prompt.prompt) > 200 else ''}")


def cmd_import_hf(args):
    """Import dataset from HuggingFace."""
    from testing import load_from_huggingface
    
    registry = get_registry()
    print(f"Importing from HuggingFace: {args.dataset}")
    
    try:
        dataset = load_from_huggingface(
            args.dataset,
            split=args.split,
            prompt_field=args.prompt_field,
            label_field=args.label_field,
        )
        registry.save_dataset(dataset)
        print(f"✓ Imported {len(dataset)} prompts as '{dataset.name}'")
    except Exception as e:
        print(f"Error: {e}")


def cmd_import_csv(args):
    """Import dataset from CSV."""
    from testing import load_from_csv
    
    registry = get_registry()
    path = Path(args.file)
    
    if not path.exists():
        print(f"File not found: {path}")
        return
    
    dataset = load_from_csv(path, args.prompt_col, args.label_col)
    registry.save_dataset(dataset)
    print(f"✓ Imported {len(dataset)} prompts as '{dataset.name}'")


# =============================================================================
# Rule Commands
# =============================================================================

def cmd_generate_rules(args):
    """Generate optimized Nova rules using AI."""
    from agents import RuleGenerationAgent
    
    async def run():
        agent = RuleGenerationAgent(verbose=args.verbose)
        
        if not args.no_promptintel:
            agent.add_promptintel_source()
        
        if args.add_huggingface:
            for dataset in args.add_huggingface:
                agent.add_huggingface_source(dataset)
        
        result = await agent.run(
            test_dataset=args.test_dataset,
            output_file=args.output,
            target_precision=args.target_precision,
            target_recall=args.target_recall,
            max_iterations=args.max_iterations,
        )
        
        print(f"\n✓ Rule generation complete!")
        print(f"  Output: rules/{args.output}")
        print(f"  Final F1: {result.final_metrics['f1']:.2%}")
    
    try:
        asyncio.run(run())
    except Exception as e:
        print(f"Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()


def cmd_sync_feed(args):
    """Sync rules from PromptIntel feed."""
    from creatine import PromptIntelFeedClient
    from creatine.detector import FEED_RULES_PATH
    
    api_key = args.api_key or os.getenv("PROMPTINTEL_API_KEY")
    if not api_key:
        print("Error: PROMPTINTEL_API_KEY not set")
        return
    
    output_path = Path(args.output) if args.output else FEED_RULES_PATH
    
    try:
        if args.smart:
            from agents import RuleGenerationAgent
            
            print("Using AI-powered rule generation...")
            agent = RuleGenerationAgent(verbose=args.verbose)
            agent.add_promptintel_source()
            
            result = asyncio.run(agent.run(
                test_dataset=None,
                output_file=output_path.name,
                max_iterations=1,
            ))
            
            if result and result.output_file:
                print(f"✓ Feed rules synced to: rules/{result.output_file}")
        else:
            from agents.rule_generator import generate_simple_rules
            
            print("Fetching IoPC feed...")
            with PromptIntelFeedClient(api_key, verbose=args.verbose) as client:
                indicators = client.fetch_all()
                
                if not indicators:
                    print("No indicators found")
                    return
                
                rules = generate_simple_rules(indicators)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(rules)
                
                print(f"✓ Synced {len(indicators)} indicators to {output_path}")
                
    except Exception as e:
        print(f"Error: {e}")


def cmd_forensics(args):
    """Run forensic analysis on a prompt."""
    from agents import ForensicsAgent
    
    async def run():
        agent = ForensicsAgent(verbose=args.verbose)
        
        if args.full:
            # Run detection + forensics
            report = await agent.analyze_with_detection(args.prompt)
        else:
            # Just forensics
            report = await agent.analyze(args.prompt)
        
        print(report.summary())
        
        if args.json:
            import json
            print(f"\n{'='*60}")
            print("Raw Analysis (JSON):")
            print(json.dumps(report.raw_analysis, indent=2))
    
    try:
        asyncio.run(run())
    except Exception as e:
        error_str = str(e)
        if "content_filter" in error_str.lower() or "content management policy" in error_str.lower():
            print(f"ℹ Forensics blocked by Azure Content Safety (attack content triggered filter)")
        else:
            print(f"Error: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()


def cmd_learn(args):
    """Learn from production logs to improve detection rules."""
    from agents.learning import LearningPipeline
    
    async def run():
        pipeline = LearningPipeline(
            min_cluster_size=args.min_cluster,
            similarity_threshold=args.similarity,
            min_precision=args.min_precision,
            verbose=not args.quiet,
        )
        
        if args.feedback:
            # Learn from user feedback
            result = await pipeline.learn_from_feedback(
                args.logs,
                output_file=args.output,
            )
        else:
            # Learn from production logs
            result = await pipeline.learn_from_logs(
                args.logs,
                validation_file=args.validation,
                output_file=args.output,
            )
        
        print(f"\n{'='*60}")
        print("LEARNING SUMMARY")
        print(f"{'='*60}")
        print(f"Logs processed: {result.logs_processed}")
        print(f"Gaps identified: {result.gaps_identified}")
        print(f"Clusters found: {result.clusters_found}")
        print(f"Rules generated: {len(result.new_rules)}")
        print(f"Rules promoted: {result.rules_promoted}")
        
        if result.output_file:
            print(f"\n✓ Rules saved to: {result.output_file}")
    
    try:
        asyncio.run(run())
    except Exception as e:
        print(f"Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Creatine - Prompt Security Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  creatine detect "test prompt"              # Adaptive detection (default)
  creatine detect "test prompt" --full       # Full detection (all tiers)
  creatine detect-pipeline "test prompt"     # Detection + forensics pipeline
  creatine detect-ensemble "test prompt"     # Parallel voting ensemble
  creatine test common_jailbreaks            # Test against dataset
  creatine forensics "suspicious prompt"     # Deep forensic analysis
""",
    )
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # detect (main command)
    p = subparsers.add_parser("detect", help="Analyze a prompt for threats")
    p.add_argument("prompt", help="Prompt to analyze")
    p.add_argument("--full", action="store_true", dest="full_mode",
                   help="Run all detection tiers (default: adaptive)")
    p.add_argument("--confidence-threshold", type=float, 
                   help="Confidence threshold for adaptive mode (default: 0.85)")
    p.add_argument("-v", "--verbose", action="store_true")
    
    # detect-pipeline
    p = subparsers.add_parser("detect-pipeline", help="Detection pipeline (detect → forensics)")
    p.add_argument("prompt", help="Prompt to analyze")
    p.add_argument("-v", "--verbose", action="store_true")
    
    # detect-ensemble
    p = subparsers.add_parser("detect-ensemble", help="Ensemble detection (parallel voting)")
    p.add_argument("prompt", help="Prompt to analyze")
    p.add_argument("-v", "--verbose", action="store_true")
    
    # test
    p = subparsers.add_parser("test", help="Run tests on a dataset")
    p.add_argument("name", help="Dataset name (or 'all')")
    p.add_argument("--adaptive", action="store_true", help="Use adaptive detection")
    p.add_argument("-c", "--concurrency", type=int, default=5)
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("-s", "--save", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--default-only", action="store_true")
    p.add_argument("--compare", action="store_true", help="Compare Adaptive vs Full modes")
    
    # list
    subparsers.add_parser("list", help="List datasets")
    
    # info
    p = subparsers.add_parser("info", help="Show dataset info")
    p.add_argument("name", help="Dataset name")
    
    # sample
    p = subparsers.add_parser("sample", help="Show sample prompts")
    p.add_argument("name", help="Dataset name")
    p.add_argument("-n", "--count", type=int, default=5)
    
    # import-hf
    p = subparsers.add_parser("import-hf", help="Import from HuggingFace")
    p.add_argument("dataset", help="HuggingFace dataset name")
    p.add_argument("--split", default="train")
    p.add_argument("--prompt-field", default="prompt")
    p.add_argument("--label-field", default="label")
    
    # import-csv
    p = subparsers.add_parser("import-csv", help="Import from CSV")
    p.add_argument("file", help="CSV file path")
    p.add_argument("--prompt-col", default="prompt")
    p.add_argument("--label-col", default="label")
    
    # generate-rules
    p = subparsers.add_parser("generate-rules", help="Generate rules with AI")
    p.add_argument("--test-dataset", required=True)
    p.add_argument("--output", default="agent_optimized.nov")
    p.add_argument("--target-precision", type=float, default=0.90)
    p.add_argument("--target-recall", type=float, default=0.80)
    p.add_argument("--max-iterations", type=int, default=5)
    p.add_argument("--no-promptintel", action="store_true")
    p.add_argument("--add-huggingface", action="append", metavar="DATASET")
    p.add_argument("-v", "--verbose", action="store_true")
    
    # sync-feed
    p = subparsers.add_parser("sync-feed", help="Sync rules from PromptIntel")
    p.add_argument("--api-key")
    p.add_argument("-o", "--output")
    p.add_argument("--smart", action="store_true", help="Use AI for rule generation")
    p.add_argument("-v", "--verbose", action="store_true")
    
    # forensics
    p = subparsers.add_parser("forensics", help="Deep forensic analysis of a prompt")
    p.add_argument("prompt", help="Prompt to analyze")
    p.add_argument("--full", action="store_true", help="Run detection first, then forensics")
    p.add_argument("--json", action="store_true", help="Output raw JSON analysis")
    p.add_argument("-v", "--verbose", action="store_true")
    
    # learn
    p = subparsers.add_parser("learn", help="Learn from production logs to improve rules")
    p.add_argument("logs", help="Path to JSONL file with production logs")
    p.add_argument("-o", "--output", default="learned_rules.nov", help="Output rule file")
    p.add_argument("--validation", help="Dataset name for rule validation")
    p.add_argument("--feedback", action="store_true", help="Learn from user feedback (FP/FN)")
    p.add_argument("--min-cluster", type=int, default=3, help="Min samples to form cluster")
    p.add_argument("--similarity", type=float, default=0.75, help="Similarity threshold for clustering")
    p.add_argument("--min-precision", type=float, default=0.9, help="Min precision for rule promotion")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Handle detect mode flag
    if args.command == "detect":
        args.mode = "full" if args.full_mode else "adaptive"
    elif args.command == "test":
        args.mode = "adaptive" if args.adaptive else "full"
    
    commands = {
        "detect": cmd_detect,
        "detect-pipeline": cmd_detect_pipeline,
        "detect-ensemble": cmd_detect_ensemble,
        "test": cmd_test,
        "list": cmd_list,
        "info": cmd_info,
        "sample": cmd_sample,
        "import-hf": cmd_import_hf,
        "import-csv": cmd_import_csv,
        "generate-rules": cmd_generate_rules,
        "sync-feed": cmd_sync_feed,
        "forensics": cmd_forensics,
        "learn": cmd_learn,
    }
    
    cmd_func = commands.get(args.command)
    if cmd_func:
        cmd_func(args)


if __name__ == "__main__":
    main()
