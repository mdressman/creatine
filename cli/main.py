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
# Analysis Commands
# =============================================================================

def cmd_analyze(args):
    """Quick single-prompt analysis."""
    from creatine import AdaptiveDetector
    
    async def run():
        detector = AdaptiveDetector(verbose=args.verbose)
        result = await detector.analyze(args.prompt)
        
        status = "🚨 THREAT" if result.is_threat else "✅ SAFE"
        print(f"{status} | {result.risk_score} | {result.confidence:.0%} confidence | {result.tier_used.name} | {result.total_time_ms:.0f}ms")
        
        if result.attack_types:
            print(f"   Attack types: {', '.join(result.attack_types)}")
    
    asyncio.run(run())


def cmd_adaptive(args):
    """Run adaptive tiered detection."""
    from creatine import AdaptiveDetector, AdaptiveConfig
    
    config = AdaptiveConfig(
        high_confidence_threshold=args.confidence_threshold,
        max_time_budget_ms=args.time_budget,
        force_full_analysis=args.force_full,
    )
    
    async def run():
        detector = AdaptiveDetector(config=config, verbose=args.verbose)
        registry = get_registry()
        
        if args.prompt:
            result = await detector.analyze(args.prompt)
            
            print(f"\n{'='*60}")
            print(f"{'🚨 THREAT DETECTED' if result.is_threat else '✅ CLEAN'}")
            print(f"{'='*60}")
            print(f"Confidence: {result.confidence:.1%}")
            print(f"Risk Score: {result.risk_score}")
            print(f"Tier Used: {result.tier_used.name}")
            print(f"Total Time: {result.total_time_ms:.1f}ms")
            print(f"Cost Saved: {result.cost_saved}")
            
            if result.attack_types:
                print(f"Attack Types: {', '.join(result.attack_types)}")
                
        elif args.dataset:
            dataset = registry.get(args.dataset)
            if not dataset:
                print(f"Dataset not found: {args.dataset}")
                return
            
            print(f"Adaptive Detection: {args.dataset} ({len(dataset)} prompts)")
            
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
        else:
            print("Error: Provide --prompt or --dataset")
    
    asyncio.run(run())


# =============================================================================
# Test Commands
# =============================================================================

def cmd_test(args):
    """Run tests on a dataset."""
    from creatine import ThreatDetector
    from testing import TestHarness, print_progress
    
    registry = get_registry()
    
    if args.compare:
        asyncio.run(run_comparison_test(args, registry))
        return
    
    enable_llm = getattr(args, 'enable_llm', False)
    enable_semantics = getattr(args, 'enable_semantics', False) or enable_llm
    
    detector = ThreatDetector(
        verbose=args.verbose,
        include_feed_rules=not args.default_only,
        enable_llm=enable_llm,
        enable_semantics=enable_semantics,
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
            
            print(f"Testing {len(dataset)} prompts from '{args.name}'...")
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
    """Run tests with all evaluation modes and compare."""
    from creatine import ThreatDetector
    from testing import TestHarness, print_progress
    
    dataset = registry.get(args.name)
    if not dataset:
        print(f"Dataset not found: {args.name}")
        return
    
    print(f"=== Evaluation Mode Comparison: {args.name} ({len(dataset)} prompts) ===\n")
    
    reports = {}
    
    # Mode 1: Keywords only
    print("[1/4] Running with KEYWORDS only...")
    detector = ThreatDetector(verbose=False, include_feed_rules=True)
    harness = TestHarness(detector, registry)
    reports['keywords'] = await harness.run_dataset(
        dataset, concurrency=args.concurrency,
        progress_callback=print_progress if not args.quiet else None,
    )
    
    # Mode 2: Keywords + Semantics
    print("\n\n[2/4] Running with KEYWORDS + SEMANTICS...")
    detector = ThreatDetector(verbose=False, include_feed_rules=True, enable_semantics=True)
    harness = TestHarness(detector, registry)
    reports['semantics'] = await harness.run_dataset(
        dataset, concurrency=args.concurrency,
        progress_callback=print_progress if not args.quiet else None,
    )
    
    # Mode 3: Keywords + Semantics + LLM
    print("\n\n[3/4] Running with KEYWORDS + SEMANTICS + LLM...")
    detector = ThreatDetector(verbose=False, include_feed_rules=True, enable_semantics=True, enable_llm=True)
    harness = TestHarness(detector, registry)
    reports['llm'] = await harness.run_dataset(
        dataset, concurrency=args.concurrency,
        progress_callback=print_progress if not args.quiet else None,
    )
    
    # Mode 4: Default rules only (baseline)
    print("\n\n[4/4] Running with DEFAULT rules only (baseline)...")
    detector = ThreatDetector(verbose=False, include_feed_rules=False)
    harness = TestHarness(detector, registry)
    reports['baseline'] = await harness.run_dataset(
        dataset, concurrency=args.concurrency,
        progress_callback=print_progress if not args.quiet else None,
    )
    
    # Print comparison table
    print("\n\n")
    print("=" * 95)
    print("                              EVALUATION MODE COMPARISON")
    print("=" * 95)
    print(f"{'Metric':<20} {'Baseline':>14} {'Keywords':>14} {'+ Semantics':>14} {'+ LLM':>14} {'Improvement':>12}")
    print("-" * 95)
    
    r = reports
    for name, attr in [("Accuracy", 'accuracy'), ("Precision", 'precision'), ("Recall", 'recall'), ("F1 Score", 'f1_score')]:
        baseline = getattr(r['baseline'], attr)
        kw = getattr(r['keywords'], attr)
        sem = getattr(r['semantics'], attr)
        llm = getattr(r['llm'], attr)
        improvement = llm - baseline
        arrow = "↑" if improvement > 0 else ("↓" if improvement < 0 else "→")
        print(f"{name:<20} {baseline:>13.2%} {kw:>13.2%} {sem:>13.2%} {llm:>13.2%} {arrow} {improvement:>+10.2%}")
    
    print("-" * 95)
    print(f"{'Avg Time (ms)':<20} {r['baseline'].avg_response_time_ms:>14.1f} {r['keywords'].avg_response_time_ms:>14.1f} {r['semantics'].avg_response_time_ms:>14.1f} {r['llm'].avg_response_time_ms:>14.1f}")
    print("=" * 95)


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


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Creatine - Prompt Security Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # analyze
    p = subparsers.add_parser("analyze", help="Quick single-prompt analysis")
    p.add_argument("prompt", help="Prompt to analyze")
    p.add_argument("-v", "--verbose", action="store_true")
    
    # adaptive
    p = subparsers.add_parser("adaptive", help="Adaptive tiered detection")
    p.add_argument("--prompt", help="Single prompt")
    p.add_argument("--dataset", help="Dataset name")
    p.add_argument("--confidence-threshold", type=float, default=0.85)
    p.add_argument("--time-budget", type=float, default=10000)
    p.add_argument("--force-full", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    
    # test
    p = subparsers.add_parser("test", help="Run tests on a dataset")
    p.add_argument("name", help="Dataset name (or 'all')")
    p.add_argument("-c", "--concurrency", type=int, default=5)
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("-s", "--save", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--default-only", action="store_true")
    p.add_argument("--compare", action="store_true", help="Compare all evaluation modes")
    p.add_argument("--enable-llm", action="store_true")
    p.add_argument("--enable-semantics", action="store_true")
    
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
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    commands = {
        "analyze": cmd_analyze,
        "adaptive": cmd_adaptive,
        "test": cmd_test,
        "list": cmd_list,
        "info": cmd_info,
        "sample": cmd_sample,
        "import-hf": cmd_import_hf,
        "import-csv": cmd_import_csv,
        "generate-rules": cmd_generate_rules,
        "sync-feed": cmd_sync_feed,
    }
    
    cmd_func = commands.get(args.command)
    if cmd_func:
        cmd_func(args)


if __name__ == "__main__":
    main()

