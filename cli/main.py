"""Creatine CLI - Command-line interface for prompt security detection."""

import asyncio
import argparse
import os
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv

load_dotenv()


def get_registry():
    """Get dataset registry."""
    from testing import DatasetRegistry
    return DatasetRegistry(Path(__file__).parent.parent / "datasets")


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


def cmd_test(args):
    """Run tests on a dataset."""
    from creatine import ThreatDetector
    from testing import TestHarness, print_progress
    
    registry = get_registry()
    
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


def cmd_list(args):
    """List available datasets."""
    from testing import DatasetRegistry
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


def main():
    parser = argparse.ArgumentParser(
        description="Creatine - Prompt Security Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Quick single-prompt analysis")
    analyze_parser.add_argument("prompt", help="Prompt to analyze")
    analyze_parser.add_argument("-v", "--verbose", action="store_true")
    
    # adaptive command
    adaptive_parser = subparsers.add_parser("adaptive", help="Adaptive tiered detection")
    adaptive_parser.add_argument("--prompt", help="Single prompt to analyze")
    adaptive_parser.add_argument("--dataset", help="Dataset to analyze")
    adaptive_parser.add_argument("--confidence-threshold", type=float, default=0.85)
    adaptive_parser.add_argument("--time-budget", type=float, default=10000)
    adaptive_parser.add_argument("--force-full", action="store_true")
    adaptive_parser.add_argument("-q", "--quiet", action="store_true")
    adaptive_parser.add_argument("-v", "--verbose", action="store_true")
    
    # test command
    test_parser = subparsers.add_parser("test", help="Run tests on a dataset")
    test_parser.add_argument("name", help="Dataset name (or 'all')")
    test_parser.add_argument("-c", "--concurrency", type=int, default=5)
    test_parser.add_argument("-q", "--quiet", action="store_true")
    test_parser.add_argument("-s", "--save", action="store_true")
    test_parser.add_argument("-v", "--verbose", action="store_true")
    test_parser.add_argument("--default-only", action="store_true")
    test_parser.add_argument("--enable-llm", action="store_true")
    test_parser.add_argument("--enable-semantics", action="store_true")
    
    # list command
    subparsers.add_parser("list", help="List datasets")
    
    # info command
    info_parser = subparsers.add_parser("info", help="Show dataset info")
    info_parser.add_argument("name", help="Dataset name")
    
    # sample command
    sample_parser = subparsers.add_parser("sample", help="Show sample prompts")
    sample_parser.add_argument("name", help="Dataset name")
    sample_parser.add_argument("-n", "--count", type=int, default=5)
    
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
    }
    
    cmd_func = commands.get(args.command)
    if cmd_func:
        cmd_func(args)


if __name__ == "__main__":
    main()
