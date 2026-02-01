"""CLI for managing datasets and running security tests."""

import asyncio
import argparse
import os
from pathlib import Path

from dotenv import load_dotenv

from dataset import (
    Dataset, DatasetRegistry, TestPrompt, AttackType, Severity,
    load_from_csv, load_from_huggingface
)
from test_harness import TestHarness, print_progress
from promptintel import PromptIntelClient, PromptIntelFeedClient, FEED_RULES_PATH

load_dotenv()


def cmd_list(args, registry: DatasetRegistry):
    """List available datasets."""
    datasets = registry.list_datasets()
    if not datasets:
        print("No datasets found. Add datasets to the 'datasets/' directory.")
        return
    
    print("Available datasets:")
    for name in datasets:
        dataset = registry.get(name)
        if dataset:
            malicious = len([p for p in dataset.prompts if p.is_malicious])
            benign = len(dataset) - malicious
            print(f"  • {name}: {len(dataset)} prompts ({malicious} malicious, {benign} benign)")


def cmd_info(args, registry: DatasetRegistry):
    """Show detailed info about a dataset."""
    dataset = registry.get(args.name)
    if not dataset:
        print(f"Dataset not found: {args.name}")
        return
    
    print(f"Dataset: {dataset.name}")
    print(f"Description: {dataset.description}")
    print(f"Version: {dataset.version}")
    print(f"Source: {dataset.source_url or 'N/A'}")
    print(f"Total prompts: {len(dataset)}")
    print()
    
    # Attack type breakdown
    print("Attack types:")
    for attack_type in AttackType:
        count = len(dataset.filter_by_type(attack_type))
        if count > 0:
            print(f"  {attack_type.value}: {count}")
    
    # Severity breakdown
    print("\nSeverity levels:")
    for severity in Severity:
        count = len(dataset.filter_by_severity(severity))
        if count > 0:
            print(f"  {severity.value}: {count}")


def cmd_sample(args, registry: DatasetRegistry):
    """Show sample prompts from a dataset."""
    dataset = registry.get(args.name)
    if not dataset:
        print(f"Dataset not found: {args.name}")
        return
    
    samples = dataset.sample(args.count)
    for i, prompt in enumerate(samples, 1):
        status = "🔴 Malicious" if prompt.is_malicious else "🟢 Benign"
        print(f"\n[{i}] {status} ({prompt.attack_type.value}, {prompt.severity.value})")
        print(f"    {prompt.prompt[:200]}{'...' if len(prompt.prompt) > 200 else ''}")


def cmd_import_hf(args, registry: DatasetRegistry):
    """Import a dataset from HuggingFace."""
    print(f"Importing from HuggingFace: {args.dataset}")
    try:
        dataset = load_from_huggingface(
            args.dataset,
            split=args.split,
            prompt_field=args.prompt_field,
            label_field=args.label_field,
        )
        registry.save_dataset(dataset)
        print(f"Imported {len(dataset)} prompts as '{dataset.name}'")
    except Exception as e:
        print(f"Error importing: {e}")


def cmd_import_csv(args, registry: DatasetRegistry):
    """Import a dataset from CSV."""
    path = Path(args.file)
    if not path.exists():
        print(f"File not found: {path}")
        return
    
    dataset = load_from_csv(path, args.prompt_col, args.label_col)
    registry.save_dataset(dataset)
    print(f"Imported {len(dataset)} prompts as '{dataset.name}'")


async def cmd_test(args, registry: DatasetRegistry):
    """Run tests on a dataset."""
    api_key = os.getenv("PROMPTINTEL_API_KEY")
    if not api_key:
        print("Warning: PROMPTINTEL_API_KEY not set. API calls may fail.")
    
    # Determine which rule sets to use
    include_feed = not args.default_only
    
    if args.compare:
        # Run comparison mode - test with both rule sets
        await run_comparison_test(args, registry, api_key)
        return
    
    # Check for advanced evaluation modes
    # --enable-llm implies --enable-semantics for full evaluation
    enable_llm = getattr(args, 'enable_llm', False)
    enable_semantics = getattr(args, 'enable_semantics', False) or enable_llm
    
    client = PromptIntelClient(
        api_key or "", 
        verbose=args.verbose,
        include_feed_rules=include_feed,
        enable_llm=enable_llm,
        enable_semantics=enable_semantics,
    )
    
    rules_desc = "default + feed" if include_feed else "default only"
    if enable_llm:
        rules_desc += " + LLM + semantic"
    elif enable_semantics:
        rules_desc += " + semantic"
    print(f"Using rules: {rules_desc} ({client.rules_info})")
    
    harness = TestHarness(client, registry)
    
    try:
        if args.name == "all":
            reports = await harness.run_all(
                concurrency=args.concurrency,
                progress_callback=print_progress if not args.quiet and not args.verbose else None,
                verbose=args.verbose,
            )
            print("\n")
            for name, report in reports.items():
                print(report.summary())
                if args.save:
                    path = harness.save_report(report)
                    print(f"Saved to: {path}")
        else:
            dataset = registry.get(args.name)
            if not dataset:
                print(f"Dataset not found: {args.name}")
                return
            
            print(f"Testing {len(dataset)} prompts from '{args.name}'...")
            report = await harness.run_dataset(
                dataset,
                concurrency=args.concurrency,
                progress_callback=print_progress if not args.quiet and not args.verbose else None,
                verbose=args.verbose,
            )
            print("\n" + report.summary())
            
            if args.save:
                suffix = "_default_only" if args.default_only else ""
                path = harness.save_report(report, suffix=suffix)
                print(f"Report saved to: {path}")
    finally:
        await client.close()


async def run_comparison_test(args, registry: DatasetRegistry, api_key: str):
    """Run tests with all evaluation modes and compare results."""
    dataset = registry.get(args.name)
    if not dataset:
        print(f"Dataset not found: {args.name}")
        return
    
    print(f"=== Evaluation Mode Comparison: {args.name} ({len(dataset)} prompts) ===\n")
    
    reports = {}
    
    # Mode 1: Keywords only (fastest)
    print("[1/4] Running with KEYWORDS only...")
    client = PromptIntelClient(api_key or "", verbose=False, include_feed_rules=True)
    harness = TestHarness(client, registry)
    reports['keywords'] = await harness.run_dataset(
        dataset, concurrency=args.concurrency,
        progress_callback=print_progress if not args.quiet else None,
    )
    await client.close()
    
    # Mode 2: Keywords + Semantics
    print("\n\n[2/4] Running with KEYWORDS + SEMANTICS...")
    client = PromptIntelClient(api_key or "", verbose=False, include_feed_rules=True, enable_semantics=True)
    harness = TestHarness(client, registry)
    reports['semantics'] = await harness.run_dataset(
        dataset, concurrency=args.concurrency,
        progress_callback=print_progress if not args.quiet else None,
    )
    await client.close()
    
    # Mode 3: Keywords + Semantics + LLM (most accurate)
    print("\n\n[3/4] Running with KEYWORDS + SEMANTICS + LLM...")
    client = PromptIntelClient(api_key or "", verbose=False, include_feed_rules=True, enable_semantics=True, enable_llm=True)
    harness = TestHarness(client, registry)
    reports['llm'] = await harness.run_dataset(
        dataset, concurrency=args.concurrency,
        progress_callback=print_progress if not args.quiet else None,
    )
    await client.close()
    
    # Mode 4: Default rules only (baseline)
    print("\n\n[4/4] Running with DEFAULT rules only (baseline)...")
    client = PromptIntelClient(api_key or "", verbose=False, include_feed_rules=False)
    harness = TestHarness(client, registry)
    reports['baseline'] = await harness.run_dataset(
        dataset, concurrency=args.concurrency,
        progress_callback=print_progress if not args.quiet else None,
    )
    await client.close()
    
    # Print comparison table
    print("\n\n")
    print("=" * 95)
    print("                              EVALUATION MODE COMPARISON")
    print("=" * 95)
    print(f"{'Metric':<20} {'Baseline':>14} {'Keywords':>14} {'+ Semantics':>14} {'+ LLM':>14} {'Improvement':>12}")
    print("-" * 95)
    
    r = reports
    metrics = [
        ("Accuracy", 'accuracy'),
        ("Precision", 'precision'),
        ("Recall", 'recall'),
        ("F1 Score", 'f1_score'),
    ]
    
    for name, attr in metrics:
        baseline = getattr(r['baseline'], attr)
        kw = getattr(r['keywords'], attr)
        sem = getattr(r['semantics'], attr)
        llm = getattr(r['llm'], attr)
        improvement = llm - baseline
        arrow = "↑" if improvement > 0 else ("↓" if improvement < 0 else "→")
        print(f"{name:<20} {baseline:>13.2%} {kw:>13.2%} {sem:>13.2%} {llm:>13.2%} {arrow} {improvement:>+10.2%}")
    
    print("-" * 95)
    print(f"{'True Positives':<20} {r['baseline'].true_positives:>14} {r['keywords'].true_positives:>14} {r['semantics'].true_positives:>14} {r['llm'].true_positives:>14} {r['llm'].true_positives - r['baseline'].true_positives:>+12}")
    print(f"{'True Negatives':<20} {r['baseline'].true_negatives:>14} {r['keywords'].true_negatives:>14} {r['semantics'].true_negatives:>14} {r['llm'].true_negatives:>14} {r['llm'].true_negatives - r['baseline'].true_negatives:>+12}")
    print(f"{'False Positives':<20} {r['baseline'].false_positives:>14} {r['keywords'].false_positives:>14} {r['semantics'].false_positives:>14} {r['llm'].false_positives:>14} {r['llm'].false_positives - r['baseline'].false_positives:>+12}")
    print(f"{'False Negatives':<20} {r['baseline'].false_negatives:>14} {r['keywords'].false_negatives:>14} {r['semantics'].false_negatives:>14} {r['llm'].false_negatives:>14} {r['llm'].false_negatives - r['baseline'].false_negatives:>+12}")
    print("-" * 95)
    print(f"{'Avg Time (ms)':<20} {r['baseline'].avg_response_time_ms:>14.1f} {r['keywords'].avg_response_time_ms:>14.1f} {r['semantics'].avg_response_time_ms:>14.1f} {r['llm'].avg_response_time_ms:>14.1f}")
    print("=" * 95)
    
    # Summary
    print("\nSummary:")
    print(f"  • Baseline (default rules only): {r['baseline'].f1_score:.1%} F1, {r['baseline'].avg_response_time_ms:.1f}ms")
    print(f"  • Keywords (+ feed rules):       {r['keywords'].f1_score:.1%} F1, {r['keywords'].avg_response_time_ms:.1f}ms")
    print(f"  • + Semantics:                   {r['semantics'].f1_score:.1%} F1, {r['semantics'].avg_response_time_ms:.1f}ms")
    print(f"  • + LLM (full):                  {r['llm'].f1_score:.1%} F1, {r['llm'].avg_response_time_ms:.1f}ms")
    
    # Save reports if requested
    if args.save:
        for mode, report in reports.items():
            path = harness.save_report(report, suffix=f"_{mode}")
            print(f"  Saved: {path}")


def cmd_add(args, registry: DatasetRegistry):
    """Add a new prompt to a dataset."""
    dataset = registry.get(args.dataset)
    if not dataset:
        # Create new dataset
        dataset = Dataset(
            name=args.dataset,
            description=f"Custom dataset: {args.dataset}",
            prompts=[],
        )
    
    prompt = TestPrompt(
        prompt=args.prompt,
        is_malicious=not args.benign,
        attack_type=AttackType(args.type) if args.type else AttackType.UNKNOWN,
        severity=Severity(args.severity) if args.severity else Severity.MEDIUM,
        description=args.description or "",
        tags=args.tags.split(",") if args.tags else [],
    )
    
    dataset.prompts.append(prompt)
    registry.save_dataset(dataset)
    print(f"Added prompt to '{args.dataset}' (total: {len(dataset)})")


def cmd_sync_feed(args):
    """Sync IoPC feed from PromptIntel and generate Nova rules."""
    api_key = args.api_key or os.getenv("PROMPTINTEL_API_KEY")
    if not api_key:
        print("Error: PROMPTINTEL_API_KEY not set. Provide via --api-key or environment variable.")
        print("Get your API key from: https://promptintel.novahunting.ai/")
        return
    
    output_path = Path(args.output) if args.output else FEED_RULES_PATH
    
    try:
        if args.smart:
            # Use Rule Generation Agent for AI-powered rule generation
            from rule_agent import RuleGenerationAgent
            
            print("Using AI-powered rule generation (requires Azure OpenAI)...")
            agent = RuleGenerationAgent(verbose=args.verbose)
            agent.add_promptintel_source()
            
            # Run without optimization (just generate from feed)
            result = asyncio.run(agent.run(
                test_dataset=None,  # No test dataset = no optimization
                output_file=output_path.name,
                max_iterations=1,
            ))
            
            if result and result.output_file:
                result_path = Path("rules") / result.output_file
                print(f"\n✓ Feed rules synced to: {result_path}")
                print(f"  Rules will be loaded automatically on next test run.")
                if args.verbose:
                    content = result_path.read_text()
                    rules_count = content.count("rule ")
                    print(f"  Generated {rules_count} rules from feed")
            else:
                print("Error: Rule generation failed")
        else:
            # Use simple keyword extraction (no AI)
            from rule_agent import generate_simple_rules
            
            if args.verbose:
                print("Fetching IoPC feed from PromptIntel...")
            
            client = PromptIntelFeedClient(api_key, verbose=args.verbose)
            try:
                indicators = client.fetch_all()
                
                if args.verbose:
                    print(f"Retrieved {len(indicators)} indicators")
                
                if not indicators:
                    raise ValueError("No indicators retrieved from feed")
                
                rules = generate_simple_rules(indicators)
                
                # Ensure directory exists
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(rules)
                
                print(f"\n✓ Feed rules synced to: {output_path}")
                print(f"  Rules will be loaded automatically on next test run.")
                
                if args.verbose:
                    rules_count = rules.count("rule ")
                    print(f"  Generated {rules_count} rules from feed")
            finally:
                client.close()
        
    except Exception as e:
        print(f"Error syncing feed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()


def cmd_feed_preview(args):
    """Preview IoPC indicators from the feed without generating rules."""
    api_key = args.api_key or os.getenv("PROMPTINTEL_API_KEY")
    if not api_key:
        print("Error: PROMPTINTEL_API_KEY not set.")
        return
    
    client = PromptIntelFeedClient(api_key, verbose=args.verbose)
    try:
        indicators, total = client.fetch_prompts(
            page=1,
            limit=args.limit,
            severity=args.severity,
            category=args.category,
        )
        
        print(f"\n=== PromptIntel Feed Preview ({len(indicators)} of {total} total) ===\n")
        
        for iopc in indicators:
            severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(
                iopc.risk_score.lower(), "⚪"
            )
            print(f"{severity_icon} [{iopc.risk_score.upper()}] {iopc.id}")
            print(f"   Category: {iopc.category}")
            if iopc.pattern:
                print(f"   Pattern: {iopc.pattern[:80]}{'...' if len(iopc.pattern) > 80 else ''}")
            if iopc.description:
                print(f"   Desc: {iopc.description[:80]}{'...' if len(iopc.description) > 80 else ''}")
            print()
            
    except Exception as e:
        print(f"Error fetching feed: {e}")
    finally:
        client.close()


async def cmd_generate_rules(args):
    """Run the Rule Generation Agent to create optimized Nova rules."""
    from rule_agent import RuleGenerationAgent
    
    try:
        agent = RuleGenerationAgent(verbose=args.verbose)
        
        # Add data sources
        if not args.no_promptintel:
            agent.add_promptintel_source()
        
        if args.add_huggingface:
            for dataset in args.add_huggingface:
                agent.add_huggingface_source(dataset)
        
        # Run optimization
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
        
    except Exception as e:
        print(f"Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()


def main():
    parser = argparse.ArgumentParser(
        description="Security Agent Test Harness",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # list command
    subparsers.add_parser("list", help="List available datasets")
    
    # info command
    info_parser = subparsers.add_parser("info", help="Show dataset details")
    info_parser.add_argument("name", help="Dataset name")
    
    # sample command
    sample_parser = subparsers.add_parser("sample", help="Show sample prompts")
    sample_parser.add_argument("name", help="Dataset name")
    sample_parser.add_argument("-n", "--count", type=int, default=5, help="Number of samples")
    
    # import-hf command
    hf_parser = subparsers.add_parser("import-hf", help="Import from HuggingFace")
    hf_parser.add_argument("dataset", help="HuggingFace dataset name (e.g., 'deepset/prompt-injections')")
    hf_parser.add_argument("--split", default="train", help="Dataset split")
    hf_parser.add_argument("--prompt-field", default="prompt", help="Field containing prompt text")
    hf_parser.add_argument("--label-field", default="label", help="Field containing label")
    
    # import-csv command
    csv_parser = subparsers.add_parser("import-csv", help="Import from CSV file")
    csv_parser.add_argument("file", help="Path to CSV file")
    csv_parser.add_argument("--prompt-col", default="prompt", help="Column with prompt text")
    csv_parser.add_argument("--label-col", default="label", help="Column with label")
    
    # test command
    test_parser = subparsers.add_parser("test", help="Run tests on a dataset")
    test_parser.add_argument("name", help="Dataset name (or 'all' for all datasets)")
    test_parser.add_argument("-c", "--concurrency", type=int, default=5, help="Concurrent requests")
    test_parser.add_argument("-q", "--quiet", action="store_true", help="Suppress progress output")
    test_parser.add_argument("-s", "--save", action="store_true", help="Save report to file")
    test_parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed API responses")
    test_parser.add_argument("--default-only", action="store_true", help="Use only default rules (no feed rules)")
    test_parser.add_argument("--compare", action="store_true", help="Compare default vs default+feed rules")
    test_parser.add_argument("--enable-llm", action="store_true", help="Enable LLM-based rule evaluation (slower, more accurate)")
    test_parser.add_argument("--enable-semantics", action="store_true", help="Enable semantic similarity matching")
    
    # add command
    add_parser = subparsers.add_parser("add", help="Add a prompt to a dataset")
    add_parser.add_argument("dataset", help="Dataset name (created if doesn't exist)")
    add_parser.add_argument("prompt", help="The prompt text")
    add_parser.add_argument("--benign", action="store_true", help="Mark as benign (default: malicious)")
    add_parser.add_argument("--type", choices=[t.value for t in AttackType], help="Attack type")
    add_parser.add_argument("--severity", choices=[s.value for s in Severity], help="Severity level")
    add_parser.add_argument("--description", help="Description of the prompt")
    add_parser.add_argument("--tags", help="Comma-separated tags")
    
    # sync-feed command
    sync_parser = subparsers.add_parser("sync-feed", help="Sync IoPC feed and generate Nova rules")
    sync_parser.add_argument("--api-key", help="PromptIntel API key (or set PROMPTINTEL_API_KEY)")
    sync_parser.add_argument("-o", "--output", help="Output path for generated rules")
    sync_parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    sync_parser.add_argument("--smart", action="store_true", help="Use AI to generate sophisticated rules (requires Azure OpenAI)")
    
    # feed-preview command
    preview_parser = subparsers.add_parser("feed-preview", help="Preview IoPC indicators from feed")
    preview_parser.add_argument("--api-key", help="PromptIntel API key (or set PROMPTINTEL_API_KEY)")
    preview_parser.add_argument("-n", "--limit", type=int, default=10, help="Number of indicators to show")
    preview_parser.add_argument("--severity", choices=["critical", "high", "medium", "low"], help="Filter by severity")
    preview_parser.add_argument("--category", help="Filter by category")
    preview_parser.add_argument("-v", "--verbose", action="store_true", help="Show HTTP requests")
    
    # generate-rules command (Rule Generation Agent)
    gen_parser = subparsers.add_parser("generate-rules", help="Run Rule Generation Agent to create optimized Nova rules")
    gen_parser.add_argument("--test-dataset", required=True, help="Dataset to test rules against")
    gen_parser.add_argument("--output", default="agent_optimized.nov", help="Output filename for rules")
    gen_parser.add_argument("--target-precision", type=float, default=0.90, help="Target precision (default: 0.90)")
    gen_parser.add_argument("--target-recall", type=float, default=0.80, help="Target recall (default: 0.80)")
    gen_parser.add_argument("--max-iterations", type=int, default=5, help="Max optimization iterations")
    gen_parser.add_argument("--no-promptintel", action="store_true", help="Don't use PromptIntel as data source")
    gen_parser.add_argument("--add-huggingface", action="append", metavar="DATASET", help="Add HuggingFace dataset as source")
    gen_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    registry = DatasetRegistry(Path(__file__).parent / "datasets")
    
    if args.command == "list":
        cmd_list(args, registry)
    elif args.command == "info":
        cmd_info(args, registry)
    elif args.command == "sample":
        cmd_sample(args, registry)
    elif args.command == "import-hf":
        cmd_import_hf(args, registry)
    elif args.command == "import-csv":
        cmd_import_csv(args, registry)
    elif args.command == "test":
        asyncio.run(cmd_test(args, registry))
    elif args.command == "add":
        cmd_add(args, registry)
    elif args.command == "sync-feed":
        cmd_sync_feed(args)
    elif args.command == "feed-preview":
        cmd_feed_preview(args)
    elif args.command == "generate-rules":
        asyncio.run(cmd_generate_rules(args))


if __name__ == "__main__":
    main()
