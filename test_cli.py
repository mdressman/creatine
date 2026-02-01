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
from promptintel import (
    PromptIntelClient, PromptIntelFeedClient, sync_feed_rules, 
    sync_feed_rules_with_ai, FEED_RULES_PATH
)

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
    
    client = PromptIntelClient(
        api_key or "", 
        verbose=args.verbose,
        include_feed_rules=include_feed,
    )
    
    rules_desc = "default + feed" if include_feed else "default only"
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
    """Run tests with both rule sets and compare results."""
    dataset = registry.get(args.name)
    if not dataset:
        print(f"Dataset not found: {args.name}")
        return
    
    print(f"=== Rule Set Comparison: {args.name} ({len(dataset)} prompts) ===\n")
    
    # Test with default rules only
    print("Running with DEFAULT rules only...")
    client_default = PromptIntelClient(api_key or "", verbose=False, include_feed_rules=False)
    harness_default = TestHarness(client_default, registry)
    report_default = await harness_default.run_dataset(
        dataset,
        concurrency=args.concurrency,
        progress_callback=print_progress if not args.quiet else None,
    )
    await client_default.close()
    
    print("\n\nRunning with DEFAULT + FEED rules...")
    client_combined = PromptIntelClient(api_key or "", verbose=False, include_feed_rules=True)
    harness_combined = TestHarness(client_combined, registry)
    report_combined = await harness_combined.run_dataset(
        dataset,
        concurrency=args.concurrency,
        progress_callback=print_progress if not args.quiet else None,
    )
    await client_combined.close()
    
    # Print comparison
    print("\n")
    print("=" * 60)
    print("                    COMPARISON RESULTS")
    print("=" * 60)
    print(f"{'Metric':<25} {'Default Only':>15} {'Default+Feed':>15} {'Change':>10}")
    print("-" * 60)
    
    metrics = [
        ("Accuracy", report_default.accuracy, report_combined.accuracy),
        ("Precision", report_default.precision, report_combined.precision),
        ("Recall", report_default.recall, report_combined.recall),
        ("F1 Score", report_default.f1_score, report_combined.f1_score),
    ]
    
    for name, default_val, combined_val in metrics:
        change = combined_val - default_val
        change_str = f"+{change:.2%}" if change >= 0 else f"{change:.2%}"
        arrow = "↑" if change > 0 else ("↓" if change < 0 else "→")
        print(f"{name:<25} {default_val:>14.2%} {combined_val:>14.2%} {arrow} {change_str:>8}")
    
    print("-" * 60)
    print(f"{'True Positives':<25} {report_default.true_positives:>15} {report_combined.true_positives:>15} {report_combined.true_positives - report_default.true_positives:>+10}")
    print(f"{'True Negatives':<25} {report_default.true_negatives:>15} {report_combined.true_negatives:>15} {report_combined.true_negatives - report_default.true_negatives:>+10}")
    print(f"{'False Positives':<25} {report_default.false_positives:>15} {report_combined.false_positives:>15} {report_combined.false_positives - report_default.false_positives:>+10}")
    print(f"{'False Negatives':<25} {report_default.false_negatives:>15} {report_combined.false_negatives:>15} {report_combined.false_negatives - report_default.false_negatives:>+10}")
    print("-" * 60)
    print(f"{'Avg Response Time (ms)':<25} {report_default.avg_response_time_ms:>15.2f} {report_combined.avg_response_time_ms:>15.2f}")
    print("=" * 60)
    
    # Save reports if requested
    if args.save:
        path1 = harness_default.save_report(report_default, suffix="_default_only")
        path2 = harness_combined.save_report(report_combined, suffix="_with_feed")
        print(f"\nReports saved to:")
        print(f"  Default only: {path1}")
        print(f"  With feed:    {path2}")


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
            # Use AI-powered rule generation
            print("Using AI-powered rule generation (requires Azure OpenAI)...")
            result_path = asyncio.run(sync_feed_rules_with_ai(
                api_key=api_key,
                output_path=output_path,
                verbose=args.verbose,
            ))
        else:
            # Use simple keyword extraction
            result_path = sync_feed_rules(
                api_key=api_key,
                output_path=output_path,
                verbose=args.verbose,
            )
        print(f"\n✓ Feed rules synced to: {result_path}")
        print(f"  Rules will be loaded automatically on next test run.")
        
        if args.verbose:
            # Show preview of generated rules
            content = result_path.read_text()
            rules_count = content.count("rule ")
            print(f"  Generated {rules_count} rules from feed")
            
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


if __name__ == "__main__":
    main()
