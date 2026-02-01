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
from promptintel import PromptIntelClient

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
    
    client = PromptIntelClient(api_key or "", verbose=args.verbose)
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
                path = harness.save_report(report)
                print(f"Report saved to: {path}")
    finally:
        await client.close()


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
    
    # add command
    add_parser = subparsers.add_parser("add", help="Add a prompt to a dataset")
    add_parser.add_argument("dataset", help="Dataset name (created if doesn't exist)")
    add_parser.add_argument("prompt", help="The prompt text")
    add_parser.add_argument("--benign", action="store_true", help="Mark as benign (default: malicious)")
    add_parser.add_argument("--type", choices=[t.value for t in AttackType], help="Attack type")
    add_parser.add_argument("--severity", choices=[s.value for s in Severity], help="Severity level")
    add_parser.add_argument("--description", help="Description of the prompt")
    add_parser.add_argument("--tags", help="Comma-separated tags")
    
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


if __name__ == "__main__":
    main()
