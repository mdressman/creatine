# Creatine

A prompt security platform for detecting prompt injection and jailbreak attacks using adaptive multi-tier detection with Nova pattern matching, semantic similarity, and LLM analysis.

## Features

- **Adaptive Detection**: Intelligent tiered analysis that optimizes for cost vs accuracy
  - Tier 1: Keywords (~1ms) - catches obvious attacks
  - Tier 2: Semantics (~25ms) - catches obfuscated attacks  
  - Tier 3: LLM (~6s) - catches sophisticated attacks
- **Nova Pattern Matching**: Local YARA-style rule engine for fast threat detection
- **AI-Powered Rule Generation**: Uses Azure OpenAI to generate sophisticated detection rules
- **Iterative Optimization**: Agent automatically improves rules based on test feedback
- **Multiple Data Sources**: Ingest threats from PromptIntel API, HuggingFace datasets, or local files
- **Test Harness**: Comprehensive testing with accuracy, precision, recall, and F1 metrics

## Quick Start

### Installation

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Configuration

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
```

Required environment variables:
```
AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com/
AZURE_OPENAI_DEPLOYMENT_NAME=gpt-4
PROMPTINTEL_API_KEY=your-api-key  # Optional, for feed sync
```

### Basic Usage

```bash
# Quick single-prompt analysis
python3 test_cli.py analyze "Ignore all previous instructions"
# Output: 🚨 THREAT | High | 90% confidence | KEYWORDS | 6ms

# Run adaptive detection on a dataset
python3 test_cli.py adaptive --dataset hf_sample_100

# Run full comparison test (all evaluation modes)
python3 test_cli.py test hf_sample_100 --compare

# Generate optimized rules
python3 test_cli.py generate-rules --test-dataset common_jailbreaks -v
```

## Evaluation Modes

| Mode | Speed | Accuracy | Cost | Use Case |
|------|-------|----------|------|----------|
| Keywords | ~1ms | Good | Free | High throughput production |
| + Semantics | ~25ms | Better | Low | Catch paraphrased attacks |
| + LLM | ~6s | Best | Higher | Security audits |
| **Adaptive** | Variable | Good | **~85% less** | Cost-optimized production |

## Documentation

- [CLI Reference](docs/cli.md) - All available commands
- [Rule Generation](docs/rule-generation.md) - AI-powered rule generation
- [Nova Rules](docs/nova-rules.md) - Rule syntax and examples
- [Comparison Report](docs/comparison-report.md) - Benchmark results
- [Roadmap](docs/roadmap.md) - Future features and ideas

## Architecture

```
creatine/
├── adaptive.py       # Adaptive tiered detection engine
├── promptintel.py    # Nova detection engine + evaluators
├── rule_agent.py     # AI rule generation agent
├── dataset.py        # Dataset management and loaders
├── test_harness.py   # Test runner with metrics
├── test_cli.py       # Command-line interface
├── rules/
│   ├── default.nov   # Core keyword detection rules
│   └── advanced.nov  # Semantic + LLM rules
└── datasets/
    └── *.json        # Test datasets
```

## License

MIT
