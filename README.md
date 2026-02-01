# Creatine

A multi-agent security testing platform for detecting prompt injection and jailbreak attacks using Nova pattern matching rules with AI-powered rule generation.

## Features

- **Nova Pattern Matching**: Local YARA-style rule engine for fast threat detection (~0.5ms per prompt)
- **AI-Powered Rule Generation**: Uses Azure OpenAI to analyze threat patterns and generate sophisticated detection rules
- **Iterative Optimization**: Agent automatically improves rules based on test feedback (precision/recall)
- **Multiple Data Sources**: Ingest threats from PromptIntel API, HuggingFace datasets, or local files
- **Test Harness**: Comprehensive testing with accuracy, precision, recall, and F1 metrics
- **Dataset Management**: Import, create, and manage test datasets

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
AZURE_OPENAI_DEPLOYMENT=gpt-4
PROMPTINTEL_API_KEY=your-api-key
```

### Basic Usage

```bash
# List available datasets
python3 test_cli.py list

# Run tests against a dataset
python3 test_cli.py test common_jailbreaks

# Generate optimized rules
python3 test_cli.py generate-rules --test-dataset common_jailbreaks -v
```

## Documentation

- [CLI Reference](docs/cli.md) - All available commands
- [Rule Generation](docs/rule-generation.md) - AI-powered rule generation
- [Nova Rules](docs/nova-rules.md) - Rule syntax and examples

## Architecture

```
creatine/
├── main.py           # Multi-agent system (Researcher, Critic, Security)
├── promptintel.py    # Nova detection engine + PromptIntel API client
├── rule_agent.py     # AI rule generation agent with optimization
├── dataset.py        # Dataset management and loaders
├── test_harness.py   # Test runner with metrics
├── test_cli.py       # Command-line interface
├── rules/
│   ├── default.nov          # Hand-crafted detection rules
│   ├── feed_generated.nov   # Rules from PromptIntel feed
│   └── agent_optimized.nov  # AI-optimized rules
└── datasets/
    └── common_jailbreaks.json
```

## License

MIT
