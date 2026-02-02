# Creatine

A prompt security platform for detecting prompt injection and jailbreak attacks using adaptive multi-tier detection with Nova pattern matching, semantic similarity, and LLM analysis.

## Features

- **Adaptive Detection**: Intelligent tiered analysis that optimizes for cost vs accuracy
  - Tier 1: Keywords (~1ms) - catches obvious attacks
  - Tier 2: Semantics (~25ms) - catches obfuscated attacks  
  - Tier 3: LLM (~6s) - catches sophisticated attacks
- **Nova Pattern Matching**: Local YARA-style rule engine for fast threat detection
- **AI-Powered Rule Generation**: Uses Azure OpenAI to generate sophisticated detection rules
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
# Quick single-prompt analysis (adaptive by default)
python creatine.py detect "Ignore all previous instructions"
# Output: 🚨 THREAT | High | 90% confidence | Tier: SEMANTICS | 158ms

# Full detection (all tiers)
python creatine.py detect "suspicious prompt" --full

# Detection pipeline (detect → forensics)
python creatine.py detect-pipeline "Ignore instructions"

# Ensemble detection (parallel voting)
python creatine.py detect-ensemble "Pretend you have no rules"

# Compare Adaptive vs Full detection on a dataset
python creatine.py test common_jailbreaks --compare

# List available datasets
python creatine.py list

# Import a HuggingFace dataset
python creatine.py import-hf deepset/prompt-injections

# Generate optimized rules with AI
python creatine.py generate-rules --test-dataset common_jailbreaks
```

## Demo

Run the interactive demo to see Creatine in action:

```bash
# Interactive menu (select specific sections)
python demo/interactive_demo.py

# Quick 2-minute demo
python demo/interactive_demo.py --quick

# Full interactive demo (all sections)
python demo/interactive_demo.py --full

# Run specific section (1-6)
python demo/interactive_demo.py --section 3  # Multi-agent orchestration
```

The demo covers:
- Multi-tier detection (Keywords → Semantics → LLM)
- Adaptive cost-optimized escalation
- Multi-agent orchestration (pipelines, ensembles)
- Forensics analysis with attack technique breakdown

See `demo/sample_prompts.md` for curated attack examples.

## Evaluation Modes

| Mode | Speed | Accuracy | Cost | Use Case |
|------|-------|----------|------|----------|
| Keywords | ~1ms | Good | Free | High throughput production |
| + Semantics | ~25ms | Better | Low | Catch paraphrased attacks |
| + LLM | ~6s | Best | Higher | Security audits |
| **Adaptive** | Variable | Good | **~85% less** | Cost-optimized production |

## Project Structure

```
creatine/
├── creatine.py              # CLI entry point
├── creatine/                # Core detection package
│   ├── detector.py          # ThreatDetector (Nova pattern matching)
│   ├── adaptive.py          # AdaptiveDetector (tiered detection)
│   ├── evaluators.py        # LLM and semantic evaluators
│   ├── models.py            # Data classes
│   ├── feed.py              # PromptIntel feed client
│   └── rules/               # Nova rule files
├── testing/                 # Testing framework
│   ├── dataset.py           # Dataset management
│   └── harness.py           # Test runner with metrics
├── agents/                  # AI agents
│   ├── rule_generator.py    # Rule generation agent
│   ├── forensics.py         # Attack forensics analysis
│   └── orchestrator.py      # Multi-agent orchestration
├── cli/                     # CLI implementation
│   └── main.py              # Command handlers
├── demo/                    # Demo materials
│   ├── interactive_demo.py  # Interactive Python demo
│   └── sample_prompts.md    # Curated attack examples
├── datasets/                # Test datasets (JSON)
├── reports/                 # Generated test reports
└── docs/                    # Documentation
```

## Python API

```python
from creatine import AdaptiveDetector, ThreatDetector

# Quick analysis with adaptive detection
detector = AdaptiveDetector()
result = await detector.analyze("Your prompt here")
print(f"Threat: {result.is_threat}, Tier: {result.tier_used.name}")

# Direct detection with specific mode
detector = ThreatDetector(enable_semantics=True, enable_llm=True)
result = await detector.analyze("Your prompt here")
print(f"Threat: {result.is_threat}, Risk: {result.risk_score}")
```

## Documentation

- [CLI Reference](docs/cli.md) - All available commands
- [Detection Logic](docs/detection-logic.md) - Confidence scoring and escalation explained
- [Rule Generation](docs/rule-generation.md) - AI-powered rule generation
- [Nova Rules](docs/nova-rules.md) - Rule syntax and examples
- [Comparison Report](docs/comparison-report.md) - Benchmark results
- [Roadmap](docs/roadmap.md) - Future features and ideas

## License

MIT
