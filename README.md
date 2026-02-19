# Creatine

**A self-improving, community-backed prompt security platform** that detects prompt injection and jailbreak attacks through adaptive multi-tier detection. Built on [Nova](https://github.com/Nova-Hunting/nova-rules) pattern matching, it combines curated community rules, semantic analysis, and LLM reasoning — then automatically learns from production traffic to continuously strengthen defenses while optimizing costs.

## Features

- **Adaptive Multi-Tier Detection**: Intelligent escalation through Keywords (~1ms) → Semantics (~25ms) → LLM (~6s), with **~85% cost savings** vs. always running full analysis
- **Community-Backed Rules**: One command (`sync-rules`) to inherit 50+ rules from [Nova-Hunting/nova-rules](https://github.com/Nova-Hunting/nova-rules) — injection, jailbreak, TTPs, policy puppetry, unicode attacks, and more
- **Self-Improving Detection**: Logs all detections, identifies gaps, clusters attack patterns, and generates new Nova rules automatically. Three rule layers: **default** → **community** → **generated**
- **Multi-Agent Orchestration**: Sequential pipelines, parallel ensemble voting, conditional routing
- **Attack Forensics**: Identifies specific techniques, severity, and actionable recommendations
- **Obfuscation Detection**: ROT13, Base64, Hex, URL encoding, zero-width chars, reversed text, and more
- **Production Ready**: CLI, Python API, batch processing, HuggingFace/CSV/PromptIntel import, Jupyter/Kusto integration

📖 **[Architecture](docs/ARCHITECTURE.md)** · **[CLI Reference](docs/cli.md)** · **[Detection Logic](docs/detection-logic.md)** · **[Nova Rules](docs/nova-rules.md)** · **[Rule Generation](docs/rule-generation.md)** · **[Roadmap](docs/roadmap.md)**

## Quick Start

```bash
# Install
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # Configure Azure OpenAI endpoint

# Sync community rules
python creatine.py sync-rules

# Detect
python creatine.py detect "Ignore all previous instructions"
# 🚨 THREAT | High | 90% confidence | Tier: SEMANTICS | 158ms
```

Required in `.env`:
```
AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com/
AZURE_OPENAI_DEPLOYMENT_NAME=gpt-4
```

## Usage

```bash
# Adaptive detection (default — escalates through tiers as needed)
python creatine.py detect "suspicious prompt"

# Full detection (all tiers)
python creatine.py detect "suspicious prompt" --full

# Detection pipeline (detect → forensics)
python creatine.py detect-pipeline "Ignore instructions"

# Ensemble detection (parallel model voting)
python creatine.py detect-ensemble "Pretend you have no rules"

# Test against datasets
python creatine.py test common_jailbreaks --compare
python creatine.py list                    # available datasets
python creatine.py import-hf deepset/prompt-injections

# Generate and learn rules
python creatine.py generate-rules --test-dataset common_jailbreaks
python creatine.py learn logs/detections_*.jsonl -v
```

## Rule Architecture

Three rule sources, layered for breadth and adaptability:

| Source | Path | Updated via | Purpose |
|--------|------|-------------|---------|
| **Default** | `rules/default.nov` | Manual edits | Built-in keyword, semantic, and LLM rules |
| **Community** | `rules/community/` | `sync-rules` | [Nova-Hunting/nova-rules](https://github.com/Nova-Hunting/nova-rules) — 50+ community rules |
| **Generated** | `rules/feed_generated.nov`, `learned_rules.nov` | `sync-feed`, `learn`, `generate-rules` | Self-improving rules from threat feeds and production logs |

All sources load automatically on startup. Community rules require a one-time `sync-rules`; subsequent runs pull the latest.

```bash
python creatine.py sync-rules                          # clone/pull Nova-Hunting rules
python creatine.py sync-rules --repo https://github.com/your-org/rules.git  # custom repo
```

## Self-Improving Pipeline

Creatine logs all detections automatically, enabling continuous improvement:

```bash
python creatine.py detect "some prompt"           # logged to logs/detections_YYYY-MM-DD.jsonl
python creatine.py learn logs/detections_*.jsonl   # generate rules from gaps
```

The pipeline identifies where LLM caught attacks that keywords missed, clusters similar patterns, and generates new rules to catch future variants at the keyword tier.

## Evaluation Modes

| Mode | Speed | Accuracy | Cost | Use Case |
|------|-------|----------|------|----------|
| Keywords | ~1ms | Good | Free | High throughput production |
| + Semantics | ~25ms | Better | Low | Catch paraphrased attacks |
| + LLM | ~6s | Best | Higher | Security audits |
| **Adaptive** | Variable | Good | **~85% less** | Cost-optimized production |

## Python API

```python
from creatine import AdaptiveDetector, ThreatDetector

# Adaptive detection (recommended)
detector = AdaptiveDetector()
result = await detector.analyze("Your prompt here")
print(f"Threat: {result.is_threat}, Tier: {result.tier_used.name}")

# Direct detection with specific evaluators
detector = ThreatDetector(enable_semantics=True, enable_llm=True)
result = await detector.analyze("Your prompt here")
print(f"Threat: {result.is_threat}, Risk: {result.risk_score}")
```

## Jupyter / Kusto Integration

```bash
pip install azure-kusto-data azure-kusto-ingest pandas matplotlib jupyter
jupyter notebook notebooks/kusto_analysis.ipynb
```

## Demo

```bash
python demo/interactive_demo.py          # interactive menu
python demo/interactive_demo.py --quick  # 2-minute demo
python demo/interactive_demo.py --full   # all sections
```

## Related: Tribunal

For multi-agent LLM-as-judge evaluation, see **[Tribunal](https://github.com/mdressman/tribunal)** — debate protocols, consistency metrics, integrable as Tier 3+.

## Project Structure

```
creatine/
├── creatine.py              # CLI entry point
├── creatine/                # Core detection package
│   ├── detector.py          # ThreatDetector (Nova pattern matching)
│   ├── adaptive.py          # AdaptiveDetector (tiered detection + logging)
│   ├── evaluators.py        # LLM and semantic evaluators
│   ├── models.py            # Data classes
│   ├── feed.py              # PromptIntel feed client
│   └── rules/               # Nova rule files (.nov)
│       ├── default.nov      # Built-in rules (keyword + semantic + LLM)
│       ├── community/       # Community rules (via sync-rules)
│       ├── feed_generated.nov   # From threat feed sync
│       └── learned_rules.nov    # From learning pipeline
├── agents/                  # AI agents
│   ├── rule_generator.py    # Rule generation agent
│   ├── forensics.py         # Attack forensics analysis
│   ├── learning.py          # Adaptive learning pipeline
│   └── orchestrator.py      # Multi-agent orchestration
├── testing/                 # Test framework & datasets
├── cli/                     # CLI implementation
├── logs/                    # Detection logs (auto-generated)
├── notebooks/               # Jupyter notebooks (Kusto integration)
├── demo/                    # Interactive demo
├── datasets/                # Test datasets (JSON)
└── docs/                    # Documentation
```

## License

MIT
