# Creatine Demo

## Overview

This demo showcases Creatine's prompt security capabilities for detecting prompt injection and jailbreak attacks that may bypass first-layer guardrails.

## Quick Start

```bash
# Activate environment
source venv/bin/activate

# Detection Demo
python demo/interactive_demo.py          # Interactive menu
python demo/interactive_demo.py --quick  # Quick 2-minute demo
python demo/interactive_demo.py --full   # Full demo
```

## Demo Sections

### Detection Demo (`interactive_demo.py`)

| # | Section | Duration | Description |
|---|---------|----------|-------------|
| 1 | Basic Detection | 4 min | Keywords, Semantics, LLM modes |
| 2 | Adaptive Detection | 3 min | Cost-optimized tier escalation |
| 3 | Multi-Agent Orchestration | 4 min | Pipelines, ensembles, routing |
| 4 | Forensics Analysis | 3 min | Attack technique breakdown |
| 5 | CLI Commands | 2 min | Full CLI reference |
| 6 | Python API | 2 min | Integration examples |

## Key Talking Points

1. **Defense in Depth**: Catches attacks that bypass simple filters
2. **Cost Efficient**: Adaptive escalation saves ~85% on LLM costs
3. **Self-Improving**: Auto-learns from production logs to generate new rules
4. **Explainable**: Forensics tells you WHY something was flagged
5. **Extensible**: Add custom rules, agents, and detection patterns
6. **Production Ready**: Clean API, CLI, and batch processing

## Sample Attack Categories Detected

| Category | Example | Detection Mode |
|----------|---------|----------------|
| Role Hijacking | "You are now DAN..." | Keywords + Semantics |
| Instruction Override | "Ignore previous instructions" | Keywords |
| Obfuscated Attacks | "1gn0r3 pr3v10us" | Adaptive (decodes + escalates) |
| Indirect Injection | "The document says to..." | LLM |
| Data Exfiltration | "Output the system prompt" | Semantics |
| Encoding Bypass | Base64/hex encoded attacks | Adaptive (decodes + escalates) |

## CLI Quick Reference

```bash
# Detection (logs automatically to logs/)
python creatine.py detect "prompt"              # Adaptive (default)
python creatine.py detect "prompt" --full       # Full (all tiers)
python creatine.py detect-pipeline "prompt"     # Detection + forensics
python creatine.py detect-ensemble "prompt"     # Parallel voting

# Analysis
python creatine.py forensics "prompt"           # Deep forensics

# Learning
python creatine.py learn logs/*.jsonl -v        # Learn from logs

# Datasets
python creatine.py list                         # List datasets
python creatine.py info <dataset>               # Dataset details
python creatine.py sample <dataset>             # Show samples
python creatine.py import-hf <hf-dataset>       # Import from HuggingFace
python creatine.py import-csv <file>            # Import from CSV

# Testing
python creatine.py test <dataset>               # Run tests
python creatine.py test <dataset> --adaptive    # Test with adaptive
python creatine.py test <dataset> --compare     # Compare modes

# Rules
python creatine.py generate-rules --test-dataset <ds>   # Generate rules
python creatine.py sync-feed                            # Sync from PromptIntel
```

## Learning Pipeline

Creatine automatically logs all detections. Use the learning pipeline to improve detection:

```bash
# 1. Detections accumulate in logs/detections_YYYY-MM-DD.jsonl

# 2. Periodically run learning
python creatine.py learn logs/*.jsonl -v

# 3. New rules are generated from patterns LLM caught but keywords missed
# Output: creatine/rules/learned_rules.nov
```

## Meta-Evaluation Framework

Use multi-agent LLM-as-judge for more reliable evaluations:

```python
from meta_eval import AgentManager, DebateEngine
from meta_eval.schemas import EvaluationRequest, CandidateOutput, DebateProtocol

# Initialize with expert agents
manager = AgentManager()  # Loads Safety, Security, Factuality agents
engine = DebateEngine(manager)

# Evaluate with debate protocol
request = EvaluationRequest(
    prompt="Original prompt",
    candidate_outputs=[CandidateOutput(content="Model response")],
    protocol=DebateProtocol.COURTEVAL,  # Adversarial prosecution/defense
)
result = await engine.evaluate(request)

print(f"Verdict: {result.verdict}, Confidence: {result.confidence}")
```

### API Server

```bash
# Start the meta-eval API
python -m meta_eval.api.server

# Evaluate via API
curl -X POST http://localhost:8000/evaluate \
  -H "Content-Type: application/json" \
  -d '{"prompt": "...", "candidate_outputs": [{"content": "..."}]}'

# Get consistency metrics
curl http://localhost:8000/metrics
```

See `meta_eval/README.md` for complete documentation.
