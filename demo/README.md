# Creatine Demo

## Overview

This demo showcases Creatine's prompt security capabilities for detecting prompt injection and jailbreak attacks that may bypass first-layer guardrails.

## Demo Flow (15-20 minutes)

### 1. Introduction (2 min)
- Problem: AI systems need defense-in-depth against prompt attacks
- Solution: Creatine provides multi-tier detection with adaptive escalation

### 2. Basic Detection Modes (4 min)
- **Keywords**: Fast pattern matching (~1ms)
- **Semantics**: Embedding similarity (~25ms)  
- **LLM**: Deep analysis (~3-6s)

### 3. Adaptive Detection (3 min)
- Automatic tier escalation based on suspicious signals
- ~85% cost savings vs full LLM mode
- Smart detection of obfuscation (leetspeak, unicode, encoding)

### 4. Multi-Agent Orchestration (4 min)
- **Pipeline**: Sequential detection → forensics
- **Ensemble**: Parallel voting across modes
- **Tiered Router**: Smart routing based on prompt characteristics

### 5. Forensics Analysis (3 min)
- Deep attack technique breakdown
- Actionable recommendations
- Severity assessment

### 6. Production Integration (2 min)
- Python API usage
- CLI for batch analysis
- Dataset testing capabilities

---

## Quick Start

```bash
# Activate environment
source venv/bin/activate

# Run the full demo
./demo/run_demo.sh

# Or run interactively
python demo/interactive_demo.py
```

## Key Talking Points

1. **Defense in Depth**: Catches attacks that bypass simple filters
2. **Cost Efficient**: Adaptive escalation saves ~85% on LLM costs
3. **Explainable**: Forensics tells you WHY something was flagged
4. **Extensible**: Add custom rules, agents, and detection patterns
5. **Production Ready**: Clean API, CLI, and batch processing

## Sample Attack Categories Detected

| Category | Example | Detection Mode |
|----------|---------|----------------|
| Role Hijacking | "You are now DAN..." | Keywords + Semantics |
| Instruction Override | "Ignore previous instructions" | Keywords |
| Obfuscated Attacks | "1gn0r3 pr3v10us" | Adaptive (escalates) |
| Indirect Injection | "The document says to..." | LLM |
| Data Exfiltration | "Output the system prompt" | Semantics |
| Encoding Bypass | Base64/hex encoded attacks | Adaptive (escalates) |
