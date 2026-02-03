# Creatine Architecture Guide: Choosing the Right Mode

This guide explains the different detection and evaluation modes in Creatine and when to use each.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           CREATINE DETECTION SYSTEM                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    creatine/ (Primary Detection)                     │   │
│  │                                                                      │   │
│  │   Tier 1 (Keywords)  →  Tier 2 (Semantic)  →  Tier 3 (LLM)         │   │
│  │        ~1ms                  ~25ms                ~6s                │   │
│  │        Free              Low cost           Higher cost              │   │
│  │                                                                      │   │
│  │   adaptive.py: Auto-escalates based on suspicious signals           │   │
│  │   detector.py: Nova rules pattern matching engine                   │   │
│  │   evaluators.py: LLM/semantic judgment plugins                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                                    ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                 agents/ (Orchestration & Analysis)                   │   │
│  │                                                                      │   │
│  │   orchestrator.py: Multi-agent pipelines, parallel execution        │   │
│  │   forensics.py: Deep attack breakdown, MITRE ATT&CK mapping         │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                                    ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                meta_eval/ (Multi-Agent Judge Panel)                  │   │
│  │                                                                      │   │
│  │   DebateEngine: MoE consensus with 5 debate protocols               │   │
│  │   ConsistencyChecker: IPI/TOV reliability metrics                   │   │
│  │   Domain Experts: SecurityResearcher, custom specialists            │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## When to Use Each Mode

### 1. AdaptiveDetector (Default - Production)

**Use for:** Real-time detection in production with cost optimization

```python
from creatine import AdaptiveDetector

detector = AdaptiveDetector()
result = detector.analyze(prompt)
```

**Characteristics:**
- Tiered escalation: starts fast/cheap, escalates only when needed
- ~85% cost savings vs. always using LLM
- Auto-detects obfuscation (ROT13, Base64, etc.) and escalates
- Best for high-volume, low-latency requirements

**When to choose:**
- ✅ Production API protection
- ✅ High throughput requirements (>100 req/s)
- ✅ Cost-sensitive deployments
- ✅ When most prompts are benign

---

### 2. ThreatDetector (Direct)

**Use for:** When you want explicit control over detection tier

```python
from creatine import ThreatDetector, DetectionMode

detector = ThreatDetector()

# Explicit tier selection
result = detector.analyze(prompt, mode=DetectionMode.KEYWORDS)  # Tier 1
result = detector.analyze(prompt, mode=DetectionMode.SEMANTIC)  # Tier 2
result = detector.analyze(prompt, mode=DetectionMode.LLM)       # Tier 3
```

**When to choose:**
- ✅ Testing/debugging specific tiers
- ✅ When you know the threat level upfront
- ✅ Benchmarking tier performance
- ❌ Not for production (use AdaptiveDetector)

---

### 3. Multi-Agent Orchestrator

**Use for:** Complex workflows combining multiple detection stages

```python
from agents.orchestrator import Pipeline, DetectorAgent, ForensicsAgent

pipeline = Pipeline([
    DetectorAgent(),      # Primary detection
    ForensicsAgent(),     # Deep analysis on flagged items
])
result = await pipeline.execute(prompt)
```

**When to choose:**
- ✅ Need forensic breakdown of attacks
- ✅ Want to chain detection → analysis → response
- ✅ Building custom detection workflows
- ✅ Parallel execution of multiple detectors

---

### 4. Meta-Eval Framework (Judge Panel)

**Use for:** High-stakes decisions requiring calibrated confidence

```python
from meta_eval import AgentManager, DebateEngine, EvaluationRequest, CandidateOutput

manager = AgentManager()
engine = DebateEngine(manager)

request = EvaluationRequest(
    prompt="User prompt",
    candidate_outputs=[CandidateOutput(content="Model response")],
)
result = await engine.evaluate(request)
```

**When to choose:**
- ✅ High-stakes decisions (legal, safety-critical)
- ✅ Need explainable verdicts with rationale
- ✅ Want multiple expert perspectives (safety, security, factuality)
- ✅ Measuring evaluation reliability (IPI/TOV metrics)
- ✅ Training/fine-tuning evaluation models
- ❌ Not for high-throughput (latency ~10-30s with debate)

---

## Relationship: Not Redundant, Complementary

| Component | Purpose | Speed | Use Case |
|-----------|---------|-------|----------|
| **AdaptiveDetector** | Fast threat detection | ~1ms-6s | Production API protection |
| **Orchestrator** | Workflow coordination | Variable | Complex pipelines |
| **Forensics** | Attack breakdown | ~5-10s | Incident analysis |
| **Meta-Eval** | Calibrated judgment | ~10-30s | High-stakes decisions |

### Integration Pattern

For maximum accuracy on critical prompts:

```python
from creatine import AdaptiveDetector
from agents.forensics import ForensicsAgent
from meta_eval import AgentManager, DebateEngine, SECURITY_RESEARCHER_AGENT

# Stage 1: Fast detection
detector = AdaptiveDetector()
result = detector.analyze(prompt)

if result.is_threat and result.confidence > 0.7:
    # Stage 2: Forensic breakdown
    forensics = ForensicsAgent()
    breakdown = await forensics.analyze(prompt)
    
    # Stage 3: Multi-agent judgment (for borderline cases)
    if 0.7 < result.confidence < 0.95:
        manager = AgentManager()
        manager.register_agent(SECURITY_RESEARCHER_AGENT)
        engine = DebateEngine(manager)
        
        judgment = await engine.evaluate(EvaluationRequest(
            prompt=prompt,
            candidate_outputs=[CandidateOutput(content=model_response)],
        ))
        
        # Use judgment.verdict, judgment.confidence
```

## Decision Tree

```
                    ┌─────────────────────┐
                    │   What's your need? │
                    └──────────┬──────────┘
                               │
           ┌───────────────────┼───────────────────┐
           │                   │                   │
           ▼                   ▼                   ▼
    ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
    │ High volume  │   │ Deep attack  │   │ High-stakes  │
    │ production   │   │ analysis     │   │ decisions    │
    └──────┬───────┘   └──────┬───────┘   └──────┬───────┘
           │                   │                   │
           ▼                   ▼                   ▼
    ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
    │ Adaptive     │   │ Orchestrator │   │  Meta-Eval   │
    │ Detector     │   │ + Forensics  │   │  Framework   │
    └──────────────┘   └──────────────┘   └──────────────┘
```

## Summary

- **AdaptiveDetector**: Your daily driver for production - fast, cheap, effective
- **Orchestrator/Forensics**: When you need to understand *how* an attack works
- **Meta-Eval**: When you need *high confidence* with explainable reasoning

They're designed to work together in a pipeline, not replace each other.
