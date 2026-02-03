# Multi-Agent Meta-Evaluation Framework

A modular, scalable evaluation system using Mixture-of-Experts (MoE) architecture with multiple LLM/SLM judges.

## Overview

This framework implements robust LLM-as-judge evaluation through:

- **Multi-agent debate protocols**: ChatEval, CourtEval, DEBATE, MoA, Consensus
- **Consistency metrics**: IPI (Intra-Pair Instability), TOV (Total Order Violation)
- **Adaptive learning**: RL-based weight tuning, Bayesian hyperparameter optimization
- **REST API**: Full evaluation, metrics, and agent management endpoints

Based on research from ["Are We on the Right Way to Assessing LLM-as-a-Judge?"](https://arxiv.org/html/2508.02990)

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        EvaluationAPI                            │
│  POST /evaluate  │  GET /metrics  │  POST /agents  │  GET /agents│
└────────────────────────────┬────────────────────────────────────┘
                             │
         ┌───────────────────┼───────────────────┐
         ▼                   ▼                   ▼
┌─────────────────┐  ┌───────────────┐  ┌─────────────────────┐
│  AgentManager   │  │ DebateEngine  │  │ ConsistencyChecker  │
│                 │  │               │  │                     │
│ • Lifecycle     │◄─┤ • Protocols   │  │ • IPI (flip detect) │
│ • Personas      │  │ • Roles       │  │ • TOV (transitivity)│
│ • Fine-tuning   │  │ • Aggregation │  │ • Calibration       │
└─────────────────┘  └───────────────┘  └─────────────────────┘
         │                   │
         ▼                   ▼
┌─────────────────┐  ┌───────────────┐
│   RLTrainer     │  │   Bayesian    │
│                 │  │   Optimizer   │
│ • Consensus RL  │  │               │
│ • Weight tuning │  │ • Hyperparam  │
└─────────────────┘  └───────────────┘
```

## Quick Start

```python
import asyncio
from meta_eval import AgentManager, DebateEngine
from meta_eval.schemas import EvaluationRequest, CandidateOutput, DebateProtocol

# Initialize components
manager = AgentManager()  # Loads default expert agents
engine = DebateEngine(manager)

# Create evaluation request
request = EvaluationRequest(
    prompt="What is the capital of France?",
    candidate_outputs=[
        CandidateOutput(content="The capital of France is Paris."),
    ],
    protocol=DebateProtocol.CHATEVAL,
)

# Run evaluation
result = asyncio.run(engine.evaluate(request))

print(f"Verdict: {result.verdict}")
print(f"Score: {result.score:.2f}")
print(f"Confidence: {result.confidence:.2f}")
print(f"Rationale: {result.rationale}")
```

## Debate Protocols

| Protocol | Description | Best For |
|----------|-------------|----------|
| **ChatEval** | Simple parallel scoring | Fast evaluations |
| **CourtEval** | Adversarial prosecution/defense | Safety assessments |
| **DEBATE** | Structured argumentation rounds | Complex judgments |
| **MoA** | Layered refinement (Mixture-of-Agents) | High accuracy |
| **Consensus** | Iterative agreement-seeking | Controversial cases |

```python
# Use different protocols
request = EvaluationRequest(
    prompt="...",
    candidate_outputs=[...],
    protocol=DebateProtocol.COURTEVAL,  # Adversarial
    max_debate_rounds=3,
    consensus_threshold=0.8,
)
```

## Agent Personas

Pre-configured expert personas:

| Persona | Focus | Default Weight |
|---------|-------|----------------|
| **Safety** | Harmful content, prompt injection | 1.5 |
| **Security** | Jailbreaks, data extraction | 1.5 |
| **Factuality** | Accuracy, hallucinations | 1.0 |
| **Coherence** | Logic, clarity | 0.8 |
| **Helpfulness** | Task completion | 1.0 |

```python
from meta_eval.schemas import AgentConfig, AgentPersona, AgentRole

# Custom agent
agent = AgentConfig(
    name="CustomSafety",
    persona=AgentPersona.SAFETY,
    roles=[AgentRole.SCORER, AgentRole.CRITIC],
    weight=2.0,
    temperature=0.2,
)
manager.register_agent(agent)
```

## Consistency Metrics

### IPI (Intra-Pair Instability)

Measures preference flips when A/B presentation order is swapped.

```python
from meta_eval import ConsistencyChecker

checker = ConsistencyChecker(manager)
ipi, violations = await checker.measure_ipi(
    prompt="Which is better?",
    output_a="Response A",
    output_b="Response B",
)
print(f"IPI: {ipi:.2%}")  # 0% = perfectly stable
```

### TOV (Total Order Violation)

Detects transitivity violations (A>B, B>C but not A>C).

```python
tov, violations = await checker.measure_tov(
    prompt="Rank these",
    outputs=["A", "B", "C"],
)
print(f"TOV: {tov:.2%}")  # 0% = fully transitive
```

## REST API

Start the API server:

```bash
python -m meta_eval.api.server
```

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/evaluate` | Submit evaluation request |
| GET | `/metrics` | Get IPI, TOV, KPIs |
| POST | `/agents` | Add/update agent |
| GET | `/agents` | List all agents |
| DELETE | `/agents/{id}` | Remove agent |
| POST | `/consistency` | Run consistency check |
| POST | `/feedback` | Submit human feedback |
| GET | `/health` | Health check |

### Example: Evaluate via API

```bash
curl -X POST http://localhost:8000/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "What is 2+2?",
    "candidate_outputs": [{"content": "4"}],
    "protocol": "chateval"
  }'
```

## Training & Optimization

### Reinforcement Learning

Adjust agent weights based on consensus agreement:

```python
from meta_eval.training import RLTrainer, TrainingConfig

trainer = RLTrainer(
    manager,
    config=TrainingConfig(
        learning_rate=0.01,
        agreement_reward=1.0,
        disagreement_penalty=-0.5,
    ),
)

# Record experience after each evaluation
trainer.record_experience(result)

# Weights are automatically adjusted
```

### Bayesian Optimization

Tune hyperparameters for optimal accuracy vs consistency:

```python
from meta_eval.training import BayesianOptimizer

optimizer = BayesianOptimizer(manager, engine, checker)

best_params = await optimizer.optimize(
    validation_samples=test_data,
    ground_truth=labels,
)
```

## Integration with Creatine

The meta-eval framework integrates with Creatine's detection pipeline:

```python
from creatine import AdaptiveDetector
from meta_eval import DebateEngine, AgentManager

# Use meta-eval for Tier 3 LLM judgment
manager = AgentManager()
engine = DebateEngine(manager)

detector = AdaptiveDetector()
# ... integrate engine.evaluate() into Tier 3 analysis
```

## Testing

```bash
# Run all tests
pytest meta_eval/tests/ -v

# Run specific test file
pytest meta_eval/tests/test_debate.py -v

# Run with coverage
pytest meta_eval/tests/ --cov=meta_eval
```

## Configuration

Environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `AZURE_OPENAI_ENDPOINT` | Azure OpenAI endpoint | Required |
| `AZURE_OPENAI_DEPLOYMENT` | Model deployment name | `gpt-4o` |
| `AZURE_OPENAI_API_VERSION` | API version | `2024-10-21` |

## References

- [Are We on the Right Way to Assessing LLM-as-a-Judge?](https://arxiv.org/html/2508.02990)
- [Mixture-of-Agents Paper](https://arxiv.org/abs/2406.04692)
- [Creatine Detection Framework](https://github.com/mdressman/creatine)
