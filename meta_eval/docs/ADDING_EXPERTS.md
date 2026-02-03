# Adding Domain Expert Agents

This guide explains how to create specialized domain expert agents for the Meta-Evaluation Framework. Domain experts bring deep subject matter knowledge to the evaluation panel, improving detection accuracy for specific threat categories.

## Overview

Domain experts differ from generic agents in three key ways:

1. **Specialized Persona**: A custom persona enum value for the domain
2. **Detailed Rubric**: Multi-criteria evaluation framework with weighted scoring
3. **Expert System Prompt**: Deep domain knowledge encoded in the agent's instructions

## Step-by-Step Process

### 1. Define the Persona (Optional)

If your domain doesn't fit existing personas, add a new one to `AgentPersona` in `meta_eval/schemas.py`:

```python
class AgentPersona(Enum):
    # ... existing personas ...
    
    # Add your domain-specific persona
    CYBER_SECURITY = "cyber_security"  # Deep technical security research
    LEGAL = "legal"                    # Legal/compliance expertise
    YOUR_DOMAIN = "your_domain"        # Description
```

### 2. Create the Evaluation Rubric

The rubric defines **what** your expert evaluates and **how** criteria are weighted.

```python
YOUR_DOMAIN_RUBRIC = EvaluationRubric(
    criteria={
        # Each criterion is: key -> description
        "criterion_1": "Detailed description of what this criterion evaluates",
        "criterion_2": "Another evaluation dimension",
        "criterion_3": "Yet another dimension to assess",
        # Add 5-10 criteria for comprehensive coverage
    },
    scoring_scale=(0, 10),  # Min and max scores
    weights={
        # Weights should sum to 1.0
        "criterion_1": 0.30,  # Most important
        "criterion_2": 0.25,
        "criterion_3": 0.20,
        # ... etc
    },
)
```

**Rubric Design Tips:**
- Include 5-10 criteria for balanced coverage
- Weight critical criteria higher (0.15-0.30)
- Ensure weights sum to 1.0
- Write descriptions that an LLM can operationalize

### 3. Write the System Prompt

The system prompt encodes the expert's knowledge and evaluation approach. Structure it as:

```python
YOUR_EXPERT_SYSTEM_PROMPT = """You are a [Role] with deep expertise in:

**TECHNICAL DOMAINS:**
- Domain area 1 with specific sub-areas
- Domain area 2 with specific sub-areas
- Domain area 3 with specific sub-areas

**DETECTION FOCUS:**
You specialize in detecting [specific threats], including:
1. **Category 1**: Specific examples and patterns
2. **Category 2**: Specific examples and patterns
3. **Category 3**: Specific examples and patterns

**EVALUATION APPROACH:**
- Key principle 1
- Key principle 2
- Key principle 3

**OUTPUT FORMAT:**
Provide structured analysis with:
- Classification
- Confidence with reasoning
- Specific indicators identified
- Risk score with justification"""
```

**System Prompt Tips:**
- Be specific about expertise areas
- List concrete detection patterns
- Define clear output structure
- Include domain-specific frameworks (e.g., MITRE ATT&CK, OWASP)

### 4. Create the Agent Configuration

```python
YOUR_EXPERT_AGENT = AgentConfig(
    name="YourExpertName",
    persona=AgentPersona.YOUR_DOMAIN,
    roles=[AgentRole.SPECIALIST, AgentRole.SCORER],  # Typical roles
    weight=2.0,          # Higher weight for domain-critical evaluations
    temperature=0.2,     # Low temp for consistent, precise analysis
    max_tokens=2048,     # Allow detailed analysis
    rubric=YOUR_DOMAIN_RUBRIC,
    system_prompt=YOUR_EXPERT_SYSTEM_PROMPT,
)

# Add to domain experts list
DOMAIN_EXPERT_AGENTS.append(YOUR_EXPERT_AGENT)
```

### 5. Register the Agent

In your application code:

```python
from meta_eval import AgentManager
from meta_eval.schemas import YOUR_EXPERT_AGENT

manager = AgentManager()
manager.register_agent(YOUR_EXPERT_AGENT)
```

Or load all domain experts:

```python
from meta_eval.schemas import DOMAIN_EXPERT_AGENTS

for agent in DOMAIN_EXPERT_AGENTS:
    manager.register_agent(agent)
```

## Example: Security Researcher Expert

See `meta_eval/schemas.py` for the complete `SECURITY_RESEARCHER_AGENT` implementation, which includes:

- **8 evaluation criteria** covering malware, recon, TTPs, IOCs, social engineering, privilege escalation, exfiltration, and evasion
- **Weighted scoring** prioritizing malware detection (0.20) and social engineering (0.15)
- **Detailed system prompt** with MITRE ATT&CK alignment and structured output format

## Role Selection Guide

Choose roles based on your expert's function:

| Role | Use When |
|------|----------|
| `SPECIALIST` | Deep domain expertise, called for specific domains |
| `SCORER` | Should vote on pass/fail verdicts |
| `CRITIC` | Should challenge other agents' evaluations |
| `DEFENDER` | Should defend against overly aggressive criticism |
| `COMMANDER` | Should synthesize and make final decisions |

Most domain experts should be `SPECIALIST + SCORER`. Add `CRITIC` if the expert should challenge other evaluations.

## Weight Guidelines

| Weight | Use Case |
|--------|----------|
| 0.5-0.8 | Supplementary perspective |
| 1.0 | Standard equal weight |
| 1.5 | Important domain |
| 2.0+ | Critical domain (security, safety) |

## Temperature Guidelines

| Temperature | Use Case |
|-------------|----------|
| 0.1-0.2 | Precise, consistent analysis (security, legal) |
| 0.3-0.5 | Balanced analysis (most domains) |
| 0.6-0.8 | Creative evaluation (content quality) |

## Testing Your Expert

```python
import asyncio
from meta_eval import AgentManager, DebateEngine, EvaluationRequest, CandidateOutput

async def test_expert():
    manager = AgentManager(auto_load_samples=False)
    manager.register_agent(YOUR_EXPERT_AGENT)
    
    engine = DebateEngine(manager)
    
    request = EvaluationRequest(
        prompt="Test prompt in your domain",
        candidate_outputs=[CandidateOutput(content="Test response")],
    )
    
    result = await engine.evaluate(request)
    print(f"Verdict: {result.verdict}")
    print(f"Score: {result.score}")
    for vote in result.agent_votes:
        print(f"  {vote.agent_name}: {vote.rationale}")

asyncio.run(test_expert())
```

## Domain Expert Ideas

| Domain | Focus Areas |
|--------|-------------|
| **Legal** | Contract analysis, compliance, regulatory violations, liability |
| **Medical** | Clinical accuracy, drug interactions, diagnostic safety, HIPAA |
| **Financial** | Market manipulation, fraud detection, AML, trading compliance |
| **Code Review** | Security vulnerabilities, code quality, best practices, OWASP |
| **Privacy** | PII detection, data handling, GDPR/CCPA compliance |
| **Misinformation** | Fact verification, source credibility, propaganda detection |

## Troubleshooting

**Expert not being selected:**
- Ensure `enabled=True` (default)
- Check persona matches request filters
- Verify roles include `SCORER` or `SPECIALIST`

**Inconsistent evaluations:**
- Lower temperature (0.1-0.2)
- Add more specific criteria to rubric
- Improve system prompt specificity

**Low confidence scores:**
- Expand system prompt with more examples
- Add more evaluation criteria
- Review rubric weight distribution
