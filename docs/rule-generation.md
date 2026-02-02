# AI-Powered Rule Generation

The Rule Generation Agent uses Azure OpenAI to analyze threat patterns and generate sophisticated Nova detection rules with iterative optimization.

## How It Works

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Data Sources  │────▶│  AI Generation   │────▶│  Initial Rules  │
│                 │     │  (Azure OpenAI)  │     │                 │
└─────────────────┘     └──────────────────┘     └────────┬────────┘
                                                          │
                                                          ▼
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Optimized      │◀────│  AI Analysis     │◀────│  Test Results   │
│  Rules          │     │  (iterate)       │     │  (FP/FN)        │
└─────────────────┘     └──────────────────┘     └─────────────────┘
```

### 1. Data Collection

The agent collects threat examples from multiple sources:

- **PromptIntel Feed**: Real-world prompt injection/jailbreak attempts
- **HuggingFace Datasets**: Public security datasets (e.g., `deepset/prompt-injections`)
- **Local Files**: Custom threat collections
- **Custom Prompts**: Manually specified examples

### 2. Initial Rule Generation

Azure OpenAI analyzes the collected prompts and generates Nova rules:

- Identifies common patterns and keywords
- Groups similar attack types
- Creates rules with appropriate severity levels
- Uses AND conditions for higher precision

### 3. Iterative Optimization

The agent tests rules against a dataset and improves them:

1. **Test**: Run rules against labeled test data
2. **Analyze**: Identify false positives (FP) and false negatives (FN)
3. **Improve**: Send error samples to AI for rule refinement
4. **Repeat**: Continue until targets met or max iterations reached

## Usage

### Basic Rule Generation

```bash
python creatine.py generate-rules --test-dataset common_jailbreaks -v
```

This will:
1. Fetch indicators from PromptIntel
2. Generate initial rules with AI
3. Test against `common_jailbreaks` dataset
4. Iterate to improve precision/recall
5. Save optimized rules to `rules/agent_optimized.nov`

### Adding Multiple Data Sources

```bash
python creatine.py generate-rules \
  --test-dataset common_jailbreaks \
  --add-huggingface deepset/prompt-injections \
  -v
```

### Custom Optimization Targets

```bash
# High precision (fewer false positives)
python creatine.py generate-rules \
  --test-dataset common_jailbreaks \
  --target-precision 0.98 \
  --target-recall 0.80 \
  -v

# High recall (catch more attacks)
python creatine.py generate-rules \
  --test-dataset common_jailbreaks \
  --target-precision 0.85 \
  --target-recall 0.95 \
  -v
```

## Optimization Process

### Metrics Tracked

| Metric | Description | Target |
|--------|-------------|--------|
| Precision | TP / (TP + FP) | 0.9 default |
| Recall | TP / (TP + FN) | 0.9 default |
| F1 Score | 2 × (P × R) / (P + R) | - |

### Error Analysis

The agent analyzes errors to improve rules:

**False Negatives (missed attacks):**
- AI examines missed malicious prompts
- Identifies missing patterns or keywords
- Adds new rules or expands existing ones

**False Positives (incorrect detections):**
- AI examines incorrectly flagged benign prompts
- Identifies overly broad patterns
- Adds AND conditions or refines keywords

### Example Optimization Output

```
Iteration 1: Precision=0.75, Recall=0.90, F1=0.82
  - 3 false positives (benign flagged as malicious)
  - 2 false negatives (attacks missed)

Iteration 2: Precision=0.88, Recall=0.95, F1=0.91
  - Added AND conditions to reduce FP
  - Added new keyword patterns for FN

Iteration 3: Precision=0.92, Recall=0.93, F1=0.92
  ✓ Targets met!
```

## Configuration

### Environment Variables

```bash
# Required for AI rule generation
AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com/
AZURE_OPENAI_DEPLOYMENT_NAME=gpt-4

# Required for PromptIntel data source
PROMPTINTEL_API_KEY=your-api-key
```

### Agent Parameters

```python
from agents import RuleGenerationAgent

agent = RuleGenerationAgent(
    target_precision=0.9,   # Minimum acceptable precision
    target_recall=0.9,      # Minimum acceptable recall
    max_iterations=3,       # Max optimization loops
    verbose=True            # Show detailed progress
)
```

## Programmatic Usage

```python
from agents import RuleGenerationAgent

# Create agent
agent = RuleGenerationAgent(verbose=True)

# Add data sources
agent.add_promptintel_source()
agent.add_huggingface_source("deepset/prompt-injections")

# Run optimization
result = await agent.run(
    test_dataset="common_jailbreaks",
    output_file="my_rules.nov",
    target_precision=0.9,
    target_recall=0.9,
)

# Access results
print(f"Final F1: {result.final_metrics['f1']:.2%}")
print(f"Rules saved to: rules/{result.output_file}")
```

## Tips for Best Results

1. **Use diverse test data**: Include both obvious attacks and subtle ones
2. **Balance your dataset**: Ensure enough benign samples to measure precision
3. **Start with lower targets**: Begin with 0.8/0.8 and increase gradually
4. **Add domain-specific data**: Include threats relevant to your use case
5. **Review generated rules**: AI rules may need manual refinement

## Limitations

- **Content filters**: Azure may block some adversarial prompts during analysis
- **Rule complexity**: Very sophisticated attacks may need manual rules
- **Dataset quality**: Results depend on test data quality and labeling
