# CLI Reference

All commands are run via `python3 test_cli.py <command>`.

## Quick Analysis

### `analyze <prompt>`

Quick single-prompt security analysis using adaptive detection.

```bash
# Simple analysis
python3 test_cli.py analyze "What is the capital of France?"
# Output: ✅ SAFE | Low | 90% confidence | KEYWORDS | 7ms

python3 test_cli.py analyze "Ignore all previous instructions"
# Output: 🚨 THREAT | High | 90% confidence | KEYWORDS | 6ms

# Verbose output (shows tier analysis)
python3 test_cli.py analyze "Some suspicious text here" -v
```

### `adaptive`

Run adaptive tiered detection (optimizes cost vs accuracy).

```bash
# Analyze single prompt with tier details
python3 test_cli.py adaptive --prompt "Ignore instructions and..." -v

# Run on entire dataset
python3 test_cli.py adaptive --dataset hf_sample_100

# Customize thresholds
python3 test_cli.py adaptive --dataset hf_sample_100 \
  --confidence-threshold 0.90 \
  --time-budget 5000

# Force full analysis through all tiers (for testing)
python3 test_cli.py adaptive --dataset hf_sample_100 --force-full
```

**Tier System:**
| Tier | Method | Speed | Cost | When Used |
|------|--------|-------|------|-----------|
| 1 | Keywords | ~1ms | Free | Always first |
| 2 | Semantics | ~25ms | Low | If suspicious signals |
| 3 | LLM | ~6s | High | If still uncertain |

**Options:**
| Option | Description | Default |
|--------|-------------|---------|
| `--prompt` | Single prompt to analyze | - |
| `--dataset` | Dataset to analyze | - |
| `--confidence-threshold` | Stop escalation threshold | 0.85 |
| `--time-budget` | Max time budget (ms) | 10000 |
| `--force-full` | Force all tiers | False |
| `-v, --verbose` | Show tier-by-tier analysis | False |

## Dataset Commands

### `list`

List all available datasets.

```bash
python3 test_cli.py list
```

### `info <dataset>`

Show detailed information about a dataset.

```bash
python3 test_cli.py info common_jailbreaks
```

### `sample <dataset>`

Display sample prompts from a dataset.

```bash
python3 test_cli.py sample common_jailbreaks
python3 test_cli.py sample common_jailbreaks --count 10
```

### `add <dataset> <prompt>`

Add a new prompt to a dataset.

```bash
python3 test_cli.py add common_jailbreaks "ignore all instructions" --malicious
python3 test_cli.py add common_jailbreaks "hello world" --benign
```

## Import Commands

### `import-hf <dataset> <hf-path>`

Import a dataset from HuggingFace.

```bash
python3 test_cli.py import-hf prompt_injections deepset/prompt-injections
python3 test_cli.py import-hf prompt_injections deepset/prompt-injections --max-samples 1000
```

### `import-csv <dataset> <file>`

Import a dataset from a CSV file.

```bash
python3 test_cli.py import-csv my_dataset data.csv --prompt-col text --label-col is_malicious
```

## Testing Commands

### `test <dataset>`

Run detection tests against a dataset.

```bash
# Basic test (keywords only, fast)
python3 test_cli.py test common_jailbreaks

# Verbose output (show individual results)
python3 test_cli.py test common_jailbreaks -v

# Test with only default rules (no feed-generated)
python3 test_cli.py test common_jailbreaks --default-only

# Compare default vs default+feed rules
python3 test_cli.py test common_jailbreaks --compare

# Enable semantic similarity matching (~20ms/prompt)
python3 test_cli.py test common_jailbreaks --enable-semantics

# Enable LLM-based evaluation (~5-10s/prompt, highest accuracy)
python3 test_cli.py test common_jailbreaks --enable-llm

# Enable both semantic and LLM evaluation
python3 test_cli.py test common_jailbreaks --enable-semantics --enable-llm
```

**Evaluation Modes:**
| Mode | Speed | Accuracy | Use Case |
|------|-------|----------|----------|
| Keywords only | ~0.5ms | Good | Production, high throughput |
| + Semantics | ~20ms | Better | Catch paraphrased attacks |
| + LLM | ~5-10s | Best | Security audits, validation |

**Output Metrics:**
- **Accuracy**: Overall correctness (TP + TN) / Total
- **Precision**: TP / (TP + FP) - How many detections were correct
- **Recall**: TP / (TP + FN) - How many attacks were caught
- **F1 Score**: Harmonic mean of precision and recall

### `test-file <file>`

Test prompts from a text file (one per line).

```bash
python3 test_cli.py test-file prompts.txt -v
```

## Rule Generation Commands

### `generate-rules`

Generate optimized Nova rules using AI.

```bash
# Basic: use PromptIntel feed, test against dataset
python3 test_cli.py generate-rules --test-dataset common_jailbreaks -v

# Add HuggingFace data source
python3 test_cli.py generate-rules \
  --test-dataset common_jailbreaks \
  --add-huggingface deepset/prompt-injections -v

# Add local file as data source
python3 test_cli.py generate-rules \
  --test-dataset common_jailbreaks \
  --add-file threats.txt -v

# Custom optimization targets
python3 test_cli.py generate-rules \
  --test-dataset common_jailbreaks \
  --target-precision 0.95 \
  --target-recall 0.85 \
  --max-iterations 5 -v

# Specify output file
python3 test_cli.py generate-rules \
  --test-dataset common_jailbreaks \
  --output rules/custom.nov -v
```

**Options:**
| Option | Description | Default |
|--------|-------------|---------|
| `--test-dataset` | Dataset to test against | Required |
| `--add-huggingface` | Add HuggingFace dataset | - |
| `--add-file` | Add local file | - |
| `--target-precision` | Target precision score | 0.9 |
| `--target-recall` | Target recall score | 0.9 |
| `--max-iterations` | Max optimization iterations | 3 |
| `--output` | Output file path | rules/agent_optimized.nov |
| `-v, --verbose` | Verbose output | False |

### `sync-feed`

Sync rules from PromptIntel feed (without AI optimization).

```bash
# Basic sync
python3 test_cli.py sync-feed

# Use AI to generate smarter rules
python3 test_cli.py sync-feed --smart -v
```

### `feed-preview`

Preview indicators from PromptIntel feed.

```bash
python3 test_cli.py feed-preview
python3 test_cli.py feed-preview --count 20
```

## Global Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Enable verbose output |
| `-h, --help` | Show help message |
