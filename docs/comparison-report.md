# Evaluation Mode Comparison Report

Generated: 2026-02-01

This report compares the accuracy and performance of different Nova evaluation modes across test datasets.

## Evaluation Modes

| Mode | Description | Speed |
|------|-------------|-------|
| **Baseline** | Default rules only (7 hand-crafted rules) | ~1ms |
| **Keywords** | Default + feed-generated rules (26 rules) | ~3ms |
| **+ Semantics** | Adds embedding-based similarity matching | ~25ms |
| **+ LLM** | Adds Azure OpenAI analysis (full evaluation) | ~6s |

## Dataset: common_jailbreaks

A curated dataset of 20 prompts (16 malicious, 4 benign) containing common jailbreak and prompt injection patterns.

| Metric | Baseline | Keywords | + Semantics | + LLM | Improvement |
|--------|----------|----------|-------------|-------|-------------|
| **Accuracy** | 90.00% | 90.00% | 95.00% | **100.00%** | ↑ +10.00% |
| **Precision** | 100.00% | 100.00% | 100.00% | **100.00%** | → +0.00% |
| **Recall** | 87.50% | 87.50% | 93.75% | **100.00%** | ↑ +12.50% |
| **F1 Score** | 93.33% | 93.33% | 96.77% | **100.00%** | ↑ +6.67% |

| Confusion Matrix | Baseline | Keywords | + Semantics | + LLM |
|------------------|----------|----------|-------------|-------|
| True Positives | 14 | 14 | 15 | 16 |
| True Negatives | 4 | 4 | 4 | 4 |
| False Positives | 0 | 0 | 0 | 0 |
| False Negatives | 2 | 2 | 1 | 0 |

| Avg Response Time | 0.5ms | 1.5ms | 20ms | 6,000ms |

**Key Findings:**
- Keywords catch most common patterns effectively (93% F1)
- Semantics adds marginal improvement (+3% F1)
- LLM achieves perfect detection on this dataset

---

## Dataset: hf_sample_100

A balanced sample of 100 prompts (50 malicious, 50 benign) from the [neuralchemy/Prompt-injection-dataset](https://huggingface.co/datasets/neuralchemy/Prompt-injection-dataset) on HuggingFace. This dataset contains more diverse and subtle attack patterns.

| Metric | Baseline | Keywords | + Semantics | + LLM | Improvement |
|--------|----------|----------|-------------|-------|-------------|
| **Accuracy** | 61.00% | 62.00% | 62.00% | **78.00%** | ↑ +17.00% |
| **Precision** | 92.31% | 92.86% | 92.86% | **93.75%** | ↑ +1.44% |
| **Recall** | 24.00% | 26.00% | 26.00% | **60.00%** | ↑ +36.00% |
| **F1 Score** | 38.10% | 40.62% | 40.62% | **73.17%** | ↑ +35.08% |

| Confusion Matrix | Baseline | Keywords | + Semantics | + LLM |
|------------------|----------|----------|-------------|-------|
| True Positives | 12 | 13 | 13 | 30 |
| True Negatives | 49 | 49 | 49 | 48 |
| False Positives | 1 | 1 | 1 | 2 |
| False Negatives | 38 | 37 | 37 | 20 |

| Avg Response Time | 0.9ms | 3.3ms | 27.2ms | 6,110ms |

**Key Findings:**
- Keywords alone miss 74% of attacks (low recall)
- Semantics provides no improvement on this dataset
- **LLM more than doubles recall** (26% → 60%)
- LLM improves F1 score by **+35 percentage points**
- High precision maintained across all modes (>92%)

---

## Summary

### Accuracy vs Speed Tradeoff

```
F1 Score
100% ┤                                    ● common_jailbreaks (LLM)
 95% ┤                              ●
 90% ┤        ●────●────●
 85% ┤
 80% ┤
 75% ┤                                    ● hf_sample (LLM)
 70% ┤
 65% ┤
 60% ┤
...  ┤
 40% ┤        ●────●────●                   hf_sample (Keywords)
 35% ┤
     └────────┴────┴────┴─────────────────┴──────────────────────
              1ms  3ms  25ms              6000ms
                    Response Time (log scale)
```

### Recommendations

| Use Case | Recommended Mode | Why |
|----------|------------------|-----|
| **Production API** | Keywords | Fast (~3ms), good precision |
| **Security Audit** | + LLM | Highest accuracy, catches subtle attacks |
| **Batch Processing** | + Semantics | Balance of speed and accuracy |
| **Real-time Chat** | Keywords | Latency-sensitive |
| **Content Moderation** | + LLM | Can't afford to miss attacks |

### When to Use Each Mode

**Keywords Only** (default)
- High-throughput production systems
- Well-known attack patterns
- Latency-sensitive applications

**+ Semantics**
- Catching paraphrased attacks
- Multilingual content
- When keywords miss too many attacks

**+ LLM**
- Security audits and penetration testing
- Validating new rule effectiveness
- When recall is critical
- Offline batch analysis

---

## Reproducing Results

```bash
# Run comparison on common_jailbreaks
python creatine.py test common_jailbreaks --compare

# Create sample from HuggingFace dataset
python -c "
from testing import DatasetRegistry, Dataset
from pathlib import Path
import random

registry = DatasetRegistry(Path('datasets'))
full = registry.get('neuralchemy_Prompt-injection-dataset')

malicious = [p for p in full.prompts if p.is_malicious]
benign = [p for p in full.prompts if not p.is_malicious]

random.seed(42)
sampled = random.sample(malicious, 50) + random.sample(benign, 50)

sample_ds = Dataset(name='hf_sample_100', description='Sample', prompts=sampled)
registry.save_dataset(sample_ds)
"

# Run comparison on sample
python creatine.py test hf_sample_100 --compare
```
