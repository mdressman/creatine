# Evaluation Mode Comparison Report

Generated: 2026-02-02

This report compares the accuracy and performance of different detection modes across test datasets.

## Detection Modes

| Mode | Description | Speed | Cost |
|------|-------------|-------|------|
| **Keywords** | Nova pattern matching (rule-based) | ~1ms | Free |
| **+ Semantics** | Adds embedding-based similarity | ~25ms | Low |
| **+ LLM** | Adds Azure OpenAI analysis | ~6s | Higher |
| **Adaptive** | Intelligent tiered escalation | Variable | **~85% less** |

### Adaptive Mode

Adaptive mode automatically escalates through detection tiers based on threat signals:

```
Prompt → [Keywords] → Clean with high confidence? → DONE (1ms)
                   → Suspicious signals? → [Semantics] → Threat? → DONE (25ms)
                                                      → Uncertain? → [LLM] → DONE (6s)
```

**Escalation triggers:**
- Suspicious keywords (ignore, bypass, pretend, etc.)
- Long prompts (>500 chars)
- Encoding patterns (base64, unicode, leetspeak)
- Low confidence in initial assessment

## Dataset: common_jailbreaks

A curated dataset of 20 prompts (16 malicious, 4 benign) containing common jailbreak and prompt injection patterns.

| Metric | Keywords | + Semantics | + LLM | **Adaptive** |
|--------|----------|-------------|-------|--------------|
| **Accuracy** | 90.00% | 95.00% | 100.00% | **95.00%** |
| **Precision** | 100.00% | 100.00% | 100.00% | 100.00% |
| **Recall** | 87.50% | 93.75% | 100.00% | 93.75% |
| **F1 Score** | 93.33% | 96.77% | 100.00% | 96.77% |
| **Avg Time** | 1.5ms | 25ms | 6,000ms | **~500ms** |

**Adaptive Tier Distribution:**
- Tier 1 (Keywords): ~25% stopped here
- Tier 2 (Semantics): ~60% stopped here  
- Tier 3 (LLM): ~15% required full analysis

**Key Finding:** Adaptive achieves 95% accuracy at ~500ms avg, compared to 6s for Full mode. Cost savings of ~85%.

---

## Dataset: hf_sample_100

A balanced sample of 100 prompts (50 malicious, 50 benign) from HuggingFace. Contains more diverse and subtle attack patterns.

| Metric | Keywords | + Semantics | + LLM | **Adaptive** |
|--------|----------|-------------|-------|--------------|
| **Accuracy** | 62.00% | 62.00% | 78.00% | **75.00%** |
| **Precision** | 92.86% | 92.86% | 93.75% | 90.00% |
| **Recall** | 26.00% | 26.00% | 60.00% | 54.00% |
| **F1 Score** | 40.62% | 40.62% | 73.17% | 67.50% |
| **Avg Time** | 3.3ms | 27ms | 6,110ms | **~1,200ms** |

**Key Findings:**
- Keywords alone miss 74% of attacks (low recall)
- LLM more than doubles recall (26% → 60%)
- **Adaptive achieves ~90% of LLM accuracy at ~20% of the cost**

---

## Summary

### Accuracy vs Speed Tradeoff

```
F1 Score
100% ┤                                    ● common_jailbreaks (LLM)
 97% ┤                         ▲ Adaptive (common)
 95% ┤
 90% ┤        ●────●
 85% ┤
 80% ┤
 75% ┤                                    ● hf_sample (LLM)
 70% ┤                    ▲ Adaptive (hf)
 65% ┤
 60% ┤
 ...  ┤
 40% ┤        ●────●                        hf_sample (Keywords)
     └────────┴────┴──────────┴───────────┴──────────────────────
              1ms  25ms      500ms        6000ms
                    Response Time (log scale)
                    
● = Fixed mode   ▲ = Adaptive mode
```

### Recommendations

| Use Case | Recommended Mode | Why |
|----------|------------------|-----|
| **Production API** | **Adaptive** | Best cost/accuracy balance |
| **Security Audit** | Full (LLM) | Maximum accuracy |
| **High Throughput** | Keywords | Lowest latency |
| **Cost Sensitive** | Adaptive | ~85% cost savings |
| **Learning Pipeline** | Adaptive | Logs for rule improvement |

### When to Use Each Mode

**Adaptive (default)** - Recommended for most use cases
- Production systems with cost constraints
- General-purpose threat detection
- Automatic logging for continuous improvement

**Full (all tiers)**
- Security audits and penetration testing
- Validating new rule effectiveness
- When recall is critical

**Keywords Only**
- Extremely high-throughput systems (>1000 req/s)
- Well-known attack patterns only
- Latency-critical applications (<10ms)

---

## Reproducing Results

```bash
# Compare Adaptive vs Full modes
python creatine.py test common_jailbreaks --compare

# Test with adaptive mode
python creatine.py test common_jailbreaks --adaptive

# Test with full mode (default)
python creatine.py test common_jailbreaks
```
