# 07: Evaluation Report

> **Status: TEMPLATE.** Populate in Phase 9 from `scripts/evaluate.py` output. Report real numbers, including
> unflattering ones.

## 1. Objective
Measure detection quality, robustness, latency, and cost of the full pipeline versus ablations.

## 2. Datasets
| Set | Source | Size | Phishing / Legit | Notes |
|---|---|---|---|---|
| URL holdout | _TBD_ | | | Domain-disjoint from training |
| Email holdout | _TBD (e.g., public phishing corpus + public ham)_ | | | |
| Adversarial set | Hand-built, synthetic | | | Injection, SSRF, evasion patterns |

Describe labeling process, dedup, and leakage checks.

## 3. Configurations (ablations)
| ID | Configuration |
|---|---|
| A | Rules/heuristics only |
| B | ML only (URLs) |
| C | LLM content analysis only |
| D | Rules + ML + intel (no LLM) |
| E | Full pipeline |

## 4. Results
| Config | Precision | Recall | F1 | FPR | p50 latency | p95 latency | Cost/scan |
|---|---|---|---|---|---|---|---|
| A | | | | | | | |
| B | | | | | | | |
| C | | | | | | | |
| D | | | | | | | |
| E | | | | | | | |

Include: confusion matrices, ROC/PR curves, score distribution by label, threshold sweep.

## 5. Targets vs actual
| Metric | Target | Actual | Met? |
|---|---|---|---|
| Recall | >= 95% | | |
| FPR | <= 2% | | |
| p95 latency | <= 15 s | | |
| Adversarial pass rate | 100% | | |

## 6. Error analysis
- Top false positives (with causes and proposed fixes)
- Top false negatives (with causes and proposed fixes)
- Slice analysis (language, brand, URL type, with/without attachments)

## 7. Robustness
Results of injection, SSRF, malformed-input, and size-limit tests. Note any residual failures.

## 8. Threshold & weight tuning
Document how thresholds/weights were chosen, on which data, and an ADR link. Avoid tuning on the test set.

## 9. Limitations & threats to validity
Dataset age, label noise, distribution shift, small adversarial set, LLM nondeterminism, free-tier API variability.

## 10. Reproducibility
Commands, seeds, commit hash, model version, LLM model name and date of run.
