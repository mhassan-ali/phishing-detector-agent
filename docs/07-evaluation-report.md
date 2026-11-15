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
- Top false positives (with causes and proposed fixes):
  - *None observed in baseline fixture suite.* Legitimate fixtures (`legit_newsletter.eml`, `legit_receipt.eml`) generate only `HDR_DMARC_PASS` (`Severity.INFO`).
- Top false negatives (with causes and proposed fixes):
  - **`fake_delivery.eml` (KNOWN FALSE NEGATIVE in static heuristics)**:
    - *Observed behavior*: Produces 0 evidence items under offline heuristic analyzers (`HeaderAnalyzer`, `URLAnalyzer`, `AttachmentAnalyzer`).
    - *Cause*: The lure utilizes an unknown brand persona (`GlobalParcel Express`), an attacker-controlled domain (`parcel-delivery.test`) that successfully passes SPF authentication, and a non-typosquatted destination URL (`customs-fee-portal.test`).
    - *Resolution / Architectural mitigation*: Per design, static heuristics are not meant to catch this alone; detection relies on multi-layered defense:
      1. `ContentAnalyzer` (LLM-based detection of customs fee pressure, urgency, and package lure).
      2. Threat intelligence (URL lookup on URLhaus / Google Safe Browsing / VirusTotal in Phase 4).
      3. ML URL feature classification (Phase 5).
      *Do not add "GlobalParcel" to `brands.yaml` to artificially force heuristic detection.*
- Slice analysis (language, brand, URL type, with/without attachments)

## 7. Robustness
Results of injection, SSRF, malformed-input, and size-limit tests. Note any residual failures.

## 8. Threshold & weight tuning
Document how thresholds/weights were chosen, on which data, and an ADR link. Avoid tuning on the test set.

## 9. Limitations & threats to validity
Dataset age, label noise, distribution shift, small adversarial set, LLM nondeterminism, free-tier API variability.

## 10. Reproducibility
Commands, seeds, commit hash, model version, LLM model name and date of run.
