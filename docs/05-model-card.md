# 05: Model Card (URL Phishing Classifier)

> **Status: TEMPLATE.** Fill in during Phase 5 with real results. Do not publish placeholder numbers as facts.

## 1. Model details
| Field | Value |
|---|---|
| Name | `phishguard-url-clf` |
| Version | _TBD_ |
| Date trained | _TBD_ |
| Type | _TBD: Logistic Regression / Random Forest / XGBoost (best by CV)_ |
| Framework | scikit-learn / XGBoost |
| Artifact | `data/models/<version>/model.joblib` + `metadata.json` |
| Owner | _<your name>_ |
| License | MIT (code); dataset licenses per source |

## 2. Intended use
- **Primary:** one signal inside the PhishGuard hybrid pipeline, scoring URLs by lexical and host features.
- **Users:** analysts and developers of PhishGuard.
- **Out of scope:** standalone blocking decisions; classifying email content; non-HTTP(S) schemes; judging
  page content (the model never fetches pages).

## 3. Data
| Item | Detail |
|---|---|
| Training source(s) | PhiUSIIL Phishing URL dataset (and optional additions); legitimate: Tranco top sites |
| Size / class balance | _TBD_ |
| Collection period | _TBD_ |
| Preprocessing | Deduplication, URL normalization, invalid-row removal |
| Split strategy | Stratified; **group by registered domain** to prevent leakage |
| Known issues | Some public datasets contain artifacts (e.g., features that trivially reveal the label); these were excluded: _TBD_ |

## 4. Features
Lexical and host-based only (must match `analyzers/url.py` where shared).
| Feature | Description |
|---|---|
| url_length, host_length, path_length | Lengths |
| digit_ratio, special_char_count | Character composition |
| entropy | Shannon entropy of host/path |
| subdomain_count, has_ip_host | Structure |
| tld_category | Hashed/grouped TLD |
| has_at_symbol, has_punycode, uses_shortener | Obfuscation flags |
| keyword_hits | login, verify, secure, update... |
| _TBD_ | Final list generated from `metadata.json` |

Excluded: any feature requiring page fetch (content-derived features), to keep inference safe and fast.

## 5. Training procedure
- Models compared: Logistic Regression (baseline), Random Forest, XGBoost.
- Stratified, domain-grouped k-fold (k=_TBD_); metric for selection: _TBD (e.g., PR-AUC with FPR constraint)_.
- Class imbalance handling: _TBD_.
- Hyperparameter search: _TBD_.
- Reproducibility: seed _TBD_; `scripts/train.py --seed N`.

## 6. Evaluation
| Metric | Value (holdout) | 95% CI |
|---|---|---|
| Precision | _TBD_ | |
| Recall | _TBD_ | |
| F1 | _TBD_ | |
| ROC-AUC | _TBD_ | |
| False-positive rate | _TBD_ | |

Include confusion matrix, threshold curve, calibration plot, and a slice analysis (by TLD, URL length bucket,
shortener use).

## 7. Explainability
Top contributing features per prediction via _SHAP / feature importances (TBD)_, surfaced as Evidence in the report.

## 8. Limitations
- Trained on URL strings only; cannot see page content or sender context.
- Dataset distribution may not match current in-the-wild campaigns (concept drift).
- Brand-new legitimate domains and legitimate long tracking URLs may look suspicious.
- Public datasets can over-represent certain TLDs and languages; performance on non-English/IDN URLs may be lower.
- Adversaries can adapt URLs to evade lexical models.

## 9. Ethical considerations & bias
- Risk of flagging small/new legitimate businesses or non-Latin-script domains more often.
- Mitigation: "suspicious" tier instead of hard block; combine with other evidence; report slice metrics.

## 10. Maintenance
Retrain cadence: _TBD_. Monitor false-positive reports (see UI feedback, stretch goal). Version every artifact.
