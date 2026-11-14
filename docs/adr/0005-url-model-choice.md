# ADR-0005: Lexical/host-feature URL classifier with tree ensembles

- **Status:** Accepted
- **Date:** 2026-11-14
- **Deciders:** Project owner

## Context
We need a fast, safe-at-inference URL signal with explainability, without fetching pages.

## Decision
Compare Logistic Regression, Random Forest, and XGBoost on lexical and host features only; select by cross-validated metrics under an FPR constraint; explain with SHAP/feature importances. Domain-grouped splits to avoid leakage.

## Alternatives considered
- **Deep/char-CNN models:** heavier, harder to explain, limited gain for the scope.
- **Content-based features requiring fetch:** rejected for safety/SSRF reasons.

## Consequences
- Fast, offline, explainable, safe.
- Cannot see page content; vulnerable to lexical evasion; mitigated by other analyzers.
- Dataset artifacts must be audited (see model card).
