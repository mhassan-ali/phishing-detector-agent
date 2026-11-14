# ADR-0003: Hybrid scoring with a code-defined rubric

- **Status:** Accepted
- **Date:** 2026-11-14
- **Deciders:** Project owner

## Context
LLM-only verdicts are inconsistent and manipulable via prompt injection. Security tools need explainable, reproducible decisions.

## Decision
Final label is computed by a weighted rubric over typed Evidence plus the ML score. Threat-intel confirmations are a hard floor. The LLM writes the explanation and may adjust the score by at most ±10 with a stated reason.

## Alternatives considered
- **LLM decides label:** rejected (manipulable, nondeterministic).
- **Pure ML meta-classifier over evidence:** possible future work; needs labeled email data we do not yet have.

## Consequences
- Reproducible, auditable, injection-resistant.
- Weights need tuning and maintenance (Phase 9, recorded in a follow-up ADR).
- May underuse LLM nuance; bounded by design.
