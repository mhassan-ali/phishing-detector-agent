# ADR-0001: Record architecture decisions

- **Status:** Accepted
- **Date:** 2026-11-14
- **Deciders:** Project owner

## Context
Many design choices (frameworks, scoring, security boundaries) need to be traceable for reviewers and future us.

## Decision
Use lightweight ADRs in `docs/adr/`, numbered `NNNN-slug.md`, using this template: Status, Date, Deciders,
Context, Decision, Alternatives considered, Consequences. Statuses: Proposed, Accepted, Superseded by ADR-XXXX.
Agents must add an ADR for any change to the tech stack, scoring rubric, or security boundary.

## Alternatives considered
Wiki pages (drift from code); no records (lost rationale).

## Consequences
Small overhead per decision; much better auditability.
