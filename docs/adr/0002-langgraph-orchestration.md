# ADR-0002: Use LangGraph for agent orchestration

- **Status:** Accepted
- **Date:** 2026-11-14
- **Deciders:** Project owner

## Context
The pipeline has parallel independent analyzers, shared state, failure handling, and a fan-in verdict step.

## Decision
Use LangGraph with a typed shared state, parallel fan-out nodes, and one state key per node to avoid write conflicts.

## Alternatives considered
- **Plain asyncio:** simplest, but we lose built-in state/graph visualization.
- **Google ADK:** good fit with Gemini; less control over deterministic fan-in at decision time.
- **CrewAI/AutoGen:** conversational multi-agent is unnecessary and less deterministic.

## Consequences
- Explicit, inspectable, testable graph.
- Learning curve; dependency on LangGraph API stability (pin version).
- Google ADK remains a viable future migration because nodes are plain functions.
