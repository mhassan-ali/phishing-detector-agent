# ADR-0006: SQLite with SQLAlchemy for cache and history

- **Status:** Accepted
- **Date:** 2026-11-14
- **Deciders:** Project owner

## Context
Local-first tool needs scan history and an intel cache with minimal ops overhead.

## Decision
Use SQLite via SQLAlchemy 2.x. Store input SHA-256, verdict JSON, and cache entries with TTL. Raw content storage is opt-in.

## Alternatives considered
- **Postgres:** unnecessary operational weight for v1.
- **Flat JSON files:** poor querying and concurrency.

## Consequences
- Zero-config, portable, adequate for single-node use.
- Limited concurrency; migrate to Postgres by changing the DB URL if needed.
- Must handle file permissions and backups.
