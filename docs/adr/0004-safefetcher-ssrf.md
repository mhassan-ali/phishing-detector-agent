# ADR-0004: Central SafeFetcher for all outbound fetches

- **Status:** Accepted
- **Date:** 2026-11-14
- **Deciders:** Project owner

## Context
URL analysis can tempt code to fetch attacker-supplied URLs, creating SSRF and internal-network exposure.

## Decision
All outbound HTTP to untrusted URLs goes through one SafeFetcher: http/https only; resolve DNS then block private, loopback, link-local, multicast, reserved, and cloud-metadata ranges (IPv4 and IPv6); re-validate every redirect hop; pin the resolved IP for the request; cap redirects, bytes, and time; no JS execution. Default analysis avoids fetching and relies on lookups.

## Alternatives considered
- **Scattered httpx calls:** rejected (inconsistent protection).
- **Headless browser by default:** rejected for v1 (large attack surface; stretch goal in isolation).

## Consequences
- One audited chokepoint; testable with adversarial cases.
- Some legitimate sites may be unreachable (acceptable).
- Must be kept updated for new IP edge cases.
