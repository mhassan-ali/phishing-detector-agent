# ADR-0007: Use Google Safe Browsing v4 Lookup API

- **Status:** Accepted
- **Date:** 2026-11-14
- **Deciders:** Project owner, Antigravity agent

## Context
PhishGuard requires reputation lookups for URLs against Google Safe Browsing. Both Safe Browsing v4 (Lookup API and Update API) and Safe Browsing v5 are production-ready. The system needs a low-complexity, reliable integration for per-scan URL queries.

## Decision
Use the **Google Safe Browsing v4 Lookup API** (`POST /v4/threatMatches:find`) over HTTPS with API key authentication.

## Alternatives considered
- **Safe Browsing v5:** Provides hash-prefix matching for enhanced client privacy (sending partial 32-bit SHA-256 prefixes rather than URLs). However, it requires maintaining local binary hash databases, periodic synchronization routines, and stateful caching infrastructure.
- **Safe Browsing v4 Update API:** Also requires local database synchronization and prefix management.
- **Third-party aggregators:** Adds unnecessary intermediate failure points and third-party credential exposure.

## Consequences
- **Pros:**
  - Stateless, straightforward HTTP/JSON REST interaction.
  - Zero local database synchronization or client-side prefix matching complexity.
  - Readily mockable and testable in unit test suites.
- **Cons & Mitigations:**
  - *Privacy:* The Lookup API sends the full URL to Google. **Mitigation:** The indicator selector strips query parameters and URL fragments by default (`PHISHGUARD_INTEL_SEND_FULL_URLS=false`), preventing transmission of authentication tokens or personal parameters.
  - *Licensing:* Safe Browsing API is restricted to non-commercial evaluation unless commercial licensing is secured from Google.
