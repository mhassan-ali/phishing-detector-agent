# Changelog

All notable changes are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning: [SemVer](https://semver.org/).

## [Unreleased]
### Added
- Phase 4 (Threat intelligence):
  - Sub-Phase 4.0: Closed remaining edge-case coverage gaps across ingestion and base analyzer infrastructure; reclassified ASCII-only leetspeak lookalikes as `URL_TYPOSQUAT_BRAND` while reserving `URL_HOMOGRAPH_CONFUSABLE` for mixed-script/IDN confusables; documented `fake_delivery.eml` as a known false negative in static heuristics; verified `pip-audit` cleanly audits `litellm`.
  - Common threat intelligence protocols and models in `src/phishguard/intel/base.py` (`Indicator`, `IntelResult`, `IntelProvider` protocol, deterministic `compute_indicator_hash`).
  - Hardened outbound client factory in `src/phishguard/intel/client.py`: enforced host allowlist (`ALLOWED_INTEL_HOSTS`), `HostNotAllowedError` boundary, HTTPS enforcement, TLS verification, `follow_redirects=False`, `trust_env=False`, 1 MB response payload cap, non-blocking token bucket rate limiters, global concurrency semaphore, secret redaction in URLs/logs, and backoff with jitter and circuit breaker on exhausted 429 retries.
  - Persistent SQLite cache in `src/phishguard/intel/cache.py` using SQLAlchemy 2.x and WAL mode: zero plaintext indicator storage (hashes only), capped threat types and summaries without raw responses, differential TTL (1h for clean/unknown, 24h for positive findings), accessed via `asyncio.to_thread`.
  - Pure indicator selector in `src/phishguard/intel/selector.py`: prioritized ordering (attachment SHA-256 hashes first for `FR-ATT-3`, flagged URLs second, remaining domains third); automatic query string and fragment stripping by default; loopback, private, link-local, and reserved IP filtering (`is_private_or_reserved_ip`).
  - Threat intelligence providers:
    - VirusTotal v3 (`virustotal.py`): File hash reputation lookup (`FR-ATT-3`), domain/URL reputation; HTTP 404 handled as unknown without submissions; zero POST calls made; per-scan lookup cap enforcement.
    - abuse.ch URLhaus (`urlhaus.py`): Exact URL, host, and payload hash queries using authenticated `URLHAUS_AUTH_KEY`.
    - OpenPhish (`openphish.py`): Community feed stream check with configurable byte cap (`OPENPHISH_MAX_FEED_BYTES`), failing soft with error if feed is truncated.
    - Google Safe Browsing v4 (`safebrowsing.py`): `threatMatches:find` queries with query key redaction and non-commercial disclaimer.
    - urlscan.io (`urlscan.py`): Strictly search-only (`GET /api/v1/search/`), query escaping against quotes and operator injection, zero raw page content copied to evidence.
  - Threat intelligence analyzer in `src/phishguard/intel/analyzer.py`: concurrent orchestration of providers with `PHISHGUARD_INTEL_DEADLINE_SECONDS` deadline; statuses (`ok`, `partial`, `skipped`); evidence emission adhering to `INTEL_CONFIRMED_MALICIOUS` (exact URLs or file hashes with $\ge 5$ engines), `INTEL_SUSPICIOUS` (domain/host hits), and `INTEL_NOT_LISTED` (emitted at most once per scan).
  - ADR-0007 (`docs/adr/0007-google-safe-browsing-v4-lookup.md`) selecting Safe Browsing v4 Lookup API over v5 hash-prefix synchronization.
  - Unit and integration tests with `respx` mocks under offline socket guard verifying all provider branches, allowlist checks, cache hits/expiry, selector priority/capping, and analyzer statuses.
- Phase 3 (Analyzers):
  - Sub-Phase 3.0: Closed error-handling coverage gaps across `ingest/extractor.py`, `ingest/normalizer.py`, and `ingest/parser.py`; added linear ReDoS verification test in `tests/adversarial/test_redos.py` (100k-char crafted payload processed in < 1.0s).
  - Package reference data in `src/phishguard/data/` (`brands.yaml`, `shorteners.yaml`, `suspicious_tlds.yaml`) loaded via `importlib.resources`.
  - Shared analyzer infrastructure in `src/phishguard/analyzers/base.py`: synchronous and asynchronous `run_analyzer` runner with duration timing and soft-failure exception trapping; `create_evidence` with bounded descriptions and deterministic 2 KB `raw_data` capping; and `deduplicate_evidence` by `(code, registered_domain)` capped at 5 per code.
  - Stable evidence code vocabulary `EvidenceCode` StrEnum in `src/phishguard/analyzers/codes.py` covering header (`HDR_*`), URL (`URL_*`), content (`CNT_*`), and attachment (`ATT_*`) findings.
  - Header analyzer in `src/phishguard/analyzers/header.py`: RFC 8601 `Authentication-Results` evaluation with configurable `PHISHGUARD_TRUSTED_AUTHSERV_IDS` validation; DMARC/SPF/DKIM pass/fail checks; SPF and DKIM alignment verification against `From`; `Reply-To` and `Return-Path` domain mismatch detection; display name spoofing against brand lists and free-mail providers; bare executive title detection (at LOW severity); and Received chain hop count, private relay, and timestamp anomaly detection.
  - URL analyzer in `src/phishguard/analyzers/url.py`: IP literal and obfuscated integer/hex detection; userinfo credential trick detection; non-standard port and excessive subdomain/length heuristics; known shortener and suspicious TLD detection; homograph and visual confusable analysis with script detection and ASCII skeleton mapping; typosquatting checks (same label different TLD, brand in subdomain, combosquatting, edit-distance fuzzy matching) with brand allowlisting; and domain registration age evaluation via `DomainAgeProvider`.
  - Content analyzer in `src/phishguard/analyzers/content.py`: Bounded LLM semantic evaluation of email text using `wrap_untrusted_content` delimiters; strict Pydantic JSON schema validation (`ContentAnalysisOutput`) with single automated retry; indicator scoring (urgency, credential harvest, impersonation, threat language, payment pressure, grammar anomalies) with severity capped at HIGH and confidence capped at 0.8; and prompt isolation guaranteeing zero exposure of headers, From addresses, or attachment names to the LLM.
  - Attachment analyzer in `src/phishguard/analyzers/attachment.py`: Metadata-only inspection (never executing files) flagging dangerous executable binaries, scripts, macro-enabled Office documents, archives, deceptive double extensions (e.g. `.pdf.exe`), Unicode RTLO characters (`\u202e`), and MIME type vs extension mismatches.
  - LLM client abstractions in `src/phishguard/core/llm.py` (`LLMClient` protocol, `FakeLLMClient` mock, and `LiteLLMClient` provider).
- Phase 2 (Ingestion and parsing):
  - Ingestion module `src/phishguard/ingest` with `parse_eml`, `parse_raw_text`, `ingest` dispatcher, `extract_urls`, `html_to_text`, `normalize_url`, `defang`, and `refang`.
  - Ingestion bounds enforcement in `ingest.limits` (`MAX_EMAIL_BYTES`, `MAX_ATTACHMENT_BYTES`, `MAX_ATTACHMENTS`, `MAX_MIME_DEPTH`, `MAX_PARTS`, `MAX_HEADER_COUNT`, `MAX_HEADER_VALUE_CHARS`, `MAX_RECEIVED_HOPS`, `MAX_BODY_CHARS_RETAINED`, `MAX_URL_LENGTH`, `MAX_URLS_PER_MESSAGE`).
  - URL normalization supporting IDNA/punycode, tracking parameter stripping, userinfo removal, decimal/octal/hex IPv4 deobfuscation, and RFC 2606 reserved suffix fallbacks (`.test`, `.invalid`, `.example`).
  - Resilient URL extraction supporting plain text, markdown links, angle brackets, and HTML DOM (`<a>`, `<img>`, `<form>`), with visible text domain mismatch detection and script/style tag decomposition.
  - Safe attachment inspection enumerating metadata, size, and SHA-256 in memory without disk writing or host execution; recursion guard treating `message/rfc822` as attachments.
  - Extended domain schemas (`NormalizedURL`, `ExtractedURL`, `ParseWarning` StrEnum) with `extra="forbid"`.
  - Added 11 synthetic and malformed `.eml` test fixtures in `tests/fixtures/emails/`.
  - Offline network socket guard fixture blocking external socket connections and DNS lookups while permitting local loopback.
- Phase 1 (Foundations):
  - Repository structure under `src/phishguard/{core,ingest,analyzers,intel,ml,agents,api,ui}` and `tests/{unit,integration,adversarial,fixtures}`.
  - Project configuration and tooling with `uv`, `pyproject.toml`, and `.pre-commit-config.yaml` (`ruff`, `mypy --strict`, `bandit[toml]`, `pytest-cov`).
  - Core configuration via `pydantic-settings` with `SecretStr` for API keys and validation for production environments.
  - Domain schemas (`Severity`, `IOC`, `Evidence`, `AnalyzerResult`, `Verdict`, `ScanRequest`, `AttachmentMetadata`, `ParsedEmail`) with `extra="forbid"`, frozen `Evidence` with capped description, and `new_scan_id()` generator.
  - Core error hierarchy in `phishguard.core.errors`.
  - Structured logging in `phishguard.core.logging` with JSON output, `scan_id` context binding, and recursive redaction of message bodies and secret keys/tokens.
  - Unit and smoke tests achieving 100% code coverage without network calls.
- Phase 0: AGENTS.md, README skeleton, docs 00-09, ADRs 0001-0006, CONTRIBUTING, SECURITY.
