# Changelog

All notable changes are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning: [SemVer](https://semver.org/).

## [Unreleased]
### Added
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
