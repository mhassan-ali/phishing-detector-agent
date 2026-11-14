# Changelog

All notable changes are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning: [SemVer](https://semver.org/).

## [Unreleased]
### Added
- Phase 1 (Foundations):
  - Repository structure under `src/phishguard/{core,ingest,analyzers,intel,ml,agents,api,ui}` and `tests/{unit,integration,adversarial,fixtures}`.
  - Project configuration and tooling with `uv`, `pyproject.toml`, and `.pre-commit-config.yaml` (`ruff`, `mypy --strict`, `bandit[toml]`, `pytest-cov`).
  - Core configuration via `pydantic-settings` with `SecretStr` for API keys and validation for production environments.
  - Domain schemas (`Severity`, `IOC`, `Evidence`, `AnalyzerResult`, `Verdict`, `ScanRequest`, `AttachmentMetadata`, `ParsedEmail`) with `extra="forbid"`, frozen `Evidence` with capped description, and `new_scan_id()` generator.
  - Core error hierarchy in `phishguard.core.errors`.
  - Structured logging in `phishguard.core.logging` with JSON output, `scan_id` context binding, and recursive redaction of message bodies and secret keys/tokens.
  - Unit and smoke tests achieving 100% code coverage without network calls.
- Phase 0: AGENTS.md, README skeleton, docs 00-09, ADRs 0001-0006, CONTRIBUTING, SECURITY.
