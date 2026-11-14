# 08: Deployment Guide

> **Status: DESIGN.** Verify every command during Phase 10.

## 1. Requirements
Python 3.11+, `uv` (or Poetry), Docker 24+ (optional), a Gemini API key (for LLM features).

## 2. Local setup
```bash
cp .env.example .env     # fill in keys
uv sync
uv run pre-commit install
uv run pytest
uv run phishguard scan-url "https://example.test"
```

## 3. Configuration reference
| Variable | Default | Description |
|---|---|---|
| `PHISHGUARD_ENV` | `dev` | `dev` / `prod` / `test` |
| `PHISHGUARD_API_KEY` | none | Required for API in prod |
| `PHISHGUARD_DB_URL` | `sqlite:///data/phishguard.db` | Storage |
| `PHISHGUARD_STORE_RAW` | `false` | Persist raw content (opt-in) |
| `PHISHGUARD_REDACT_PII` | `true` | Redact before LLM |
| `PHISHGUARD_MAX_UPLOAD_MB` | `10` | Upload cap |
| `PHISHGUARD_RATE_LIMIT` | `30/minute` | Per API key |
| `PHISHGUARD_TRUSTED_AUTHSERV_IDS` | none | Comma-separated trusted authserv-ids |
| `PHISHGUARD_DOMAIN_AGE_ENABLED` | `false` | Enable domain age verification |
| `PHISHGUARD_LLM_ENABLED` | `false` | Enable LLM content analyzer |
| `LLM_MODEL` | `gemini/gemini-2.5-flash` | LiteLLM model string (verify current name) |
| `GEMINI_API_KEY` | none | LLM access |
| `VIRUSTOTAL_API_KEY`, `URLSCAN_API_KEY`, `GOOGLE_SAFE_BROWSING_KEY` | none | Optional intel |
| `INTEL_CACHE_TTL_HOURS` | `24` | Intel cache lifetime |
| `LOG_LEVEL` | `INFO` | Logging |

## 4. Docker
```bash
docker compose up --build
# API: http://localhost:8000/docs   UI: http://localhost:8501
```
Container requirements: non-root user, read-only root filesystem where possible, volume only for `data/`,
no secrets baked into the image (pass via env or secrets).

## 5. Production hardening checklist
- [ ] Set a strong `PHISHGUARD_API_KEY`; serve behind HTTPS (reverse proxy)
- [ ] Restrict CORS origins
- [ ] Keep `PHISHGUARD_STORE_RAW=false` unless required
- [ ] Egress firewall: allow only LLM/intel hosts and DNS
- [ ] Run `pip-audit` and rebuild images regularly
- [ ] Back up the SQLite volume; set log retention
- [ ] Monitor LLM/intel quota usage

## 6. Operations
- **Model updates:** place new artifact in `data/models/<version>/`, update `MODEL_VERSION`, restart.
- **Cache purge:** `phishguard cache clear`.
- **Troubleshooting:** LLM errors → check key/quota (scan continues degraded); slow scans → check intel timeouts;
  empty results → check logs by `scan_id`.

## 9. Rollback
Redeploy the previous image tag; databases are forward-compatible within a minor version (migrations noted in CHANGELOG).
