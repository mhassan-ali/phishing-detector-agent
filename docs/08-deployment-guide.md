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
| `VIRUSTOTAL_ENABLED` | `true` | Enable VirusTotal reputation provider |
| `URLHAUS_ENABLED` | `true` | Enable abuse.ch URLhaus provider |
| `OPENPHISH_ENABLED` | `true` | Enable OpenPhish community feed provider |
| `SAFEBROWSING_ENABLED` | `true` | Enable Google Safe Browsing provider |
| `URLSCAN_ENABLED` | `true` | Enable urlscan.io search provider |
| `VIRUSTOTAL_API_KEY` | none | VirusTotal API key (public key is non-commercial) |
| `URLHAUS_AUTH_KEY` | none | abuse.ch URLhaus Auth-Key (free account) |
| `URLSCAN_API_KEY` | none | urlscan.io API key (optional for search) |
| `GOOGLE_SAFE_BROWSING_KEY` | none | Google Safe Browsing API key (non-commercial) |
| `PHISHGUARD_INTEL_DEADLINE_SECONDS` | `8.0` | Global timeout deadline for intel lookups |
| `PHISHGUARD_INTEL_MAX_INDICATORS` | `5` | Maximum total indicators queried per scan |
| `PHISHGUARD_INTEL_SEND_FULL_URLS` | `false` | Whether to send full URLs with query parameters |
| `OPENPHISH_MAX_FEED_BYTES` | `2097152` | Size cap in bytes (2 MB) for OpenPhish feed |
| `INTEL_CACHE_TTL_HOURS` | `24` | Intel cache lifetime (positive findings) |
| `LOG_LEVEL` | `INFO` | Logging |

### 3.1 Threat Intelligence Providers: Verified Documentation & Terms
- **VirusTotal v3**: [Official Documentation](https://docs.virustotal.com/reference/overview) (Verified Nov 2026).
  - *Terms*: Public API keys are strictly for non-commercial evaluation (4 requests/minute, 500 requests/day).
- **abuse.ch URLhaus**: [Official Documentation](https://urlhaus-api.abuse.ch/v1/) (Verified Nov 2026).
  - *Terms*: Requires free community `Auth-Key` from abuse.ch (~1 request/sec).
- **OpenPhish Community Feed**: [Official Feed Documentation](https://openphish.com/feed.txt) (Verified Nov 2026).
  - *Terms*: Community feed free for defensive security use. Refreshed regularly.
- **Google Safe Browsing v4 Lookup**: [Official Documentation](https://developers.google.com/safe-browsing/v4/lookup-api) (Verified Nov 2026).
  - *Terms*: Free up to 10,000 requests/day for non-commercial usage. Sends full URLs to Google (query stripping enabled by default).
- **urlscan.io Search API**: [Official Documentation](https://urlscan.io/docs/api/#search) (Verified Nov 2026).
  - *Terms*: Free search tier allows up to 30 requests/minute. Scans are strictly search-only (no live crawls initiated).

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
