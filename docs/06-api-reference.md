# 06: API Reference

> **Status: DESIGN.** Regenerate from the live OpenAPI spec in Phase 8 (`/docs`, `/openapi.json`) and
> reconcile with this file.

Base URL (local): `http://localhost:8000`
Auth: header `X-API-Key: <PHISHGUARD_API_KEY>` on all endpoints except `/health`.
Limits: max upload size `PHISHGUARD_MAX_UPLOAD_MB` (default 10 MB); rate limit per key (default 30/min).

## Endpoints

### `GET /health`
Liveness/readiness. No auth.
```json
{"status": "ok", "version": "0.1.0", "llm_available": true, "model_loaded": true}
```

### `POST /scan/email`
Multipart upload of an `.eml` file, or JSON with raw text.
```bash
curl -X POST http://localhost:8000/scan/email \
  -H "X-API-Key: $KEY" -F "file=@tests/fixtures/emails/fake_bank.eml"
```

### `POST /scan/url`
```bash
curl -X POST http://localhost:8000/scan/url \
  -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '{"url": "https://example.test/login"}'
```

### `GET /scan/{scan_id}`
Returns a stored verdict. 404 if unknown.

## Response schema: `Verdict`
```json
{
  "scan_id": "4a1b2c3d4e5f67890123456789abcdef",
  "label": "phishing",
  "risk_score": 87,
  "confidence": 0.82,
  "reasons": ["DMARC failed for claimed sender domain", "Link text does not match destination"],
  "iocs": [{"type": "url", "value": "hxxps://example[.]test/login", "context": "body link"}],
  "recommended_actions": ["Do not click links", "Report to your security team"],
  "evidence": [
    {"source": "header", "code": "HDR_DMARC_FAIL", "severity": "high",
     "description": "DMARC result: fail", "confidence": 0.95, "raw_data": {}}
  ],
  "degraded_components": []
}
```

## Errors
| Status | Meaning |
|---|---|
| 400 | Malformed input / unsupported type |
| 401 | Missing or invalid API key |
| 404 | Scan not found |
| 413 | Payload too large |
| 422 | Validation error |
| 429 | Rate limit exceeded |
| 500 | Unexpected error (no internals leaked) |

Error body: `{"error": {"code": "...", "message": "..."}}`.

## Notes
- IOCs are always defanged in responses.
- Raw message content is never returned unless it was stored under `PHISHGUARD_STORE_RAW=true`.
