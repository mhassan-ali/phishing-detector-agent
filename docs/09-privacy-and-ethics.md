# 09: Privacy & Ethics

## 1. Data handled
Emails (headers, bodies, attachments metadata), URLs, derived verdicts. Emails may contain personal data of
the user and third parties.

## 2. Data flow & minimization
| Stage | Data | Policy |
|---|---|---|
| Input | Raw email/URL | Held in memory; not persisted by default |
| LLM | Redacted, length-capped text | Emails/phones masked when `PHISHGUARD_REDACT_PII=true`; third-party processing disclosed |
| Threat intel | URLs, hashes, domains | No message body or attachment content sent |
| Storage | Hash, verdict, evidence | Raw content only if opt-in |
| Logs | Scan ID, event names, timings | No bodies, no keys |

### Ingestion Memory Retention Policy
- **Transient Memory**: Raw email content and MIME structures reside in memory only during the active scan pipeline execution and are freed upon garbage collection.
- **Attachment Payloads**: Attachment byte buffers are traversed strictly in-memory to compute SHA-256 hashes, size in bytes, and MIME content types. Attachment payloads are never persisted to disk, never executed, and discarded immediately after metadata enumeration.
- **Body Truncation**: Plain text and HTML bodies are capped at `MAX_BODY_CHARS_RETAINED` (500,000 characters) to prevent unbounded memory growth.
- **Persistence Boundary**: Raw message bodies and attachments are never persisted to SQLite unless `PHISHGUARD_STORE_RAW=true` is explicitly configured.

## 3. Third-party processing
Submitting URLs/hashes to VirusTotal, urlscan.io, etc. may make them visible to those services (urlscan scans can
be public). Default to **private** scan visibility where supported, and warn users in UI/README.

### Free-Tier LLM Data Usage Policy
- **Free-Tier LLM Providers**: Commercial LLM APIs operating under free tiers (such as Google AI Studio free tier) reserve the right to log, inspect, and use submitted prompts and completions for human review and model training.
- **Sensitive Email Advisory**: Users and operators MUST NOT submit sensitive, confidential, legally privileged, or personally identifiable email content using free-tier LLM API keys.
- **Paid / Enterprise Tier**: Organizations handling proprietary communications should exclusively configure paid API keys (where provider terms guarantee zero data retention and no model training on customer payloads) or utilize self-hosted models.

## 4. User responsibilities
Analyze only messages you are authorized to inspect (your own mail, or with consent / organizational policy).

## 5. Ethical use
- Defensive use only; the project must not be used to craft or refine phishing.
- Test fixtures are synthetic; real phishing samples handled in isolated environments and never committed.
- Do not use for surveillance of others' communications.

## 6. Fairness & transparency
- Explanations cite concrete evidence; confidence and limitations are shown.
- "Suspicious" tier avoids overconfident binary decisions.
- Model card documents bias risks (e.g., non-Latin domains, new small businesses).

## 7. Retention & deletion
Default retention for scan history: _configurable (default 30 days)_. Provide `DELETE /scan/{id}` and a CLI purge
(add during Phase 8 if not present).

## 8. Disclaimer
PhishGuard provides risk assessments, not guarantees. Users should verify through trusted channels before
acting, especially on financial or credential requests.
