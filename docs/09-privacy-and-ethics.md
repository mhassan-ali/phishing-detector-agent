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

## 3. Third-party processing
Submitting URLs/hashes to VirusTotal, urlscan.io, etc. may make them visible to those services (urlscan scans can
be public). Default to **private** scan visibility where supported, and warn users in UI/README.

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
