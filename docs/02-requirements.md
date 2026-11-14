# 02: Requirements

Priority: **M** = must, **S** = should, **C** = could. Status is updated as phases complete.

## 1. Functional requirements

### Ingestion (FR-ING)
| ID | Requirement | Pri | Phase |
|---|---|---|---|
| FR-ING-1 | Accept .eml files, raw RFC 5322 text, a single URL, or pasted text | M | 2 |
| FR-ING-2 | Parse headers: From, Reply-To, Return-Path, Received chain, Authentication-Results, Message-ID, Date | M | 2 |
| FR-ING-3 | Extract plain and HTML bodies; handle multipart and charset issues | M | 2 |
| FR-ING-4 | Enumerate attachments (name, MIME type, size, SHA-256) without opening or executing them | M | 2 |
| FR-ING-5 | Extract URLs from text and HTML, including visible-text vs href mismatches | M | 2 |
| FR-ING-6 | Normalize URLs (lowercase host, punycode, tracking-param stripping) and defang output | M | 2 |
| FR-ING-7 | Handle malformed MIME without crashing | M | 2 |

### Header analysis (FR-HDR)
| ID | Requirement | Pri | Phase |
|---|---|---|---|
| FR-HDR-1 | Evaluate SPF, DKIM, DMARC results from Authentication-Results | M | 3 |
| FR-HDR-2 | Detect From / Return-Path / Reply-To mismatches | M | 3 |
| FR-HDR-3 | Detect display-name spoofing of known brands/executives | M | 3 |
| FR-HDR-4 | Flag free-mail senders claiming brand identity | S | 3 |
| FR-HDR-5 | Flag anomalous Received chains (timing, private hops, count) | C | 3 |

### URL analysis (FR-URL)
| ID | Requirement | Pri | Phase |
|---|---|---|---|
| FR-URL-1 | Detect IP-literal hosts, excessive subdomains, `@` tricks, odd ports | M | 3 |
| FR-URL-2 | Detect homograph/punycode lookalikes | M | 3 |
| FR-URL-3 | Detect typosquatting vs a configurable brand list (edit distance) | M | 3 |
| FR-URL-4 | Detect known URL shorteners and suspicious TLDs | M | 3 |
| FR-URL-5 | Compute domain age (WHOIS/RDAP) with graceful failure | S | 3 |
| FR-URL-6 | Follow redirects only through SafeFetcher with limits | S | 7 |

### Content analysis (FR-CNT)
| ID | Requirement | Pri | Phase |
|---|---|---|---|
| FR-CNT-1 | LLM-based detection of urgency, credential requests, impersonation, threats, payment pressure | M | 3 |
| FR-CNT-2 | LLM output must conform to a strict JSON schema, validated by Pydantic | M | 3 |
| FR-CNT-3 | Untrusted text wrapped in delimiters; instructions state it is data only | M | 3 |
| FR-CNT-4 | Detect prompt-injection phrases in content and raise them as evidence | M | 7 |
| FR-CNT-5 | Optional PII redaction before LLM calls | S | 7 |

### Attachment analysis (FR-ATT)
| ID | Requirement | Pri | Phase |
|---|---|---|---|
| FR-ATT-1 | Flag dangerous extensions, double extensions, macro-enabled Office types, archives | M | 3 |
| FR-ATT-2 | Compare MIME type to extension; flag mismatches | S | 3 |
| FR-ATT-3 | Hash-based reputation lookup (no upload of file content by default) | S | 4 |

### Threat intelligence (FR-INT)
| ID | Requirement | Pri | Phase |
|---|---|---|---|
| FR-INT-1 | Common `IntelProvider` interface returning `IntelResult` | M | 4 |
| FR-INT-2 | Providers: VirusTotal, URLhaus, OpenPhish, Google Safe Browsing, urlscan.io | S | 4 |
| FR-INT-3 | Missing API keys degrade gracefully; never crash | M | 4 |
| FR-INT-4 | Rate limiting, retries with backoff, timeouts | M | 4 |
| FR-INT-5 | SQLite cache with TTL | S | 4 |

### Machine learning (FR-ML)
| ID | Requirement | Pri | Phase |
|---|---|---|---|
| FR-ML-1 | URL feature extraction shared by training and inference | M | 5 |
| FR-ML-2 | Train and compare >= 3 models with stratified CV | M | 5 |
| FR-ML-3 | Report precision, recall, F1, ROC-AUC, FPR; handle class imbalance | M | 5 |
| FR-ML-4 | Predict probability plus top contributing features | M | 5 |
| FR-ML-5 | Versioned model artifact + metadata JSON | M | 5 |
| FR-ML-6 | Leakage controls (dedup, domain-aware split) | M | 5 |

### Agent & verdict (FR-AGT / FR-VER)
| ID | Requirement | Pri | Phase |
|---|---|---|---|
| FR-AGT-1 | LangGraph pipeline: normalize → parallel analyzers → ML → verdict | M | 6 |
| FR-AGT-2 | Analyzer failure lowers confidence but does not abort the run | M | 6 |
| FR-AGT-3 | Parallel execution of independent analyzers | S | 6 |
| FR-VER-1 | Verdict agent receives only structured Evidence, not raw email text | M | 6 |
| FR-VER-2 | Deterministic weighted rubric computes label and base score | M | 6 |
| FR-VER-3 | LLM writes explanation and actions; score adjustment bounded to ±10 | M | 6 |
| FR-VER-4 | Output includes reasons, IOCs (defanged), recommended actions, confidence | M | 6 |
| FR-VER-5 | CLI: `phishguard scan <file>` and `phishguard scan-url <url>` | M | 6 |

### API & UI (FR-API / FR-UI)
| ID | Requirement | Pri | Phase |
|---|---|---|---|
| FR-API-1 | `POST /scan/email`, `POST /scan/url`, `GET /scan/{id}`, `GET /health` | M | 8 |
| FR-API-2 | API key auth, request-size limits, rate limiting, CORS config | M | 8 |
| FR-API-3 | Persist hashes + verdicts; raw content storage opt-in | M | 8 |
| FR-API-4 | OpenAPI docs auto-generated | M | 8 |
| FR-UI-1 | Streamlit: upload/paste, risk gauge, per-analyzer evidence, IOCs, explanation | M | 8 |
| FR-UI-2 | Scan history and JSON export | S | 8 |

### Evaluation (FR-EVL)
| ID | Requirement | Pri | Phase |
|---|---|---|---|
| FR-EVL-1 | `scripts/evaluate.py` runs the full pipeline on a labeled holdout | M | 9 |
| FR-EVL-2 | Ablations: rules-only, ML-only, LLM-only, full | M | 9 |
| FR-EVL-3 | Report latency and cost per scan; error analysis of FP/FN | M | 9 |

## 2. Non-functional requirements

| ID | Category | Requirement | Phase |
|---|---|---|---|
| NFR-SEC-1 | Security | All outbound fetches via SafeFetcher; block private/loopback/link-local/metadata IPs incl. post-redirect and post-DNS | 7 |
| NFR-SEC-2 | Security | Prompt-injection defenses: delimiters, length caps, schema validation, rubric authority | 3, 7 |
| NFR-SEC-3 | Security | No secrets in repo/logs; `.env` only | 1 |
| NFR-SEC-4 | Security | Attachments never executed; no untrusted JS rendering | 2, 7 |
| NFR-SEC-5 | Security | `bandit` and `pip-audit` clean (or documented exceptions) | 7, 10 |
| NFR-PRV-1 | Privacy | Raw content not stored by default; PII redaction option | 7, 8 |
| NFR-PRV-2 | Privacy | Logs contain IDs/hashes, not bodies | 1 |
| NFR-PERF-1 | Performance | p95 <= 15 s per email with warm cache; analyzers run concurrently | 6, 9 |
| NFR-REL-1 | Reliability | Graceful degradation for missing keys, timeouts, quota errors | 4, 6 |
| NFR-QUAL-1 | Quality | Coverage >= 85%; ruff + mypy strict clean | 1, 9 |
| NFR-MNT-1 | Maintainability | Modular layout; each analyzer independently testable | 1 |
| NFR-OBS-1 | Observability | Structured logs with scan ID; per-node timing | 1, 6 |
| NFR-OPS-1 | Operations | Multi-stage non-root Docker image; CI on every push | 10 |
| NFR-DOC-1 | Documentation | Docs match code; ADR per significant decision | 10 |
| NFR-EXP-1 | Explainability | Every verdict traces to listed Evidence items | 6 |

## 3. Traceability
Tick when implemented and tested.

| Requirement group | Implemented | Tested | Documented |
|---|---|---|---|
| FR-ING | ☑ (FR-ING-1 to FR-ING-7) | ☑ | ☑ |
| FR-HDR | ☑ (FR-HDR-1 to FR-HDR-5) | ☑ | ☑ |
| FR-URL | ☑ (FR-URL-1 to FR-URL-5) | ☑ | ☑ |
| FR-CNT | ☑ (FR-CNT-1 to FR-CNT-3) | ☑ | ☑ |
| FR-ATT | ☑ (FR-ATT-1 to FR-ATT-2) | ☑ | ☑ |
| FR-INT | ☐ | ☐ | ☐ |
| FR-ML | ☐ | ☐ | ☐ |
| FR-AGT / FR-VER | ☐ | ☐ | ☐ |
| FR-API / FR-UI | ☐ | ☐ | ☐ |
| FR-EVL | ☐ | ☐ | ☐ |
| NFR-* | ☑ (Phase 1: MNT-1, SEC-3, PRV-2, QUAL-1, OBS-1) | ☑ | ☑ |
