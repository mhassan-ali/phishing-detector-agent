# 01: Project Charter

| Field | Value |
|---|---|
| Project | PhishGuard: Agentic Phishing Detector |
| Owner | _<your name>_ |
| Version | 0.1 (draft) |
| Last updated | 2026-11-14 |
| Status | Planning |

## 1. Problem statement
Phishing remains one of the most common initial-access techniques. Users and small teams struggle to judge
suspicious messages; signature-only filters miss novel campaigns; and pure-LLM "is this phishing?" tools are
opaque, inconsistent, and vulnerable to prompt injection embedded in the message itself.

## 2. Vision
An **explainable, hybrid, agentic** phishing analysis assistant that shows *why* a message is risky, using
verifiable evidence rather than a black-box opinion, and that is itself hardened against attack.

## 3. Target users
| User | Need |
|---|---|
| Everyday user | Quick "is this safe?" check with a plain explanation |
| SOC / IT analyst | Triage aid with IOCs, header findings, and exportable JSON |
| Student / researcher | Reproducible, documented reference architecture |

## 4. Goals
- G1: Classify emails and URLs as safe / suspicious / phishing with a 0-100 risk score.
- G2: Provide evidence-backed, human-readable explanations and IOCs.
- G3: Combine rules, ML, threat intel, and LLM reasoning through an orchestrated agent graph.
- G4: Be robust against prompt injection and SSRF.
- G5: Ship with complete documentation, tests, and reproducible evaluation.

## 5. Non-goals
- Not an email gateway or mail server; no inline blocking of live mail flow.
- Not a malware sandbox; attachments are never executed.
- No generation of phishing content, and no offensive tooling.
- No guarantee of detection; this is an assistive tool.
- Not a full browser-isolation or takedown service.

## 6. Scope
**In scope (v1):** .eml and raw header/body input; URL input; header auth analysis; URL heuristics; LLM
content analysis; attachment metadata analysis; threat-intel lookups; ML URL classifier; LangGraph pipeline;
CLI, REST API, Streamlit UI; scan history; documentation and CI.

**Stretch (post-v1):** browser extension, screenshot/visual brand analysis, analyst feedback loop,
Gmail/Outlook integration, MCP server exposure.

## 7. Success metrics
| Metric | Target | Measured in |
|---|---|---|
| Recall (phishing class), full pipeline | >= 95% | Evaluation report |
| False-positive rate on legitimate samples | <= 2% | Evaluation report |
| p95 latency (email, threat intel cached) | <= 15 s | Evaluation report |
| Unit/integration coverage | >= 85% | CI |
| Adversarial test pass rate (injection, SSRF) | 100% | CI |
| Docs complete & consistent with code | 100% of checklist | Phase 10 audit |

> Targets are goals, not promises; the evaluation report must state actual results and caveats.

## 8. Constraints & assumptions
- Free-tier LLM and threat-intel quotas; must degrade gracefully when rate-limited or missing.
- Public datasets only; no private user mail used for training.
- Python 3.11+, local-first deployment; Docker for reproducibility.
- Assumes inputs are legitimate user submissions, not a high-volume hostile load (rate limiting still required).

## 9. Risks
| ID | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | Prompt injection manipulates the LLM | High | High | Delimiters, schema validation, rubric authority, injection detector, adversarial tests |
| R2 | SSRF through URL fetching | Medium | High | SafeFetcher; threat-intel by lookup only |
| R3 | Dataset bias / leakage inflates metrics | Medium | Medium | Dedup, domain-based splits, honest evaluation |
| R4 | API quota exhaustion | High | Medium | Caching, graceful degradation |
| R5 | High false positives on legit marketing mail | Medium | Medium | Ham corpus testing, threshold tuning, "suspicious" tier |
| R6 | PII leakage to third-party LLM | Medium | High | Redaction, opt-in raw storage, privacy doc |
| R7 | Scope creep | High | Medium | Phase gates, non-goals list |

## 10. Deliverables
Source code, tests, trained model + model card, evaluation report, API + UI, Docker + CI, and docs 00-09 + ADRs.

## 11. Ethics & legal note
Use only on messages you are authorized to analyze. Follow `docs/09-privacy-and-ethics.md`.

## 12. Sign-off
| Role | Name | Date |
|---|---|---|
| Owner | | |
