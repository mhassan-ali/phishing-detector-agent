"""Header analyzer evaluating SPF/DKIM/DMARC, spoofing, and routing anomalies."""

import email.utils
import ipaddress
import re
from typing import Any

import tldextract

from phishguard.analyzers.base import create_evidence
from phishguard.analyzers.brands import load_brands
from phishguard.analyzers.codes import EvidenceCode
from phishguard.core.config import get_settings
from phishguard.core.schemas import AnalyzerResult, Evidence, ParsedEmail, Severity

_EXTRACTOR = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=())

FREEMAIL_DOMAINS: frozenset[str] = frozenset(
    {
        "gmail.com",
        "yahoo.com",
        "hotmail.com",
        "outlook.com",
        "aol.com",
        "protonmail.com",
        "icloud.com",
        "mail.com",
        "zoho.com",
        "free-mail.example.org",
    }
)

EXECUTIVE_TITLES: frozenset[str] = frozenset(
    {
        "admin",
        "administrator",
        "it support",
        "security team",
        "helpdesk",
        "ceo",
        "cfo",
        "human resources",
        "hr department",
        "payroll",
        "billing team",
        "customer support",
    }
)


def extract_registered_domain(email_or_host: str | None) -> str:
    """Extract registered domain from an email address or hostname."""
    if not email_or_host:
        return ""
    addr = email_or_host.strip().lower()
    if "@" in addr:
        addr = addr.split("@")[-1].strip(" <>[]()")

    tld = _EXTRACTOR(addr)
    top_dom = getattr(tld, "top_domain_under_public_suffix", "")
    if not top_dom and tld.suffix:
        top_dom = f"{tld.domain}.{tld.suffix}"
    if top_dom:
        return str(top_dom)

    # Fallback for synthetic/unlisted TLDs (.test, .invalid, .example)
    parts = addr.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return addr


def parse_auth_header(value: str) -> dict[str, Any]:
    """Parse an RFC 8601 Authentication-Results header into structured fields."""
    parts = [p.strip() for p in value.split(";")]
    if not parts:
        return {}

    first = parts[0]
    authserv_tokens = first.split()
    authserv_id = authserv_tokens[0].lower() if authserv_tokens else ""

    parsed: dict[str, Any] = {"authserv_id": authserv_id}

    # Extract method results via robust token search
    spf_match = re.search(r"\bspf=([a-zA-Z]+)", value, re.IGNORECASE)
    if spf_match:
        parsed["spf"] = spf_match.group(1).lower()

    dkim_match = re.search(r"\bdkim=([a-zA-Z]+)", value, re.IGNORECASE)
    if dkim_match:
        parsed["dkim"] = dkim_match.group(1).lower()

    dmarc_match = re.search(r"\bdmarc=([a-zA-Z]+)", value, re.IGNORECASE)
    if dmarc_match:
        parsed["dmarc"] = dmarc_match.group(1).lower()

    mailfrom_match = re.search(r"\bsmtp\.mailfrom=([^\s;()]+)", value, re.IGNORECASE)
    if mailfrom_match:
        parsed["smtp.mailfrom"] = mailfrom_match.group(1).lower()

    header_d_match = re.search(r"\bheader\.d=([^\s;()]+)", value, re.IGNORECASE)
    if header_d_match:
        parsed["header.d"] = header_d_match.group(1).lower()

    header_from_match = re.search(r"\bheader\.from=([^\s;()]+)", value, re.IGNORECASE)
    if header_from_match:
        parsed["header.from"] = header_from_match.group(1).lower()

    return parsed


class HeaderAnalyzer:
    """Analyzer evaluating email authentication, sender integrity, and header anomalies."""

    name: str = "header_analyzer"

    def run(self, parsed: ParsedEmail) -> AnalyzerResult:
        """Run header analysis checks on ingested ParsedEmail."""
        if not parsed.raw_headers:
            return AnalyzerResult(
                analyzer=self.name,
                status="skipped",
                evidence=[],
                duration_ms=0,
            )

        evidence: list[Evidence] = []
        cfg = get_settings()
        trusted_authserv_ids = cfg.trusted_authserv_ids_list

        from_reg_domain = extract_registered_domain(parsed.from_addr)

        # 1. Authentication-Results Analysis
        if len(parsed.auth_results) > 1:
            evidence.append(
                create_evidence(
                    source=self.name,
                    code=EvidenceCode.HDR_MULTIPLE_AUTH_RESULTS,
                    severity=Severity.LOW,
                    description=(
                        "Multiple Authentication-Results headers (possible spoofing artifact)."
                    ),
                    confidence=0.8,
                    raw_data={"count": len(parsed.auth_results)},
                )
            )

        if not parsed.auth_results:
            evidence.append(
                create_evidence(
                    source=self.name,
                    code=EvidenceCode.HDR_MISSING_AUTH_RESULTS,
                    severity=Severity.LOW,
                    description="No Authentication-Results header found in message.",
                    confidence=0.5,
                )
            )
        else:
            top_auth_raw = parsed.auth_results[0].get("value", "")
            top_auth = parse_auth_header(top_auth_raw)
            authserv_id = top_auth.get("authserv_id", "")

            # Check authserv-id trust
            is_trusted = True
            auth_confidence = 0.95
            if trusted_authserv_ids:
                if authserv_id not in trusted_authserv_ids:
                    is_trusted = False
                    evidence.append(
                        create_evidence(
                            source=self.name,
                            code=EvidenceCode.HDR_UNTRUSTED_AUTH_RESULTS,
                            severity=Severity.LOW,
                            description=(
                                f"Authentication-Results authserv-id '{authserv_id}' is untrusted."
                            ),
                            confidence=0.8,
                            raw_data={"authserv_id": authserv_id},
                        )
                    )
            else:
                # Untrusted/unconfigured trust list reduces confidence
                auth_confidence = 0.70

            if is_trusted:
                # DMARC
                dmarc = top_auth.get("dmarc")
                if dmarc == "fail":
                    evidence.append(
                        create_evidence(
                            source=self.name,
                            code=EvidenceCode.HDR_DMARC_FAIL,
                            severity=Severity.HIGH,
                            description="DMARC verification failed for sending domain.",
                            confidence=auth_confidence,
                            raw_data={"dmarc": dmarc, "domain": from_reg_domain},
                        )
                    )
                elif dmarc == "pass":
                    evidence.append(
                        create_evidence(
                            source=self.name,
                            code=EvidenceCode.HDR_DMARC_PASS,
                            severity=Severity.INFO,
                            description="DMARC verification passed.",
                            confidence=auth_confidence,
                            raw_data={"dmarc": dmarc, "domain": from_reg_domain},
                        )
                    )

                # SPF
                spf = top_auth.get("spf")
                if spf == "fail":
                    evidence.append(
                        create_evidence(
                            source=self.name,
                            code=EvidenceCode.HDR_SPF_FAIL,
                            severity=Severity.HIGH,
                            description="SPF verification failed (hard fail) for sending host.",
                            confidence=auth_confidence,
                            raw_data={"spf": spf, "domain": from_reg_domain},
                        )
                    )
                elif spf == "softfail":
                    evidence.append(
                        create_evidence(
                            source=self.name,
                            code=EvidenceCode.HDR_SPF_FAIL,
                            severity=Severity.MEDIUM,
                            description="SPF verification returned softfail for sending host.",
                            confidence=auth_confidence,
                            raw_data={"spf": spf, "domain": from_reg_domain},
                        )
                    )

                # DKIM
                dkim = top_auth.get("dkim")
                if dkim in ("fail", "permerror"):
                    evidence.append(
                        create_evidence(
                            source=self.name,
                            code=EvidenceCode.HDR_DKIM_FAIL,
                            severity=Severity.MEDIUM,
                            description=f"DKIM signature verification failed with result: {dkim}.",
                            confidence=auth_confidence,
                            raw_data={"dkim": dkim, "domain": from_reg_domain},
                        )
                    )

                # SPF alignment
                mailfrom = top_auth.get("smtp.mailfrom") or parsed.return_path
                if mailfrom and from_reg_domain:
                    mailfrom_reg = extract_registered_domain(mailfrom)
                    if mailfrom_reg and mailfrom_reg != from_reg_domain:
                        evidence.append(
                            create_evidence(
                                source=self.name,
                                code=EvidenceCode.HDR_SPF_ALIGNMENT_FAIL,
                                severity=Severity.MEDIUM,
                                description=(
                                    "SPF envelope sender domain does not align with From domain."
                                ),
                                confidence=auth_confidence,
                                raw_data={
                                    "mailfrom_domain": mailfrom_reg,
                                    "from_domain": from_reg_domain,
                                },
                            )
                        )

                # DKIM alignment
                header_d = top_auth.get("header.d")
                if header_d and from_reg_domain:
                    dkim_reg = extract_registered_domain(header_d)
                    if dkim_reg and dkim_reg != from_reg_domain:
                        evidence.append(
                            create_evidence(
                                source=self.name,
                                code=EvidenceCode.HDR_DKIM_ALIGNMENT_FAIL,
                                severity=Severity.MEDIUM,
                                description=(
                                    "DKIM domain (header.d) does not align with From domain."
                                ),
                                confidence=auth_confidence,
                                raw_data={
                                    "dkim_domain": dkim_reg,
                                    "from_domain": from_reg_domain,
                                },
                            )
                        )

        # 2. Domain Mismatches (From vs Reply-To, From vs Return-Path)
        if parsed.reply_to and from_reg_domain:
            reply_reg_domain = extract_registered_domain(parsed.reply_to)
            if reply_reg_domain and reply_reg_domain != from_reg_domain:
                evidence.append(
                    create_evidence(
                        source=self.name,
                        code=EvidenceCode.HDR_DOMAIN_MISMATCH_REPLYTO,
                        severity=Severity.HIGH,
                        description=(
                            "Reply-To points to a different domain than sender From address."
                        ),
                        confidence=0.9,
                        raw_data={
                            "from_domain": from_reg_domain,
                            "reply_domain": reply_reg_domain,
                        },
                    )
                )

        if parsed.return_path and from_reg_domain:
            return_reg_domain = extract_registered_domain(parsed.return_path)
            if return_reg_domain and return_reg_domain != from_reg_domain:
                evidence.append(
                    create_evidence(
                        source=self.name,
                        code=EvidenceCode.HDR_DOMAIN_MISMATCH_RETURNPATH,
                        severity=Severity.MEDIUM,
                        description="Return-Path envelope domain differs from From header domain.",
                        confidence=0.85,
                        raw_data={
                            "from_domain": from_reg_domain,
                            "return_domain": return_reg_domain,
                        },
                    )
                )

        # 3. Display Name and Freemail Spoofing
        if parsed.from_display_name and parsed.from_addr:
            disp_lower = parsed.from_display_name.lower()
            matched_brand_name: str | None = None

            for brand in load_brands():
                b_name_lower = brand.name.lower()
                # Check if brand name or keyword appears as a token or substring in display name
                is_brand_match = b_name_lower in disp_lower or any(
                    kw.lower() in disp_lower for kw in brand.keywords
                )
                if is_brand_match:
                    brand_registered_domains = {extract_registered_domain(d) for d in brand.domains}
                    if from_reg_domain not in brand_registered_domains:
                        matched_brand_name = brand.name
                        evidence.append(
                            create_evidence(
                                source=self.name,
                                code=EvidenceCode.HDR_DISPLAY_NAME_SPOOF,
                                severity=Severity.HIGH,
                                description=(
                                    "Sender display name impersonates a brand from unknown domain."
                                ),
                                confidence=0.95,
                                raw_data={
                                    "brand": brand.name,
                                    "from_domain": from_reg_domain,
                                    "display_name": parsed.from_display_name,
                                },
                            )
                        )
                        # Check if sent from free-mail service
                        from_host = parsed.from_addr.split("@")[-1].strip(" <>[]()").lower()
                        if (
                            from_reg_domain in FREEMAIL_DOMAINS
                            or from_host in FREEMAIL_DOMAINS
                            or "free-mail" in from_host
                            or "freemail" in from_host
                        ):
                            evidence.append(
                                create_evidence(
                                    source=self.name,
                                    code=EvidenceCode.HDR_FREEMAIL_BRAND_SPOOF,
                                    severity=Severity.HIGH,
                                    description=(
                                        "Free-mail provider address used claiming brand identity."
                                    ),
                                    confidence=0.95,
                                    raw_data={
                                        "brand": brand.name,
                                        "from_domain": from_reg_domain,
                                    },
                                )
                            )
                        break

            # If no brand matched, check for bare executive / administrative titles
            if not matched_brand_name:
                for title in EXECUTIVE_TITLES:
                    if title in disp_lower:
                        evidence.append(
                            create_evidence(
                                source=self.name,
                                code=EvidenceCode.HDR_EXECUTIVE_TITLE_SPOOF,
                                severity=Severity.LOW,
                                description=(
                                    "Sender display name uses an administrative or executive title."
                                ),
                                confidence=0.6,
                                raw_data={"title": title},
                            )
                        )
                        break

        # 4. Received Chain Anomalies
        chain = parsed.received_chain
        if len(chain) > 10:
            evidence.append(
                create_evidence(
                    source=self.name,
                    code=EvidenceCode.HDR_RECEIVED_HOP_COUNT_HIGH,
                    severity=Severity.LOW,
                    description="Email routing contains an unusually high number of Received hops.",
                    confidence=0.7,
                    raw_data={"hop_count": len(chain)},
                )
            )

        # Check for intermediate private IP relays and timestamp anomalies
        hop_dates: list[float] = []
        for i, hop in enumerate(chain):
            # Private IP check (skip first hop from sender MUA if internal)
            if i > 0:
                ip_candidates = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", hop)
                for ip_str in ip_candidates:
                    try:
                        ip_obj = ipaddress.ip_address(ip_str)
                        if ip_obj.is_private:
                            evidence.append(
                                create_evidence(
                                    source=self.name,
                                    code=EvidenceCode.HDR_RECEIVED_PRIVATE_RELAY,
                                    severity=Severity.LOW,
                                    description=(
                                        "Intermediate Received hop routed through private IP space."
                                    ),
                                    confidence=0.6,
                                    raw_data={"hop_index": i, "private_ip": ip_str},
                                )
                            )
                            break
                    except ValueError:
                        continue

            # Timestamp parsing
            if ";" in hop:
                date_part = hop.split(";")[-1].strip()
                try:
                    dt = email.utils.parsedate_to_datetime(date_part)
                    hop_dates.append(dt.timestamp())
                except (ValueError, TypeError, IndexError):
                    continue

        # Check backward timestamp anomaly (hop 0 is latest recipient, hop N earliest sender)
        if len(hop_dates) >= 2:
            for j in range(len(hop_dates) - 1):
                # hop_dates[j] should be >= hop_dates[j+1]
                # If earlier relay (j+1) is > 60s later than relay (j), clock is skewed backward
                if hop_dates[j + 1] - hop_dates[j] > 60:
                    evidence.append(
                        create_evidence(
                            source=self.name,
                            code=EvidenceCode.HDR_RECEIVED_TIME_ANOMALY,
                            severity=Severity.LOW,
                            description=(
                                "Routing timestamps across Received hops are non-chronological."
                            ),
                            confidence=0.6,
                        )
                    )
                    break

        return AnalyzerResult(
            analyzer=self.name,
            status="ok",
            evidence=evidence,
            duration_ms=0,
        )
