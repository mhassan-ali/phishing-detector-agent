"""URL analyzer evaluating host heuristics, homographs, typosquatting, and domain traits."""

from typing import Protocol

import rapidfuzz
import tldextract

from phishguard.analyzers.base import create_evidence
from phishguard.analyzers.brands import load_brands, load_shorteners, load_suspicious_tlds
from phishguard.analyzers.codes import EvidenceCode
from phishguard.analyzers.confusables import get_ascii_skeleton, is_mixed_script
from phishguard.core.config import get_settings
from phishguard.core.schemas import AnalyzerResult, Evidence, ParsedEmail, Severity

_EXTRACTOR = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=())


def _extract_brand_label_and_suffix(domain_str: str) -> tuple[str, str]:
    """Extract domain label and suffix from a domain string, handling unlisted PSL suffixes."""
    ext = _EXTRACTOR(domain_str)
    if ext.suffix:
        return ext.domain.lower(), ext.suffix.lower()
    parts = domain_str.lower().split(".")
    if len(parts) >= 2:
        return parts[-2], parts[-1]
    return domain_str.lower(), ""


class DomainAgeProvider(Protocol):
    """Protocol for querying domain registration age."""

    def get_domain_age_days(self, domain: str) -> int | None:
        """Return the age of domain registration in days, or None if unavailable."""
        ...


class StubDomainAgeProvider:
    """Stub domain age provider returning None or simulated age."""

    def __init__(self, stub_age_days: int | None = None) -> None:
        self._stub_age_days = stub_age_days

    def get_domain_age_days(self, domain: str) -> int | None:
        return self._stub_age_days


class URLAnalyzer:
    """Analyzer inspecting extracted URLs for phishing indicators and domain deception."""

    name: str = "url_analyzer"

    def __init__(self, age_provider: DomainAgeProvider | None = None) -> None:
        """Initialize URLAnalyzer.

        Args:
            age_provider: Optional provider for domain age lookups.
        """
        self.age_provider = age_provider or StubDomainAgeProvider()

    def run(self, parsed: ParsedEmail) -> AnalyzerResult:
        """Run URL analysis heuristics on extracted URLs and alternative schemes."""
        if not parsed.extracted_urls and not parsed.other_schemes:
            return AnalyzerResult(
                analyzer=self.name,
                status="skipped",
                evidence=[],
                duration_ms=0,
            )

        evidence: list[Evidence] = []
        cfg = get_settings()

        # 1. Non-http(s) schemes (e.g. javascript:, data:, file:)
        for other_url in parsed.other_schemes:
            evidence.append(
                create_evidence(
                    source=self.name,
                    code=EvidenceCode.URL_NON_HTTP_SCHEME,
                    severity=Severity.MEDIUM,
                    description=(
                        "Non-standard or dangerous URI scheme detected (e.g. javascript/data/file)."
                    ),
                    confidence=0.9,
                    raw_data={"url": other_url[:100]},
                )
            )

        if not parsed.extracted_urls:
            return AnalyzerResult(
                analyzer=self.name,
                status="ok",
                evidence=evidence,
                duration_ms=0,
            )

        brands = load_brands()
        shorteners = load_shorteners()
        suspicious_tlds = load_suspicious_tlds()

        # Build set of all legitimate brand domains (allowlist for typosquatting)
        all_brand_domains: set[str] = {d.lower() for b in brands for d in b.domains}

        # Track registered domains for deduplication before brand comparison
        evaluated_reg_domains: set[str] = set()

        for item in parsed.extracted_urls:
            norm = item.normalized_url
            host_clean = norm.host.lower()
            reg_domain = norm.registered_domain.lower()

            # Link text mismatch
            if item.link_text_mismatch:
                evidence.append(
                    create_evidence(
                        source=self.name,
                        code=EvidenceCode.URL_LINK_TEXT_MISMATCH,
                        severity=Severity.HIGH,
                        description=(
                            "Visible anchor text displays different domain than destination href."
                        ),
                        confidence=0.9,
                        raw_data={
                            "href_domain": reg_domain or host_clean,
                            "visible_text": item.visible_text or "",
                        },
                    )
                )

            # IP host checks
            if norm.ip_obfuscated:
                evidence.append(
                    create_evidence(
                        source=self.name,
                        code=EvidenceCode.URL_IP_OBFUSCATED,
                        severity=Severity.HIGH,
                        description="Host uses obfuscated IP encoding (octal, hex, or dword).",
                        confidence=0.95,
                        raw_data={"host": host_clean, "canonical_ip": norm.url},
                    )
                )
            elif norm.is_ip_literal:
                evidence.append(
                    create_evidence(
                        source=self.name,
                        code=EvidenceCode.URL_IP_LITERAL,
                        severity=Severity.MEDIUM,
                        description="URL points directly to an IP literal rather than hostname.",
                        confidence=0.9,
                        raw_data={"host": host_clean},
                    )
                )

            # Userinfo trick (@ symbol)
            if norm.has_userinfo:
                evidence.append(
                    create_evidence(
                        source=self.name,
                        code=EvidenceCode.URL_USERINFO_TRICK,
                        severity=Severity.HIGH,
                        description="URL contains embedded userinfo trick before @ symbol.",
                        confidence=0.95,
                        raw_data={"host": host_clean},
                    )
                )

            # Excessive subdomains (>= 3 labels in subdomain)
            if norm.subdomain:
                sub_labels = [lbl for lbl in norm.subdomain.split(".") if lbl]
                if len(sub_labels) >= 3:
                    evidence.append(
                        create_evidence(
                            source=self.name,
                            code=EvidenceCode.URL_EXCESSIVE_SUBDOMAINS,
                            severity=Severity.LOW,
                            description="Host contains excessive subdomain levels (>= 3).",
                            confidence=0.7,
                            raw_data={"subdomain": norm.subdomain, "count": len(sub_labels)},
                        )
                    )

            # Odd non-standard port
            if norm.port is not None and norm.port not in (80, 443):
                evidence.append(
                    create_evidence(
                        source=self.name,
                        code=EvidenceCode.URL_ODD_PORT,
                        severity=Severity.MEDIUM,
                        description="URL targets a non-standard HTTP/HTTPS network port.",
                        confidence=0.85,
                        raw_data={"port": norm.port, "host": host_clean},
                    )
                )

            # Excessive URL length
            if len(item.raw_url) > 200:
                evidence.append(
                    create_evidence(
                        source=self.name,
                        code=EvidenceCode.URL_EXCESSIVE_LENGTH,
                        severity=Severity.LOW,
                        description="URL length exceeds 200 characters.",
                        confidence=0.6,
                        raw_data={"length": len(item.raw_url)},
                    )
                )

            # Known shortener
            if reg_domain in shorteners or host_clean in shorteners:
                evidence.append(
                    create_evidence(
                        source=self.name,
                        code=EvidenceCode.URL_KNOWN_SHORTENER,
                        severity=Severity.LOW,
                        description="URL utilizes a known shortening service.",
                        confidence=0.8,
                        raw_data={"domain": reg_domain or host_clean},
                    )
                )

            # Suspicious TLD
            if norm.suffix and norm.suffix.lower() in suspicious_tlds:
                evidence.append(
                    create_evidence(
                        source=self.name,
                        code=EvidenceCode.URL_SUSPICIOUS_TLD,
                        severity=Severity.MEDIUM,
                        description="Domain is registered under a high-abuse or suspicious TLD.",
                        confidence=0.85,
                        raw_data={"suffix": norm.suffix, "domain": reg_domain},
                    )
                )

            # Check if domain was already evaluated for brand typosquatting / homographs
            target_reg = reg_domain or host_clean
            if not target_reg or target_reg in evaluated_reg_domains:
                continue
            evaluated_reg_domains.add(target_reg)

            # 2. Homographs & Confusables
            # Check IDN, punycode, or non-ASCII
            host_unicode = norm.host
            is_idn = norm.is_idn or norm.has_punycode or any(ord(c) >= 128 for c in host_unicode)

            # Extract label of registered domain (e.g. 'acmetrust' from 'acmetrust.test')
            domain_label = norm.domain.lower() if norm.domain else host_clean.split(".")[0]
            skeleton = get_ascii_skeleton(domain_label)

            # Check mixed script
            mixed_script = is_mixed_script(host_unicode) or is_mixed_script(domain_label)

            # Check if skeleton matches a brand label
            matched_skeleton_brand: str | None = None
            if not norm.is_ip_literal:
                for b in brands:
                    for b_dom in b.domains:
                        b_lbl, _ = _extract_brand_label_and_suffix(b_dom)
                        if skeleton == b_lbl and target_reg not in b.domains:
                            matched_skeleton_brand = b.name
                            break
                    if matched_skeleton_brand:
                        break

            if mixed_script or (matched_skeleton_brand and is_idn):
                evidence.append(
                    create_evidence(
                        source=self.name,
                        code=EvidenceCode.URL_HOMOGRAPH_CONFUSABLE,
                        severity=Severity.HIGH,
                        description=(
                            "Domain utilizes mixed-script characters or visual confusables."
                        ),
                        confidence=0.95,
                        raw_data={
                            "host": host_clean,
                            "skeleton": skeleton,
                            "matched_brand": matched_skeleton_brand or "",
                            "mixed_script": mixed_script,
                        },
                    )
                )
            elif is_idn:
                evidence.append(
                    create_evidence(
                        source=self.name,
                        code=EvidenceCode.URL_HOMOGRAPH_IDN,
                        severity=Severity.LOW,
                        description=(
                            "Internationalized domain name (punycode xn--) without confusable."
                        ),
                        confidence=0.6,
                        raw_data={"host": host_clean},
                    )
                )

            # 3. Typosquatting vs Brand Reference List
            # Skip if IP or if domain is in legitimate brand allowlist
            if norm.is_ip_literal or target_reg in all_brand_domains:
                continue

            for brand in brands:
                for b_domain in brand.domains:
                    b_label, b_suffix = _extract_brand_label_and_suffix(b_domain)

                    # Exact brand label match under different TLD
                    if domain_label == b_label and norm.suffix.lower() != b_suffix:
                        evidence.append(
                            create_evidence(
                                source=self.name,
                                code=EvidenceCode.URL_SAME_LABEL_DIFF_TLD,
                                severity=Severity.HIGH,
                                description=(
                                    "Domain uses exact brand name registered under unapproved TLD."
                                ),
                                confidence=0.9,
                                raw_data={
                                    "brand": brand.name,
                                    "registered_domain": target_reg,
                                    "target_tld": norm.suffix,
                                },
                            )
                        )
                        break

                    # Brand in subdomain
                    if norm.subdomain:
                        sub_parts = [p.lower() for p in norm.subdomain.split(".")]
                        if b_label in sub_parts:
                            evidence.append(
                                create_evidence(
                                    source=self.name,
                                    code=EvidenceCode.URL_BRAND_IN_SUBDOMAIN,
                                    severity=Severity.HIGH,
                                    description="Brand name placed in subdomain to mislead users.",
                                    confidence=0.9,
                                    raw_data={
                                        "brand": brand.name,
                                        "subdomain": norm.subdomain,
                                        "domain": target_reg,
                                    },
                                )
                            )
                            break

                    # Brand + keyword (combosquatting)
                    if b_label in domain_label and domain_label != b_label:
                        evidence.append(
                            create_evidence(
                                source=self.name,
                                code=EvidenceCode.URL_TYPOSQUAT_BRAND,
                                severity=Severity.HIGH,
                                confidence=0.92,
                                description=(
                                    "Domain combines brand name with keywords (combosquatting)."
                                ),
                                raw_data={
                                    "brand": brand.name,
                                    "registered_domain": target_reg,
                                    "technique": "combosquatting",
                                },
                            )
                        )
                        break

                    # Fuzzy edit distance comparison (skip short labels <= 3 chars)
                    if len(domain_label) > 3 and len(b_label) > 3:
                        similarity = rapidfuzz.fuzz.ratio(domain_label, b_label) / 100.0
                        if similarity >= 0.82 and domain_label != b_label:
                            evidence.append(
                                create_evidence(
                                    source=self.name,
                                    code=EvidenceCode.URL_TYPOSQUAT_BRAND,
                                    severity=Severity.HIGH,
                                    description=("Domain exhibits high similarity to a brand."),
                                    confidence=0.9,
                                    raw_data={
                                        "brand": brand.name,
                                        "registered_domain": target_reg,
                                        "similarity": round(similarity, 3),
                                    },
                                )
                            )
                            break

            # 4. Domain Age Verification
            if cfg.PHISHGUARD_DOMAIN_AGE_ENABLED and not norm.is_ip_literal:
                try:
                    age_days = self.age_provider.get_domain_age_days(target_reg)
                    if age_days is not None and age_days < 30:
                        evidence.append(
                            create_evidence(
                                source=self.name,
                                code=EvidenceCode.URL_DOMAIN_TOO_NEW,
                                severity=Severity.HIGH,
                                description=(
                                    "Domain was registered within last 30 days (newly registered)."
                                ),
                                confidence=0.85,
                                raw_data={"age_days": age_days, "domain": target_reg},
                            )
                        )
                except (RuntimeError, ValueError, TimeoutError, OSError):
                    # Domain age lookup fails soft per FR-URL-5
                    continue

        return AnalyzerResult(
            analyzer=self.name,
            status="ok",
            evidence=evidence,
            duration_ms=0,
        )
