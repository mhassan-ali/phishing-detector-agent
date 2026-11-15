"""Unit tests for URL analyzer covering heuristics, homographs, and typosquatting."""

from pathlib import Path

import pytest

from phishguard.analyzers.brands import load_brands
from phishguard.analyzers.codes import EvidenceCode
from phishguard.analyzers.url import StubDomainAgeProvider, URLAnalyzer
from phishguard.core.config import Settings
from phishguard.core.schemas import ExtractedURL, ParsedEmail, Severity
from phishguard.ingest.extractor import extract_urls
from phishguard.ingest.normalizer import normalize_url
from phishguard.ingest.parser import parse_eml

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "emails"


def _make_extracted_url(raw: str, link_text: str | None = None) -> ExtractedURL:
    norm = normalize_url(raw)
    mismatch = False
    if link_text and "." in link_text:
        vis_norm = normalize_url(link_text if "://" in link_text else f"http://{link_text}")
        if vis_norm.registered_domain and vis_norm.registered_domain != norm.registered_domain:
            mismatch = True
    return ExtractedURL(
        raw_url=raw,
        normalized_url=norm,
        visible_text=link_text,
        link_text_mismatch=mismatch,
        source_locations=["body_html"],
    )


def test_url_analyzer_skipped_when_empty() -> None:
    """Verify analyzer returns status='skipped' when no extracted URLs or other schemes exist."""
    analyzer = URLAnalyzer()
    parsed = ParsedEmail(sha256="dummy")
    res = analyzer.run(parsed)
    assert res.status == "skipped"
    assert res.evidence == []


def test_url_analyzer_non_http_schemes() -> None:
    """Verify non-http(s) schemes emit URL_NON_HTTP_SCHEME."""
    analyzer = URLAnalyzer()
    parsed = ParsedEmail(
        other_schemes=["javascript:alert(1)", "data:text/html;base64,..."],
        sha256="dummy",
    )
    res = analyzer.run(parsed)
    codes = [e.code for e in res.evidence]
    assert EvidenceCode.URL_NON_HTTP_SCHEME in codes


def test_url_analyzer_ip_literals_and_obfuscation() -> None:
    """Verify IP literal and obfuscated integer/octal IPs are detected."""
    analyzer = URLAnalyzer()

    # Plain IP
    u1 = _make_extracted_url("http://198.51.100.1/path")
    parsed1 = ParsedEmail(extracted_urls=[u1], sha256="dummy")
    res1 = analyzer.run(parsed1)
    codes1 = [e.code for e in res1.evidence]
    assert EvidenceCode.URL_IP_LITERAL in codes1

    # Obfuscated dword IP
    u2 = _make_extracted_url("http://0x7f000001/admin")
    parsed2 = ParsedEmail(extracted_urls=[u2], sha256="dummy")
    res2 = analyzer.run(parsed2)
    codes2 = [e.code for e in res2.evidence]
    assert EvidenceCode.URL_IP_OBFUSCATED in codes2


def test_url_analyzer_userinfo_and_odd_ports() -> None:
    """Verify userinfo trick and non-standard ports emit evidence."""
    analyzer = URLAnalyzer()
    u = _make_extracted_url("http://legit-brand.com:secret@phishing-drop.test:8080/login")
    parsed = ParsedEmail(extracted_urls=[u], sha256="dummy")
    res = analyzer.run(parsed)
    codes = [e.code for e in res.evidence]
    assert EvidenceCode.URL_USERINFO_TRICK in codes
    assert EvidenceCode.URL_ODD_PORT in codes


def test_url_analyzer_excessive_subdomains_and_length() -> None:
    """Verify >= 3 subdomain levels and > 200 length trigger heuristics."""
    analyzer = URLAnalyzer()
    long_path = "a" * 210
    u = _make_extracted_url(f"https://one.two.three.target-domain.test/{long_path}")
    parsed = ParsedEmail(extracted_urls=[u], sha256="dummy")
    res = analyzer.run(parsed)
    codes = [e.code for e in res.evidence]
    assert EvidenceCode.URL_EXCESSIVE_SUBDOMAINS in codes
    assert EvidenceCode.URL_EXCESSIVE_LENGTH in codes


def test_url_analyzer_shorteners_and_suspicious_tlds() -> None:
    """Verify known shorteners and suspicious TLDs emit evidence."""
    analyzer = URLAnalyzer()
    u = _make_extracted_url("https://bit.ly/claim-prize")
    parsed = ParsedEmail(extracted_urls=[u], sha256="dummy")
    res = analyzer.run(parsed)
    codes = [e.code for e in res.evidence]
    assert EvidenceCode.URL_KNOWN_SHORTENER in codes


def test_url_analyzer_link_text_mismatch() -> None:
    """Verify anchor text domain mismatch emits URL_LINK_TEXT_MISMATCH at HIGH severity."""
    analyzer = URLAnalyzer()
    u = _make_extracted_url(
        "https://credential-stealer.test/login",
        link_text="https://secure.acmetrust.test/login",
    )
    parsed = ParsedEmail(extracted_urls=[u], sha256="dummy")
    res = analyzer.run(parsed)
    codes = {e.code: e for e in res.evidence}
    assert EvidenceCode.URL_LINK_TEXT_MISMATCH in codes
    assert codes[EvidenceCode.URL_LINK_TEXT_MISMATCH].severity == Severity.HIGH


def test_url_analyzer_homographs() -> None:
    """Verify mixed-script homographs emit URL_HOMOGRAPH_CONFUSABLE."""
    analyzer = URLAnalyzer()
    # Cyrillic а (\u0430) in acmetrust -> xn--cmetrust-06g.test
    u = _make_extracted_url("https://xn--cmetrust-06g.test/login")
    parsed = ParsedEmail(extracted_urls=[u], sha256="dummy")
    res = analyzer.run(parsed)
    codes = {e.code: e for e in res.evidence}
    assert EvidenceCode.URL_HOMOGRAPH_CONFUSABLE in codes
    assert codes[EvidenceCode.URL_HOMOGRAPH_CONFUSABLE].severity == Severity.HIGH


def test_url_analyzer_typosquatting_variants() -> None:
    """Verify brand-in-subdomain, same-label-different-TLD, combosquatting, and edit-distance."""
    analyzer = URLAnalyzer()

    # 1. Brand in subdomain
    u1 = _make_extracted_url("https://acmetrust.untrusted-relay.test/portal")
    res1 = analyzer.run(ParsedEmail(extracted_urls=[u1], sha256="dummy"))
    assert EvidenceCode.URL_BRAND_IN_SUBDOMAIN in [e.code for e in res1.evidence]

    # 2. Same label, different TLD (acmetrust.com when brand is acmetrust.test)
    u2 = _make_extracted_url("https://acmetrust.org/login")
    res2 = analyzer.run(ParsedEmail(extracted_urls=[u2], sha256="dummy"))
    assert EvidenceCode.URL_SAME_LABEL_DIFF_TLD in [e.code for e in res2.evidence]

    # 3. Brand + keyword combosquatting
    u3 = _make_extracted_url("https://acmetrust-security-verify.test/login")
    res3 = analyzer.run(ParsedEmail(extracted_urls=[u3], sha256="dummy"))
    assert EvidenceCode.URL_TYPOSQUAT_BRAND in [e.code for e in res3.evidence]

    # 4. Leetspeak digit substitution (paypa1 -> paypal, g00gle -> google)
    u4 = _make_extracted_url("https://paypa1.com/signin")
    res4 = analyzer.run(ParsedEmail(extracted_urls=[u4], sha256="dummy"))
    codes4 = [e.code for e in res4.evidence]
    assert EvidenceCode.URL_TYPOSQUAT_BRAND in codes4
    assert EvidenceCode.URL_HOMOGRAPH_CONFUSABLE not in codes4


def test_url_analyzer_leetspeak_vs_ordinary_digits() -> None:
    """Reclassify leetspeak as typosquatting and verify ordinary digits do not trigger."""
    analyzer = URLAnalyzer()

    # Leetspeak: g00gle.com -> skeleton google -> brand Google
    u_leet = _make_extracted_url("https://g00gle.com/search")
    res_leet = analyzer.run(ParsedEmail(extracted_urls=[u_leet], sha256="dummy"))
    codes_leet = [e.code for e in res_leet.evidence]
    assert EvidenceCode.URL_TYPOSQUAT_BRAND in codes_leet
    assert EvidenceCode.URL_HOMOGRAPH_CONFUSABLE not in codes_leet

    # Ordinary domains with digits (web3, cloud24) must NOT trigger brand or homograph evidence
    u_web3 = _make_extracted_url("https://web3-portal.test/dashboard")
    res_web3 = analyzer.run(ParsedEmail(extracted_urls=[u_web3], sha256="dummy"))
    codes_web3 = [e.code for e in res_web3.evidence]
    assert EvidenceCode.URL_TYPOSQUAT_BRAND not in codes_web3
    assert EvidenceCode.URL_HOMOGRAPH_CONFUSABLE not in codes_web3
    assert EvidenceCode.URL_SAME_LABEL_DIFF_TLD not in codes_web3

    u_cloud = _make_extracted_url("https://cloud24.test/status")
    res_cloud = analyzer.run(ParsedEmail(extracted_urls=[u_cloud], sha256="dummy"))
    codes_cloud = [e.code for e in res_cloud.evidence]
    assert EvidenceCode.URL_TYPOSQUAT_BRAND not in codes_cloud
    assert EvidenceCode.URL_HOMOGRAPH_CONFUSABLE not in codes_cloud


@pytest.mark.parametrize("brand", load_brands())
def test_brand_own_domains_never_trigger_typosquatting(brand: object) -> None:
    """Amendment 6: Parametrized test that every brand domain never triggers typosquatting."""
    analyzer = URLAnalyzer()
    b = brand  # type: ignore[attr-defined]
    for dom in b.domains:
        u = _make_extracted_url(f"https://{dom}/home")
        parsed = ParsedEmail(extracted_urls=[u], sha256="dummy")
        res = analyzer.run(parsed)
        codes = [e.code for e in res.evidence]
        assert EvidenceCode.URL_TYPOSQUAT_BRAND not in codes, f"{dom} triggered typosquatting"
        assert EvidenceCode.URL_SAME_LABEL_DIFF_TLD not in codes, f"{dom} triggered diff TLD"
        assert EvidenceCode.URL_HOMOGRAPH_CONFUSABLE not in codes, f"{dom} triggered homograph"


def test_url_analyzer_domain_age(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify domain age generates URL_DOMAIN_TOO_NEW only when enabled and age < 30 days."""
    monkeypatch.setattr(
        "phishguard.analyzers.url.get_settings",
        lambda: Settings(_env_file=None, PHISHGUARD_DOMAIN_AGE_ENABLED=True),
    )
    stub_provider = StubDomainAgeProvider(stub_age_days=12)
    analyzer = URLAnalyzer(age_provider=stub_provider)
    u = _make_extracted_url("https://brand-new-phish.test/index")
    parsed = ParsedEmail(extracted_urls=[u], sha256="dummy")
    res = analyzer.run(parsed)
    codes = [e.code for e in res.evidence]
    assert EvidenceCode.URL_DOMAIN_TOO_NEW in codes


def test_url_analyzer_fixtures() -> None:
    """Verify URL analyzer on real email fixtures."""
    analyzer = URLAnalyzer()

    # homograph_link.eml
    p_homograph = parse_eml((FIXTURES_DIR / "homograph_link.eml").read_bytes())
    p_homograph.extracted_urls = extract_urls(p_homograph)
    res_homo = analyzer.run(p_homograph)
    assert EvidenceCode.URL_HOMOGRAPH_CONFUSABLE in [e.code for e in res_homo.evidence]

    # link_mismatch.eml
    p_mismatch = parse_eml((FIXTURES_DIR / "link_mismatch.eml").read_bytes())
    p_mismatch.extracted_urls = extract_urls(p_mismatch)
    res_mis = analyzer.run(p_mismatch)
    assert EvidenceCode.URL_LINK_TEXT_MISMATCH in [e.code for e in res_mis.evidence]

    # fake_bank.eml
    p_bank = parse_eml((FIXTURES_DIR / "fake_bank.eml").read_bytes())
    p_bank.extracted_urls = extract_urls(p_bank)
    res_bank = analyzer.run(p_bank)
    assert EvidenceCode.URL_TYPOSQUAT_BRAND in [e.code for e in res_bank.evidence]

    # Legit fixtures must have NO High/Critical and NO typosquat/homograph codes
    for fixture_name in ("legit_newsletter.eml", "legit_receipt.eml"):
        p_legit = parse_eml((FIXTURES_DIR / fixture_name).read_bytes())
        p_legit.extracted_urls = extract_urls(p_legit)
        res_legit = analyzer.run(p_legit)
        for ev in res_legit.evidence:
            assert ev.severity not in (Severity.HIGH, Severity.CRITICAL), (
                f"{fixture_name} had {ev.severity}: {ev.code}"
            )
            assert ev.code not in (
                EvidenceCode.URL_TYPOSQUAT_BRAND,
                EvidenceCode.URL_HOMOGRAPH_CONFUSABLE,
                EvidenceCode.URL_SAME_LABEL_DIFF_TLD,
            ), f"{fixture_name} emitted unexpected code: {ev.code}"
