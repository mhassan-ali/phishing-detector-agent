"""Unit tests for the header analyzer covering SPF/DKIM/DMARC, spoofing, and routing anomalies."""

from pathlib import Path

import pytest

from phishguard.analyzers.codes import EvidenceCode
from phishguard.analyzers.header import HeaderAnalyzer, parse_auth_header
from phishguard.core.config import Settings
from phishguard.core.schemas import ParsedEmail, Severity
from phishguard.ingest.parser import parse_eml

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "emails"


def test_parse_auth_header() -> None:
    """Verify RFC 8601 auth header parsing."""
    hdr = (
        "mx.google.com; spf=pass (google.com: domain designates ...) "
        "smtp.mailfrom=user@example.com; dkim=pass header.d=example.com; "
        "dmarc=pass header.from=example.com"
    )
    parsed = parse_auth_header(hdr)
    assert parsed["authserv_id"] == "mx.google.com"
    assert parsed["spf"] == "pass"
    assert parsed["dkim"] == "pass"
    assert parsed["dmarc"] == "pass"
    assert parsed["smtp.mailfrom"] == "user@example.com"
    assert parsed["header.d"] == "example.com"
    assert parsed["header.from"] == "example.com"


def test_header_analyzer_skipped_no_headers() -> None:
    """Verify analyzer returns status='skipped' when raw_headers is empty."""
    analyzer = HeaderAnalyzer()
    parsed = ParsedEmail(sha256="dummy")
    res = analyzer.run(parsed)
    assert res.status == "skipped"
    assert res.evidence == []


def test_header_analyzer_missing_auth_results() -> None:
    """Verify missing Authentication-Results emits HDR_MISSING_AUTH_RESULTS."""
    analyzer = HeaderAnalyzer()
    parsed = ParsedEmail(
        from_addr="user@example.com",
        raw_headers={"from": ["user@example.com"]},
        sha256="dummy",
    )
    res = analyzer.run(parsed)
    codes = [e.code for e in res.evidence]
    assert EvidenceCode.HDR_MISSING_AUTH_RESULTS in codes


def test_header_analyzer_multiple_auth_results() -> None:
    """Verify multiple Authentication-Results headers emit HDR_MULTIPLE_AUTH_RESULTS."""
    analyzer = HeaderAnalyzer()
    parsed = ParsedEmail(
        from_addr="user@example.com",
        auth_results=[
            {"index": 0, "header": "Authentication-Results", "value": "mx.example.com; spf=pass"},
            {"index": 5, "header": "Authentication-Results", "value": "spoof.net; spf=fail"},
        ],
        raw_headers={"authentication-results": ["...", "..."]},
        sha256="dummy",
    )
    res = analyzer.run(parsed)
    codes = [e.code for e in res.evidence]
    assert EvidenceCode.HDR_MULTIPLE_AUTH_RESULTS in codes


def test_header_analyzer_untrusted_authserv_id(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify untrusted authserv-id emits HDR_UNTRUSTED_AUTH_RESULTS and is not evaluated."""
    monkeypatch.setattr(
        "phishguard.analyzers.header.get_settings",
        lambda: Settings(
            _env_file=None,
            PHISHGUARD_TRUSTED_AUTHSERV_IDS="mx.corporate.corp,gateway.corporate.corp",
        ),
    )
    analyzer = HeaderAnalyzer()
    parsed = ParsedEmail(
        from_addr="user@example.com",
        auth_results=[
            {
                "index": 0,
                "header": "Authentication-Results",
                "value": "untrusted-mx.attacker.test; spf=fail; dmarc=fail",
            }
        ],
        raw_headers={"authentication-results": ["..."]},
        sha256="dummy",
    )
    res = analyzer.run(parsed)
    codes = [e.code for e in res.evidence]
    assert EvidenceCode.HDR_UNTRUSTED_AUTH_RESULTS in codes
    # SPF/DMARC fail are NOT trusted from untrusted authserv-id
    assert EvidenceCode.HDR_DMARC_FAIL not in codes
    assert EvidenceCode.HDR_SPF_FAIL not in codes


def test_header_analyzer_trusted_auth_failures() -> None:
    """Verify SPF, DKIM, and DMARC failures emit appropriate evidence."""
    analyzer = HeaderAnalyzer()
    parsed = ParsedEmail(
        from_addr="sender@victim.test",
        auth_results=[
            {
                "index": 0,
                "header": "Authentication-Results",
                "value": (
                    "mx.victim.test; spf=fail smtp.mailfrom=attacker@other.test; "
                    "dkim=fail header.d=other.test; dmarc=fail"
                ),
            }
        ],
        raw_headers={"authentication-results": ["..."]},
        sha256="dummy",
    )
    res = analyzer.run(parsed)
    codes = {e.code: e for e in res.evidence}
    assert EvidenceCode.HDR_DMARC_FAIL in codes
    assert codes[EvidenceCode.HDR_DMARC_FAIL].severity == Severity.HIGH
    assert EvidenceCode.HDR_SPF_FAIL in codes
    assert EvidenceCode.HDR_DKIM_FAIL in codes
    assert EvidenceCode.HDR_SPF_ALIGNMENT_FAIL in codes
    assert EvidenceCode.HDR_DKIM_ALIGNMENT_FAIL in codes


def test_header_analyzer_spf_softfail() -> None:
    """Verify SPF softfail generates MEDIUM severity evidence."""
    analyzer = HeaderAnalyzer()
    parsed = ParsedEmail(
        from_addr="sender@example.com",
        auth_results=[
            {
                "index": 0,
                "header": "Authentication-Results",
                "value": "mx.example.com; spf=softfail smtp.mailfrom=sender@example.com",
            }
        ],
        raw_headers={"authentication-results": ["..."]},
        sha256="dummy",
    )
    res = analyzer.run(parsed)
    codes = {e.code: e for e in res.evidence}
    assert EvidenceCode.HDR_SPF_FAIL in codes
    assert codes[EvidenceCode.HDR_SPF_FAIL].severity == Severity.MEDIUM


def test_header_analyzer_reply_to_and_return_path_mismatches() -> None:
    """Verify Reply-To and Return-Path mismatches emit corresponding evidence."""
    analyzer = HeaderAnalyzer()
    parsed = ParsedEmail(
        from_addr="billing@legit-company.test",
        reply_to="attacker@harvest-drop.test",
        return_path="bounces@bulk-sender.test",
        raw_headers={"from": ["..."]},
        sha256="dummy",
    )
    res = analyzer.run(parsed)
    codes = [e.code for e in res.evidence]
    assert EvidenceCode.HDR_DOMAIN_MISMATCH_REPLYTO in codes
    assert EvidenceCode.HDR_DOMAIN_MISMATCH_RETURNPATH in codes


def test_header_analyzer_display_name_brand_spoof() -> None:
    """Verify display name claiming a known brand with unrelated from domain is HIGH severity."""
    analyzer = HeaderAnalyzer()
    parsed = ParsedEmail(
        from_addr="attacker@unrelated-host.test",
        from_display_name="AcmeTrust Customer Support",
        raw_headers={"from": ["..."]},
        sha256="dummy",
    )
    res = analyzer.run(parsed)
    codes = {e.code: e for e in res.evidence}
    assert EvidenceCode.HDR_DISPLAY_NAME_SPOOF in codes
    assert codes[EvidenceCode.HDR_DISPLAY_NAME_SPOOF].severity == Severity.HIGH


def test_header_analyzer_freemail_brand_spoof() -> None:
    """Verify free-mail account claiming a known corporate brand triggers freemail spoof."""
    analyzer = HeaderAnalyzer()
    parsed = ParsedEmail(
        from_addr="fraudster@free-mail.example.org",
        from_display_name="PayPal Security Team",
        raw_headers={"from": ["..."]},
        sha256="dummy",
    )
    res = analyzer.run(parsed)
    codes = [e.code for e in res.evidence]
    assert EvidenceCode.HDR_DISPLAY_NAME_SPOOF in codes
    assert EvidenceCode.HDR_FREEMAIL_BRAND_SPOOF in codes


def test_header_analyzer_bare_executive_title_is_low() -> None:
    """Verify bare administrative titles without brand match emit LOW severity evidence only."""
    analyzer = HeaderAnalyzer()
    parsed = ParsedEmail(
        from_addr="user@company.test",
        from_display_name="IT Support Helpdesk",
        raw_headers={"from": ["..."]},
        sha256="dummy",
    )
    res = analyzer.run(parsed)
    codes = {e.code: e for e in res.evidence}
    assert EvidenceCode.HDR_EXECUTIVE_TITLE_SPOOF in codes
    assert codes[EvidenceCode.HDR_EXECUTIVE_TITLE_SPOOF].severity == Severity.LOW
    assert EvidenceCode.HDR_DISPLAY_NAME_SPOOF not in codes


def test_header_analyzer_received_chain_anomalies() -> None:
    """Verify hop count, intermediate private relays, and backward time anomalies."""
    analyzer = HeaderAnalyzer()
    parsed = ParsedEmail(
        from_addr="sender@example.com",
        raw_headers={"received": ["..."]},
        received_chain=[
            # Hop 0 (latest recipient)
            "from mx.relay.net by mx.final.com; Fri, 14 Nov 2026 12:00:00 +0000",
            # Hop 1 (intermediate private relay with future timestamp -> time anomaly)
            "from internal-host (192.168.1.50) by mx.relay.net; Fri, 14 Nov 2026 12:05:00 +0000",
        ]
        + ["from relay.node by relay.node; Fri, 14 Nov 2026 11:50:00 +0000"] * 10,
        sha256="dummy",
    )
    res = analyzer.run(parsed)
    codes = [e.code for e in res.evidence]
    assert EvidenceCode.HDR_RECEIVED_HOP_COUNT_HIGH in codes
    assert EvidenceCode.HDR_RECEIVED_PRIVATE_RELAY in codes
    assert EvidenceCode.HDR_RECEIVED_TIME_ANOMALY in codes


def test_header_analyzer_with_fake_bank_fixture() -> None:
    """Verify header analyzer on fake_bank.eml identifies spoofing and DMARC failure."""
    eml_data = (FIXTURES_DIR / "fake_bank.eml").read_bytes()
    parsed = parse_eml(eml_data)
    analyzer = HeaderAnalyzer()
    res = analyzer.run(parsed)
    codes = [e.code for e in res.evidence]
    assert EvidenceCode.HDR_DMARC_FAIL in codes
    assert EvidenceCode.HDR_SPF_FAIL in codes
    assert EvidenceCode.HDR_DOMAIN_MISMATCH_REPLYTO in codes


def test_header_analyzer_with_display_name_spoof_fixture() -> None:
    """Verify header analyzer on display_name_spoof.eml flags brand impersonation."""
    eml_data = (FIXTURES_DIR / "display_name_spoof.eml").read_bytes()
    parsed = parse_eml(eml_data)
    analyzer = HeaderAnalyzer()
    res = analyzer.run(parsed)
    codes = [e.code for e in res.evidence]
    assert EvidenceCode.HDR_DISPLAY_NAME_SPOOF in codes
    assert EvidenceCode.HDR_FREEMAIL_BRAND_SPOOF in codes


def test_header_analyzer_with_legit_fixtures() -> None:
    """Verify legit fixtures produce no HIGH/CRITICAL evidence in header analyzer."""
    for fixture_name in ("legit_newsletter.eml", "legit_receipt.eml"):
        eml_data = (FIXTURES_DIR / fixture_name).read_bytes()
        parsed = parse_eml(eml_data)
        analyzer = HeaderAnalyzer()
        res = analyzer.run(parsed)
        for ev in res.evidence:
            assert ev.severity not in (Severity.HIGH, Severity.CRITICAL), (
                f"Unexpected {ev.severity} in {fixture_name}: {ev.code} - {ev.description}"
            )
