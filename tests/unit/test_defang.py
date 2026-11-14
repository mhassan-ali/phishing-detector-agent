"""Unit tests for indicator defanging and refanging routines."""

from phishguard.core.schemas import IOC
from phishguard.ingest.defang import defang, refang


def test_defang_urls() -> None:
    """Verify standard and secure URLs are properly defanged."""
    assert defang("http://example.com") == "hxxp://example[.]com"
    assert defang("https://example.com/path/test") == "hxxps://example[.]com/path/test"
    assert (
        defang("https://sub.domain.example.com?query=1")
        == "hxxps://sub[.]domain[.]example[.]com?query=1"
    )


def test_defang_ips_and_emails() -> None:
    """Verify IP addresses and email addresses are defanged."""
    assert defang("192.168.1.1") == "192[.]168[.]1[.]1"
    assert defang("user@example.com") == "user[at]example[.]com"
    assert defang("alert@sub.domain.com") == "alert[at]sub[.]domain[.]com"


def test_defang_idempotent() -> None:
    """Verify calling defang multiple times does not produce nested brackets."""
    first = defang("https://test.example.com")
    second = defang(first)
    assert second == "hxxps://test[.]example[.]com"


def test_refang_round_trip() -> None:
    """Verify refang restores defanged values to standard network indicators."""
    orig_url = "https://sub.domain.example.com/test?a=1"
    defanged = defang(orig_url)
    assert defanged != orig_url
    assert refang(defanged) == orig_url

    orig_email = "analyst@example.com"
    assert refang(defang(orig_email)) == orig_email


def test_ioc_schema_stores_defanged_values() -> None:
    """Verify IOC domain models store defanged indicators."""
    raw_indicator = "https://malicious.example.test/payload"
    ioc = IOC(
        type="url",
        value=defang(raw_indicator),
        context="email_body",
    )
    assert "hxxps://" in ioc.value
    assert "[.]" in ioc.value
    assert "https://" not in ioc.value


def test_defang_refang_empty_and_http() -> None:
    """Verify empty string handling and http/hxxp conversion."""
    assert defang("") == ""
    assert refang("") == ""
    assert defang("http://plain.test") == "hxxp://plain[.]test"
    assert refang("hxxp://plain[.]test") == "http://plain.test"
