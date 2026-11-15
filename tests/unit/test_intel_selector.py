"""Unit tests for indicator selection, prioritization, and SSRF/IP filtering."""

from phishguard.core.schemas import AttachmentMetadata, ExtractedURL, ParsedEmail
from phishguard.ingest.normalizer import normalize_url
from phishguard.intel.selector import (
    is_private_or_reserved_ip,
    select_indicators,
    strip_url_query_and_fragment,
)


def _make_url(url: str, *, link_mismatch: bool = False, is_ip: bool = False) -> ExtractedURL:
    norm = normalize_url(url)
    return ExtractedURL(
        raw_url=url,
        normalized_url=norm,
        link_text_mismatch=link_mismatch,
    )


def test_is_private_or_reserved_ip() -> None:
    """Verify loopback, RFC 1918, link-local, and metadata IPs are flagged (Amendment 6)."""
    assert is_private_or_reserved_ip("127.0.0.1") is True
    assert is_private_or_reserved_ip("::1") is True
    assert is_private_or_reserved_ip("192.168.1.100") is True
    assert is_private_or_reserved_ip("10.0.0.1") is True
    assert is_private_or_reserved_ip("172.16.0.1") is True
    assert is_private_or_reserved_ip("169.254.169.254") is True  # Cloud metadata
    assert is_private_or_reserved_ip("[fe80::1]") is True  # IPv6 link-local
    assert is_private_or_reserved_ip("8.8.8.8") is False  # Public IP


def test_strip_url_query_and_fragment() -> None:
    """Verify query parameters and fragments are stripped for privacy."""
    url = "https://example.com/login?token=secret123&user=john#section"
    stripped = strip_url_query_and_fragment(url)
    assert stripped == "https://example.com/login"
    assert "token" not in stripped
    assert "section" not in stripped


def test_select_indicators_prioritization_and_filtering() -> None:
    """Verify prioritization: attachment hash first (FR-ATT-3), then flagged URLs, then domains."""
    parsed = ParsedEmail(
        attachments=[
            AttachmentMetadata(
                filename="payload.exe",
                content_type="application/octet-stream",
                size_bytes=1024,
                sha256="deadbeef" * 8,
            )
        ],
        extracted_urls=[
            # Private IP URL -> must be dropped (Amendment 6)
            _make_url("http://127.0.0.1/admin", is_ip=True),
            # Flagged URL (link mismatch)
            _make_url("https://phish.example.test/auth?token=123", link_mismatch=True),
            # Normal URL
            _make_url("https://news.example.com/story"),
        ],
        sha256="dummy",
    )

    indicators = select_indicators(parsed, max_indicators=5, send_full_urls=False)

    # 1. Attachment SHA-256 is first
    assert indicators[0].type == "sha256"
    assert indicators[0].value == "deadbeef" * 8

    # 2. Flagged URL is second, with query stripped
    assert indicators[1].type == "url"
    assert indicators[1].value == "https://phish.example.test/auth"
    assert "token" not in indicators[1].value

    # 3. Private IP was dropped
    values = [ind.value for ind in indicators]
    assert "127.0.0.1" not in values
    assert "http://127.0.0.1/admin" not in values

    # 4. Remaining unique domain is present
    assert any(ind.type == "domain" and ind.value == "example.com" for ind in indicators)


def test_select_indicators_send_full_urls_toggle() -> None:
    """Verify PHISHGUARD_INTEL_SEND_FULL_URLS preserves queries when enabled."""
    parsed = ParsedEmail(
        extracted_urls=[
            _make_url("https://phish.example.test/auth?token=123", link_mismatch=True),
        ],
        sha256="dummy",
    )
    indicators = select_indicators(parsed, max_indicators=5, send_full_urls=True)
    assert indicators[0].value == "https://phish.example.test/auth?token=123"
