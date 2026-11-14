"""Unit tests for URL extraction, link-text mismatch detection, and HTML resilience."""

from phishguard.core.schemas import ParsedEmail
from phishguard.ingest.extractor import (
    extract_urls,
    extract_urls_from_content,
    html_to_text,
)


def test_plain_text_url_extraction() -> None:
    """Verify URLs in plain text with trailing punctuation, angle brackets, and markdown."""
    text = (
        "Check this link: https://example.com/page. "
        "Also visit <https://secure.example.com/test> and "
        "review our [Documentation Portal](https://docs.example.com/guide). "
        "Visit www.example.org/about for info."
    )
    urls, other_schemes, warnings = extract_urls_from_content(body_plain=text)
    extracted_urls = [u.normalized_url.url for u in urls]

    assert "https://example.com/page" in extracted_urls
    assert "https://secure.example.com/test" in extracted_urls
    assert "https://docs.example.com/guide" in extracted_urls
    assert "http://www.example.org/about" in extracted_urls

    # Check markdown visible text captured
    doc_link = next(u for u in urls if "docs.example.com" in u.raw_url)
    assert doc_link.visible_text == "Documentation Portal"


def test_html_tag_extraction_a_img_form() -> None:
    """Verify URL extraction from <a>, <img>, and <form> tags."""
    html = """
    <html>
      <body>
        <p><a href="https://portal.example.test/welcome">Click Here</a></p>
        <img src="https://cdn.example.test/images/logo.png" alt="Logo">
        <form action="https://login.example.test/auth" method="post">
          <input type="submit" value="Submit">
        </form>
      </body>
    </html>
    """
    urls, other, warnings = extract_urls_from_content(body_html=html)
    locations = {u.normalized_url.url: u.source_locations for u in urls}

    assert "https://portal.example.test/welcome" in locations
    assert "html_anchor" in locations["https://portal.example.test/welcome"]

    assert "https://cdn.example.test/images/logo.png" in locations
    assert "html_img" in locations["https://cdn.example.test/images/logo.png"]

    assert "https://login.example.test/auth" in locations
    assert "html_form" in locations["https://login.example.test/auth"]


def test_script_and_style_tags_ignored() -> None:
    """Verify malicious payloads and URLs inside script and style tags are never extracted."""
    html = """
    <html>
      <head>
        <script>
          const evilUrl = "https://evil-analytics.test/track";
          function execute() { alert(1); }
        </script>
        <style>
          body { background: url('https://evil-css.test/bg.jpg'); }
        </style>
      </head>
      <body>
        <p><a href="https://legit.example.test/home">Legit Link</a></p>
      </body>
    </html>
    """
    urls, other, warnings = extract_urls_from_content(body_html=html)
    found_urls = [u.normalized_url.url for u in urls]

    assert "https://legit.example.test/home" in found_urls
    assert "https://evil-analytics.test/track" not in found_urls
    assert "https://evil-css.test/bg.jpg" not in found_urls


def test_link_text_mismatch_detection_standard_and_rfc2606() -> None:
    """Verify link-text mismatch detection on standard domains and RFC 2606 .test domains."""
    html = """
    <div>
      <!-- Mismatch on .test domains -->
      <a href="https://harvest-creds.test/login">https://secure.acmetrust.test/login</a>

      <!-- Matching domain -->
      <a href="https://sub.example.com/checkout">https://example.com/store</a>

      <!-- Non-domain visible text (no mismatch) -->
      <a href="https://external.test/page">Click here to continue</a>
    </div>
    """
    urls, other, warnings = extract_urls_from_content(body_html=html)
    url_by_href = {u.normalized_url.url: u for u in urls}

    mismatch_url = url_by_href["https://harvest-creds.test/login"]
    assert mismatch_url.link_text_mismatch is True
    assert mismatch_url.visible_text == "https://secure.acmetrust.test/login"

    matching_url = url_by_href["https://sub.example.com/checkout"]
    assert matching_url.link_text_mismatch is False

    click_here_url = url_by_href["https://external.test/page"]
    assert click_here_url.link_text_mismatch is False


def test_url_deduplication_aggregates_source_locations() -> None:
    """Verify identical URLs across plain text and HTML are deduplicated and locations tracked."""
    plain = "See https://common.example.test/page for details."
    html = '<p><a href="https://common.example.test/page">Link</a></p>'
    urls, other, warnings = extract_urls_from_content(body_plain=plain, body_html=html)

    assert len(urls) == 1
    common = urls[0]
    assert "body_plain" in common.source_locations
    assert "html_anchor" in common.source_locations


def test_non_http_schemes_routed_to_other_schemes() -> None:
    """Verify javascript: and data: schemes are recorded in other_schemes and not dropped."""
    html = """
    <a href="javascript:void(0)">Click me</a>
    <a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">Payload</a>
    <a href="https://legit.example.test">Real Link</a>
    """
    urls, other_schemes, warnings = extract_urls_from_content(body_html=html)

    assert len(urls) == 1
    assert any("javascript:" in s for s in other_schemes)
    assert any("data:" in s for s in other_schemes)


def test_html_deeply_nested_tags_resilience() -> None:
    """Verify HTML parser safely handles 10,000 nested tags without recursion crash."""
    nested_html = "<div>" * 10000 + "<p>deep content</p>" + "</div>" * 10000
    text = html_to_text(nested_html)
    assert "deep content" in text

    # Extract URLs from deep markup without raising unhandled exception
    urls, other, warnings = extract_urls_from_content(body_html=nested_html)
    assert isinstance(urls, list)


def test_html_to_text_helper() -> None:
    """Verify html_to_text produces clean text without scripts."""
    markup = "<p>Hello <b>World</b></p><script>alert(1);</script><span>Footer</span>"
    clean = html_to_text(markup)
    assert "Hello World" in clean
    assert "Footer" in clean
    assert "alert" not in clean


def test_extract_urls_on_parsed_email() -> None:
    """Verify extract_urls modifies ParsedEmail in place."""
    parsed = ParsedEmail(
        body_plain="Check https://example.test/1",
        body_html='<a href="https://example.test/2">Two</a>',
    )
    urls = extract_urls(parsed)
    assert len(urls) == 2
    assert len(parsed.extracted_urls) == 2


def test_empty_content_extraction() -> None:
    """Verify empty plain text and HTML return empty lists without warnings."""
    urls, other, warnings = extract_urls_from_content(body_plain="", body_html="")
    assert urls == []
    assert other == []
    assert warnings == []
    assert html_to_text("") == ""


def test_html_to_text_parser_exception_fallback(monkeypatch) -> None:
    """Verify html_to_text falls back to regex tag stripping if BeautifulSoup raises."""
    import bs4

    def mock_soup_init(*args, **kwargs):
        raise RecursionError("Simulated recursion")

    monkeypatch.setattr(bs4, "BeautifulSoup", mock_soup_init)
    res = html_to_text("<p>Fallback <b>Content</b></p>")
    assert "Fallback" in res
    assert "Content" in res


def test_extractor_edge_cases() -> None:
    """Verify unparseable URLs and single label domains in extractor."""
    from phishguard.ingest.extractor import detect_link_mismatch, extract_registered_domain

    assert extract_registered_domain("singlelabel") == "singlelabel"
    assert extract_registered_domain("") == ""
    assert detect_link_mismatch(None, "example.com") is False
    assert detect_link_mismatch("No domain here", "example.com") is False
    assert detect_link_mismatch("https://example.com", "") is False

    # HTML anchor with invalid URL scheme that raises ValueError in normalize_url
    html = '<a href="http://[invalid-ipv6">Broken</a>'
    urls, other, warnings = extract_urls_from_content(body_html=html)
    assert urls == []
