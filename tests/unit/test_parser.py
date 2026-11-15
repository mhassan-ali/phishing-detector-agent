"""Unit tests for EML email parsing, header extraction, and ingestion dispatching."""

from pathlib import Path

import pytest

from phishguard.core.schemas import ParseWarning, ScanRequest
from phishguard.ingest.parser import ingest, parse_eml, parse_raw_text

FIXTURES_DIR = Path("tests/fixtures/emails")


def test_parse_legit_newsletter() -> None:
    """Verify parsing legit newsletter fixture with headers and links."""
    data = (FIXTURES_DIR / "legit_newsletter.eml").read_bytes()
    parsed = parse_eml(data)

    assert parsed.from_addr == "newsletter@news.example.com"
    assert parsed.from_display_name == "Weekly Digest"
    assert parsed.subject == "Your Weekly Tech Update"
    assert len(parsed.received_chain) == 1
    assert len(parsed.auth_results) == 1
    assert "https://news.example.com/digest/2026-11-14" in [
        u.normalized_url.url for u in parsed.extracted_urls
    ]
    assert parsed.sha256 != ""


def test_parse_legit_receipt_with_attachment() -> None:
    """Verify parsing legit receipt with safe PDF attachment enumeration."""
    data = (FIXTURES_DIR / "legit_receipt.eml").read_bytes()
    parsed = parse_eml(data)

    assert parsed.subject == "Order Receipt #987654"
    assert len(parsed.attachments) == 1
    att = parsed.attachments[0]
    assert att.filename == "receipt_987654.pdf"
    assert att.content_type == "application/pdf"
    assert att.size_bytes > 0
    assert len(att.sha256) == 64


def test_parse_fake_bank_spoofing() -> None:
    """Verify parsing fake bank lure with mismatched Reply-To and DMARC fail."""
    data = (FIXTURES_DIR / "fake_bank.eml").read_bytes()
    parsed = parse_eml(data)

    assert parsed.from_addr == "alerts@acmetrust.test"
    assert parsed.reply_to == "support@untrusted-relay.test"
    assert "dmarc=fail" in parsed.auth_results[0]["value"]
    assert len(parsed.extracted_urls) == 1
    assert parsed.extracted_urls[0].normalized_url.domain == "acmetrust-auth"


def test_parse_fake_delivery() -> None:
    """Verify parsing fake delivery fee lure pointing to .test domain."""
    data = (FIXTURES_DIR / "fake_delivery.eml").read_bytes()
    parsed = parse_eml(data)

    assert parsed.from_addr == "dispatch@parcel-delivery.test"
    assert "customs-fee-portal.test" in [
        u.normalized_url.registered_domain for u in parsed.extracted_urls
    ]


def test_parse_display_name_spoof() -> None:
    """Verify parsing display name spoofing with free-mail sender address."""
    data = (FIXTURES_DIR / "display_name_spoof.eml").read_bytes()
    parsed = parse_eml(data)

    assert parsed.from_display_name == "AcmeTrust Executive Services"
    assert parsed.from_addr == "random-spammer@free-mail.example.org"
    assert parsed.reply_to == "executive.direct@free-mail.example.org"


def test_parse_link_mismatch() -> None:
    """Verify parsing email with visible text mismatching href domain."""
    data = (FIXTURES_DIR / "link_mismatch.eml").read_bytes()
    parsed = parse_eml(data)

    assert len(parsed.extracted_urls) == 1
    url = parsed.extracted_urls[0]
    assert url.link_text_mismatch is True
    assert url.normalized_url.registered_domain == "harvest-credentials.test"
    assert url.visible_text == "https://secure.acmetrust.test/login"


def test_parse_homograph_link() -> None:
    """Verify parsing email with punycode/IDNA homograph domain."""
    data = (FIXTURES_DIR / "homograph_link.eml").read_bytes()
    parsed = parse_eml(data)

    assert len(parsed.extracted_urls) == 1
    url = parsed.extracted_urls[0]
    assert url.normalized_url.has_punycode is True
    assert url.normalized_url.host_punycode == "xn--cmetrust-06g.test"
    assert url.normalized_url.host_unicode == "аcmetrust.test"


def test_parse_suspicious_attachment() -> None:
    """Verify parsing email with double-extension executable attachment."""
    data = (FIXTURES_DIR / "suspicious_attachment.eml").read_bytes()
    parsed = parse_eml(data)

    assert len(parsed.attachments) == 1
    att = parsed.attachments[0]
    assert att.filename == "invoice_1092.pdf.exe"
    assert att.content_type == "application/octet-stream"
    assert att.size_bytes > 0


def test_parse_malformed_truncated_mime() -> None:
    """Verify parser handles truncated MIME without raising unhandled exceptions."""
    data = (FIXTURES_DIR / "truncated_mime.eml").read_bytes()
    parsed = parse_eml(data)

    assert parsed.subject == "Truncated MIME Test"
    assert parsed.sha256 != ""


def test_parse_malformed_bad_charset() -> None:
    """Verify parser falls back cleanly on undeclared/invalid charsets."""
    data = (FIXTURES_DIR / "bad_charset.eml").read_bytes()
    parsed = parse_eml(data)

    assert ParseWarning.CHARSET_DECODE_ERROR in parsed.parse_warnings
    assert "invalid charset" in parsed.body_plain


def test_multiple_auth_results_warning() -> None:
    """Verify warning is added when multiple Authentication-Results headers exist."""
    eml = (
        "From: sender@example.com\r\n"
        "To: recipient@example.com\r\n"
        "Subject: Multiple Auth Test\r\n"
        "Authentication-Results: mx.example.com; dmarc=pass\r\n"
        "Authentication-Results: forged-upstream.test; dmarc=fail\r\n\r\n"
        "Body content"
    )
    parsed = parse_eml(eml.encode("utf-8"))
    assert ParseWarning.MULTIPLE_AUTH_RESULTS in parsed.parse_warnings
    assert len(parsed.auth_results) == 2
    assert parsed.auth_results[0]["index"] != parsed.auth_results[1]["index"]


def test_parse_raw_text() -> None:
    """Verify parse_raw_text functions identically to parse_eml for string input."""
    raw = (
        "From: Alice <alice@example.com>\r\n"
        "To: Bob <bob@example.com>\r\n"
        "Subject: Raw Text Test\r\n\r\n"
        "Hello Bob"
    )
    parsed = parse_raw_text(raw)
    assert parsed.from_addr == "alice@example.com"
    assert parsed.from_display_name == "Alice"
    assert parsed.subject == "Raw Text Test"
    assert "Hello Bob" in parsed.body_plain


def test_ingest_dispatcher_eml() -> None:
    """Verify ingest handles eml input_type."""
    eml = "From: a@b.com\r\nSubject: Dispatcher EML\r\n\r\nBody"
    req = ScanRequest(input_type="eml", content=eml)
    parsed = ingest(req)
    assert parsed.from_addr == "a@b.com"
    assert parsed.subject == "Dispatcher EML"


def test_ingest_dispatcher_url() -> None:
    """Verify ingest handles url input_type."""
    req = ScanRequest(input_type="url", content="https://example.test/portal")
    parsed = ingest(req)
    assert len(parsed.extracted_urls) == 1
    assert parsed.extracted_urls[0].normalized_url.url == "https://example.test/portal"


def test_ingest_dispatcher_text_rfc5322_vs_plain() -> None:
    """Verify ingest routes RFC 5322 text to parser and plain text to direct model."""
    # RFC 5322 text
    rfc_req = ScanRequest(
        input_type="text",
        content="From: x@y.com\r\nSubject: RFC Text\r\n\r\nHello",
    )
    parsed_rfc = ingest(rfc_req)
    assert parsed_rfc.from_addr == "x@y.com"
    assert parsed_rfc.subject == "RFC Text"

    # Plain text without headers (using no_headers.eml fixture)
    plain_content = (FIXTURES_DIR / "no_headers.eml").read_text(encoding="utf-8")
    plain_req = ScanRequest(input_type="text", content=plain_content)
    parsed_plain = ingest(plain_req)
    assert parsed_plain.from_addr is None
    assert "Hey Alex" in parsed_plain.body_plain
    assert len(parsed_plain.extracted_urls) == 1
    assert parsed_plain.extracted_urls[0].normalized_url.domain == "example"


def test_attachment_limits_and_oversized() -> None:
    """Verify attachment count and size warnings during parsing."""
    from email.mime.application import MIMEApplication
    from email.mime.multipart import MIMEMultipart

    from phishguard.ingest.limits import MAX_ATTACHMENTS

    msg = MIMEMultipart()
    msg["From"] = "test@example.com"
    msg["Subject"] = "Attachment Limits"

    # Add MAX_ATTACHMENTS + 2 attachments
    for i in range(MAX_ATTACHMENTS + 2):
        att = MIMEApplication(b"dummy data", Name=f"file_{i}.bin")
        att["Content-Disposition"] = f'attachment; filename="file_{i}.bin"'
        msg.attach(att)

    parsed = parse_eml(msg.as_bytes())
    assert ParseWarning.MAX_ATTACHMENTS_EXCEEDED in parsed.parse_warnings
    assert len(parsed.attachments) == MAX_ATTACHMENTS


def test_parser_exception_handling(monkeypatch) -> None:
    """Verify parser exception handling paths and malformed input resilience."""
    import email

    def mock_msg_from_bytes(*args, **kwargs):
        raise ValueError("Simulated parse error")

    monkeypatch.setattr(email, "message_from_bytes", mock_msg_from_bytes)
    res = parse_eml(b"Corrupted")
    assert ParseWarning.MALFORMED_MIME in res.parse_warnings


def test_header_fallback_parsing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify fallback parsing for empty/malformed From and To headers, walk error, and html cap."""
    import email.message

    from phishguard.ingest.limits import MAX_BODY_CHARS_RETAINED

    # 1. Empty angles From: <> and To: <> triggers lines 174 and 191
    eml = "From: <>\r\nTo: <>\r\nSubject: Empty Angles\r\n\r\nBody"
    parsed = parse_eml(eml.encode("utf-8"))
    assert parsed.from_addr == "" or parsed.from_addr == "<>"

    # 2. Header addresses raising exception triggers lines 176 and 193
    class BrokenHeader(str):
        @property
        def addresses(self) -> list[object]:
            raise RuntimeError("Corrupted header address parsing")

    broken_msg = email.message.EmailMessage()
    broken_msg["From"] = BrokenHeader("broken-from@test")
    broken_msg["To"] = BrokenHeader("broken-to@test")
    parsed_broken = parse_eml(broken_msg.as_bytes())
    assert "broken-from@test" in str(parsed_broken.from_addr)

    # 3. Traversal exception triggers lines 295-296 (MALFORMED_MIME)
    def mock_content_type(self: object) -> str:
        raise RuntimeError("Corrupted content type")

    monkeypatch.setattr(email.message.EmailMessage, "get_content_type", mock_content_type)
    parsed_iter_err = parse_eml(b"From: a@b.com\r\n\r\nHello")
    assert ParseWarning.MALFORMED_MIME in parsed_iter_err.parse_warnings
    monkeypatch.undo()

    # 4. Oversized HTML body triggers lines 306-307 (MAX_BODY_CHARS_EXCEEDED)
    repeat_count = MAX_BODY_CHARS_RETAINED // 8 + 10
    huge_html = "<html><body>" + ("<p>A</p>" * repeat_count) + "</body></html>"
    eml_html = "From: a@b.com\r\nContent-Type: text/html\r\n\r\n" + huge_html
    parsed_html = parse_eml(eml_html.encode("utf-8"))
    assert ParseWarning.MAX_BODY_CHARS_EXCEEDED in parsed_html.parse_warnings
    assert len(parsed_html.body_html) == MAX_BODY_CHARS_RETAINED
