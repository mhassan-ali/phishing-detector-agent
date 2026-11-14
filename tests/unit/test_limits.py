"""Unit tests for ingestion bounds, resource limits, and recursion guards."""

from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import pytest

from phishguard.core.errors import EmailParseError
from phishguard.core.schemas import ParseWarning
from phishguard.ingest.extractor import extract_urls_from_content
from phishguard.ingest.limits import (
    MAX_BODY_CHARS_RETAINED,
    MAX_EMAIL_BYTES,
    MAX_HEADER_COUNT,
    MAX_HEADER_VALUE_CHARS,
    MAX_MIME_DEPTH,
    MAX_PARTS,
    MAX_RECEIVED_HOPS,
    MAX_URLS_PER_MESSAGE,
)
from phishguard.ingest.parser import parse_eml


def test_oversized_email_raises_controlled_error() -> None:
    """Verify exceeding MAX_EMAIL_BYTES raises EmailParseError."""
    huge_data = b"From: a@b.com\r\n\r\n" + b"X" * (MAX_EMAIL_BYTES + 10)
    with pytest.raises(EmailParseError, match="exceeds limit"):
        parse_eml(huge_data)


def test_programmatic_deep_nested_multipart() -> None:
    """Verify deeply nested multipart MIME generates ParseWarning.MAX_MIME_DEPTH_EXCEEDED."""
    root = MIMEMultipart()
    root["From"] = "test@example.com"
    root["To"] = "test@example.com"
    root["Subject"] = "Deep MIME Nesting"

    current = root
    # Nest 25 levels deep (MAX_MIME_DEPTH is 20)
    for _ in range(MAX_MIME_DEPTH + 5):
        sub = MIMEMultipart()
        current.attach(sub)
        current = sub

    current.attach(MIMEText("Deepest leaf content"))

    raw_bytes = root.as_bytes()
    parsed = parse_eml(raw_bytes)
    assert ParseWarning.MAX_MIME_DEPTH_EXCEEDED in parsed.parse_warnings


def test_excessive_parts_limit() -> None:
    """Verify exceeding MAX_PARTS triggers ParseWarning.MAX_PARTS_EXCEEDED."""
    root = MIMEMultipart()
    root["From"] = "test@example.com"
    root["Subject"] = "Many Parts"

    # Add 105 parts (MAX_PARTS is 100)
    for i in range(MAX_PARTS + 5):
        part = MIMEText(f"Part {i}")
        root.attach(part)

    parsed = parse_eml(root.as_bytes())
    assert ParseWarning.MAX_PARTS_EXCEEDED in parsed.parse_warnings


def test_excessive_headers_limit() -> None:
    """Verify exceeding MAX_HEADER_COUNT truncates and flags ParseWarning.MAX_HEADERS_EXCEEDED."""
    headers = [f"X-Custom-Header-{i}: value-{i}" for i in range(MAX_HEADER_COUNT + 10)]
    eml_str = (
        "From: sender@example.com\r\n"
        "To: recipient@example.com\r\n"
        "Subject: Too many headers\r\n" + "\r\n".join(headers) + "\r\n\r\nBody text"
    )
    parsed = parse_eml(eml_str.encode("utf-8"))
    assert ParseWarning.MAX_HEADERS_EXCEEDED in parsed.parse_warnings


def test_excessive_received_hops_limit() -> None:
    """Verify exceeding MAX_RECEIVED_HOPS is capped and warned."""
    hops = [
        (
            f"Received: from hop-{i}.example.com by mx.example.com; "
            f"Fri, 14 Nov 2026 12:00:{i:02d} +0000"
        )
        for i in range(MAX_RECEIVED_HOPS + 10)
    ]
    eml_str = (
        "From: sender@example.com\r\n"
        "To: recipient@example.com\r\n"
        "Subject: Many hops\r\n" + "\r\n".join(hops) + "\r\n\r\nBody text"
    )
    parsed = parse_eml(eml_str.encode("utf-8"))
    assert ParseWarning.MAX_RECEIVED_HOPS_EXCEEDED in parsed.parse_warnings
    assert len(parsed.received_chain) == MAX_RECEIVED_HOPS


def test_huge_header_value_truncated() -> None:
    """Verify individual header value exceeding MAX_HEADER_VALUE_CHARS is truncated."""
    huge_val = "A" * (MAX_HEADER_VALUE_CHARS + 500)
    eml_str = f"From: sender@example.com\r\nSubject: Test\r\nX-Huge-Header: {huge_val}\r\n\r\nBody"
    parsed = parse_eml(eml_str.encode("utf-8"))
    assert ParseWarning.HEADER_VALUE_TRUNCATED in parsed.parse_warnings
    assert len(parsed.raw_headers["X-Huge-Header"][0]) == MAX_HEADER_VALUE_CHARS


def test_oversized_body_truncated() -> None:
    """Verify body text exceeding MAX_BODY_CHARS_RETAINED is truncated and warned."""
    huge_body = "B" * (MAX_BODY_CHARS_RETAINED + 1000)
    eml_str = f"From: sender@example.com\r\nSubject: Huge Body\r\n\r\n{huge_body}"
    parsed = parse_eml(eml_str.encode("utf-8"))
    assert ParseWarning.MAX_BODY_CHARS_EXCEEDED in parsed.parse_warnings
    assert len(parsed.body_plain) == MAX_BODY_CHARS_RETAINED


def test_message_rfc822_not_recursed_but_hashed_as_attachment() -> None:
    """Verify message/rfc822 parts are treated as attachments without recursive parsing."""
    parent = MIMEMultipart()
    parent["From"] = "parent@example.com"
    parent["Subject"] = "Outer Container"

    child = MIMEBase("message", "rfc822")
    child.set_payload(b"From: inner@example.com\r\nSubject: Inner\r\n\r\nSecret payload")
    parent.attach(child)

    parsed = parse_eml(parent.as_bytes())
    assert len(parsed.attachments) == 1
    att = parsed.attachments[0]
    assert att.content_type == "message/rfc822"
    assert att.sha256 != ""
    assert "Secret payload" not in parsed.body_plain


def test_excessive_urls_limit() -> None:
    """Verify extracting more than MAX_URLS_PER_MESSAGE triggers warning and stops."""
    urls_text = " ".join(
        f"https://domain-{i}.example.test/page" for i in range(MAX_URLS_PER_MESSAGE + 20)
    )
    urls, other, warnings = extract_urls_from_content(body_plain=urls_text)
    assert ParseWarning.MAX_URLS_EXCEEDED in warnings
    assert len(urls) == MAX_URLS_PER_MESSAGE
