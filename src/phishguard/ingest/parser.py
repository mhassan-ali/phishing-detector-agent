"""RFC 5322 EML and raw text ingestion, header extraction, and safe attachment enumeration."""

import email
import email.policy
import hashlib
import re
from typing import Any

from phishguard.core.errors import EmailParseError
from phishguard.core.schemas import (
    AttachmentMetadata,
    ParsedEmail,
    ParseWarning,
    ScanRequest,
)
from phishguard.ingest.extractor import extract_urls
from phishguard.ingest.limits import (
    MAX_ATTACHMENT_BYTES,
    MAX_ATTACHMENTS,
    MAX_BODY_CHARS_RETAINED,
    MAX_EMAIL_BYTES,
    MAX_HEADER_COUNT,
    MAX_HEADER_VALUE_CHARS,
    MAX_MIME_DEPTH,
    MAX_PARTS,
    MAX_RECEIVED_HOPS,
)

RFC_HEADER_DETECT_PATTERN = re.compile(
    r"^(From|To|Subject|Date|Message-ID|Received|Return-Path|Reply-To):\s",
    re.IGNORECASE,
)


def is_rfc5322_text(text: str) -> bool:
    """Determine whether pasted text contains RFC 5322 email headers.

    Args:
        text: Raw text string.

    Returns:
        True if text begins with at least two recognizable RFC header lines.
    """
    lines = text.strip().splitlines()
    matching_headers = 0
    for line in lines[:25]:
        if not line.strip():
            break
        if RFC_HEADER_DETECT_PATTERN.match(line):
            matching_headers += 1
    return matching_headers >= 2


def safe_decode_payload(part: email.message.Message, warnings: list[ParseWarning]) -> str:
    """Safely decode text payload from an email part with charset fallback handling.

    Args:
        part: Email part object.
        warnings: Warnings list to append to on decode errors.

    Returns:
        Decoded string content.
    """
    charset = part.get_content_charset() or "utf-8"
    raw_payload = part.get_payload(decode=True)
    if raw_payload is None:
        content = part.get_payload()
        return str(content) if content else ""

    if not isinstance(raw_payload, bytes):
        return str(raw_payload)

    # Attempt decode with declared charset
    try:
        return raw_payload.decode(charset, errors="strict")
    except (UnicodeDecodeError, LookupError):
        if ParseWarning.CHARSET_DECODE_ERROR not in warnings:
            warnings.append(ParseWarning.CHARSET_DECODE_ERROR)

    # Fallbacks: utf-8 with replace, then latin-1
    try:
        return raw_payload.decode("utf-8", errors="replace")
    except Exception:
        return raw_payload.decode("latin-1", errors="replace")


def parse_eml(data: bytes) -> ParsedEmail:
    """Parse raw bytes representing an RFC 5322 email into a structured ParsedEmail.

    Guarantees:
      - Memory bounds and depth guards (never unbounded recursion)
      - Attachments are never written to disk or executed (hashes only)
      - Malformed MIME never raises an unhandled exception
      - Full Received chain and position-aware Authentication-Results tracking

    Args:
        data: Raw email bytes.

    Returns:
        ParsedEmail domain model.

    Raises:
        EmailParseError: If the message payload exceeds MAX_EMAIL_BYTES.
    """
    if len(data) > MAX_EMAIL_BYTES:
        raise EmailParseError(
            f"Email payload size ({len(data)} bytes) exceeds limit ({MAX_EMAIL_BYTES} bytes)"
        )

    msg_sha256 = hashlib.sha256(data).hexdigest()
    warnings: list[ParseWarning] = []

    try:
        msg = email.message_from_bytes(data, policy=email.policy.default)
    except Exception:
        warnings.append(ParseWarning.MALFORMED_MIME)
        return ParsedEmail(
            sha256=msg_sha256,
            parse_warnings=warnings,
        )

    # 1. Parse and record headers with limits
    raw_headers: dict[str, list[str]] = {}
    auth_results: list[dict[str, Any]] = []
    received_chain: list[str] = []

    header_items = list(msg.items())
    if len(header_items) > MAX_HEADER_COUNT:
        warnings.append(ParseWarning.MAX_HEADERS_EXCEEDED)
        header_items = header_items[:MAX_HEADER_COUNT]

    for idx, (name, val_obj) in enumerate(header_items):
        name_str = str(name).strip()
        val_str = str(val_obj).strip()

        if len(val_str) > MAX_HEADER_VALUE_CHARS:
            warnings.append(ParseWarning.HEADER_VALUE_TRUNCATED)
            val_str = val_str[:MAX_HEADER_VALUE_CHARS]

        raw_headers.setdefault(name_str, []).append(val_str)

        # Track Authentication-Results
        if name_str.lower() == "authentication-results":
            auth_results.append(
                {
                    "index": idx,
                    "header": name_str,
                    "value": val_str,
                }
            )

        # Track Received chain in order
        if name_str.lower() == "received":
            if len(received_chain) < MAX_RECEIVED_HOPS:
                received_chain.append(val_str)
            elif ParseWarning.MAX_RECEIVED_HOPS_EXCEEDED not in warnings:
                warnings.append(ParseWarning.MAX_RECEIVED_HOPS_EXCEEDED)

    # Flag multiple Authentication-Results headers (sender spoofing / injection vector)
    if len(auth_results) > 1:
        warnings.append(ParseWarning.MULTIPLE_AUTH_RESULTS)

    # Extract core header fields
    from_addr: str | None = None
    from_display_name: str | None = None
    from_hdr = msg.get("From")
    if from_hdr:
        try:
            if hasattr(from_hdr, "addresses") and from_hdr.addresses:
                addr_obj = from_hdr.addresses[0]
                from_addr = addr_obj.addr_spec
                from_display_name = addr_obj.display_name or None
            else:
                from_addr = str(from_hdr).strip()
        except Exception:
            from_addr = str(from_hdr).strip()

    reply_to = str(msg.get("Reply-To", "")).strip() or None
    return_path = str(msg.get("Return-Path", "")).strip() or None
    subject = str(msg.get("Subject", "")).strip()
    date_str = str(msg.get("Date", "")).strip() or None
    message_id = str(msg.get("Message-ID", "")).strip() or None

    to_addresses: list[str] = []
    to_hdr = msg.get("To")
    if to_hdr:
        try:
            if hasattr(to_hdr, "addresses") and to_hdr.addresses:
                to_addresses = [a.addr_spec for a in to_hdr.addresses if a.addr_spec]
            else:
                to_addresses = [str(to_hdr).strip()]
        except Exception:
            to_addresses = [str(to_hdr).strip()]

    # 2. Traverse MIME structure
    body_plain_parts: list[str] = []
    body_html_parts: list[str] = []
    attachments: list[AttachmentMetadata] = []

    visited_parts = 0

    def walk_parts(part: email.message.Message, depth: int) -> None:
        nonlocal visited_parts
        visited_parts += 1

        if visited_parts > MAX_PARTS:
            if ParseWarning.MAX_PARTS_EXCEEDED not in warnings:
                warnings.append(ParseWarning.MAX_PARTS_EXCEEDED)
            return

        if depth > MAX_MIME_DEPTH:
            if ParseWarning.MAX_MIME_DEPTH_EXCEEDED not in warnings:
                warnings.append(ParseWarning.MAX_MIME_DEPTH_EXCEEDED)
            return

        content_type = part.get_content_type().lower()

        # Guard: message/rfc822 parts are treated as attachments without recursing
        if content_type == "message/rfc822":
            raw_rfc822 = part.get_payload(decode=True)
            if raw_rfc822 is None and part.is_multipart():
                raw_rfc822 = part.as_bytes()
            elif not isinstance(raw_rfc822, bytes):
                raw_rfc822 = str(raw_rfc822).encode("utf-8", errors="replace")

            if len(attachments) < MAX_ATTACHMENTS:
                size_b = len(raw_rfc822)
                if size_b > MAX_ATTACHMENT_BYTES:
                    warnings.append(ParseWarning.ATTACHMENT_OVERSIZED)
                att_hash = hashlib.sha256(raw_rfc822).hexdigest()
                rfc_filename = part.get_filename() or "forwarded_message.eml"
                attachments.append(
                    AttachmentMetadata(
                        filename=rfc_filename,
                        content_type=content_type,
                        size_bytes=size_b,
                        sha256=att_hash,
                    )
                )
            return

        # Check for attachment disposition
        is_att = part.is_attachment() if hasattr(part, "is_attachment") else False
        disposition = str(part.get("Content-Disposition", "")).lower()
        part_filename: str | None = part.get_filename()

        if is_att or "attachment" in disposition or part_filename:
            if len(attachments) >= MAX_ATTACHMENTS:
                if ParseWarning.MAX_ATTACHMENTS_EXCEEDED not in warnings:
                    warnings.append(ParseWarning.MAX_ATTACHMENTS_EXCEEDED)
                return

            raw_att = part.get_payload(decode=True)
            if raw_att is None:
                raw_att = b""
            elif not isinstance(raw_att, bytes):
                raw_att = str(raw_att).encode("utf-8", errors="replace")

            size_bytes = len(raw_att)
            if size_bytes > MAX_ATTACHMENT_BYTES:
                warnings.append(ParseWarning.ATTACHMENT_OVERSIZED)

            att_sha256 = hashlib.sha256(raw_att).hexdigest()
            sanitized_filename = part_filename or f"attachment_{len(attachments) + 1}"

            attachments.append(
                AttachmentMetadata(
                    filename=sanitized_filename,
                    content_type=content_type,
                    size_bytes=size_bytes,
                    sha256=att_sha256,
                )
            )
            return

        # Handle body components
        if content_type == "text/plain":
            text = safe_decode_payload(part, warnings)
            body_plain_parts.append(text)
        elif content_type == "text/html":
            html = safe_decode_payload(part, warnings)
            body_html_parts.append(html)
        elif part.is_multipart():
            subparts = (
                part.iter_parts()
                if isinstance(part, email.message.EmailMessage)
                else (part.get_payload() if isinstance(part.get_payload(), list) else [])
            )
            for subpart in subparts:
                if isinstance(subpart, email.message.Message):
                    walk_parts(subpart, depth + 1)

    try:
        walk_parts(msg, 1)
    except Exception:
        warnings.append(ParseWarning.MALFORMED_MIME)

    # Consolidate and cap body strings
    full_plain = "\n\n".join(body_plain_parts)
    if len(full_plain) > MAX_BODY_CHARS_RETAINED:
        warnings.append(ParseWarning.MAX_BODY_CHARS_EXCEEDED)
        full_plain = full_plain[:MAX_BODY_CHARS_RETAINED]

    full_html = "\n\n".join(body_html_parts)
    if len(full_html) > MAX_BODY_CHARS_RETAINED:
        warnings.append(ParseWarning.MAX_BODY_CHARS_EXCEEDED)
        full_html = full_html[:MAX_BODY_CHARS_RETAINED]

    parsed = ParsedEmail(
        from_addr=from_addr,
        from_display_name=from_display_name,
        reply_to=reply_to,
        return_path=return_path,
        to=to_addresses,
        subject=subject,
        date=date_str,
        message_id=message_id,
        received_chain=received_chain,
        auth_results=auth_results,
        body_plain=full_plain,
        body_html=full_html,
        extracted_urls=[],
        other_schemes=[],
        attachments=attachments,
        parse_warnings=warnings,
        raw_headers=raw_headers,
        sha256=msg_sha256,
    )

    # Extract and normalize URLs
    extract_urls(parsed)

    return parsed


def parse_raw_text(text: str) -> ParsedEmail:
    """Parse raw RFC 5322 text string by encoding to UTF-8 and reusing parse_eml.

    Args:
        text: Raw RFC 5322 email string.

    Returns:
        Structured ParsedEmail.
    """
    return parse_eml(text.encode("utf-8", errors="replace"))


def ingest(request: ScanRequest) -> ParsedEmail:
    """Ingest a ScanRequest dispatcher covering eml, url, and plain/raw text inputs.

    Args:
        request: Validated ScanRequest model.

    Returns:
        Structured ParsedEmail representation.
    """
    content = request.content

    if request.input_type == "eml":
        return parse_eml(content.encode("utf-8", errors="replace"))

    if request.input_type == "url":
        # Create a synthetic ParsedEmail wrapping the single URL
        url_bytes = content.encode("utf-8", errors="replace")
        sha256 = hashlib.sha256(url_bytes).hexdigest()
        parsed = ParsedEmail(
            subject=f"Scan URL: {content[:100]}",
            body_plain=content,
            sha256=sha256,
        )
        extract_urls(parsed)
        return parsed

    # input_type == "text"
    if is_rfc5322_text(content):
        return parse_raw_text(content)

    # Plain text without RFC headers
    content_bytes = content.encode("utf-8", errors="replace")
    sha256 = hashlib.sha256(content_bytes).hexdigest()
    parsed = ParsedEmail(
        body_plain=content[:MAX_BODY_CHARS_RETAINED],
        sha256=sha256,
    )
    extract_urls(parsed)
    return parsed
