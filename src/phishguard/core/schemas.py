"""Core domain schemas for PhishGuard."""

import uuid
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


def new_scan_id() -> str:
    """Generate a unique 32-character hexadecimal scan identifier.

    Returns:
        Hexadecimal string representing a UUIDv4.
    """
    return uuid.uuid4().hex


class Severity(StrEnum):
    """Severity ratings for observed evidence."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ParseWarning(StrEnum):
    """Stable identifiers for non-fatal email and content parsing warnings."""

    MULTIPLE_AUTH_RESULTS = "multiple_auth_results"
    MAX_PARTS_EXCEEDED = "max_parts_exceeded"
    MAX_MIME_DEPTH_EXCEEDED = "max_mime_depth_exceeded"
    MAX_URLS_EXCEEDED = "max_urls_exceeded"
    MAX_ATTACHMENTS_EXCEEDED = "max_attachments_exceeded"
    ATTACHMENT_OVERSIZED = "attachment_oversized"
    MAX_BODY_CHARS_EXCEEDED = "max_body_chars_exceeded"
    MAX_HEADERS_EXCEEDED = "max_headers_exceeded"
    MAX_RECEIVED_HOPS_EXCEEDED = "max_received_hops_exceeded"
    HEADER_VALUE_TRUNCATED = "header_value_truncated"
    CHARSET_DECODE_ERROR = "charset_decode_error"
    HTML_PARSE_ERROR = "html_parse_error"
    MALFORMED_MIME = "malformed_mime"
    MALFORMED_HEADER = "malformed_header"
    SUSPICIOUS_MIME_RECURSION = "suspicious_mime_recursion"


class IOC(BaseModel):
    """Indicator of compromise (IOC), defanged for safe reporting."""

    model_config = ConfigDict(extra="forbid")

    type: str = Field(..., description="Indicator type: url, domain, ip, sha256, or email.")
    value: str = Field(..., description="Defanged indicator value (e.g. hxxps://...).")
    context: str | None = Field(
        default=None, description="Contextual origin where indicator was identified."
    )


class Evidence(BaseModel):
    """An atomic, verifiable piece of evidence emitted by an analyzer or model."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source: str = Field(..., description="Identifier of the emitting analyzer component.")
    code: str = Field(..., description="Stable evidence identifier (e.g. HDR_DMARC_FAIL).")
    severity: Severity = Field(..., description="Severity classification.")
    description: str = Field(
        ..., max_length=500, description="Human-readable explanation of the finding."
    )
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Confidence rating between 0.0 and 1.0."
    )
    raw_data: dict[str, Any] = Field(
        default_factory=dict, description="Structured non-sensitive evidence metadata."
    )


class AnalyzerResult(BaseModel):
    """Execution output from a single analyzer."""

    model_config = ConfigDict(extra="forbid")

    analyzer: str = Field(..., description="Analyzer name.")
    status: Literal["ok", "partial", "error", "skipped"] = Field(
        ..., description="Execution status outcome."
    )
    evidence: list[Evidence] = Field(
        default_factory=list, description="List of evidence items discovered."
    )
    duration_ms: int = Field(default=0, ge=0, description="Execution duration in milliseconds.")
    error: str | None = Field(default=None, description="Error message if execution failed.")


class Verdict(BaseModel):
    """Final analysis verdict, risk assessment, and explainability report."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str = Field(..., description="Unique scan identifier.")
    label: Literal["safe", "suspicious", "phishing"] = Field(
        ..., description="Final classification label computed by the rubric."
    )
    risk_score: int = Field(
        ..., ge=0, le=100, description="Calculated aggregate risk score from 0 to 100."
    )
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Aggregate confidence rating between 0.0 and 1.0."
    )
    reasons: list[str] = Field(
        default_factory=list, description="Key explanatory reasons behind the verdict."
    )
    iocs: list[IOC] = Field(
        default_factory=list, description="Defanged indicators extracted during scan."
    )
    recommended_actions: list[str] = Field(
        default_factory=list, description="Recommended defensive user actions."
    )
    evidence: list[Evidence] = Field(
        default_factory=list, description="Complete compilation of evidence collected."
    )
    degraded_components: list[str] = Field(
        default_factory=list, description="List of analyzers that degraded or errored."
    )


class ScanRequest(BaseModel):
    """Ingestion request payload for scanning an email, URL, or pasted text."""

    model_config = ConfigDict(extra="forbid")

    input_type: Literal["eml", "url", "text"] = Field(
        ..., description="Category of input payload submitted for analysis."
    )
    content: str = Field(..., description="Raw message text, URL, or email string.")
    scan_id: str | None = Field(
        default=None, description="Optional caller-supplied scan identifier."
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Optional non-sensitive client metadata."
    )


class AttachmentMetadata(BaseModel):
    """Metadata and integrity hash for an email attachment (never executed)."""

    model_config = ConfigDict(extra="forbid")

    filename: str = Field(..., description="Sanitized attachment filename.")
    content_type: str = Field(..., description="MIME content type reported by attachment headers.")
    size_bytes: int = Field(..., ge=0, description="Attachment byte size.")
    sha256: str = Field(..., description="SHA-256 digest of attachment content.")


class NormalizedURL(BaseModel):
    """Canonical normalized URL representation with structural decomposition."""

    model_config = ConfigDict(extra="forbid")

    raw_url: str = Field(..., description="Original raw URL before normalization.")
    url: str = Field(..., description="Canonical normalized URL string without userinfo.")
    scheme: str = Field(..., description="Normalized scheme: http or https.")
    host: str = Field(..., description="Normalized lowercase hostname.")
    host_unicode: str = Field(..., description="Decoded Unicode representation of hostname.")
    host_punycode: str = Field(..., description="ASCII IDNA / Punycode representation.")
    subdomain: str = Field(default="", description="Subdomain component (e.g. 'mail').")
    domain: str = Field(..., description="Second-level or registered name component.")
    suffix: str = Field(default="", description="Public suffix (e.g. 'com', 'co.uk').")
    registered_domain: str = Field(
        ..., description="Complete registered domain (e.g. 'example.com')."
    )
    port: int | None = Field(default=None, description="Explicit port number if non-default.")
    path: str = Field(default="", description="Normalized path component.")
    query: str = Field(default="", description="Sanitized query string without tracking tags.")
    has_tracking_params: bool = Field(
        default=False, description="Whether tracking parameters were stripped."
    )
    is_ip_literal: bool = Field(
        default=False, description="Whether the host is an IPv4 or IPv6 address."
    )
    has_userinfo: bool = Field(
        default=False, description="Whether the URL contained credentials (user:pass@)."
    )
    is_idn: bool = Field(
        default=False, description="Whether host contains internationalized characters."
    )
    has_punycode: bool = Field(
        default=False, description="Whether host starts with or contains 'xn--'."
    )
    ip_obfuscated: bool = Field(
        default=False,
        description="Whether an IPv4 host used decimal, octal, or hex obfuscation.",
    )
    suffix_known: bool = Field(
        default=True,
        description="Whether public suffix was found in PSL (False for RFC 2606 .test domains).",
    )


class ExtractedURL(BaseModel):
    """URL extracted from message body or headers with contextual metadata."""

    model_config = ConfigDict(extra="forbid")

    raw_url: str = Field(..., description="Raw extracted URL string.")
    normalized_url: NormalizedURL = Field(
        ..., description="Structured canonical normalization of the URL."
    )
    visible_text: str | None = Field(
        default=None, description="Visible anchor link text if extracted from HTML."
    )
    link_text_mismatch: bool = Field(
        default=False,
        description="True if visible text looks like a domain different from href target.",
    )
    source_locations: list[str] = Field(
        default_factory=list,
        description="List of locations where URL was observed (e.g. 'body_plain', 'html_anchor').",
    )


class ParsedEmail(BaseModel):
    """Structured representation of a parsed email or text submission."""

    model_config = ConfigDict(extra="forbid")

    from_addr: str | None = Field(default=None, description="Sender email address.")
    from_display_name: str | None = Field(default=None, description="Sender display name.")
    reply_to: str | None = Field(default=None, description="Reply-To address if provided.")
    return_path: str | None = Field(default=None, description="Return-Path envelope sender.")
    to: list[str] = Field(default_factory=list, description="Recipient email addresses.")
    subject: str = Field(default="", description="Email subject line.")
    date: str | None = Field(default=None, description="Date header string.")
    message_id: str | None = Field(default=None, description="Message-ID header string.")
    received_chain: list[str] = Field(
        default_factory=list, description="Ordered list of Received header hop entries."
    )
    auth_results: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Ordered Authentication-Results headers with position indices.",
    )
    body_plain: str = Field(default="", description="Extracted plain text body content.")
    body_html: str = Field(default="", description="Extracted HTML body content.")
    extracted_urls: list[ExtractedURL] = Field(
        default_factory=list, description="All extracted and normalized URLs with context."
    )
    other_schemes: list[str] = Field(
        default_factory=list,
        description="Non-http(s) scheme URLs encountered (e.g. javascript:, data:, file:).",
    )
    attachments: list[AttachmentMetadata] = Field(
        default_factory=list, description="Enumerated attachment metadata entries."
    )
    parse_warnings: list[ParseWarning] = Field(
        default_factory=list, description="Non-fatal warnings encountered during parsing."
    )
    raw_headers: dict[str, list[str]] = Field(
        default_factory=dict, description="Preserved raw header key-value occurrences."
    )
    sha256: str = Field(default="", description="SHA-256 digest of raw email input.")
