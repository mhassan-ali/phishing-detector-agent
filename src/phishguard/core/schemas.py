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


class ParsedEmail(BaseModel):
    """Structured representation of a parsed email."""

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
    auth_results: dict[str, Any] = Field(
        default_factory=dict,
        description="Parsed Authentication-Results headers (SPF, DKIM, DMARC).",
    )
    body_plain: str = Field(default="", description="Extracted plain text body content.")
    body_html: str = Field(default="", description="Extracted HTML body content.")
    urls: list[str] = Field(
        default_factory=list, description="All unique URLs extracted from message bodies."
    )
    attachments: list[AttachmentMetadata] = Field(
        default_factory=list, description="Enumerated attachment metadata entries."
    )
    parse_warnings: list[str] = Field(
        default_factory=list, description="Non-fatal warnings encountered during MIME parsing."
    )
    sha256: str = Field(default="", description="SHA-256 digest of raw email input.")
