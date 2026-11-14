"""Unit tests for core domain schemas, validation rules, and immutability."""

import pytest
from pydantic import ValidationError

from phishguard.core.schemas import (
    IOC,
    AnalyzerResult,
    AttachmentMetadata,
    Evidence,
    ParsedEmail,
    ScanRequest,
    Severity,
    Verdict,
    new_scan_id,
)


def test_severity_enum() -> None:
    """Verify Severity enum members and string representations."""
    assert Severity.INFO == "info"
    assert Severity.LOW == "low"
    assert Severity.MEDIUM == "medium"
    assert Severity.HIGH == "high"
    assert Severity.CRITICAL == "critical"
    assert len(Severity) == 5


def test_ioc_valid_and_forbid_extra() -> None:
    """Verify IOC schema validation and extra fields rejection."""
    ioc = IOC(type="url", value="hxxps://example[.]test/login", context="email body link")
    assert ioc.type == "url"
    assert ioc.value == "hxxps://example[.]test/login"
    assert ioc.context == "email body link"

    with pytest.raises(ValidationError):
        IOC(type="url", value="hxxp://test[.]invalid", unexpected="forbidden")  # type: ignore[call-arg]


def test_evidence_valid_and_constraints() -> None:
    """Verify Evidence schema constraints, frozenness, and length caps."""
    evidence = Evidence(
        source="header_analyzer",
        code="HDR_DMARC_FAIL",
        severity=Severity.HIGH,
        description="DMARC verification failed for sender domain.",
        confidence=0.95,
        raw_data={"domain": "example.test", "dmarc_action": "reject"},
    )
    assert evidence.code == "HDR_DMARC_FAIL"
    assert evidence.severity == Severity.HIGH
    assert evidence.confidence == 0.95

    # Frozen: cannot mutate attributes
    with pytest.raises(ValidationError):
        evidence.confidence = 0.5  # type: ignore[misc]

    # Extra attributes forbidden
    with pytest.raises(ValidationError):
        Evidence(  # type: ignore[call-arg]
            source="test",
            code="TEST",
            severity=Severity.LOW,
            description="test",
            confidence=0.5,
            extra_field="rejected",
        )

    # Confidence bounds
    with pytest.raises(ValidationError):
        Evidence(
            source="test",
            code="TEST",
            severity=Severity.LOW,
            description="test",
            confidence=1.5,
        )
    with pytest.raises(ValidationError):
        Evidence(
            source="test",
            code="TEST",
            severity=Severity.LOW,
            description="test",
            confidence=-0.1,
        )

    # Description max length (<= 500 chars)
    long_desc = "x" * 501
    with pytest.raises(ValidationError):
        Evidence(
            source="test",
            code="TEST",
            severity=Severity.LOW,
            description=long_desc,
            confidence=0.5,
        )


def test_analyzer_result_validation() -> None:
    """Verify AnalyzerResult schema and constraints."""
    res = AnalyzerResult(
        analyzer="header",
        status="ok",
        evidence=[],
        duration_ms=45,
    )
    assert res.analyzer == "header"
    assert res.status == "ok"
    assert res.duration_ms == 45
    assert res.error is None

    # Invalid status
    with pytest.raises(ValidationError):
        AnalyzerResult(analyzer="test", status="invalid_status")  # type: ignore[arg-type]

    # Negative duration rejected
    with pytest.raises(ValidationError):
        AnalyzerResult(analyzer="test", status="ok", duration_ms=-1)

    # Extra fields forbidden
    with pytest.raises(ValidationError):
        AnalyzerResult(analyzer="test", status="ok", unexpected="reject")  # type: ignore[call-arg]


def test_verdict_validation() -> None:
    """Verify Verdict model bounds and allowed labels."""
    verdict = Verdict(
        scan_id="0123456789abcdef0123456789abcdef",
        label="phishing",
        risk_score=85,
        confidence=0.9,
        reasons=["DMARC failed", "Lookalike domain detected"],
        iocs=[IOC(type="url", value="hxxps://bad[.]test")],
        recommended_actions=["Do not open links", "Report to SOC"],
        evidence=[],
        degraded_components=[],
    )
    assert verdict.label == "phishing"
    assert verdict.risk_score == 85

    # Risk score bounds [0, 100]
    with pytest.raises(ValidationError):
        Verdict(
            scan_id="test",
            label="phishing",
            risk_score=101,
            confidence=0.5,
        )
    with pytest.raises(ValidationError):
        Verdict(
            scan_id="test",
            label="safe",
            risk_score=-5,
            confidence=0.5,
        )

    # Confidence bounds [0.0, 1.0]
    with pytest.raises(ValidationError):
        Verdict(
            scan_id="test",
            label="safe",
            risk_score=20,
            confidence=1.1,
        )

    # Invalid label
    with pytest.raises(ValidationError):
        Verdict(
            scan_id="test",
            label="malicious",  # type: ignore[arg-type]
            risk_score=50,
            confidence=0.5,
        )

    # Extra fields forbidden
    with pytest.raises(ValidationError):
        Verdict(  # type: ignore[call-arg]
            scan_id="test",
            label="safe",
            risk_score=10,
            confidence=0.9,
            extra_attr="forbid",
        )


def test_scan_request_validation() -> None:
    """Verify ScanRequest payload constraints."""
    req = ScanRequest(input_type="url", content="https://example.test")
    assert req.input_type == "url"
    assert req.content == "https://example.test"
    assert req.scan_id is None

    # Invalid input_type
    with pytest.raises(ValidationError):
        ScanRequest(input_type="executable", content="bin")  # type: ignore[arg-type]

    # Extra fields forbidden
    with pytest.raises(ValidationError):
        ScanRequest(input_type="text", content="hello", extra="rejected")  # type: ignore[call-arg]


def test_attachment_metadata_validation() -> None:
    """Verify AttachmentMetadata schema and size validation."""
    att = AttachmentMetadata(
        filename="invoice.pdf",
        content_type="application/pdf",
        size_bytes=1024,
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    assert att.size_bytes == 1024

    with pytest.raises(ValidationError):
        AttachmentMetadata(
            filename="bad.bin",
            content_type="application/octet-stream",
            size_bytes=-10,
            sha256="abc",
        )

    with pytest.raises(ValidationError):
        AttachmentMetadata(  # type: ignore[call-arg]
            filename="a.txt",
            content_type="text/plain",
            size_bytes=10,
            sha256="abc",
            extra="rejected",
        )


def test_parsed_email_schema_concrete_fields() -> None:
    """Verify ParsedEmail includes all required concrete fields and forbids extra."""
    parsed = ParsedEmail(
        from_addr="user@example.com",
        from_display_name="User Name",
        reply_to="reply@example.com",
        return_path="bounce@example.com",
        to=["recipient@example.com"],
        subject="Important Notice",
        date="2026-11-14T10:00:00Z",
        message_id="<msg-123@example.com>",
        received_chain=["from mail.example.com by mx.google.com"],
        auth_results={"dmarc": "pass", "spf": "pass"},
        body_plain="Please see attached invoice.",
        body_html="<p>Please see attached invoice.</p>",
        urls=["https://example.com/invoice"],
        attachments=[
            AttachmentMetadata(
                filename="doc.pdf",
                content_type="application/pdf",
                size_bytes=512,
                sha256="abcdef123456",
            )
        ],
        parse_warnings=[],
        sha256="hash123",
    )
    assert parsed.from_addr == "user@example.com"
    assert parsed.subject == "Important Notice"
    assert len(parsed.attachments) == 1
    assert parsed.attachments[0].filename == "doc.pdf"

    # Extra fields forbidden
    with pytest.raises(ValidationError):
        ParsedEmail(unexpected_field="forbidden")  # type: ignore[call-arg]


def test_new_scan_id_uniqueness_and_format() -> None:
    """Verify new_scan_id yields unique 32-character hex UUID strings."""
    id1 = new_scan_id()
    id2 = new_scan_id()
    assert len(id1) == 32
    assert len(id2) == 32
    assert id1 != id2
    # Verify hex characters only
    int(id1, 16)
    int(id2, 16)

