"""Unit tests for attachment analyzer covering extensions, double extensions, and MIME."""

from pathlib import Path

from phishguard.analyzers.attachment import AttachmentAnalyzer
from phishguard.analyzers.codes import EvidenceCode
from phishguard.core.schemas import AttachmentMetadata, ParsedEmail, Severity
from phishguard.ingest.parser import parse_eml

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "emails"


def test_attachment_analyzer_skipped_when_empty() -> None:
    """Verify analyzer returns status='skipped' when no attachments exist."""
    analyzer = AttachmentAnalyzer()
    parsed = ParsedEmail(sha256="dummy")
    res = analyzer.run(parsed)
    assert res.status == "skipped"
    assert res.evidence == []


def test_attachment_analyzer_dangerous_and_script_extensions() -> None:
    """Verify dangerous binaries and script files emit appropriate evidence."""
    analyzer = AttachmentAnalyzer()
    parsed = ParsedEmail(
        attachments=[
            AttachmentMetadata(
                filename="payload.exe",
                content_type="application/x-msdownload",
                size_bytes=5000,
                sha256="1111",
            ),
            AttachmentMetadata(
                filename="setup.ps1",
                content_type="text/plain",
                size_bytes=1200,
                sha256="2222",
            ),
        ],
        sha256="dummy",
    )
    res = analyzer.run(parsed)
    dangerous_ev = [e for e in res.evidence if e.code == EvidenceCode.ATT_DANGEROUS_EXTENSION]
    assert any(e.severity == Severity.CRITICAL for e in dangerous_ev)
    assert EvidenceCode.ATT_SCRIPT_TYPE in [e.code for e in res.evidence]


def test_attachment_analyzer_macro_and_archive() -> None:
    """Verify macro-enabled Office files and archives emit evidence."""
    analyzer = AttachmentAnalyzer()
    parsed = ParsedEmail(
        attachments=[
            AttachmentMetadata(
                filename="invoice.docm",
                content_type="application/vnd.ms-word.document.macroEnabled.12",
                size_bytes=25000,
                sha256="3333",
            ),
            AttachmentMetadata(
                filename="data.zip",
                content_type="application/zip",
                size_bytes=10000,
                sha256="4444",
            ),
        ],
        sha256="dummy",
    )
    res = analyzer.run(parsed)
    codes = [e.code for e in res.evidence]
    assert EvidenceCode.ATT_MACRO_ENABLED in codes
    assert EvidenceCode.ATT_ARCHIVE in codes


def test_attachment_analyzer_double_extension() -> None:
    """Verify deceptive double extensions emit ATT_DOUBLE_EXTENSION at CRITICAL severity."""
    analyzer = AttachmentAnalyzer()
    parsed = ParsedEmail(
        attachments=[
            AttachmentMetadata(
                filename="report.pdf.exe",
                content_type="application/octet-stream",
                size_bytes=8000,
                sha256="5555",
            )
        ],
        sha256="dummy",
    )
    res = analyzer.run(parsed)
    codes = {e.code: e for e in res.evidence}
    assert EvidenceCode.ATT_DOUBLE_EXTENSION in codes
    assert codes[EvidenceCode.ATT_DOUBLE_EXTENSION].severity == Severity.CRITICAL


def test_attachment_analyzer_rtlo_character() -> None:
    """Verify Right-to-Left Override character triggers ATT_RTLO_CHAR at CRITICAL severity."""
    analyzer = AttachmentAnalyzer()
    parsed = ParsedEmail(
        attachments=[
            AttachmentMetadata(
                filename="photo\u202egpj.exe",
                content_type="application/octet-stream",
                size_bytes=4000,
                sha256="6666",
            )
        ],
        sha256="dummy",
    )
    res = analyzer.run(parsed)
    codes = {e.code: e for e in res.evidence}
    assert EvidenceCode.ATT_RTLO_CHAR in codes
    assert codes[EvidenceCode.ATT_RTLO_CHAR].severity == Severity.CRITICAL


def test_attachment_analyzer_mime_mismatch() -> None:
    """Verify document extension with executable or generic octet-stream MIME triggers mismatch."""
    analyzer = AttachmentAnalyzer()
    parsed = ParsedEmail(
        attachments=[
            AttachmentMetadata(
                filename="document.pdf",
                content_type="application/x-dosexec",
                size_bytes=9000,
                sha256="7777",
            )
        ],
        sha256="dummy",
    )
    res = analyzer.run(parsed)
    codes = [e.code for e in res.evidence]
    assert EvidenceCode.ATT_MIME_MISMATCH in codes


def test_attachment_analyzer_oversized() -> None:
    """Verify attachments exceeding 25MB trigger ATT_OVERSIZED."""
    analyzer = AttachmentAnalyzer()
    parsed = ParsedEmail(
        attachments=[
            AttachmentMetadata(
                filename="big_archive.zip",
                content_type="application/zip",
                size_bytes=30 * 1024 * 1024,
                sha256="8888",
            )
        ],
        sha256="dummy",
    )
    res = analyzer.run(parsed)
    codes = [e.code for e in res.evidence]
    assert EvidenceCode.ATT_OVERSIZED in codes


def test_attachment_analyzer_fixtures() -> None:
    """Verify attachment analyzer on suspicious and legitimate fixtures."""
    analyzer = AttachmentAnalyzer()

    # suspicious_attachment.eml
    p_suspicious = parse_eml((FIXTURES_DIR / "suspicious_attachment.eml").read_bytes())
    res_susp = analyzer.run(p_suspicious)
    codes_susp = [e.code for e in res_susp.evidence]
    assert EvidenceCode.ATT_DOUBLE_EXTENSION in codes_susp
    assert EvidenceCode.ATT_DANGEROUS_EXTENSION in codes_susp

    # legit_receipt.eml (legitimate PDF attachment)
    p_legit = parse_eml((FIXTURES_DIR / "legit_receipt.eml").read_bytes())
    res_legit = analyzer.run(p_legit)
    for ev in res_legit.evidence:
        assert ev.severity not in (Severity.HIGH, Severity.CRITICAL), (
            f"legit_receipt.eml had {ev.severity}: {ev.code}"
        )
