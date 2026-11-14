"""Attachment analyzer evaluating extensions, double extensions, and MIME integrity."""

import os
import re

from phishguard.analyzers.base import create_evidence
from phishguard.analyzers.codes import EvidenceCode
from phishguard.core.schemas import AnalyzerResult, Evidence, ParsedEmail, Severity

DANGEROUS_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".vbs",
        ".js",
        ".jse",
        ".wsf",
        ".wsh",
        ".ps1",
        ".hta",
        ".pif",
        ".cpl",
        ".msi",
        ".jar",
        ".iso",
        ".img",
        ".vhd",
    }
)

SCRIPT_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".ps1",
        ".bat",
        ".cmd",
        ".vbs",
        ".js",
        ".wsf",
        ".sh",
        ".py",
        ".hta",
    }
)

MACRO_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".docm",
        ".xlsm",
        ".pptm",
        ".dotm",
        ".xltm",
        ".xlam",
        ".potm",
        ".ppam",
        ".docb",
    }
)

ARCHIVE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".zip",
        ".rar",
        ".7z",
        ".tar",
        ".gz",
        ".bz2",
        ".xz",
        ".cab",
    }
)

DOCUMENT_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        ".txt",
        ".csv",
        ".jpg",
        ".jpeg",
        ".png",
    }
)

MAX_EXPECTED_ATTACHMENT_BYTES: int = 25 * 1024 * 1024  # 25 MB


class AttachmentAnalyzer:
    """Analyzer inspecting email attachment metadata for evasion and malware traits."""

    name: str = "attachment_analyzer"

    def run(self, parsed: ParsedEmail) -> AnalyzerResult:
        """Evaluate attachment metadata without executing or opening file payloads."""
        if not parsed.attachments:
            return AnalyzerResult(
                analyzer=self.name,
                status="skipped",
                evidence=[],
                duration_ms=0,
            )

        evidence: list[Evidence] = []

        for att in parsed.attachments:
            raw_filename = att.filename or "unnamed_attachment"
            ext = os.path.splitext(raw_filename)[1].lower()
            mime_type = (att.content_type or "").lower()

            # 1. Right-to-Left Override (RTLO) character \u202e
            if "\u202e" in raw_filename:
                evidence.append(
                    create_evidence(
                        source=self.name,
                        code=EvidenceCode.ATT_RTLO_CHAR,
                        severity=Severity.CRITICAL,
                        description="Filename contains Right-to-Left Override (RTLO) character.",
                        confidence=0.99,
                        raw_data={"sha256": att.sha256},
                    )
                )

            # 2. Double extensions (e.g. invoice.pdf.exe)
            parts = [p for p in re.split(r"\.+", raw_filename) if p]
            if len(parts) >= 3:
                inner_ext = f".{parts[-2].lower()}"
                outer_ext = f".{parts[-1].lower()}"
                if inner_ext in DOCUMENT_EXTENSIONS and outer_ext in (
                    DANGEROUS_EXTENSIONS | SCRIPT_EXTENSIONS
                ):
                    evidence.append(
                        create_evidence(
                            source=self.name,
                            code=EvidenceCode.ATT_DOUBLE_EXTENSION,
                            severity=Severity.CRITICAL,
                            description=(
                                "Attachment uses deceptive double extension to disguise payload."
                            ),
                            confidence=0.98,
                            raw_data={
                                "inner_ext": inner_ext,
                                "outer_ext": outer_ext,
                                "sha256": att.sha256,
                            },
                        )
                    )

            # 3. Dangerous executable extensions
            if ext in DANGEROUS_EXTENSIONS:
                evidence.append(
                    create_evidence(
                        source=self.name,
                        code=EvidenceCode.ATT_DANGEROUS_EXTENSION,
                        severity=(
                            Severity.CRITICAL
                            if ext in (".exe", ".scr", ".pif", ".cpl")
                            else Severity.HIGH
                        ),
                        description="Attachment has a dangerous executable or installer extension.",
                        confidence=0.95,
                        raw_data={"extension": ext, "sha256": att.sha256},
                    )
                )

            # 4. Script extensions
            if ext in SCRIPT_EXTENSIONS:
                evidence.append(
                    create_evidence(
                        source=self.name,
                        code=EvidenceCode.ATT_SCRIPT_TYPE,
                        severity=Severity.HIGH,
                        description="Attachment is a standalone executable script file.",
                        confidence=0.92,
                        raw_data={"extension": ext, "sha256": att.sha256},
                    )
                )

            # 5. Macro-enabled Office extensions
            if ext in MACRO_EXTENSIONS:
                evidence.append(
                    create_evidence(
                        source=self.name,
                        code=EvidenceCode.ATT_MACRO_ENABLED,
                        severity=Severity.HIGH,
                        description="Attachment is a macro-enabled Office document.",
                        confidence=0.9,
                        raw_data={"extension": ext, "sha256": att.sha256},
                    )
                )

            # 6. Archive extensions
            if ext in ARCHIVE_EXTENSIONS:
                evidence.append(
                    create_evidence(
                        source=self.name,
                        code=EvidenceCode.ATT_ARCHIVE,
                        severity=Severity.LOW,
                        description="Attachment is a compressed archive.",
                        confidence=0.6,
                        raw_data={"extension": ext, "sha256": att.sha256},
                    )
                )

            # 7. MIME type vs extension mismatch
            if ext in DOCUMENT_EXTENSIONS and any(
                x in mime_type for x in ("dosexec", "octet-stream", "x-msdownload", "executable")
            ):
                evidence.append(
                    create_evidence(
                        source=self.name,
                        code=EvidenceCode.ATT_MIME_MISMATCH,
                        severity=Severity.HIGH,
                        description="Document extension conflicts with executable MIME type.",
                        confidence=0.9,
                        raw_data={
                            "extension": ext,
                            "mime_type": mime_type,
                            "sha256": att.sha256,
                        },
                    )
                )

            # 8. Oversized attachment
            if att.size_bytes > MAX_EXPECTED_ATTACHMENT_BYTES:
                evidence.append(
                    create_evidence(
                        source=self.name,
                        code=EvidenceCode.ATT_OVERSIZED,
                        severity=Severity.LOW,
                        description="Attachment exceeds mail payload size threshold (>25MB).",
                        confidence=0.7,
                        raw_data={"size": att.size_bytes, "sha256": att.sha256},
                    )
                )

        return AnalyzerResult(
            analyzer=self.name,
            status="ok",
            evidence=evidence,
            duration_ms=0,
        )
