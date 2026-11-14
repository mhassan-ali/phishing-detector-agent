"""Analyzers for email headers, URLs, content, and attachments."""

from phishguard.analyzers.attachment import AttachmentAnalyzer
from phishguard.analyzers.base import (
    Analyzer,
    create_evidence,
    deduplicate_evidence,
    run_analyzer,
)
from phishguard.analyzers.codes import EvidenceCode
from phishguard.analyzers.content import ContentAnalyzer
from phishguard.analyzers.header import HeaderAnalyzer
from phishguard.analyzers.url import URLAnalyzer

__all__ = [
    "Analyzer",
    "AttachmentAnalyzer",
    "ContentAnalyzer",
    "EvidenceCode",
    "HeaderAnalyzer",
    "URLAnalyzer",
    "create_evidence",
    "deduplicate_evidence",
    "run_analyzer",
]
