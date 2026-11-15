"""Unit tests for IntelAnalyzer evidence generation, statuses, and deadline handling."""

import asyncio

import pytest

from phishguard.analyzers.codes import EvidenceCode
from phishguard.core.config import Settings
from phishguard.core.schemas import AttachmentMetadata, ParsedEmail, Severity
from phishguard.intel.analyzer import IntelAnalyzer
from phishguard.intel.base import Indicator, IntelProvider, IntelResult
from phishguard.intel.cache import IntelCache


class StubProvider(IntelProvider):
    def __init__(self, name: str, verdict: str = "clean", delay: float = 0.0) -> None:
        self.name = name
        self.verdict = verdict
        self.delay = delay
        self.calls = 0

    async def lookup(self, indicator: Indicator) -> IntelResult:
        self.calls += 1
        if self.delay > 0:
            await asyncio.sleep(self.delay)
        return IntelResult(
            provider=self.name,
            indicator=indicator,
            verdict=self.verdict,  # type: ignore[arg-type]
            threat_types=["phishing"] if self.verdict == "malicious" else [],
        )


@pytest.mark.asyncio
async def test_intel_analyzer_skipped_when_empty() -> None:
    """Verify analyzer returns status='skipped' when ParsedEmail has no indicators."""
    analyzer = IntelAnalyzer(
        providers=[StubProvider("stub")], cache=IntelCache("sqlite:///:memory:")
    )
    res = await analyzer.run(ParsedEmail(sha256="dummy"))
    assert res.status == "skipped"
    assert res.evidence == []


@pytest.mark.asyncio
async def test_intel_analyzer_malicious_and_suspicious_evidence() -> None:
    """Verify emission of INTEL_CONFIRMED_MALICIOUS and INTEL_SUSPICIOUS."""
    cache = IntelCache("sqlite:///:memory:")
    provider_malicious = StubProvider("provider_mal", verdict="malicious")
    provider_suspicious = StubProvider("provider_susp", verdict="suspicious")

    analyzer = IntelAnalyzer(
        providers=[provider_malicious, provider_suspicious],
        cache=cache,
    )

    parsed = ParsedEmail(
        attachments=[
            AttachmentMetadata(
                filename="lure.pdf",
                content_type="application/pdf",
                size_bytes=100,
                sha256="a" * 64,
            )
        ],
        sha256="dummy",
    )

    res = await analyzer.run(parsed)
    assert res.status == "ok"
    codes = [e.code for e in res.evidence]
    assert EvidenceCode.INTEL_CONFIRMED_MALICIOUS in codes
    assert EvidenceCode.INTEL_SUSPICIOUS in codes

    # Find confirmed malicious evidence
    crit_ev = next(e for e in res.evidence if e.code == EvidenceCode.INTEL_CONFIRMED_MALICIOUS)
    assert crit_ev.severity == Severity.CRITICAL
    assert crit_ev.confidence == 1.0


@pytest.mark.asyncio
async def test_intel_analyzer_not_listed_emitted_at_most_once() -> None:
    """Verify INTEL_NOT_LISTED is emitted at most once per scan (Amendment 11)."""
    cache = IntelCache("sqlite:///:memory:")
    clean_p1 = StubProvider("clean_p1", verdict="clean")
    clean_p2 = StubProvider("clean_p2", verdict="clean")

    analyzer = IntelAnalyzer(providers=[clean_p1, clean_p2], cache=cache)
    parsed = ParsedEmail(
        attachments=[
            AttachmentMetadata(
                filename="a.pdf",
                content_type="application/pdf",
                size_bytes=100,
                sha256="b" * 64,
            )
        ],
        sha256="dummy",
    )

    res = await analyzer.run(parsed)
    assert res.status == "ok"
    not_listed_ev = [e for e in res.evidence if e.code == EvidenceCode.INTEL_NOT_LISTED]
    # Strictly at most once per scan (Amendment 11)
    assert len(not_listed_ev) == 1
    assert not_listed_ev[0].severity == Severity.INFO


@pytest.mark.asyncio
async def test_intel_analyzer_deadline_triggers_partial(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify overall deadline timeout sets status='partial' (Amendment 3)."""
    monkeypatch.setattr(
        "phishguard.intel.analyzer.get_settings",
        lambda: Settings(_env_file=None, PHISHGUARD_INTEL_DEADLINE_SECONDS=0.1),
    )
    slow_provider = StubProvider("slow", verdict="clean", delay=0.3)
    analyzer = IntelAnalyzer(
        providers=[slow_provider],
        cache=IntelCache("sqlite:///:memory:"),
    )
    parsed = ParsedEmail(
        attachments=[
            AttachmentMetadata(
                filename="a.pdf",
                content_type="application/pdf",
                size_bytes=100,
                sha256="c" * 64,
            )
        ],
        sha256="dummy",
    )
    res = await analyzer.run(parsed)
    assert res.status == "partial"
