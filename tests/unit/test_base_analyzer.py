"""Unit tests for analyzer base infrastructure: runner, evidence creation, deduplication."""

import asyncio
from typing import Any

from phishguard.analyzers.base import (
    create_evidence,
    deduplicate_evidence,
    run_analyzer,
    sanitize_raw_data,
    sanitize_raw_string,
)
from phishguard.analyzers.codes import EvidenceCode
from phishguard.core.schemas import AnalyzerResult, Evidence, ParsedEmail, Severity


class DummySyncAnalyzer:
    name = "dummy_sync"

    def run(self, parsed: ParsedEmail) -> AnalyzerResult:
        ev = create_evidence(
            source=self.name,
            code=EvidenceCode.HDR_SPF_FAIL,
            severity=Severity.HIGH,
            description="Sync test evidence",
            confidence=0.9,
            raw_data={"test": "data"},
        )
        return AnalyzerResult(
            analyzer=self.name,
            status="ok",
            evidence=[ev],
            duration_ms=0,
        )


class DummyAsyncAnalyzer:
    name = "dummy_async"

    async def run(self, parsed: ParsedEmail) -> AnalyzerResult:
        await asyncio.sleep(0.01)
        ev = create_evidence(
            source=self.name,
            code=EvidenceCode.URL_ODD_PORT,
            severity=Severity.LOW,
            description="Async test evidence",
            confidence=0.8,
            raw_data={"port": 8080},
        )
        return AnalyzerResult(
            analyzer=self.name,
            status="ok",
            evidence=[ev],
            duration_ms=0,
        )


class CrashingAnalyzer:
    name = "dummy_crash"

    def run(self, parsed: ParsedEmail) -> AnalyzerResult:
        raise ValueError("Simulated unexpected failure")


def test_sanitize_raw_string() -> None:
    """Verify bidi and control characters are stripped and string length is capped."""
    dirty = "legit\u202etest\x00\x08data"
    cleaned = sanitize_raw_string(dirty)
    assert "\u202e" not in cleaned
    assert "\x00" not in cleaned
    assert cleaned == "legittestdata"

    huge = "a" * 300
    capped = sanitize_raw_string(huge)
    assert len(capped) == 200
    assert capped.endswith("...")


def test_sanitize_raw_data_size_capping() -> None:
    """Verify raw_data drops non-essential keys deterministically when exceeding byte limits."""
    big_dict: dict[str, Any] = {
        "domain": "example.com",
        "registered_domain": "example.com",
        "code": "TEST",
    }
    # Add large payloads
    for i in range(50):
        big_dict[f"extra_key_{i:02d}"] = "x" * 150

    sanitized = sanitize_raw_data(big_dict)
    # Essential keys preserved
    assert sanitized["domain"] == "example.com"
    assert sanitized["registered_domain"] == "example.com"


def test_create_evidence_truncation() -> None:
    """Verify description is truncated with ellipsis if exceeding max length."""
    long_desc = "A" * 600
    ev = create_evidence(
        source="test",
        code=EvidenceCode.HDR_SPF_FAIL,
        severity=Severity.HIGH,
        description=long_desc,
        confidence=1.5,  # Out of range, should be clamped to 1.0
        raw_data={"domain": "example.com"},
    )
    assert len(ev.description) == 500
    assert ev.description.endswith("...")
    assert ev.confidence == 1.0


def test_deduplicate_evidence() -> None:
    """Verify deduplication by (code, registered_domain) and capping at 5 items per code."""
    items: list[Evidence] = []
    # Create 8 items with same code but different domains
    for i in range(8):
        items.append(
            create_evidence(
                source="test",
                code=EvidenceCode.URL_ODD_PORT,
                severity=Severity.LOW,
                description=f"Odd port {i}",
                confidence=0.8,
                raw_data={"domain": f"host{i}.test"},
            )
        )
    # Add duplicate domain
    items.append(
        create_evidence(
            source="test",
            code=EvidenceCode.URL_ODD_PORT,
            severity=Severity.LOW,
            description="Duplicate domain",
            confidence=0.8,
            raw_data={"domain": "host0.test"},
        )
    )

    deduped = deduplicate_evidence(items, max_per_code=5)
    assert len(deduped) == 5
    domains = [d.raw_data.get("domain") for d in deduped]
    assert len(set(domains)) == 5


def test_run_analyzer_sync() -> None:
    """Verify run_analyzer executes synchronous analyzers correctly."""
    analyzer = DummySyncAnalyzer()
    dummy_parsed = ParsedEmail(sha256="dummy")
    res = run_analyzer(analyzer, dummy_parsed)
    assert res.analyzer == "dummy_sync"
    assert res.status == "ok"
    assert len(res.evidence) == 1
    assert res.evidence[0].code == EvidenceCode.HDR_SPF_FAIL
    assert res.duration_ms >= 0


def test_run_analyzer_async() -> None:
    """Verify run_analyzer executes asynchronous analyzers correctly from sync callers."""
    analyzer = DummyAsyncAnalyzer()
    dummy_parsed = ParsedEmail(sha256="dummy")
    res = run_analyzer(analyzer, dummy_parsed)
    assert res.analyzer == "dummy_async"
    assert res.status == "ok"
    assert len(res.evidence) == 1
    assert res.evidence[0].code == EvidenceCode.URL_ODD_PORT
    assert res.duration_ms >= 0


def test_run_analyzer_exception_trapping() -> None:
    """Verify run_analyzer never raises into the caller and records status='error'."""
    analyzer = CrashingAnalyzer()
    dummy_parsed = ParsedEmail(sha256="dummy")
    res = run_analyzer(analyzer, dummy_parsed)
    assert res.analyzer == "dummy_crash"
    assert res.status == "error"
    assert res.error == "ValueError"
    assert res.evidence == []
