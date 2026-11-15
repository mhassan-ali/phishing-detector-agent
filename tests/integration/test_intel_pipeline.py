"""Integration tests for threat intelligence pipeline with mocked provider endpoints."""

import httpx
import pytest
import respx

from phishguard.analyzers.codes import EvidenceCode
from phishguard.core.config import Settings
from phishguard.core.schemas import AttachmentMetadata
from phishguard.ingest.extractor import extract_urls
from phishguard.ingest.parser import parse_eml
from phishguard.intel.analyzer import IntelAnalyzer
from phishguard.intel.cache import IntelCache


@respx.mock
@pytest.mark.asyncio
async def test_intel_pipeline_end_to_end(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    """Verify threat intelligence flow: parsing, indicator selection, caching, and evidence."""
    db_file = tmp_path / "intel_test.db"
    cache = IntelCache(db_url=f"sqlite:///{db_file}")

    monkeypatch.setattr(
        "phishguard.intel.analyzer.get_settings",
        lambda: Settings(
            _env_file=None,
            VIRUSTOTAL_ENABLED=True,
            URLHAUS_ENABLED=True,
            OPENPHISH_ENABLED=True,
            SAFEBROWSING_ENABLED=True,
            URLSCAN_ENABLED=True,
            VIRUSTOTAL_API_KEY="vt-key",
            URLHAUS_AUTH_KEY="urlhaus-key",
            GOOGLE_SAFE_BROWSING_KEY="gsb-key",
            URLSCAN_API_KEY="urlscan-key",
        ),
    )
    monkeypatch.setattr(
        "phishguard.intel.virustotal.get_settings",
        lambda: Settings(
            _env_file=None,
            VIRUSTOTAL_ENABLED=True,
            VIRUSTOTAL_API_KEY="vt-key",
        ),
    )
    monkeypatch.setattr(
        "phishguard.intel.urlhaus.get_settings",
        lambda: Settings(
            _env_file=None,
            URLHAUS_ENABLED=True,
            URLHAUS_AUTH_KEY="urlhaus-key",
        ),
    )
    monkeypatch.setattr(
        "phishguard.intel.safebrowsing.get_settings",
        lambda: Settings(
            _env_file=None,
            SAFEBROWSING_ENABLED=True,
            GOOGLE_SAFE_BROWSING_KEY="gsb-key",
        ),
    )
    monkeypatch.setattr(
        "phishguard.intel.urlscan.get_settings",
        lambda: Settings(
            _env_file=None,
            URLSCAN_ENABLED=True,
            URLSCAN_API_KEY="urlscan-key",
        ),
    )
    monkeypatch.setattr(
        "phishguard.intel.openphish.get_settings",
        lambda: Settings(
            _env_file=None,
            OPENPHISH_ENABLED=True,
        ),
    )

    # 1. Setup mock routes
    vt_route = respx.get(url__startswith="https://www.virustotal.com").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 6, "suspicious": 0, "harmless": 50},
                        "last_analysis_results": {},
                    }
                }
            },
        )
    )
    respx.post(url__startswith="https://urlhaus-api.abuse.ch").mock(
        return_value=httpx.Response(200, json={"query_status": "no_results"})
    )
    respx.get("https://openphish.com/feed.txt").mock(
        return_value=httpx.Response(200, text="https://other.test/phish\n")
    )
    respx.post(url__startswith="https://safebrowsing.googleapis.com").mock(
        return_value=httpx.Response(200, json={})
    )
    respx.get(url__startswith="https://urlscan.io").mock(
        return_value=httpx.Response(200, json={"results": []})
    )

    analyzer = IntelAnalyzer(cache=cache)

    raw_eml = (
        "From: alerts@finance-update.test\r\n"
        "To: user@example.com\r\n"
        "Subject: Urgent security patch\r\n\r\n"
        "Please visit https://portal.finance-update.test/patch immediately."
    )
    parsed = parse_eml(raw_eml.encode("utf-8"))
    extract_urls(parsed)
    # Add attachment metadata (FR-ATT-3)
    parsed.attachments = [
        AttachmentMetadata(
            filename="patch.exe",
            content_type="application/octet-stream",
            size_bytes=5000,
            sha256="deadbeef" * 8,
        )
    ]

    # First run: queries providers, populates cache
    res1 = await analyzer.run(parsed)
    assert res1.status in ("ok", "partial")
    codes1 = [e.code for e in res1.evidence]
    assert EvidenceCode.INTEL_CONFIRMED_MALICIOUS in codes1
    vt_calls = vt_route.call_count
    assert vt_calls > 0

    # Second run: should hit cache without making additional external HTTP calls
    res2 = await analyzer.run(parsed)
    assert res2.status in ("ok", "partial")
    assert EvidenceCode.INTEL_CONFIRMED_MALICIOUS in [e.code for e in res2.evidence]
    # No new VT call was made because it hit cache
    assert vt_route.call_count == vt_calls
