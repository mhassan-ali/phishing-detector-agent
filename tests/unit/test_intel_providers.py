"""Unit tests for individual threat intelligence providers using respx mocks."""

import httpx
import pytest
import respx

from phishguard.core.config import Settings
from phishguard.intel.base import Indicator
from phishguard.intel.openphish import OpenPhishProvider
from phishguard.intel.safebrowsing import GoogleSafeBrowsingProvider
from phishguard.intel.urlhaus import URLhausProvider
from phishguard.intel.urlscan import URLScanProvider, escape_urlscan_query_value
from phishguard.intel.virustotal import VirusTotalProvider


@respx.mock
@pytest.mark.asyncio
async def test_virustotal_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify VirusTotal lookups for files (FR-ATT-3), 404 unknown handling, and scan caps."""
    monkeypatch.setattr(
        "phishguard.intel.virustotal.get_settings",
        lambda: Settings(
            _env_file=None,
            VIRUSTOTAL_ENABLED=True,
            VIRUSTOTAL_API_KEY="test-vt-key",
        ),
    )
    provider = VirusTotalProvider()

    # 1. File hash with >= 5 malicious detections -> verdict="malicious" (FR-ATT-3)
    sample_sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    sha_ind = Indicator(type="sha256", value=sample_sha)
    respx.get(f"https://www.virustotal.com/api/v3/files/{sha_ind.value}").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 8, "suspicious": 1, "harmless": 60},
                        "last_analysis_results": {
                            "EngineA": {"category": "malicious", "result": "Trojan.Generic"},
                        },
                    }
                }
            },
        )
    )
    res_sha = await provider.lookup(sha_ind)
    assert res_sha.verdict == "malicious"
    assert res_sha.score == 8.0
    assert "Trojan.Generic" in res_sha.threat_types

    # 2. Domain lookup with detections caps at "suspicious" (Amendment 4)
    dom_ind = Indicator(type="domain", value="suspicious-domain.test")
    respx.get(f"https://www.virustotal.com/api/v3/domains/{dom_ind.value}").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 4, "suspicious": 2, "harmless": 20},
                    }
                }
            },
        )
    )
    res_dom = await provider.lookup(dom_ind)
    assert res_dom.verdict == "suspicious"

    # 3. HTTP 404 response yields "unknown" and never submits a scan (Amendment 8)
    unknown_ind = Indicator(type="domain", value="unseen-domain.test")
    respx.get(f"https://www.virustotal.com/api/v3/domains/{unknown_ind.value}").mock(
        return_value=httpx.Response(404)
    )
    # Beyond VT_MAX_LOOKUPS_PER_SCAN (2 queries used so far)
    res_capped = await provider.lookup(unknown_ind)
    assert res_capped.verdict == "skipped"

    # Reset scan budget and verify 404 handling
    provider.reset_scan_budget()
    res_404 = await provider.lookup(unknown_ind)
    assert res_404.verdict == "unknown"


@respx.mock
@pytest.mark.asyncio
async def test_urlhaus_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify URLhaus lookups for URLs, hosts, and clean responses."""
    monkeypatch.setattr(
        "phishguard.intel.urlhaus.get_settings",
        lambda: Settings(
            _env_file=None,
            URLHAUS_ENABLED=True,
            URLHAUS_AUTH_KEY="test-urlhaus-auth-key",
        ),
    )
    provider = URLhausProvider()

    # 1. Malicious URL match -> verdict="malicious"
    url_ind = Indicator(type="url", value="https://malicious-drop.test/malware.exe")
    respx.post("https://urlhaus-api.abuse.ch/v1/url/").mock(
        return_value=httpx.Response(
            200,
            json={
                "query_status": "ok",
                "threat": "malware_download",
                "url_status": "online",
            },
        )
    )
    res_url = await provider.lookup(url_ind)
    assert res_url.verdict == "malicious"
    assert "malware_download" in res_url.threat_types

    # 2. Host query -> capped at "suspicious" (Amendment 4)
    host_ind = Indicator(type="domain", value="malicious-host.test")
    respx.post("https://urlhaus-api.abuse.ch/v1/host/").mock(
        return_value=httpx.Response(
            200,
            json={"query_status": "ok", "threat": "malware_download"},
        )
    )
    res_host = await provider.lookup(host_ind)
    assert res_host.verdict == "suspicious"

    # 3. Not listed -> verdict="clean"
    from phishguard.intel.client import URLHAUS_BUCKET

    URLHAUS_BUCKET.tokens = 2.0
    clean_ind = Indicator(type="url", value="https://legit.example.test/")
    respx.post("https://urlhaus-api.abuse.ch/v1/url/").mock(
        return_value=httpx.Response(200, json={"query_status": "no_results"})
    )
    res_clean = await provider.lookup(clean_ind)
    assert res_clean.verdict == "clean"


@respx.mock
@pytest.mark.asyncio
async def test_openphish_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify OpenPhish community feed matching, domain match, and size cap error."""
    monkeypatch.setattr(
        "phishguard.intel.openphish.get_settings",
        lambda: Settings(
            _env_file=None,
            OPENPHISH_ENABLED=True,
            OPENPHISH_MAX_FEED_BYTES=10000,
        ),
    )
    provider = OpenPhishProvider()

    # 1. Normal feed download and URL match
    feed_content = "https://phish1.example.test/login\nhttps://phish2.example.test/verify\n"
    respx.get("https://openphish.com/feed.txt").mock(
        return_value=httpx.Response(200, text=feed_content)
    )

    url_ind = Indicator(type="url", value="https://phish1.example.test/login")
    res_match = await provider.lookup(url_ind)
    assert res_match.verdict == "malicious"
    assert "phishing" in res_match.threat_types

    # Domain match in feed -> capped at "suspicious" (Amendment 4)
    dom_ind = Indicator(type="domain", value="phish2.example.test")
    res_dom = await provider.lookup(dom_ind)
    assert res_dom.verdict == "suspicious"

    # 2. Oversized feed triggers provider "error" (Amendment 9)
    provider_oversized = OpenPhishProvider()
    respx.get("https://openphish.com/feed.txt").mock(
        return_value=httpx.Response(200, content=b"A" * 20000)
    )
    res_err = await provider_oversized.lookup(url_ind)
    assert res_err.verdict == "error"


@respx.mock
@pytest.mark.asyncio
async def test_google_safebrowsing_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify Google Safe Browsing lookups and clean response."""
    monkeypatch.setattr(
        "phishguard.intel.safebrowsing.get_settings",
        lambda: Settings(
            _env_file=None,
            SAFEBROWSING_ENABLED=True,
            GOOGLE_SAFE_BROWSING_KEY="test-gsb-key",
        ),
    )
    provider = GoogleSafeBrowsingProvider()

    url_ind = Indicator(type="url", value="https://deceptive-portal.test/auth")
    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=test-gsb-key"

    # 1. Threat match -> verdict="malicious"
    respx.post(endpoint).mock(
        return_value=httpx.Response(
            200,
            json={
                "matches": [
                    {
                        "threatType": "SOCIAL_ENGINEERING",
                        "platformType": "ANY_PLATFORM",
                        "threat": {"url": url_ind.value},
                    }
                ]
            },
        )
    )
    res_match = await provider.lookup(url_ind)
    assert res_match.verdict == "malicious"
    assert "SOCIAL_ENGINEERING" in res_match.threat_types

    # 2. Clean response
    respx.post(endpoint).mock(return_value=httpx.Response(200, json={}))
    res_clean = await provider.lookup(url_ind)
    assert res_clean.verdict == "clean"


@respx.mock
@pytest.mark.asyncio
async def test_urlscan_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify urlscan search quoting, injection resistance, and strictly search-only behavior."""
    monkeypatch.setattr(
        "phishguard.intel.urlscan.get_settings",
        lambda: Settings(
            _env_file=None,
            URLSCAN_ENABLED=True,
            URLSCAN_API_KEY="test-urlscan-key",
        ),
    )
    provider = URLScanProvider()

    # 1. Query escaping against injection (Amendment 5)
    dirty_input = 'test" OR 1=1; -- \\'
    escaped = escape_urlscan_query_value(dirty_input)
    assert '\\"' in escaped
    assert "\\\\" in escaped

    # 2. Malicious search result
    dom_ind = Indicator(type="domain", value="phishing-site.test")
    respx.get(url__startswith="https://urlscan.io/api/v1/search/").mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {
                        "verdicts": {
                            "overall": {
                                "malicious": True,
                                "score": 100,
                                "categories": ["phishing"],
                            }
                        }
                    }
                ]
            },
        )
    )
    res_match = await provider.lookup(dom_ind)
    # Domain search hit caps at "suspicious" (Amendment 4)
    assert res_match.verdict == "suspicious"
    assert res_match.score == 100.0
    assert "phishing" in res_match.threat_types
    # Verify no raw page text was leaked into raw metadata
    assert "page_text" not in res_match.raw


@respx.mock
@pytest.mark.asyncio
async def test_virustotal_disabled_and_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify VirusTotal disabled state, error responses, and URL queries."""
    monkeypatch.setattr(
        "phishguard.intel.virustotal.get_settings",
        lambda: Settings(_env_file=None, VIRUSTOTAL_ENABLED=False),
    )
    provider = VirusTotalProvider()
    res_disabled = await provider.lookup(Indicator(type="sha256", value="a" * 64))
    assert res_disabled.verdict == "skipped"

    # URL query with malicious score
    monkeypatch.setattr(
        "phishguard.intel.virustotal.get_settings",
        lambda: Settings(
            _env_file=None,
            VIRUSTOTAL_ENABLED=True,
            VIRUSTOTAL_API_KEY="test-key",
        ),
    )
    respx.get(url__startswith="https://www.virustotal.com/api/v3/urls/").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 6, "suspicious": 0, "harmless": 20},
                    }
                }
            },
        )
    )
    res_url = await provider.lookup(Indicator(type="url", value="https://threat.test/drop"))
    assert res_url.verdict == "malicious"

    # 500 error response
    provider.reset_scan_budget()
    respx.get(url__startswith="https://www.virustotal.com/api/v3/files/").mock(
        return_value=httpx.Response(500)
    )
    res_err = await provider.lookup(Indicator(type="sha256", value="b" * 64))
    assert res_err.verdict == "error"


@respx.mock
@pytest.mark.asyncio
async def test_urlscan_disabled_and_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify urlscan disabled state, empty results, and URL queries."""
    monkeypatch.setattr(
        "phishguard.intel.urlscan.get_settings",
        lambda: Settings(_env_file=None, URLSCAN_ENABLED=False),
    )
    provider = URLScanProvider()
    res_disabled = await provider.lookup(Indicator(type="url", value="https://test.example"))
    assert res_disabled.verdict == "skipped"

    # Enabled with empty search results -> clean
    monkeypatch.setattr(
        "phishguard.intel.urlscan.get_settings",
        lambda: Settings(
            _env_file=None,
            URLSCAN_ENABLED=True,
            URLSCAN_API_KEY="test-key",
        ),
    )
    respx.get(url__startswith="https://urlscan.io/api/v1/search/").mock(
        return_value=httpx.Response(200, json={"results": []})
    )
    res_empty = await provider.lookup(Indicator(type="url", value="https://test.example"))
    assert res_empty.verdict == "clean"

    # Enabled with URL indicator matching malicious scan -> malicious
    provider.reset_scan_budget()
    respx.get(url__startswith="https://urlscan.io/api/v1/search/").mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {
                        "verdicts": {
                            "overall": {
                                "malicious": True,
                                "score": 100,
                                "categories": ["phishing"],
                            }
                        }
                    }
                ]
            },
        )
    )
    res_url_mal = await provider.lookup(Indicator(type="url", value="https://phish.example/login"))
    assert res_url_mal.verdict == "malicious"


@respx.mock
@pytest.mark.asyncio
async def test_urlhaus_and_safebrowsing_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify disabled behavior for URLhaus and Google Safe Browsing."""
    monkeypatch.setattr(
        "phishguard.intel.urlhaus.get_settings",
        lambda: Settings(_env_file=None, URLHAUS_ENABLED=False),
    )
    provider_uh = URLhausProvider()
    res_uh = await provider_uh.lookup(Indicator(type="url", value="https://example.com"))
    assert res_uh.verdict == "skipped"

    monkeypatch.setattr(
        "phishguard.intel.safebrowsing.get_settings",
        lambda: Settings(_env_file=None, SAFEBROWSING_ENABLED=False),
    )
    provider_sb = GoogleSafeBrowsingProvider()
    res_sb = await provider_sb.lookup(Indicator(type="url", value="https://example.com"))
    assert res_sb.verdict == "skipped"
