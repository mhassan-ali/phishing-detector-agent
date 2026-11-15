"""Unit tests for threat intelligence HTTP client, security boundary, and rate limiting."""

import httpx
import pytest
import respx

from phishguard.core.errors import HostNotAllowedError
from phishguard.intel.client import (
    CircuitBreaker,
    TokenBucket,
    execute_intel_request,
    sanitize_url_for_logging,
    validate_intel_url,
)


def test_validate_intel_url_allowlist() -> None:
    """Verify host allowlist enforcement and HTTPS scheme requirement (Amendment 7)."""
    # Allowed hosts with HTTPS succeed
    validate_intel_url("https://www.virustotal.com/api/v3/urls/123")
    validate_intel_url("https://urlhaus-api.abuse.ch/v1/url/")
    validate_intel_url("https://openphish.com/feed.txt")
    validate_intel_url("https://safebrowsing.googleapis.com/v4/threatMatches:find")
    validate_intel_url("https://urlscan.io/api/v1/search/")

    # Disallowed hosts raise HostNotAllowedError
    with pytest.raises(HostNotAllowedError, match="not in the allowed"):
        validate_intel_url("https://evil-site.test/api")

    with pytest.raises(HostNotAllowedError, match="not in the allowed"):
        validate_intel_url("https://127.0.0.1/api")

    # Non-HTTPS schemes raise HostNotAllowedError
    with pytest.raises(HostNotAllowedError, match="must use HTTPS"):
        validate_intel_url("http://www.virustotal.com/api/v3/urls/123")


def test_sanitize_url_for_logging() -> None:
    """Verify secrets in query strings are redacted before logging."""
    url = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=AIzaSySuperSecretKey123&other=val"
    sanitized = sanitize_url_for_logging(url)
    assert "AIzaSySuperSecretKey123" not in sanitized
    assert "key=[REDACTED]" in sanitized
    assert "other=val" in sanitized


@pytest.mark.asyncio
async def test_token_bucket_nonblocking() -> None:
    """Verify non-blocking token bucket allows within capacity and rejects when empty."""
    bucket = TokenBucket(capacity=2.0, refill_rate=0.1)
    # First 2 requests succeed
    assert await bucket.acquire_nonblocking() is True
    assert await bucket.acquire_nonblocking() is True
    # Third request immediately fails without blocking
    assert await bucket.acquire_nonblocking() is False


def test_circuit_breaker() -> None:
    """Verify circuit breaker trips and resets after cooldown."""
    cb = CircuitBreaker()
    assert cb.is_tripped() is False
    cb.trip()
    assert cb.is_tripped() is True
    # Simulate cooldown
    cb.cooldown_seconds = 0.01
    import time

    time.sleep(0.02)
    assert cb.is_tripped() is False


@respx.mock
@pytest.mark.asyncio
async def test_execute_intel_request_retries_and_caps() -> None:
    """Verify 5xx retries with backoff and response size capping."""
    url = "https://urlhaus-api.abuse.ch/v1/url/"

    # 1. 500 error followed by 200 success
    respx.post(url).mock(
        side_effect=[
            httpx.Response(500),
            httpx.Response(200, json={"query_status": "ok"}),
        ]
    )
    resp = await execute_intel_request("POST", url, provider_name="test_urlhaus")
    assert resp.status_code == 200
    assert resp.json()["query_status"] == "ok"

    # 2. Response exceeding byte cap raises error
    oversized_url = "https://openphish.com/feed.txt"
    respx.get(oversized_url).mock(return_value=httpx.Response(200, content=b"A" * 1500))
    with pytest.raises(httpx.RequestError, match="exceeded limit"):
        await execute_intel_request(
            "GET",
            oversized_url,
            provider_name="test_openphish",
            max_response_bytes=1000,
        )

    # 3. 429 Rate limit trips circuit breaker
    from phishguard.intel.client import PROVIDER_CIRCUITS

    PROVIDER_CIRCUITS["urlscan"].tripped = False
    respx.get("https://urlscan.io/api/v1/search/").mock(
        return_value=httpx.Response(429, headers={"Retry-After": "60"})
    )
    resp_429 = await execute_intel_request(
        "GET",
        "https://urlscan.io/api/v1/search/",
        provider_name="urlscan",
    )
    assert resp_429.status_code == 429
    assert PROVIDER_CIRCUITS["urlscan"].is_tripped() is True
    PROVIDER_CIRCUITS["urlscan"].tripped = False
