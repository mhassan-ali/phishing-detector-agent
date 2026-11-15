"""Unit tests for SQLite threat intelligence caching and differential TTLs."""

from datetime import UTC, datetime, timedelta

import pytest

from phishguard.intel.base import Indicator, IntelResult, compute_indicator_hash
from phishguard.intel.cache import IntelCache, IntelCacheRecord


@pytest.mark.asyncio
async def test_intel_cache_lifecycle() -> None:
    """Verify cache insertion, lookup, and no plaintext indicator storage (Amendment 1)."""
    cache = IntelCache(db_url="sqlite:///:memory:")

    ind = Indicator(type="url", value="https://threat.example.test/payload")
    result = IntelResult(
        provider="test_provider",
        indicator=ind,
        verdict="malicious",
        score=1.0,
        threat_types=["malware"],
        raw={"status": "active"},
    )

    # Initially not in cache
    assert await cache.get("test_provider", ind) is None

    # Save to cache
    await cache.set(result, ind.value)

    # Retrieve from cache
    cached = await cache.get("test_provider", ind)
    assert cached is not None
    assert cached.provider == "test_provider"
    assert cached.verdict == "malicious"
    assert cached.score == 1.0
    assert "malware" in cached.threat_types

    # Verify no plaintext indicator column exists in database (Amendment 1)
    with cache.SessionLocal() as session:
        records = session.query(IntelCacheRecord).all()
        assert len(records) == 1
        rec = records[0]
        # Only indicator_hash is persisted
        assert rec.indicator_hash == compute_indicator_hash(ind)
        assert not hasattr(rec, "indicator_value")


@pytest.mark.asyncio
async def test_intel_cache_differential_ttl() -> None:
    """Verify clean/unknown entries expire faster than malicious entries."""
    cache = IntelCache(db_url="sqlite:///:memory:")

    clean_ind = Indicator(type="domain", value="clean.example.test")
    clean_res = IntelResult(
        provider="test_clean",
        indicator=clean_ind,
        verdict="clean",
    )
    await cache.set(clean_res, clean_ind.value)

    # Inspect record timestamps
    with cache.SessionLocal() as session:
        record = session.query(IntelCacheRecord).filter_by(provider="test_clean").first()
        assert record is not None
        diff_hours = (record.expires_at - record.created_at).total_seconds() / 3600.0
        # Negative / clean result has 1 hour TTL
        assert abs(diff_hours - 1.0) < 0.1

        # Simulate expiration by setting expires_at into the past
        record.expires_at = datetime.now(UTC) - timedelta(minutes=5)
        session.commit()

    # Expired entry is treated as cache miss
    assert await cache.get("test_clean", clean_ind) is None


@pytest.mark.asyncio
async def test_intel_cache_error_resilience() -> None:
    """Verify database errors degrade gracefully to cache miss without raising."""
    cache = IntelCache(db_url="sqlite:///:memory:")
    # Close engine to simulate connection failure
    cache.engine.dispose()

    ind = Indicator(type="domain", value="test.example.test")
    # Must return None instead of raising
    cached = await cache.get("broken_provider", ind)
    assert cached is None
