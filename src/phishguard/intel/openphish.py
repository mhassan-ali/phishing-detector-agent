"""OpenPhish community feed intelligence provider."""

import time
import urllib.parse

import httpx
import structlog

from phishguard.core.config import get_settings
from phishguard.intel.base import Indicator, IntelProvider, IntelResult
from phishguard.intel.client import execute_intel_request

logger = structlog.get_logger(__name__)


class OpenPhishProvider(IntelProvider):
    """Intelligence provider querying the OpenPhish community feed.

    Verified official documentation: https://openphish.com/ (Nov 2026).
    Free community feed at https://openphish.com/feed.txt.
    """

    name = "openphish"

    def __init__(self) -> None:
        self._cached_urls: set[str] = set()
        self._cached_domains: set[str] = set()
        self._feed_timestamp: float = 0.0
        self._cache_ttl_seconds: float = 3600.0  # 1 hour local feed cache

    async def _refresh_feed_if_needed(self) -> bool:
        """Download and cache the latest community feed.

        Enforces configurable size cap. If feed exceeds cap, returns False and
        never uses a truncated feed (Amendment 9).

        Returns:
            True if feed is fresh or refreshed successfully; False on error.
        """
        now = time.monotonic()
        if self._cached_urls and (now - self._feed_timestamp < self._cache_ttl_seconds):
            return True

        cfg = get_settings()
        max_bytes = cfg.OPENPHISH_MAX_FEED_BYTES
        url = "https://openphish.com/feed.txt"

        try:
            resp = await execute_intel_request(
                method="GET",
                url=url,
                provider_name=self.name,
                max_response_bytes=max_bytes,
            )
            if resp.status_code != 200:
                logger.warning("openphish_feed_download_failed", status=resp.status_code)
                return False

            text = resp.text
            lines = [line.strip() for line in text.splitlines() if line.strip()]
            new_urls: set[str] = set()
            new_domains: set[str] = set()

            for line in lines:
                new_urls.add(line)
                try:
                    host = urllib.parse.urlsplit(line).netloc.split(":")[0].lower()
                    if host:
                        new_domains.add(host)
                except (ValueError, AttributeError):
                    continue

            self._cached_urls = new_urls
            self._cached_domains = new_domains
            self._feed_timestamp = now
            return True

        except (httpx.HTTPError, Exception) as exc:
            logger.warning(
                "openphish_feed_error_exceeded_cap_or_network",
                error=type(exc).__name__,
            )
            return False

    async def lookup(self, indicator: Indicator) -> IntelResult:
        """Check if indicator exists in the OpenPhish community feed.

        Args:
            indicator: Indicator model (URL or domain).

        Returns:
            Standardized IntelResult.
        """
        cfg = get_settings()
        if not cfg.OPENPHISH_ENABLED:
            return IntelResult(provider=self.name, indicator=indicator, verdict="skipped")

        if indicator.type not in ("url", "domain"):
            return IntelResult(provider=self.name, indicator=indicator, verdict="skipped")

        t0 = time.perf_counter()
        refreshed = await self._refresh_feed_if_needed()
        if not refreshed:
            # Feed over size cap or download failed -> provider error (Amendment 9)
            return IntelResult(
                provider=self.name,
                indicator=indicator,
                verdict="error",
                duration_ms=int((time.perf_counter() - t0) * 1000),
            )

        elapsed_ms = int((time.perf_counter() - t0) * 1000)

        if indicator.type == "url":
            # Exact URL match -> INTEL_CONFIRMED_MALICIOUS (Amendment 4)
            target = indicator.value.strip()
            if target in self._cached_urls or target.rstrip("/") in self._cached_urls:
                return IntelResult(
                    provider=self.name,
                    indicator=indicator,
                    verdict="malicious",
                    score=1.0,
                    threat_types=["phishing"],
                    raw={"source": "openphish_community_feed"},
                    duration_ms=elapsed_ms,
                )
            return IntelResult(
                provider=self.name,
                indicator=indicator,
                verdict="clean",
                duration_ms=elapsed_ms,
            )

        elif indicator.type == "domain":
            # Domain-level match caps at INTEL_SUSPICIOUS (Amendment 4)
            dom = indicator.value.strip().lower()
            if dom in self._cached_domains:
                return IntelResult(
                    provider=self.name,
                    indicator=indicator,
                    verdict="suspicious",
                    score=0.75,
                    threat_types=["phishing"],
                    raw={"source": "openphish_community_feed"},
                    duration_ms=elapsed_ms,
                )
            return IntelResult(
                provider=self.name,
                indicator=indicator,
                verdict="clean",
                duration_ms=elapsed_ms,
            )

        return IntelResult(provider=self.name, indicator=indicator, verdict="skipped")
