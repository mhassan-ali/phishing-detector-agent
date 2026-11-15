"""urlscan.io search-only intelligence provider."""

import time
import urllib.parse
from typing import Any

import httpx
import structlog

from phishguard.core.config import get_settings
from phishguard.intel.base import Indicator, IntelProvider, IntelResult, IntelVerdict
from phishguard.intel.client import URLSCAN_BUCKET, execute_intel_request
from phishguard.intel.constants import URLSCAN_MAX_LOOKUPS_PER_SCAN

logger = structlog.get_logger(__name__)


def escape_urlscan_query_value(value: str) -> str:
    """Escape and quote indicator value for urlscan.io ElasticSearch query syntax.

    Per Amendment 5: Escapes backslashes and quotes to prevent query injection.

    Args:
        value: Raw indicator string.

    Returns:
        Escaped string safe to place inside quotes.
    """
    # Escape backslashes first, then double quotes
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    # Disallow newlines and carriage returns
    return escaped.replace("\r", "").replace("\n", "")


class URLScanProvider(IntelProvider):
    """Intelligence provider searching existing scans on urlscan.io.

    Verified official documentation: https://urlscan.io/docs/api/#search (Nov 2026).
    STRICT SEARCH ONLY: Never submits scans or makes POST requests.
    """

    name = "urlscan"

    def __init__(self) -> None:
        self._lookups_this_scan = 0

    def reset_scan_budget(self) -> None:
        """Reset per-scan lookup counter."""
        self._lookups_this_scan = 0

    async def lookup(self, indicator: Indicator) -> IntelResult:
        """Query existing public scan results on urlscan.io.

        Args:
            indicator: Indicator model (URL, domain, ip, or SHA-256).

        Returns:
            Standardized IntelResult.
        """
        cfg = get_settings()
        if not cfg.URLSCAN_ENABLED:
            return IntelResult(provider=self.name, indicator=indicator, verdict="skipped")

        # Per-scan lookup cap (Amendment 3)
        if self._lookups_this_scan >= URLSCAN_MAX_LOOKUPS_PER_SCAN:
            logger.info("urlscan_scan_cap_reached", cap=URLSCAN_MAX_LOOKUPS_PER_SCAN)
            return IntelResult(provider=self.name, indicator=indicator, verdict="skipped")

        acquired = await URLSCAN_BUCKET.acquire_nonblocking()
        if not acquired:
            logger.warning("urlscan_token_bucket_exhausted")
            return IntelResult(provider=self.name, indicator=indicator, verdict="skipped")

        self._lookups_this_scan += 1

        # Build escaped search query (Amendment 5)
        escaped_val = escape_urlscan_query_value(indicator.value)
        if indicator.type == "domain":
            q_str = f'page.domain:"{escaped_val}"'
        elif indicator.type == "url":
            q_str = f'page.url:"{escaped_val}"'
        elif indicator.type == "sha256":
            q_str = f'files.hash:"{escaped_val}"'
        elif indicator.type == "ip":
            q_str = f'page.ip:"{escaped_val}"'
        else:
            return IntelResult(provider=self.name, indicator=indicator, verdict="skipped")

        endpoint = f"https://urlscan.io/api/v1/search/?q={urllib.parse.quote(q_str)}&size=5"
        headers: dict[str, str] = {"Accept": "application/json"}
        if cfg.URLSCAN_API_KEY:
            headers["API-Key"] = cfg.URLSCAN_API_KEY.get_secret_value()

        t0 = time.perf_counter()
        try:
            resp = await execute_intel_request(
                method="GET",
                url=endpoint,
                provider_name=self.name,
                headers=headers,
            )

            if resp.status_code == 404:
                return IntelResult(
                    provider=self.name,
                    indicator=indicator,
                    verdict="clean",
                    duration_ms=int((time.perf_counter() - t0) * 1000),
                )

            if resp.status_code != 200:
                return IntelResult(
                    provider=self.name,
                    indicator=indicator,
                    verdict="error",
                    duration_ms=int((time.perf_counter() - t0) * 1000),
                )

            data = resp.json()
            results = data.get("results", [])
            elapsed_ms = int((time.perf_counter() - t0) * 1000)

            if not results:
                return IntelResult(
                    provider=self.name,
                    indicator=indicator,
                    verdict="clean",
                    duration_ms=elapsed_ms,
                )

            # Analyze verdicts across recent scans
            is_malicious = False
            max_score = 0
            threat_tags: list[str] = []

            for r in results:
                v = r.get("verdicts", {}).get("overall", {})
                if v.get("malicious", False):
                    is_malicious = True
                score = int(v.get("score", 0))
                if score > max_score:
                    max_score = score
                for cat in v.get("categories", []):
                    if cat not in threat_tags:
                        threat_tags.append(str(cat))

            # Classification per Amendment 4: domain hits cap at INTEL_SUSPICIOUS
            verdict: IntelVerdict
            if is_malicious or max_score >= 100:
                verdict = "malicious" if indicator.type in ("url", "sha256") else "suspicious"
            elif max_score > 0:
                verdict = "suspicious"
            else:
                verdict = "clean"

            # Controlled summary metadata ONLY - never copy raw untrusted page text (Amendment 5)
            summary_raw: dict[str, Any] = {
                "results_count": len(results),
                "is_malicious": is_malicious,
                "max_score": max_score,
            }

            return IntelResult(
                provider=self.name,
                indicator=indicator,
                verdict=verdict,
                score=float(max_score),
                threat_types=threat_tags[:5],
                raw=summary_raw,
                duration_ms=elapsed_ms,
            )

        except (httpx.HTTPError, Exception) as exc:
            logger.warning("urlscan_lookup_failed", error=type(exc).__name__)
            return IntelResult(
                provider=self.name,
                indicator=indicator,
                verdict="error",
                duration_ms=int((time.perf_counter() - t0) * 1000),
            )
