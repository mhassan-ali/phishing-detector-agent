"""Google Safe Browsing v4 threatMatches:find intelligence provider."""

import time
from typing import Any

import httpx
import structlog

from phishguard.core.config import get_settings
from phishguard.intel.base import Indicator, IntelProvider, IntelResult, IntelVerdict
from phishguard.intel.client import SAFEBROWSING_BUCKET, execute_intel_request

logger = structlog.get_logger(__name__)


class GoogleSafeBrowsingProvider(IntelProvider):
    """Intelligence provider querying Google Safe Browsing v4 Lookup API.

    Verified docs: https://developers.google.com/safe-browsing/v4/lookup-api (Nov 2026).
    Free tier allows up to 10,000 queries/day for non-commercial use.
    """

    name = "safebrowsing"

    async def lookup(self, indicator: Indicator) -> IntelResult:
        """Query Google Safe Browsing v4 for known malware or social engineering threats.

        Args:
            indicator: Indicator model (URL or domain).

        Returns:
            Standardized IntelResult.
        """
        cfg = get_settings()
        if not cfg.SAFEBROWSING_ENABLED or not cfg.GOOGLE_SAFE_BROWSING_KEY:
            return IntelResult(provider=self.name, indicator=indicator, verdict="skipped")

        if indicator.type not in ("url", "domain"):
            return IntelResult(provider=self.name, indicator=indicator, verdict="skipped")

        acquired = await SAFEBROWSING_BUCKET.acquire_nonblocking()
        if not acquired:
            logger.warning("safebrowsing_token_bucket_exhausted")
            return IntelResult(provider=self.name, indicator=indicator, verdict="skipped")

        # Format URL for query
        query_url = (
            indicator.value
            if indicator.type == "url"
            else f"https://{indicator.value.lower().strip()}/"
        )

        api_key = cfg.GOOGLE_SAFE_BROWSING_KEY.get_secret_value()
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"

        payload: dict[str, Any] = {
            "client": {"clientId": "phishguard", "clientVersion": "0.1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": query_url}],
            },
        }

        t0 = time.perf_counter()
        try:
            resp = await execute_intel_request(
                method="POST",
                url=endpoint,
                provider_name=self.name,
                json_data=payload,
            )

            if resp.status_code != 200:
                return IntelResult(
                    provider=self.name,
                    indicator=indicator,
                    verdict="error",
                    duration_ms=int((time.perf_counter() - t0) * 1000),
                )

            data = resp.json()
            matches = data.get("matches", [])
            elapsed_ms = int((time.perf_counter() - t0) * 1000)

            if matches:
                threats = [str(m.get("threatType", "")) for m in matches if m.get("threatType")]
                # Exact URL -> CONFIRMED_MALICIOUS; domain caps at SUSPICIOUS (Amendment 4)
                verdict: IntelVerdict = "malicious" if indicator.type == "url" else "suspicious"
                summary_raw: dict[str, Any] = {
                    "matches_count": len(matches),
                    "first_threat": threats[0] if threats else "threat",
                }
                return IntelResult(
                    provider=self.name,
                    indicator=indicator,
                    verdict=verdict,
                    score=1.0,
                    threat_types=threats[:5],
                    raw=summary_raw,
                    duration_ms=elapsed_ms,
                )

            return IntelResult(
                provider=self.name,
                indicator=indicator,
                verdict="clean",
                duration_ms=elapsed_ms,
            )

        except (httpx.HTTPError, Exception) as exc:
            logger.warning("safebrowsing_lookup_failed", error=type(exc).__name__)
            return IntelResult(
                provider=self.name,
                indicator=indicator,
                verdict="error",
                duration_ms=int((time.perf_counter() - t0) * 1000),
            )
