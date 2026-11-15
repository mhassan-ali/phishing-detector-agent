"""abuse.ch URLhaus intelligence provider."""

import time
from typing import Any

import httpx
import structlog

from phishguard.core.config import get_settings
from phishguard.intel.base import Indicator, IntelProvider, IntelResult, IntelVerdict
from phishguard.intel.client import URLHAUS_BUCKET, execute_intel_request

logger = structlog.get_logger(__name__)


class URLhausProvider(IntelProvider):
    """Intelligence provider for URLs, domains, and payload hashes via abuse.ch URLhaus API.

    Verified official documentation: https://urlhaus-api.abuse.ch/v1/ (Nov 2026).
    Requires free community account Auth-Key.
    """

    name = "urlhaus"

    async def lookup(self, indicator: Indicator) -> IntelResult:
        """Query URLhaus API for malicious status of indicator.

        Args:
            indicator: Indicator model (URL, domain, or SHA-256).

        Returns:
            Standardized IntelResult.
        """
        cfg = get_settings()
        if not cfg.URLHAUS_ENABLED or not cfg.URLHAUS_AUTH_KEY:
            return IntelResult(provider=self.name, indicator=indicator, verdict="skipped")

        acquired = await URLHAUS_BUCKET.acquire_nonblocking()
        if not acquired:
            logger.warning("urlhaus_token_bucket_exhausted")
            return IntelResult(provider=self.name, indicator=indicator, verdict="skipped")

        # Determine endpoint and payload
        headers = {
            "Auth-Key": cfg.URLHAUS_AUTH_KEY.get_secret_value(),
            "Accept": "application/json",
        }

        if indicator.type == "url":
            endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
            form_data = {"url": indicator.value}
        elif indicator.type == "domain":
            endpoint = "https://urlhaus-api.abuse.ch/v1/host/"
            form_data = {"host": indicator.value}
        elif indicator.type == "sha256":
            endpoint = "https://urlhaus-api.abuse.ch/v1/payload/"
            form_data = {"sha256_hash": indicator.value.lower()}
        else:
            return IntelResult(provider=self.name, indicator=indicator, verdict="skipped")

        t0 = time.perf_counter()
        try:
            resp = await execute_intel_request(
                method="POST",
                url=endpoint,
                provider_name=self.name,
                headers=headers,
                data=form_data,
            )

            if resp.status_code != 200:
                return IntelResult(
                    provider=self.name,
                    indicator=indicator,
                    verdict="error",
                    duration_ms=int((time.perf_counter() - t0) * 1000),
                )

            data = resp.json()
            query_status = data.get("query_status", "").lower()

            if query_status == "ok":
                threat = data.get("threat", "malware_download")
                # Domain/host-level hits cap at INTEL_SUSPICIOUS (Amendment 4)
                verdict: IntelVerdict = "suspicious" if indicator.type == "domain" else "malicious"

                threat_types = [str(threat)] if threat else []
                summary_raw: dict[str, Any] = {
                    "query_status": query_status,
                    "threat": threat,
                    "url_status": data.get("url_status", ""),
                }
                return IntelResult(
                    provider=self.name,
                    indicator=indicator,
                    verdict=verdict,
                    score=1.0,
                    threat_types=threat_types,
                    raw=summary_raw,
                    duration_ms=int((time.perf_counter() - t0) * 1000),
                )

            if query_status in ("no_results", "not_found"):
                return IntelResult(
                    provider=self.name,
                    indicator=indicator,
                    verdict="clean",
                    duration_ms=int((time.perf_counter() - t0) * 1000),
                )

            return IntelResult(
                provider=self.name,
                indicator=indicator,
                verdict="error",
                raw={"query_status": query_status},
                duration_ms=int((time.perf_counter() - t0) * 1000),
            )

        except (httpx.HTTPError, Exception) as exc:
            logger.warning("urlhaus_lookup_failed", error=type(exc).__name__)
            return IntelResult(
                provider=self.name,
                indicator=indicator,
                verdict="error",
                duration_ms=int((time.perf_counter() - t0) * 1000),
            )
