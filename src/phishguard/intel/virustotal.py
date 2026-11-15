"""VirusTotal API v3 intelligence provider."""

import base64
import time
from typing import Any

import httpx
import structlog

from phishguard.core.config import get_settings
from phishguard.intel.base import Indicator, IntelProvider, IntelResult, IntelVerdict
from phishguard.intel.client import VT_BUCKET, execute_intel_request
from phishguard.intel.constants import (
    VT_HOST_SUSPICIOUS_THRESHOLD,
    VT_MALICIOUS_THRESHOLD,
    VT_MAX_LOOKUPS_PER_SCAN,
)

logger = structlog.get_logger(__name__)


class VirusTotalProvider(IntelProvider):
    """Reputation provider for files, URLs, domains, and IPs via VirusTotal API v3.

    Verified official documentation: https://docs.virustotal.com/reference/overview (Nov 2026).
    Free tier allows 4 requests/minute, 500/day for non-commercial evaluation.
    """

    name = "virustotal"

    def __init__(self) -> None:
        self._lookups_this_scan = 0

    def reset_scan_budget(self) -> None:
        """Reset per-scan lookup counter."""
        self._lookups_this_scan = 0

    async def lookup(self, indicator: Indicator) -> IntelResult:
        """Query VirusTotal v3 for reputation of given indicator.

        Never submits scans or makes POST requests (Amendment 8).
        Respects non-blocking token bucket and per-scan lookup cap (Amendment 3).

        Args:
            indicator: Indicator to query.

        Returns:
            Standardized IntelResult.
        """
        cfg = get_settings()
        if not cfg.VIRUSTOTAL_ENABLED or not cfg.VIRUSTOTAL_API_KEY:
            return IntelResult(provider=self.name, indicator=indicator, verdict="skipped")

        # Per-scan cap check (Amendment 3)
        if self._lookups_this_scan >= VT_MAX_LOOKUPS_PER_SCAN:
            logger.info("virustotal_scan_cap_reached", cap=VT_MAX_LOOKUPS_PER_SCAN)
            return IntelResult(provider=self.name, indicator=indicator, verdict="skipped")

        # Non-blocking token bucket check (Amendment 3)
        acquired = await VT_BUCKET.acquire_nonblocking()
        if not acquired:
            logger.warning("virustotal_token_bucket_exhausted")
            return IntelResult(provider=self.name, indicator=indicator, verdict="skipped")

        self._lookups_this_scan += 1

        # Determine endpoint path
        if indicator.type == "sha256":
            path = f"files/{indicator.value.lower()}"
        elif indicator.type == "url":
            b64_url = base64.urlsafe_b64encode(indicator.value.encode("utf-8")).decode().rstrip("=")
            path = f"urls/{b64_url}"
        elif indicator.type == "domain":
            path = f"domains/{indicator.value.lower()}"
        elif indicator.type == "ip":
            path = f"ip_addresses/{indicator.value}"
        else:
            return IntelResult(provider=self.name, indicator=indicator, verdict="skipped")

        url = f"https://www.virustotal.com/api/v3/{path}"
        headers = {
            "x-apikey": cfg.VIRUSTOTAL_API_KEY.get_secret_value(),
            "Accept": "application/json",
        }

        t0 = time.perf_counter()
        try:
            # Strictly GET - never POST (Amendment 8)
            resp = await execute_intel_request(
                method="GET",
                url=url,
                provider_name=self.name,
                headers=headers,
            )

            # 404 indicates not found / unknown (Amendment 8)
            if resp.status_code == 404:
                return IntelResult(
                    provider=self.name,
                    indicator=indicator,
                    verdict="unknown",
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
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            malicious_count = int(stats.get("malicious", 0))
            suspicious_count = int(stats.get("suspicious", 0))

            # Threat classification based on indicator type (Amendment 4)
            verdict: IntelVerdict
            if indicator.type == "sha256":
                # File-hash matches >= 5 -> INTEL_CONFIRMED_MALICIOUS
                if malicious_count >= VT_MALICIOUS_THRESHOLD:
                    verdict = "malicious"
                elif malicious_count >= 1 or suspicious_count >= 2:
                    verdict = "suspicious"
                else:
                    verdict = "clean"
            elif indicator.type in ("domain", "ip"):
                # Domain/host-level hits cap at INTEL_SUSPICIOUS (Amendment 4)
                if malicious_count >= VT_HOST_SUSPICIOUS_THRESHOLD or suspicious_count >= 3:
                    verdict = "suspicious"
                else:
                    verdict = "clean"
            else:  # url
                if malicious_count >= VT_MALICIOUS_THRESHOLD:
                    verdict = "malicious"
                elif malicious_count >= 1 or suspicious_count >= 2:
                    verdict = "suspicious"
                else:
                    verdict = "clean"

            # Extract threat categories if present
            results_dict = attributes.get("last_analysis_results", {})
            categories: list[str] = []
            for engine_result in results_dict.values():
                cat = engine_result.get("category")
                if cat in ("malicious", "suspicious"):
                    engine_name = engine_result.get("result", "")
                    if engine_name and engine_name not in categories:
                        categories.append(engine_name)

            elapsed_ms = int((time.perf_counter() - t0) * 1000)
            summary_raw: dict[str, Any] = {
                "malicious": malicious_count,
                "suspicious": suspicious_count,
                "harmless": stats.get("harmless", 0),
            }

            return IntelResult(
                provider=self.name,
                indicator=indicator,
                verdict=verdict,
                score=float(malicious_count),
                threat_types=categories[:5],
                raw=summary_raw,
                duration_ms=elapsed_ms,
            )

        except (httpx.HTTPError, Exception) as exc:
            logger.warning("virustotal_lookup_failed", error=type(exc).__name__)
            return IntelResult(
                provider=self.name,
                indicator=indicator,
                verdict="error",
                duration_ms=int((time.perf_counter() - t0) * 1000),
            )
