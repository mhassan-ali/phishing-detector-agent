"""Threat intelligence analyzer orchestrating concurrent provider queries and caching."""

import asyncio
import time

import structlog

from phishguard.analyzers.base import create_evidence
from phishguard.analyzers.codes import EvidenceCode
from phishguard.core.config import get_settings
from phishguard.core.schemas import AnalyzerResult, Evidence, ParsedEmail, Severity
from phishguard.intel.base import Indicator, IntelProvider, IntelResult
from phishguard.intel.cache import IntelCache
from phishguard.intel.constants import (
    DESC_INTEL_CONFIRMED_MALICIOUS,
    DESC_INTEL_NOT_LISTED,
    DESC_INTEL_SUSPICIOUS,
)
from phishguard.intel.openphish import OpenPhishProvider
from phishguard.intel.safebrowsing import GoogleSafeBrowsingProvider
from phishguard.intel.selector import select_indicators
from phishguard.intel.urlhaus import URLhausProvider
from phishguard.intel.urlscan import URLScanProvider
from phishguard.intel.virustotal import VirusTotalProvider

logger = structlog.get_logger(__name__)


class IntelAnalyzer:
    """Analyzer protocol implementation coordinating threat intelligence lookups."""

    name = "intel_analyzer"

    def __init__(
        self,
        providers: list[IntelProvider] | None = None,
        cache: IntelCache | None = None,
    ) -> None:
        """Initialize IntelAnalyzer with optional providers and cache override.

        Args:
            providers: List of configured IntelProvider instances.
            cache: Persistent IntelCache instance.
        """
        self.providers: list[IntelProvider] = (
            providers
            if providers is not None
            else [
                VirusTotalProvider(),
                URLhausProvider(),
                OpenPhishProvider(),
                GoogleSafeBrowsingProvider(),
                URLScanProvider(),
            ]
        )
        self.cache = cache or IntelCache()

    async def _query_provider_with_cache(
        self,
        provider: IntelProvider,
        indicator: Indicator,
    ) -> IntelResult:
        """Query persistent cache before invoking provider lookup.

        Args:
            provider: Provider instance.
            indicator: Indicator to evaluate.

        Returns:
            IntelResult from cache or live provider query.
        """
        cached = await self.cache.get(provider.name, indicator)
        if cached is not None:
            return cached

        result = await provider.lookup(indicator)
        if result.verdict not in ("skipped", "error"):
            await self.cache.set(result, indicator.value)
        return result

    async def run(self, parsed: ParsedEmail) -> AnalyzerResult:
        """Execute threat intelligence queries across all prioritized indicators.

        Args:
            parsed: Ingested ParsedEmail instance.

        Returns:
            AnalyzerResult model containing threat intelligence evidence.
        """
        cfg = get_settings()
        t0 = time.perf_counter()

        # Pure selection of prioritized indicators (Amendment 2)
        indicators = select_indicators(
            parsed,
            max_indicators=cfg.PHISHGUARD_INTEL_MAX_INDICATORS,
            send_full_urls=cfg.PHISHGUARD_INTEL_SEND_FULL_URLS,
        )

        if not indicators:
            return AnalyzerResult(
                analyzer=self.name,
                status="skipped",
                evidence=[],
                duration_ms=0,
            )

        # Reset per-scan provider budgets (Amendment 3)
        for p in self.providers:
            if hasattr(p, "reset_scan_budget"):
                p.reset_scan_budget()

        # Build query tasks
        tasks = [
            self._query_provider_with_cache(provider, indicator)
            for indicator in indicators
            for provider in self.providers
        ]

        results: list[IntelResult] = []
        status: str = "ok"

        # Apply overall deadline (Amendment 3)
        deadline = cfg.PHISHGUARD_INTEL_DEADLINE_SECONDS
        try:
            completed_results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=deadline,
            )
            for res_or_exc in completed_results:
                if isinstance(res_or_exc, IntelResult):
                    results.append(res_or_exc)
                else:
                    status = "partial"
                    logger.warning("intel_task_failed", error=str(res_or_exc))

        except TimeoutError:
            logger.warning("intel_overall_deadline_exceeded", deadline=deadline)
            status = "partial"

        # Check provider statuses
        skipped_count = sum(1 for r in results if r.verdict == "skipped")
        error_count = sum(1 for r in results if r.verdict == "error")
        valid_results = [r for r in results if r.verdict not in ("skipped", "error")]

        if not valid_results and skipped_count > 0:
            status = "skipped"
        elif (error_count > 0 or skipped_count > 0) and status != "skipped":
            status = "partial"

        # Synthesize evidence
        evidence: list[Evidence] = []
        has_malicious = False
        has_suspicious = False
        has_clean = False

        for r in valid_results:
            if r.verdict == "malicious":
                has_malicious = True
                evidence.append(
                    create_evidence(
                        source=self.name,
                        code=EvidenceCode.INTEL_CONFIRMED_MALICIOUS,
                        severity=Severity.CRITICAL,
                        description=DESC_INTEL_CONFIRMED_MALICIOUS,
                        confidence=1.0,
                        raw_data={
                            "provider": r.provider,
                            "indicator_type": r.indicator.type,
                            "threat_types": r.threat_types[:3],
                            "score": r.score or 1.0,
                        },
                    )
                )
            elif r.verdict == "suspicious":
                has_suspicious = True
                evidence.append(
                    create_evidence(
                        source=self.name,
                        code=EvidenceCode.INTEL_SUSPICIOUS,
                        severity=Severity.MEDIUM,
                        description=DESC_INTEL_SUSPICIOUS,
                        confidence=0.75,
                        raw_data={
                            "provider": r.provider,
                            "indicator_type": r.indicator.type,
                            "threat_types": r.threat_types[:3],
                            "score": r.score or 0.5,
                        },
                    )
                )
            elif r.verdict == "clean":
                has_clean = True

        # Emit INTEL_NOT_LISTED at most once per scan if clean and no hits (Amendment 11)
        if not has_malicious and not has_suspicious and has_clean:
            evidence.append(
                create_evidence(
                    source=self.name,
                    code=EvidenceCode.INTEL_NOT_LISTED,
                    severity=Severity.INFO,
                    description=DESC_INTEL_NOT_LISTED,
                    confidence=0.5,
                    raw_data={"queried_indicators_count": len(indicators)},
                )
            )

        elapsed_ms = int((time.perf_counter() - t0) * 1000)
        return AnalyzerResult(
            analyzer=self.name,
            status=status,  # type: ignore[arg-type]
            evidence=evidence,
            duration_ms=elapsed_ms,
        )
