"""Shared infrastructure for analyzers: runner, protocols, and Evidence sanitization."""

import asyncio
import inspect
import json
import time
from collections import Counter
from collections.abc import Awaitable
from typing import Any, Protocol

from phishguard.core.schemas import AnalyzerResult, Evidence, ParsedEmail, Severity

MAX_DESCRIPTION_CHARS: int = 500
MAX_RAW_DATA_BYTES: int = 2048
MAX_RAW_STRING_CHARS: int = 200
MAX_EVIDENCE_PER_CODE: int = 5

# Bidirectional override characters that can alter visual display
BIDI_CHARS: frozenset[str] = frozenset(
    {
        "\u202a",
        "\u202b",
        "\u202c",
        "\u202d",
        "\u202e",
        "\u2066",
        "\u2067",
        "\u2068",
        "\u2069",
    }
)


def sanitize_raw_string(s: str) -> str:
    """Sanitize string values in raw_data by stripping control/bidi chars and capping length."""
    cleaned = "".join(c for c in s if ord(c) >= 32 and c not in BIDI_CHARS)
    if len(cleaned) > MAX_RAW_STRING_CHARS:
        return cleaned[: MAX_RAW_STRING_CHARS - 3] + "..."
    return cleaned


def sanitize_raw_data(data: dict[str, Any]) -> dict[str, Any]:
    """Sanitize raw_data dictionary, enforcing individual string and total serialized size caps."""
    sanitized: dict[str, Any] = {}
    for k, v in data.items():
        clean_k = sanitize_raw_string(str(k))
        if isinstance(v, str):
            sanitized[clean_k] = sanitize_raw_string(v)
        elif isinstance(v, (int, float, bool)) or v is None:
            sanitized[clean_k] = v
        elif isinstance(v, (list, tuple)):
            sanitized[clean_k] = [
                sanitize_raw_string(str(item))
                if isinstance(item, str)
                else (item if isinstance(item, (int, float, bool)) else str(item)[:50])
                for item in v[:10]
            ]
        elif isinstance(v, dict):
            sanitized[clean_k] = {
                sanitize_raw_string(str(dk)): sanitize_raw_string(str(dv))
                for dk, dv in list(v.items())[:5]
            }
        else:
            sanitized[clean_k] = sanitize_raw_string(str(v))

    # Ensure total serialized size is under MAX_RAW_DATA_BYTES
    try:
        serialized = json.dumps(sanitized)
        if len(serialized) > MAX_RAW_DATA_BYTES:
            # Deterministically drop keys until under limit
            keys = sorted(sanitized.keys(), reverse=True)
            for key in keys:
                if key in ("domain", "registered_domain", "code"):
                    continue
                sanitized.pop(key, None)
                if len(json.dumps(sanitized)) <= MAX_RAW_DATA_BYTES:
                    break
    except Exception:
        sanitized = {"sanitization_fallback": True}

    return sanitized


def create_evidence(
    source: str,
    code: str,
    severity: Severity,
    description: str,
    confidence: float,
    raw_data: dict[str, Any] | None = None,
) -> Evidence:
    """Construct an Evidence instance with fixed-template descriptions and bounded raw_data.

    Args:
        source: Emitting analyzer identifier.
        code: Stable evidence code string.
        severity: Severity rating.
        description: Template description string (truncated with ellipsis if > 500 chars).
        confidence: Confidence rating between 0.0 and 1.0.
        raw_data: Non-sensitive structured metadata.

    Returns:
        Validated Evidence domain model.
    """
    clean_desc = description.strip()
    if len(clean_desc) > MAX_DESCRIPTION_CHARS:
        clean_desc = clean_desc[: MAX_DESCRIPTION_CHARS - 3] + "..."

    clamped_conf = max(0.0, min(1.0, float(confidence)))
    sanitized_raw = sanitize_raw_data(raw_data or {})

    return Evidence(
        source=source,
        code=code,
        severity=severity,
        description=clean_desc,
        confidence=clamped_conf,
        raw_data=sanitized_raw,
    )


def deduplicate_evidence(
    evidence_list: list[Evidence],
    max_per_code: int = MAX_EVIDENCE_PER_CODE,
) -> list[Evidence]:
    """Deduplicate evidence items by (code, registered_domain) and cap items per code.

    Args:
        evidence_list: Raw list of collected evidence.
        max_per_code: Maximum number of evidence items allowed per unique code.

    Returns:
        Deduplicated, capped list of Evidence items.
    """
    seen_keys: set[tuple[str, str]] = set()
    code_counts: Counter[str] = Counter()
    deduped: list[Evidence] = []

    for item in evidence_list:
        reg_domain = str(
            item.raw_data.get("registered_domain")
            or item.raw_data.get("domain")
            or item.raw_data.get("host")
            or ""
        ).lower()

        dedupe_key = (item.code, reg_domain)
        if dedupe_key in seen_keys:
            continue

        if code_counts[item.code] >= max_per_code:
            continue

        seen_keys.add(dedupe_key)
        code_counts[item.code] += 1
        deduped.append(item)

    return deduped


class Analyzer(Protocol):
    """Protocol implemented by all PhishGuard analyzers."""

    name: str

    def run(self, parsed: ParsedEmail) -> AnalyzerResult | Awaitable[AnalyzerResult]:
        """Execute analysis on a ParsedEmail instance."""
        ...


def run_analyzer(analyzer: Analyzer, parsed: ParsedEmail) -> AnalyzerResult:
    """Safely execute an analyzer, timing execution and trapping all exceptions into status='error'.

    Supports both synchronous and asynchronous analyzer implementations.

    Args:
        analyzer: Analyzer component instance.
        parsed: Ingested ParsedEmail model.

    Returns:
        AnalyzerResult model with trapped errors and execution duration.
    """
    t0 = time.perf_counter()
    try:
        result_or_coro = analyzer.run(parsed)
        if inspect.iscoroutine(result_or_coro):
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None

            if loop and loop.is_running():
                import concurrent.futures

                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    result = pool.submit(asyncio.run, result_or_coro).result()
            else:
                result = asyncio.run(result_or_coro)
        else:
            result = result_or_coro

        elapsed_ms = int((time.perf_counter() - t0) * 1000)
        # Apply evidence deduplication
        deduped = deduplicate_evidence(result.evidence)
        return AnalyzerResult(
            analyzer=analyzer.name,
            status=result.status,
            evidence=deduped,
            duration_ms=elapsed_ms,
            error=result.error,
        )

    except Exception as exc:
        elapsed_ms = int((time.perf_counter() - t0) * 1000)
        return AnalyzerResult(
            analyzer=analyzer.name,
            status="error",
            evidence=[],
            duration_ms=elapsed_ms,
            error=exc.__class__.__name__,
        )
