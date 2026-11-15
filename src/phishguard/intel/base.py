"""Core schemas and protocol for threat intelligence providers."""

import hashlib
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

IntelVerdict = Literal["malicious", "suspicious", "clean", "unknown", "error", "skipped"]


class Indicator(BaseModel):
    """An observable indicator extracted from an ingested message."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    type: Literal["url", "domain", "ip", "sha256"]
    value: str
    is_flagged: bool = False


class IntelResult(BaseModel):
    """Standardized outcome of an indicator query against a threat intelligence provider."""

    model_config = ConfigDict(extra="forbid")

    provider: str
    indicator: Indicator
    verdict: IntelVerdict
    score: float | None = None
    threat_types: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)
    duration_ms: int = 0


class IntelProvider(Protocol):
    """Protocol implemented by all threat intelligence provider clients."""

    name: str

    async def lookup(self, indicator: Indicator) -> IntelResult:
        """Query the provider for reputation or intelligence regarding an indicator.

        Args:
            indicator: The Indicator model to evaluate.

        Returns:
            Standardized IntelResult model.
        """
        ...


def compute_indicator_hash(indicator: Indicator) -> str:
    """Compute deterministic SHA-256 hash for indicator type and canonical value.

    Args:
        indicator: Indicator instance.

    Returns:
        Hex-encoded SHA-256 digest string.
    """
    canonical = f"{indicator.type}:{indicator.value.strip().lower()}".encode()
    return hashlib.sha256(canonical).hexdigest()
