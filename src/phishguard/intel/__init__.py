"""Threat intelligence subsystem for indicator reputation lookups and caching."""

from phishguard.intel.analyzer import IntelAnalyzer
from phishguard.intel.base import Indicator, IntelProvider, IntelResult

__all__ = [
    "Indicator",
    "IntelAnalyzer",
    "IntelProvider",
    "IntelResult",
]
