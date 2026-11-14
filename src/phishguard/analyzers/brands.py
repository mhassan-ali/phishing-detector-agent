"""Reference data loaders for brands, URL shorteners, and suspicious TLDs."""

import importlib.resources
from functools import lru_cache

import yaml
from pydantic import BaseModel, ConfigDict


class Brand(BaseModel):
    """Brand profile for typosquatting and display-name spoofing defense."""

    model_config = ConfigDict(extra="forbid")

    name: str
    domains: list[str]
    keywords: list[str]


@lru_cache(maxsize=1)
def load_brands() -> list[Brand]:
    """Load and validate the reference brand list from package data.

    Returns:
        List of validated Brand models.
    """
    data_pkg = importlib.resources.files("phishguard.data")
    content = (data_pkg / "brands.yaml").read_text(encoding="utf-8")
    parsed = yaml.safe_load(content)
    return [Brand.model_validate(b) for b in parsed.get("brands", [])]


@lru_cache(maxsize=1)
def load_shorteners() -> frozenset[str]:
    """Load known URL shortener domains from package data.

    Returns:
        Frozenset of lowercase shortener domains.
    """
    data_pkg = importlib.resources.files("phishguard.data")
    content = (data_pkg / "shorteners.yaml").read_text(encoding="utf-8")
    parsed = yaml.safe_load(content)
    return frozenset(s.lower().strip() for s in parsed.get("shorteners", []))


@lru_cache(maxsize=1)
def load_suspicious_tlds() -> frozenset[str]:
    """Load suspicious and high-risk TLDs from package data.

    Returns:
        Frozenset of lowercase suspicious TLD names without leading dots.
    """
    data_pkg = importlib.resources.files("phishguard.data")
    content = (data_pkg / "suspicious_tlds.yaml").read_text(encoding="utf-8")
    parsed = yaml.safe_load(content)
    return frozenset(t.lower().strip().lstrip(".") for t in parsed.get("suspicious_tlds", []))
