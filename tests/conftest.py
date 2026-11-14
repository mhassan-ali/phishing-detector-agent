"""Global pytest fixtures and test environment setup."""

import os
from collections.abc import Generator

import pytest

CLEAN_ENV_VARS = [
    "PHISHGUARD_ENV",
    "PHISHGUARD_API_KEY",
    "PHISHGUARD_DB_URL",
    "PHISHGUARD_STORE_RAW",
    "PHISHGUARD_REDACT_PII",
    "PHISHGUARD_MAX_UPLOAD_MB",
    "PHISHGUARD_RATE_LIMIT",
    "LLM_MODEL",
    "GEMINI_API_KEY",
    "VIRUSTOTAL_API_KEY",
    "URLSCAN_API_KEY",
    "GOOGLE_SAFE_BROWSING_KEY",
    "INTEL_CACHE_TTL_HOURS",
    "LOG_LEVEL",
]


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch: pytest.MonkeyPatch) -> Generator[None, None, None]:
    """Ensure no ambient PHISHGUARD_* or API key environment variables leak into tests."""
    for var in list(os.environ.keys()):
        if var.startswith("PHISHGUARD_") or var in CLEAN_ENV_VARS:
            monkeypatch.delenv(var, raising=False)
    yield
