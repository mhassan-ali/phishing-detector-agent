"""Unit tests for configuration loading, overrides, and security enforcement."""

import pytest
from pydantic import ValidationError

from phishguard.core.config import Settings, get_settings
from phishguard.core.errors import ConfigurationError


def test_default_settings() -> None:
    """Verify standard default configuration values."""
    settings = Settings(_env_file=None)
    assert settings.PHISHGUARD_ENV == "dev"
    assert settings.PHISHGUARD_API_KEY is None
    assert settings.PHISHGUARD_DB_URL == "sqlite:///data/phishguard.db"
    assert settings.PHISHGUARD_STORE_RAW is False
    assert settings.PHISHGUARD_REDACT_PII is True
    assert settings.PHISHGUARD_MAX_UPLOAD_MB == 10
    assert settings.PHISHGUARD_RATE_LIMIT == "30/minute"
    assert settings.LLM_MODEL == "gemini/gemini-2.5-flash"
    assert settings.GEMINI_API_KEY is None
    assert settings.VIRUSTOTAL_API_KEY is None
    assert settings.URLSCAN_API_KEY is None
    assert settings.GOOGLE_SAFE_BROWSING_KEY is None
    assert settings.INTEL_CACHE_TTL_HOURS == 24
    assert settings.LOG_LEVEL == "INFO"


def test_env_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify environment variables correctly override defaults."""
    monkeypatch.setenv("PHISHGUARD_ENV", "test")
    monkeypatch.setenv("PHISHGUARD_API_KEY", "super-secret-key")
    monkeypatch.setenv("PHISHGUARD_DB_URL", "sqlite:///test.db")
    monkeypatch.setenv("PHISHGUARD_STORE_RAW", "true")
    monkeypatch.setenv("PHISHGUARD_REDACT_PII", "false")
    monkeypatch.setenv("PHISHGUARD_MAX_UPLOAD_MB", "25")
    monkeypatch.setenv("PHISHGUARD_RATE_LIMIT", "60/minute")
    monkeypatch.setenv("LLM_MODEL", "gemini/gemini-pro")
    monkeypatch.setenv("GEMINI_API_KEY", "gemini-secret")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-secret")
    monkeypatch.setenv("URLSCAN_API_KEY", "urlscan-secret")
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_KEY", "gsb-secret")
    monkeypatch.setenv("INTEL_CACHE_TTL_HOURS", "48")
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")

    settings = Settings(_env_file=None)
    assert settings.PHISHGUARD_ENV == "test"
    assert settings.PHISHGUARD_API_KEY is not None
    assert settings.PHISHGUARD_API_KEY.get_secret_value() == "super-secret-key"
    assert settings.PHISHGUARD_DB_URL == "sqlite:///test.db"
    assert settings.PHISHGUARD_STORE_RAW is True
    assert settings.PHISHGUARD_REDACT_PII is False
    assert settings.PHISHGUARD_MAX_UPLOAD_MB == 25
    assert settings.PHISHGUARD_RATE_LIMIT == "60/minute"
    assert settings.LLM_MODEL == "gemini/gemini-pro"
    assert settings.GEMINI_API_KEY is not None
    assert settings.GEMINI_API_KEY.get_secret_value() == "gemini-secret"
    assert settings.VIRUSTOTAL_API_KEY is not None
    assert settings.VIRUSTOTAL_API_KEY.get_secret_value() == "vt-secret"
    assert settings.URLSCAN_API_KEY is not None
    assert settings.URLSCAN_API_KEY.get_secret_value() == "urlscan-secret"
    assert settings.GOOGLE_SAFE_BROWSING_KEY is not None
    assert settings.GOOGLE_SAFE_BROWSING_KEY.get_secret_value() == "gsb-secret"
    assert settings.INTEL_CACHE_TTL_HOURS == 48
    assert settings.LOG_LEVEL == "DEBUG"


def test_secret_str_masking() -> None:
    """Verify secrets are masked in str and repr representations."""
    settings = Settings(
        _env_file=None,
        PHISHGUARD_API_KEY="secret-token-12345",  # type: ignore[arg-type]
    )
    assert settings.PHISHGUARD_API_KEY is not None
    assert "secret-token-12345" not in str(settings.PHISHGUARD_API_KEY)
    assert "secret-token-12345" not in repr(settings.PHISHGUARD_API_KEY)
    assert settings.PHISHGUARD_API_KEY.get_secret_value() == "secret-token-12345"


def test_production_api_key_required_and_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify production mode rejects missing or default placeholder API keys."""
    monkeypatch.setenv("PHISHGUARD_ENV", "prod")

    # Missing API key
    with pytest.raises(ConfigurationError, match="PHISHGUARD_API_KEY must be configured"):
        Settings(_env_file=None)

    # Placeholder API key
    monkeypatch.setenv("PHISHGUARD_API_KEY", "change-me")
    with pytest.raises(ConfigurationError, match="PHISHGUARD_API_KEY must be configured"):
        Settings(_env_file=None)

    # Empty API key
    monkeypatch.setenv("PHISHGUARD_API_KEY", "")
    with pytest.raises(ConfigurationError, match="PHISHGUARD_API_KEY must be configured"):
        Settings(_env_file=None)

    # Valid strong API key in prod passes
    monkeypatch.setenv("PHISHGUARD_API_KEY", "strong-production-key-999")
    settings = Settings(_env_file=None)
    assert settings.PHISHGUARD_ENV == "prod"
    assert settings.PHISHGUARD_API_KEY is not None
    assert settings.PHISHGUARD_API_KEY.get_secret_value() == "strong-production-key-999"


def test_invalid_upload_mb_rejected() -> None:
    """Verify boundary constraint on upload size."""
    with pytest.raises(ValidationError):
        Settings(_env_file=None, PHISHGUARD_MAX_UPLOAD_MB=0)


def test_invalid_intel_ttl_rejected() -> None:
    """Verify boundary constraint on intel cache TTL."""
    with pytest.raises(ValidationError):
        Settings(_env_file=None, INTEL_CACHE_TTL_HOURS=0)


def test_phase3_config_fields() -> None:
    """Verify Phase 3 configuration fields and trusted authserv IDs parsing."""
    settings = Settings(
        _env_file=None,
        PHISHGUARD_LLM_ENABLED=True,
        PHISHGUARD_TRUSTED_AUTHSERV_IDS="mx.google.com, gateway.corp.local , MX.OUTLOOK.COM",
        PHISHGUARD_DOMAIN_AGE_ENABLED=True,
    )
    assert settings.PHISHGUARD_LLM_ENABLED is True
    assert settings.PHISHGUARD_DOMAIN_AGE_ENABLED is True
    assert settings.trusted_authserv_ids_list == [
        "mx.google.com",
        "gateway.corp.local",
        "mx.outlook.com",
    ]


def test_get_settings_cached() -> None:
    """Verify get_settings returns a singleton Settings instance."""
    get_settings.cache_clear()
    s1 = get_settings()
    s2 = get_settings()
    assert s1 is s2
