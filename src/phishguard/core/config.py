"""Configuration settings loaded from environment and .env files."""

from functools import lru_cache
from typing import Literal, Self

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from phishguard.core.errors import ConfigurationError


class Settings(BaseSettings):
    """Central configuration for PhishGuard."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # Core environment and API security
    PHISHGUARD_ENV: Literal["dev", "prod", "test"] = Field(
        default="dev",
        description="Deployment environment mode: dev, prod, or test.",
    )
    PHISHGUARD_API_KEY: SecretStr | None = Field(
        default=None,
        description="Secret API key required to access authenticated API endpoints in prod.",
    )
    PHISHGUARD_DB_URL: str = Field(
        default="sqlite:///data/phishguard.db",
        description="Database connection URL for verdicts and intelligence caching.",
    )
    PHISHGUARD_STORE_RAW: bool = Field(
        default=False,
        description="Whether to persistently store raw email messages and URLs (opt-in).",
    )
    PHISHGUARD_REDACT_PII: bool = Field(
        default=True,
        description="Whether to mask sensitive PII before sending context to LLMs.",
    )
    PHISHGUARD_MAX_UPLOAD_MB: int = Field(
        default=10,
        ge=1,
        description="Maximum permitted payload upload size in megabytes.",
    )
    PHISHGUARD_RATE_LIMIT: str = Field(
        default="30/minute",
        description="Default client rate limit per API key (e.g. '30/minute').",
    )
    PHISHGUARD_TRUSTED_AUTHSERV_IDS: str = Field(
        default="",
        description="Comma-separated trusted Authentication-Results authserv-id hostnames.",
    )
    PHISHGUARD_DOMAIN_AGE_ENABLED: bool = Field(
        default=False,
        description="Whether live or stub domain age lookup checks are enabled.",
    )

    # LLM configuration
    PHISHGUARD_LLM_ENABLED: bool = Field(
        default=False,
        description="Whether LLM semantic analysis is enabled.",
    )
    LLM_MODEL: str = Field(
        default="gemini/gemini-2.5-flash",
        description="LiteLLM provider and model identifier.",
    )
    GEMINI_API_KEY: SecretStr | None = Field(
        default=None,
        description="API key for Google Gemini / Vertex LLM access.",
    )

    # Threat intelligence provider keys and limits
    PHISHGUARD_INTEL_DEADLINE_SECONDS: float = Field(
        default=8.0,
        ge=0.01,
        description="Overall timeout deadline in seconds for threat intelligence queries.",
    )
    PHISHGUARD_INTEL_MAX_INDICATORS: int = Field(
        default=5,
        ge=1,
        description="Maximum total indicators queried per scan.",
    )
    PHISHGUARD_INTEL_SEND_FULL_URLS: bool = Field(
        default=False,
        description="Whether to send full URLs including queries and fragments to external intel.",
    )
    VIRUSTOTAL_ENABLED: bool = Field(
        default=True,
        description="Whether VirusTotal provider lookups are enabled.",
    )
    URLHAUS_ENABLED: bool = Field(
        default=True,
        description="Whether URLhaus provider lookups are enabled.",
    )
    OPENPHISH_ENABLED: bool = Field(
        default=True,
        description="Whether OpenPhish community feed lookups are enabled.",
    )
    SAFEBROWSING_ENABLED: bool = Field(
        default=True,
        description="Whether Google Safe Browsing lookups are enabled.",
    )
    URLSCAN_ENABLED: bool = Field(
        default=True,
        description="Whether urlscan.io search lookups are enabled.",
    )
    VIRUSTOTAL_API_KEY: SecretStr | None = Field(
        default=None,
        description="API key for VirusTotal reputation lookups.",
    )
    URLHAUS_AUTH_KEY: SecretStr | None = Field(
        default=None,
        description="Auth key for abuse.ch URLhaus API lookups.",
    )
    URLSCAN_API_KEY: SecretStr | None = Field(
        default=None,
        description="API key for urlscan.io intelligence search lookups.",
    )
    GOOGLE_SAFE_BROWSING_KEY: SecretStr | None = Field(
        default=None,
        description="API key for Google Safe Browsing API lookups.",
    )
    OPENPHISH_MAX_FEED_BYTES: int = Field(
        default=2 * 1024 * 1024,
        ge=1024,
        description="Maximum byte size cap when downloading the OpenPhish feed.",
    )
    INTEL_CACHE_TTL_HOURS: int = Field(
        default=24,
        ge=1,
        description="TTL duration in hours for caching threat intelligence results.",
    )

    # Observability
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO",
        description="Minimum logging level.",
    )

    @property
    def trusted_authserv_ids_list(self) -> list[str]:
        """Parsed list of trusted authserv-id hostnames."""
        return [
            s.strip().lower() for s in self.PHISHGUARD_TRUSTED_AUTHSERV_IDS.split(",") if s.strip()
        ]

    @model_validator(mode="after")
    def validate_production_security(self) -> Self:
        """Enforce production security rules such as mandatory API keys.

        Raises:
            ConfigurationError: If running in production with insecure defaults.
        """
        if self.PHISHGUARD_ENV == "prod" and (
            not self.PHISHGUARD_API_KEY
            or self.PHISHGUARD_API_KEY.get_secret_value() in ("", "change-me")
        ):
            raise ConfigurationError(
                "PHISHGUARD_API_KEY must be configured with a non-default secret in production."
            )
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Retrieve cached application settings instance.

    Returns:
        Singleton Settings object loaded from environment and .env file.
    """
    return Settings()
