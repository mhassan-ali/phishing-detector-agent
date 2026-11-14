"""Exception hierarchy for PhishGuard."""


class PhishGuardError(Exception):
    """Base exception for all PhishGuard domain errors."""

    def __init__(self, message: str, *args: object) -> None:
        super().__init__(message, *args)
        self.message = message


class ConfigurationError(PhishGuardError):
    """Raised when application configuration is missing, invalid, or conflicting."""


class ValidationError(PhishGuardError):
    """Raised when an internal domain model or payload fails domain validation."""


class IngestionError(PhishGuardError):
    """Raised when parsing or extracting data from an input payload fails."""


class EmailParseError(IngestionError):
    """Raised when parsing an RFC 5322 / EML email fails."""


class URLExtractionError(IngestionError):
    """Raised when extracting or normalizing URLs fails."""


class AnalyzerError(PhishGuardError):
    """Raised when an analyzer encounters an operational failure."""


class ThreatIntelError(PhishGuardError):
    """Base exception for threat intelligence provider failures."""


class RateLimitExceededError(ThreatIntelError):
    """Raised when an external threat intelligence provider quota or rate limit is hit."""


class ProviderUnavailableError(ThreatIntelError):
    """Raised when a threat intelligence provider is unreachable or returns a server error."""


class LLMError(PhishGuardError):
    """Raised when an LLM provider fails, times out, or returns unparseable content."""


class SecurityError(PhishGuardError):
    """Base exception for security boundary violations."""


class SSRFBlockedError(SecurityError):
    """Raised when a URL targets a forbidden IP (private, loopback, link-local, metadata)."""


class PromptInjectionDetectedError(SecurityError):
    """Raised when prompt injection patterns or phrases are detected."""

