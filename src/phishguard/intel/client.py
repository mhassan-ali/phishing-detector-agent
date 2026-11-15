"""HTTP client factory, security boundaries, rate limiting, and retry handling for intel APIs."""

import asyncio
import secrets
import time
import urllib.parse
from typing import Any

import httpx
import structlog

from phishguard.core.errors import HostNotAllowedError

logger = structlog.get_logger(__name__)

# Fixed host allowlist per AGENTS.md section 2 and Amendment 7
ALLOWED_INTEL_HOSTS: frozenset[str] = frozenset(
    {
        "www.virustotal.com",
        "urlhaus-api.abuse.ch",
        "openphish.com",
        "safebrowsing.googleapis.com",
        "urlscan.io",
    }
)

# Standard timeouts in seconds
CONNECT_TIMEOUT: float = 3.0
READ_TIMEOUT: float = 5.0
DEFAULT_TOTAL_TIMEOUT: float = 8.0

# Max response payload cap to prevent memory exhaustion
DEFAULT_MAX_RESPONSE_BYTES: int = 1024 * 1024  # 1 MB


def sanitize_url_for_logging(url: str) -> str:
    """Scrub query parameters and secrets from URL before logging.

    Args:
        url: Full URL string.

    Returns:
        Sanitized URL string with sensitive parameters redacted.
    """
    try:
        parsed = urllib.parse.urlsplit(url)
        if not parsed.query:
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        # Scrub all query values
        q_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        sanitized_q = "&".join(
            f"{k}=[REDACTED]"
            if any(term in k.lower() for term in ("key", "token", "auth", "secret"))
            else f"{k}={v[:30]}"
            for k, v in q_pairs
        )
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{sanitized_q}"
    except Exception:
        return "[UNPARSEABLE_URL]"


class TokenBucket:
    """Thread-safe and async-compatible in-memory non-blocking token bucket rate limiter."""

    def __init__(self, capacity: float, refill_rate: float) -> None:
        """Initialize token bucket.

        Args:
            capacity: Maximum burst tokens.
            refill_rate: Tokens added per second.
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = capacity
        self.last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire_nonblocking(self) -> bool:
        """Attempt to consume 1 token without blocking.

        Returns:
            True if a token was available and consumed; False otherwise.
        """
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            self.last_refill = now
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)

            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True
            return False


class CircuitBreaker:
    """Simple circuit breaker to avoid hammering providers during active rate limits or outages."""

    def __init__(self) -> None:
        self.tripped: bool = False
        self.trip_time: float = 0.0
        self.cooldown_seconds: float = 60.0

    def trip(self) -> None:
        """Trip the circuit breaker."""
        self.tripped = True
        self.trip_time = time.monotonic()

    def is_tripped(self) -> bool:
        """Check if circuit breaker is currently open."""
        if not self.tripped:
            return False
        if time.monotonic() - self.trip_time > self.cooldown_seconds:
            self.tripped = False
            return False
        return True


# Global concurrency limiter across all threat intelligence requests
GLOBAL_SEMAPHORE = asyncio.Semaphore(5)

# Per-provider token buckets (configured for free tiers)
# VirusTotal: 4 requests/min -> capacity 4, 4/60 per sec
VT_BUCKET = TokenBucket(capacity=4.0, refill_rate=4.0 / 60.0)
# URLhaus: ~1 request/sec -> capacity 2, 1 per sec
URLHAUS_BUCKET = TokenBucket(capacity=2.0, refill_rate=1.0)
# urlscan.io: 30 requests/min -> capacity 2, 0.5 per sec
URLSCAN_BUCKET = TokenBucket(capacity=2.0, refill_rate=0.5)
# Google Safe Browsing: high quota (~10,000/day) -> capacity 10, 5 per sec
SAFEBROWSING_BUCKET = TokenBucket(capacity=10.0, refill_rate=5.0)

# Per-provider circuit breakers
PROVIDER_CIRCUITS: dict[str, CircuitBreaker] = {
    "virustotal": CircuitBreaker(),
    "urlhaus": CircuitBreaker(),
    "openphish": CircuitBreaker(),
    "safebrowsing": CircuitBreaker(),
    "urlscan": CircuitBreaker(),
}


def validate_intel_url(url: str) -> None:
    """Validate that the target URL scheme is HTTPS and host is in the allowlist.

    Args:
        url: URL string to inspect.

    Raises:
        HostNotAllowedError: If the scheme is not https or host is not in ALLOWED_INTEL_HOSTS.
    """
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme.lower() != "https":
        raise HostNotAllowedError(f"Threat intelligence queries must use HTTPS: {parsed.scheme}")

    host = parsed.netloc.split(":")[0].lower()
    if host not in ALLOWED_INTEL_HOSTS:
        raise HostNotAllowedError(f"Host '{host}' is not in the allowed threat intel hosts list.")


async def execute_intel_request(
    method: str,
    url: str,
    *,
    provider_name: str,
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    json_data: Any = None,
    data: Any = None,
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
) -> httpx.Response:
    """Execute an outbound HTTP request to an allowed threat intelligence provider.

    Enforces host allowlist, strict security settings (no redirects, no trust_env, verify TLS),
    response byte limits, backoff on 5xx/timeouts, and circuit breaker trip on 429 exhaustion.

    Args:
        method: HTTP method (GET, POST).
        url: Destination HTTPS URL.
        provider_name: Identifier for rate limiting and circuit breaking.
        headers: Request headers.
        params: Query parameters.
        json_data: JSON payload.
        data: Form or raw data.
        max_response_bytes: Maximum allowed bytes in response.

    Returns:
        httpx.Response on success.

    Raises:
        HostNotAllowedError: If URL fails validation.
        httpx.HTTPError: If request fails after retries.
    """
    validate_intel_url(url)

    circuit = PROVIDER_CIRCUITS.get(provider_name)
    if circuit and circuit.is_tripped():
        raise httpx.HTTPStatusError(
            "Circuit breaker open for provider",
            request=httpx.Request(method, url),
            response=httpx.Response(429),
        )

    timeout = httpx.Timeout(
        timeout=DEFAULT_TOTAL_TIMEOUT,
        connect=CONNECT_TIMEOUT,
        read=READ_TIMEOUT,
    )

    async with (
        GLOBAL_SEMAPHORE,
        httpx.AsyncClient(
            follow_redirects=False,
            trust_env=False,
            verify=True,
            timeout=timeout,
        ) as client,
    ):
        max_retries = 2
        for attempt in range(max_retries + 1):
            try:
                response = await client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    params=params,
                    json=json_data,
                    data=data,
                )

                # Check for rate limit
                if response.status_code == 429:
                    retry_after_str = response.headers.get("Retry-After", "")
                    retry_after = 1.0
                    if retry_after_str.isdigit():
                        retry_after = min(float(retry_after_str), 2.0)

                    if attempt < max_retries and retry_after <= 2.0:
                        await asyncio.sleep(retry_after)
                        continue

                    # Rate limit exhausted -> trip circuit breaker
                    if circuit:
                        circuit.trip()
                    logger.warning(
                        "intel_rate_limited",
                        provider=provider_name,
                        status=429,
                    )
                    return response

                # Retry on 5xx server errors with exponential backoff + jitter
                if response.status_code >= 500 and attempt < max_retries:
                    delay = (2**attempt) * 0.5 + secrets.SystemRandom().uniform(0.1, 0.3)
                    await asyncio.sleep(delay)
                    continue

                # Check response size cap
                content_length = response.headers.get("Content-Length")
                if content_length and int(content_length) > max_response_bytes:
                    raise httpx.RequestError(
                        f"Response size exceeded limit: {content_length} bytes",
                        request=response.request,
                    )

                # Enforce byte cap on body
                if len(response.content) > max_response_bytes:
                    raise httpx.RequestError(
                        f"Response content length {len(response.content)} exceeds limit",
                        request=response.request,
                    )

                return response

            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                if attempt < max_retries:
                    delay = (2**attempt) * 0.5 + secrets.SystemRandom().uniform(0.1, 0.3)
                    await asyncio.sleep(delay)
                    continue
                sanitized_url = sanitize_url_for_logging(url)
                logger.warning(
                    "intel_network_error",
                    provider=provider_name,
                    target=sanitized_url,
                    error=type(exc).__name__,
                )
                raise

        raise httpx.RequestError(
            f"Intel request to {sanitize_url_for_logging(url)} failed after retries"
        )
