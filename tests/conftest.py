"""Global pytest fixtures and test environment setup."""

import os
import socket
from collections.abc import Generator
from typing import Any

import pytest

CLEAN_ENV_VARS = [
    "PHISHGUARD_ENV",
    "PHISHGUARD_API_KEY",
    "PHISHGUARD_DB_URL",
    "PHISHGUARD_STORE_RAW",
    "PHISHGUARD_REDACT_PII",
    "PHISHGUARD_MAX_UPLOAD_MB",
    "PHISHGUARD_RATE_LIMIT",
    "PHISHGUARD_LLM_ENABLED",
    "PHISHGUARD_TRUSTED_AUTHSERV_IDS",
    "PHISHGUARD_DOMAIN_AGE_ENABLED",
    "LLM_MODEL",
    "GEMINI_API_KEY",
    "VIRUSTOTAL_API_KEY",
    "URLHAUS_AUTH_KEY",
    "URLSCAN_API_KEY",
    "GOOGLE_SAFE_BROWSING_KEY",
    "VIRUSTOTAL_ENABLED",
    "URLHAUS_ENABLED",
    "OPENPHISH_ENABLED",
    "SAFEBROWSING_ENABLED",
    "URLSCAN_ENABLED",
    "PHISHGUARD_INTEL_DEADLINE_SECONDS",
    "PHISHGUARD_INTEL_MAX_INDICATORS",
    "PHISHGUARD_INTEL_SEND_FULL_URLS",
    "OPENPHISH_MAX_FEED_BYTES",
    "INTEL_CACHE_TTL_HOURS",
    "LOG_LEVEL",
]

LOOPBACK_HOSTS: frozenset[str] = frozenset(
    {
        "127.0.0.1",
        "::1",
        "localhost",
        "0.0.0.0",
    }
)


def _is_loopback(host: Any) -> bool:
    if host is None:
        return True
    if not isinstance(host, str):
        return False
    host_clean = host.strip().lower()
    if host_clean in LOOPBACK_HOSTS:
        return True
    return host_clean.startswith("127.")


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch: pytest.MonkeyPatch) -> Generator[None, None, None]:
    """Ensure no ambient PHISHGUARD_* or API key environment variables leak into tests."""
    for var in list(os.environ.keys()):
        if var.startswith("PHISHGUARD_") or var in CLEAN_ENV_VARS:
            monkeypatch.delenv(var, raising=False)

    # Reset threat intel rate-limiting token buckets for test isolation
    try:
        from phishguard.intel.client import (
            SAFEBROWSING_BUCKET,
            URLHAUS_BUCKET,
            URLSCAN_BUCKET,
            VT_BUCKET,
        )

        VT_BUCKET.tokens = VT_BUCKET.capacity
        URLHAUS_BUCKET.tokens = URLHAUS_BUCKET.capacity
        URLSCAN_BUCKET.tokens = URLSCAN_BUCKET.capacity
        SAFEBROWSING_BUCKET.tokens = SAFEBROWSING_BUCKET.capacity
    except ImportError:
        pass

    yield


@pytest.fixture(autouse=True)
def offline_network_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    """Block external socket connections and DNS lookups, allowing loopback only."""
    orig_connect = socket.socket.connect
    orig_getaddrinfo = socket.getaddrinfo
    orig_gethostbyname = socket.gethostbyname

    def guarded_connect(self: socket.socket, address: Any) -> Any:
        if isinstance(address, tuple) and len(address) >= 1:
            dest_host = address[0]
            if not _is_loopback(dest_host):
                raise RuntimeError(
                    f"External network call forbidden in tests: socket.connect to {dest_host}"
                )
        return orig_connect(self, address)

    def guarded_getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
        if not _is_loopback(host):
            raise RuntimeError(
                f"External DNS resolution forbidden in tests: getaddrinfo for {host}"
            )
        return orig_getaddrinfo(host, *args, **kwargs)

    def guarded_gethostbyname(host: str) -> str:
        if not _is_loopback(host):
            raise RuntimeError(
                f"External DNS resolution forbidden in tests: gethostbyname for {host}"
            )
        return orig_gethostbyname(host)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket, "getaddrinfo", guarded_getaddrinfo)
    monkeypatch.setattr(socket, "gethostbyname", guarded_gethostbyname)
