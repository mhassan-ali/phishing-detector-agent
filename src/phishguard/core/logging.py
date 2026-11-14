"""Structured logging with JSON output, scan_id context binding, and privacy filtering."""

import logging
import sys
from collections.abc import Mapping, MutableMapping
from typing import Any, cast

import structlog
from pydantic import SecretStr
from structlog.types import Processor

REDACTED_PLACEHOLDER = "[REDACTED]"

SENSITIVE_EXACT_KEYS: frozenset[str] = frozenset(
    {
        "body",
        "email_body",
        "content",
        "raw_content",
        "body_plain",
        "body_html",
        "password",
        "secret",
        "token",
        "api_key",
        "authorization",
    }
)

SENSITIVE_SUFFIXES: tuple[str, ...] = (
    "_key",
    "_token",
    "_secret",
    "_password",
    "_auth",
)


def is_sensitive_key(key: str) -> bool:
    """Determine whether a dictionary key represents sensitive content or credentials.

    Args:
        key: The dictionary key name to inspect.

    Returns:
        True if the key matches exact sensitive terms or designated sensitive suffixes.
    """
    lowered = key.lower()
    if lowered in SENSITIVE_EXACT_KEYS:
        return True
    return any(lowered.endswith(suffix) for suffix in SENSITIVE_SUFFIXES)


def sanitize_value(value: Any) -> Any:
    """Recursively sanitize an object by replacing secrets and sensitive items.

    Args:
        value: Any data value (scalar, collection, SecretStr, or dictionary).

    Returns:
        The sanitized object with secrets and sensitive fields masked.
    """
    if isinstance(value, SecretStr):
        return REDACTED_PLACEHOLDER

    # Handle arbitrary objects exposing get_secret_value
    if hasattr(value, "get_secret_value") and callable(value.get_secret_value):
        return REDACTED_PLACEHOLDER

    if isinstance(value, Mapping):
        return {
            k: (REDACTED_PLACEHOLDER if is_sensitive_key(str(k)) else sanitize_value(v))
            for k, v in value.items()
        }

    if isinstance(value, list):
        return [sanitize_value(item) for item in value]

    if isinstance(value, tuple):
        return tuple(sanitize_value(item) for item in value)

    if isinstance(value, set):
        return {sanitize_value(item) for item in value}

    return value


def redact_sensitive_processor(
    logger: logging.Logger | None,
    method_name: str,
    event_dict: MutableMapping[str, Any],
) -> MutableMapping[str, Any]:
    """Structlog processor that recursively strips bodies and secret credentials from log events.

    Args:
        logger: Structlog logger reference (if wrapped).
        method_name: Logging method name.
        event_dict: Event dictionary being processed.

    Returns:
        Sanitized event dictionary.
    """
    keys = list(event_dict.keys())
    for k in keys:
        if is_sensitive_key(str(k)):
            event_dict[k] = REDACTED_PLACEHOLDER
        else:
            event_dict[k] = sanitize_value(event_dict[k])
    return event_dict


def bind_scan_id(scan_id: str) -> None:
    """Bind a scan_id into the current async context for all subsequent logs.

    Args:
        scan_id: Unique scan identifier.
    """
    structlog.contextvars.bind_contextvars(scan_id=scan_id)


def clear_scan_id() -> None:
    """Clear any bound scan_id from the current async context."""
    structlog.contextvars.unbind_contextvars("scan_id")


def configure_logging(level: str = "INFO", json_output: bool = True) -> None:
    """Configure structlog and standard library logging.

    Args:
        level: Minimum log level string (e.g. DEBUG, INFO).
        json_output: Whether to output JSON lines (default True).
    """
    log_level = getattr(logging, level.upper(), logging.INFO)

    shared_processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        redact_sensitive_processor,
    ]

    renderer: Processor = (
        structlog.processors.JSONRenderer() if json_output else structlog.dev.ConsoleRenderer()
    )

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
        force=True,
    )

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=False,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    for handler in root_logger.handlers:
        handler.setFormatter(formatter)


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Obtain a structured logger bound to a module or component name.

    Args:
        name: Logger name (defaults to caller module name).

    Returns:
        Structured bound logger.
    """
    return cast(structlog.stdlib.BoundLogger, structlog.get_logger(name))
