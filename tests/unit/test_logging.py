"""Unit tests for structured logging, recursive redaction, and scan_id context binding."""

import io
import json
import logging

from pydantic import SecretStr

from phishguard.core.logging import (
    REDACTED_PLACEHOLDER,
    bind_scan_id,
    clear_scan_id,
    configure_logging,
    get_logger,
    is_sensitive_key,
    redact_sensitive_processor,
    sanitize_value,
)


def test_is_sensitive_key() -> None:
    """Verify exact sensitive keys and sensitive suffixes are detected."""
    # Exact keys
    assert is_sensitive_key("body")
    assert is_sensitive_key("email_body")
    assert is_sensitive_key("content")
    assert is_sensitive_key("raw_content")
    assert is_sensitive_key("body_plain")
    assert is_sensitive_key("body_html")
    assert is_sensitive_key("password")
    assert is_sensitive_key("secret")
    assert is_sensitive_key("token")
    assert is_sensitive_key("api_key")
    assert is_sensitive_key("authorization")

    # Suffixes
    assert is_sensitive_key("gemini_api_key")
    assert is_sensitive_key("VIRUSTOTAL_API_KEY")
    assert is_sensitive_key("access_token")
    assert is_sensitive_key("db_password")
    assert is_sensitive_key("client_secret")
    assert is_sensitive_key("bearer_auth")

    # Non-sensitive keys
    assert not is_sensitive_key("scan_id")
    assert not is_sensitive_key("status")
    assert not is_sensitive_key("event")
    assert not is_sensitive_key("duration_ms")
    assert not is_sensitive_key("confidence")


def test_sanitize_value_recursive_and_secret_str() -> None:
    """Verify recursive sanitization for scalar, SecretStr, nested dicts, and lists."""
    secret = SecretStr("super-secret")
    assert sanitize_value(secret) == REDACTED_PLACEHOLDER

    # Custom object with get_secret_value
    class MockSecret:
        def get_secret_value(self) -> str:
            return "hidden"

    assert sanitize_value(MockSecret()) == REDACTED_PLACEHOLDER

    nested_data = {
        "scan_id": "test-123",
        "user_token": "token-xyz",
        "nested": {
            "body_html": "<p>bad</p>",
            "safe_counter": 42,
            "secret_holder": SecretStr("inside-secret"),
        },
        "list_items": [
            {"password": "secret-pass", "item_name": "alpha"},
            {"safe_val": "ok"},
        ],
        "tuple_items": ({"api_key": "k123"}, "safe_tuple_item"),
        "set_items": {"plain_string"},
    }

    sanitized = sanitize_value(nested_data)
    assert sanitized["scan_id"] == "test-123"
    assert sanitized["user_token"] == REDACTED_PLACEHOLDER
    assert sanitized["nested"]["body_html"] == REDACTED_PLACEHOLDER
    assert sanitized["nested"]["safe_counter"] == 42
    assert sanitized["nested"]["secret_holder"] == REDACTED_PLACEHOLDER
    assert sanitized["list_items"][0]["password"] == REDACTED_PLACEHOLDER
    assert sanitized["list_items"][0]["item_name"] == "alpha"
    assert sanitized["list_items"][1]["safe_val"] == "ok"
    assert sanitized["tuple_items"][0]["api_key"] == REDACTED_PLACEHOLDER
    assert sanitized["tuple_items"][1] == "safe_tuple_item"


def test_redact_sensitive_processor() -> None:
    """Verify redact_sensitive_processor modifies top-level and nested event dict keys."""
    event_dict = {
        "event": "scan_started",
        "body": "Untrusted email raw body",
        "user_secret": "my-secret",
        "meta": {"token": "secret-token", "safe_meta": 100},
        "safe_field": "safe_value",
    }

    processed = redact_sensitive_processor(None, "info", event_dict)
    assert processed["event"] == "scan_started"
    assert processed["body"] == REDACTED_PLACEHOLDER
    assert processed["user_secret"] == REDACTED_PLACEHOLDER
    assert processed["meta"]["token"] == REDACTED_PLACEHOLDER
    assert processed["meta"]["safe_meta"] == 100
    assert processed["safe_field"] == "safe_value"


def test_scan_id_binding_and_json_logging() -> None:
    """Verify bind_scan_id attaches scan_id context and configure_logging emits valid JSON."""
    stream = io.StringIO()

    configure_logging(level="INFO", json_output=True)

    # Attach string stream to root logger handlers to capture output
    root = logging.getLogger()
    for handler in root.handlers:
        if isinstance(handler, logging.StreamHandler):
            handler.stream = stream

    bind_scan_id("scan-abc-456")
    logger = get_logger("test_json")
    logger.info("testing_log_event", body="sensitive email text", safe_field="verified")

    output = stream.getvalue().strip()
    assert output, "Expected log output in stream"

    # Find the JSON line corresponding to our event
    lines = [line for line in output.splitlines() if "testing_log_event" in line]
    assert lines, f"Event not found in log lines: {output}"
    log_json = json.loads(lines[-1])

    assert log_json["event"] == "testing_log_event"
    assert log_json["scan_id"] == "scan-abc-456"
    assert log_json["body"] == REDACTED_PLACEHOLDER
    assert log_json["safe_field"] == "verified"

    # Test clear_scan_id
    clear_scan_id()
    stream.truncate(0)
    stream.seek(0)
    logger.info("subsequent_event")
    lines2 = [line for line in stream.getvalue().splitlines() if "subsequent_event" in line]
    assert lines2
    log_json2 = json.loads(lines2[-1])
    assert "scan_id" not in log_json2
