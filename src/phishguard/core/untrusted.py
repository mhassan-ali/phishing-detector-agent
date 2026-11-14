"""Utilities for wrapping and isolating untrusted content before LLM evaluation."""

import secrets

DEFAULT_MAX_UNTRUSTED_CHARS: int = 10_000


def wrap_untrusted_content(
    text: str, max_chars: int = DEFAULT_MAX_UNTRUSTED_CHARS
) -> tuple[str, str]:
    """Wrap untrusted input inside random delimiters, neutralizing escape attempts.

    Ensures untrusted text cannot break out of delimiters by neutralizing literal delimiter markers
    and capping total length.

    Args:
        text: Untrusted raw text (e.g. email body, subject).
        max_chars: Maximum character limit to retain.

    Returns:
        Tuple of (wrapped_content_block, delimiter_token).
    """
    token = secrets.token_hex(16)
    truncated = text[:max_chars]

    # Neutralize any delimiter escape sequences or breakout syntax
    safe_text = (
        truncated.replace("<<<", "< < <")
        .replace(">>>", "> > >")
        .replace(f"UNTRUSTED_CONTENT_{token}", "NEUTRALIZED_TOKEN")
        .replace(f"END_UNTRUSTED_CONTENT_{token}", "NEUTRALIZED_END_TOKEN")
    )

    wrapped = f"<<<UNTRUSTED_CONTENT_{token}>>>\n{safe_text}\n<<<END_UNTRUSTED_CONTENT_{token}>>>"
    return wrapped, token
