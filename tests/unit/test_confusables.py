"""Unit tests for Unicode confusables, script classification, and ASCII skeleton generation."""

from phishguard.analyzers.confusables import (
    get_ascii_skeleton,
    get_char_script,
    is_mixed_script,
)


def test_get_char_script() -> None:
    """Verify script classification for Latin, Cyrillic, Greek, and common characters."""
    assert get_char_script("a") == "LATIN"
    assert get_char_script("1") == "COMMON"
    assert get_char_script(".") == "COMMON"
    assert get_char_script("\u0430") == "CYRILLIC"  # Cyrillic small letter a
    assert get_char_script("\u03b1") == "GREEK"  # Greek small letter alpha
    assert get_char_script("\u00e9") == "LATIN"  # Latin letter with acute
    assert get_char_script("\u0905") == "DEVANAGARI"  # Devanagari letter
    assert get_char_script("\U000e0000") == "UNKNOWN"  # Unassigned / no name


def test_is_mixed_script() -> None:
    """Verify detection of mixed alphabetic scripts."""
    assert not is_mixed_script("paypal")
    assert not is_mixed_script("microsoft")
    # Mix Latin 'p', 'y', 'p', 'l' with Cyrillic 'а' (\u0430)
    assert is_mixed_script("p\u0430yp\u0430l")


def test_get_ascii_skeleton() -> None:
    """Verify ASCII skeleton maps confusables and leetspeak correctly."""
    assert get_ascii_skeleton("p\u0430yp\u0430l") == "paypal"
    assert get_ascii_skeleton("g00gle") == "google"
    assert get_ascii_skeleton("micr0s0ft") == "microsoft"
