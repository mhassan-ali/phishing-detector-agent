"""Unicode confusables mapping, script detection, and ASCII skeleton generation."""

import unicodedata

# Curated confusable mapping from non-Latin and visual lookalikes to ASCII Latin
CONFUSABLES_MAP: dict[str, str] = {
    # Cyrillic lowercase
    "\u0430": "a",  # а
    "\u0441": "c",  # с
    "\u0434": "d",  # д
    "\u0435": "e",  # е
    "\u0451": "e",  # ё
    "\u0456": "i",  # і
    "\u0458": "j",  # ј
    "\u043a": "k",  # к
    "\u043e": "o",  # о
    "\u0440": "p",  # р
    "\u0455": "s",  # ѕ
    "\u0442": "t",  # т
    "\u0443": "y",  # у
    "\u0445": "x",  # х
    "\u0501": "d",  # ԁ
    "\u051b": "q",  # ԛ
    "\u051d": "w",  # ԝ
    # Greek lowercase
    "\u03b1": "a",  # α
    "\u03b2": "b",  # β
    "\u03b3": "y",  # γ
    "\u03b5": "e",  # ε
    "\u03b7": "n",  # η
    "\u03b9": "i",  # ι
    "\u03ba": "k",  # κ
    "\u03bd": "v",  # ν
    "\u03bf": "o",  # ο
    "\u03c1": "p",  # ρ
    "\u03c4": "t",  # τ
    "\u03c5": "u",  # υ
    "\u03c7": "x",  # χ
    # Numeric/symbol leetspeak lookalikes
    "0": "o",
    "1": "l",
    "3": "e",
    "5": "s",
}


def get_char_script(char: str) -> str:
    """Derive the script name for a Unicode character using unicodedata.name prefixes.

    Args:
        char: Single character string.

    Returns:
        Script classification string (e.g. 'LATIN', 'CYRILLIC', 'GREEK', 'COMMON').
    """
    if ord(char) < 128:
        if char.isalpha():
            return "LATIN"
        return "COMMON"

    try:
        name = unicodedata.name(char).upper()
        first_word = name.split()[0]
        if first_word in ("CYRILLIC", "GREEK", "HEBREW", "ARABIC", "ARMENIAN"):
            return first_word
        if "LATIN" in name:
            return "LATIN"
        return first_word
    except ValueError:
        return "UNKNOWN"


def is_mixed_script(label: str) -> bool:
    """Determine whether a domain label mixes multiple alphabetic scripts (e.g. Latin + Cyrillic).

    Args:
        label: Hostname label string.

    Returns:
        True if the label contains characters from two or more distinct alphabetic scripts.
    """
    scripts: set[str] = set()
    for ch in label:
        s = get_char_script(ch)
        if s not in ("COMMON", "UNKNOWN"):
            scripts.add(s)
    return len(scripts) >= 2


def get_ascii_skeleton(label: str) -> str:
    """Compute the normalized ASCII skeleton of a label using the confusables map.

    Args:
        label: Hostname label string.

    Returns:
        Normalized ASCII representation.
    """
    return "".join(CONFUSABLES_MAP.get(ch, ch) for ch in label.lower())
