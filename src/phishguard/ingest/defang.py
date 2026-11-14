"""Defanging and refanging routines for indicators of compromise (IOCs)."""


def defang(value: str) -> str:
    """Defang a URL, hostname, IP address, or email for safe display and logging.

    Transformations:
      - 'http://' -> 'hxxp://'
      - 'https://' -> 'hxxps://'
      - '.' -> '[.]'
      - '@' -> '[at]'

    Args:
        value: Raw indicator string.

    Returns:
        Defanged indicator string.
    """
    if not value:
        return value

    defanged = value
    if defanged.lower().startswith("https://"):
        defanged = "hxxps://" + defanged[8:]
    elif defanged.lower().startswith("http://"):
        defanged = "hxxp://" + defanged[7:]

    # Normalize existing defanging if any to prevent nested brackets like [[.]]
    defanged = defanged.replace("[at]", "@")
    defanged = defanged.replace("@", "[at]")

    defanged = defanged.replace("[.]", ".")
    defanged = defanged.replace(".", "[.]")

    return defanged


def refang(value: str) -> str:
    """Reconstruct a defanged indicator back to its standard network form.

    This function must ONLY be called explicitly for trusted backend operations,
    and never by default on untrusted user reports.

    Args:
        value: Defanged indicator string.

    Returns:
        Standard network indicator string.
    """
    if not value:
        return value

    refanged = value
    if refanged.lower().startswith("hxxps://"):
        refanged = "https://" + refanged[8:]
    elif refanged.lower().startswith("hxxp://"):
        refanged = "http://" + refanged[7:]

    refanged = refanged.replace("[at]", "@")
    refanged = refanged.replace("[.]", ".")

    return refanged
