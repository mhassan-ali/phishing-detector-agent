"""URL normalization, structural parsing, IDNA handling, and tracking parameter stripping."""

import ipaddress
import re
import urllib.parse

import idna
import tldextract

from phishguard.core.schemas import NormalizedURL

# Offline singleton relying solely on the bundled Public Suffix List snapshot
TLD_EXTRACTOR: tldextract.TLDExtract = tldextract.TLDExtract(
    suffix_list_urls=(),
    cache_dir=None,
)

TRACKING_PREFIXES: tuple[str, ...] = ("utm_",)
TRACKING_EXACT: frozenset[str] = frozenset(
    {
        "fbclid",
        "gclid",
        "mc_eid",
        "igshid",
        "msclkid",
        "yclid",
        "_hsenc",
        "_hsmi",
        "mkt_tok",
    }
)

IPV4_DECIMAL_PATTERN = re.compile(r"^\d{4,10}$")


def is_tracking_param(param_name: str) -> bool:
    """Check whether a query parameter is a known analytics or marketing tracking tag.

    Args:
        param_name: Query parameter name string.

    Returns:
        True if the parameter should be stripped.
    """
    lowered = param_name.lower()
    if lowered in TRACKING_EXACT:
        return True
    return any(lowered.startswith(prefix) for prefix in TRACKING_PREFIXES)


def parse_ipv4_obfuscation(host: str) -> tuple[str | None, bool]:
    """Detect and convert obfuscated IPv4 representations to canonical dotted-decimal form.

    Supports:
      - 32-bit decimal integer formats (e.g. 2130706433 -> 127.0.0.1)
      - Hex and octal dotted quad notations (e.g. 0x7f.0.0.1, 0177.0.0.1)

    Args:
        host: Raw hostname or IP candidate string.

    Returns:
        Tuple of (canonical_ip_or_none, is_obfuscated_flag).
    """
    cleaned = host.strip().lower()

    # Case 1: Pure single integer (decimal or hex)
    if IPV4_DECIMAL_PATTERN.match(cleaned):
        try:
            val = int(cleaned, 10)
            if 0 <= val <= 0xFFFFFFFF:
                return str(ipaddress.IPv4Address(val)), True
        except ValueError:
            pass

    if cleaned.startswith("0x") and len(cleaned) <= 10:
        try:
            val = int(cleaned, 16)
            if 0 <= val <= 0xFFFFFFFF:
                return str(ipaddress.IPv4Address(val)), True
        except ValueError:
            pass

    # Case 2: Dotted components (octal, hex, or decimal)
    parts = cleaned.split(".")
    if len(parts) == 4:
        obfuscated = False
        parsed_octets: list[int] = []
        for p in parts:
            if not p:
                return None, False
            try:
                if p.startswith("0x"):
                    obfuscated = True
                    octet = int(p, 16)
                elif p.startswith("0") and len(p) > 1 and p.isdigit():
                    obfuscated = True
                    octet = int(p, 8)
                else:
                    octet = int(p, 10)

                if 0 <= octet <= 255:
                    parsed_octets.append(octet)
                else:
                    return None, False
            except ValueError:
                return None, False

        canonical = ".".join(str(o) for o in parsed_octets)
        return canonical, obfuscated

    return None, False


def clean_url_string(raw: str) -> str:
    """Sanitize raw URL by stripping control characters and normalizing slashes.

    Args:
        raw: Raw uncleaned URL string.

    Returns:
        Cleaned URL string.
    """
    # Treat backslashes as forward slashes
    cleaned = raw.replace("\\", "/")
    # Strip whitespace, newlines, carriage returns, tabs, and non-printable control chars
    return "".join(c for c in cleaned.strip() if c not in "\r\n\t" and ord(c) >= 32)


def normalize_url(url: str) -> NormalizedURL:
    """Normalize a URL into canonical form and extract its structural components.

    Performs:
      - Whitespace and control character stripping
      - Backslash to forward slash normalization
      - Extraction and stripping of userinfo credentials
      - Scheme and hostname lowercasing
      - Punycode and IDNA bidirectional resolution (host_unicode and host_punycode)
      - Obfuscated IP normalization (decimal, octal, hex)
      - Public Suffix List decomposition with RFC 2606 fallback (.test, .invalid, .example)
      - Tracking parameter stripping and deterministic query parameter sorting
      - Fragment removal

    Args:
        url: Raw URL string.

    Returns:
        Structured NormalizedURL object.

    Raises:
        ValueError: If the URL scheme is unsupported or structure cannot be parsed.
    """
    cleaned = clean_url_string(url)

    # Prepend scheme if missing but starts with www.
    if cleaned.lower().startswith("www."):
        cleaned = "http://" + cleaned

    try:
        parsed = urllib.parse.urlsplit(cleaned)
    except ValueError as exc:
        raise ValueError(f"Malformed URL structure: {exc}") from exc

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"Unsupported scheme '{scheme}' for web normalization")

    # Handle userinfo
    has_userinfo = False
    netloc = parsed.netloc
    if "@" in netloc:
        has_userinfo = True
        netloc = netloc.split("@")[-1]

    # Handle port if explicitly in netloc
    port: int | None = None
    host = netloc
    if ":" in netloc and not netloc.endswith("]"):  # Guard IPv6 [::1]:8080
        parts = netloc.rsplit(":", 1)
        host = parts[0]
        try:
            parsed_port = int(parts[1])
            if (scheme == "http" and parsed_port != 80) or (
                scheme == "https" and parsed_port != 443
            ):
                port = parsed_port
        except ValueError:
            pass
    elif parsed.port and (
        (scheme == "http" and parsed.port != 80) or (scheme == "https" and parsed.port != 443)
    ):
        port = parsed.port

    # Clean host brackets for IPv6 or lowercasing
    host = host.lower().strip()

    # Check for IP literal or obfuscated IP
    is_ip_literal = False
    ip_obfuscated = False

    # Check IPv6
    if host.startswith("[") and host.endswith("]"):
        try:
            ipaddress.IPv6Address(host[1:-1])
            is_ip_literal = True
        except ValueError:
            pass

    # Check IPv4
    if not is_ip_literal:
        canonical_ip, was_obfuscated = parse_ipv4_obfuscation(host)
        if canonical_ip:
            host = canonical_ip
            is_ip_literal = True
            ip_obfuscated = was_obfuscated
        else:
            try:
                ipaddress.IPv4Address(host)
                is_ip_literal = True
            except ValueError:
                pass

    # IDNA & Punycode handling
    is_idn = False
    has_punycode = False
    host_unicode = host
    host_punycode = host

    if not is_ip_literal:
        if "xn--" in host:
            has_punycode = True
            try:
                host_unicode = idna.decode(host)
                is_idn = True
            except idna.IDNAError:
                host_unicode = host

        try:
            encoded = idna.encode(host_unicode).decode("ascii")
            host_punycode = encoded
            if encoded != host_unicode:
                is_idn = True
                has_punycode = "xn--" in encoded
        except idna.IDNAError:
            host_punycode = host

    # PSL domain / suffix extraction with RFC 2606 fallback
    if is_ip_literal:
        subdomain = ""
        domain = host
        suffix = ""
        registered_domain = host
        suffix_known = False
    else:
        extracted = TLD_EXTRACTOR(host_unicode)
        if hasattr(extracted, "top_domain_under_public_suffix"):
            top_domain = extracted.top_domain_under_public_suffix
        else:
            top_domain = extracted.registered_domain
        if extracted.suffix:
            subdomain = extracted.subdomain
            domain = extracted.domain
            suffix = extracted.suffix
            registered_domain = top_domain
            suffix_known = True
        else:
            # Suffix not found in PSL (e.g. .test, .invalid, .example, .local)
            suffix_known = False
            labels = [lbl for lbl in host_unicode.split(".") if lbl]
            if len(labels) >= 2:
                suffix = labels[-1]
                domain = labels[-2]
                subdomain = ".".join(labels[:-2])
                registered_domain = f"{domain}.{suffix}"
            elif len(labels) == 1:
                subdomain = ""
                domain = labels[0]
                suffix = ""
                registered_domain = labels[0]
            else:
                subdomain = ""
                domain = host_unicode
                suffix = ""
                registered_domain = host_unicode

    # Query sanitization: remove tracking tags and sort deterministically
    has_tracking_params = False
    sanitized_query_str = ""
    if parsed.query:
        query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        filtered_pairs: list[tuple[str, str]] = []
        for k, v in query_pairs:
            if is_tracking_param(k):
                has_tracking_params = True
            else:
                filtered_pairs.append((k, v))

        if filtered_pairs:
            filtered_pairs.sort(key=lambda item: (item[0], item[1]))
            sanitized_query_str = urllib.parse.urlencode(filtered_pairs)

    # Normalize path (ensure leading slash if netloc exists, strip trailing dot-segments)
    path = parsed.path
    if not path and (netloc or host):
        path = "/"
    elif path and not path.startswith("/"):
        path = "/" + path

    # Reconstruct canonical normalized URL without userinfo and fragments
    port_str = f":{port}" if port is not None else ""
    query_str = f"?{sanitized_query_str}" if sanitized_query_str else ""
    canonical_url = f"{scheme}://{host_punycode}{port_str}{path}{query_str}"

    return NormalizedURL(
        raw_url=url,
        url=canonical_url,
        scheme=scheme,
        host=host_punycode,
        host_unicode=host_unicode,
        host_punycode=host_punycode,
        subdomain=subdomain,
        domain=domain,
        suffix=suffix,
        registered_domain=registered_domain,
        port=port,
        path=path,
        query=sanitized_query_str,
        has_tracking_params=has_tracking_params,
        is_ip_literal=is_ip_literal,
        has_userinfo=has_userinfo,
        is_idn=is_idn,
        has_punycode=has_punycode,
        ip_obfuscated=ip_obfuscated,
        suffix_known=suffix_known,
    )
