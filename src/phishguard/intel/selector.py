"""Indicator prioritization, selection, and sanitization for threat intelligence queries."""

import ipaddress
import urllib.parse

from phishguard.analyzers.brands import load_shorteners, load_suspicious_tlds
from phishguard.core.schemas import ParsedEmail
from phishguard.intel.base import Indicator


def is_private_or_reserved_ip(ip_str: str) -> bool:
    """Check if an IP address string is loopback, private, reserved, or link-local.

    Per Amendment 6: Drops internal or non-routable IPs before any lookup.

    Args:
        ip_str: IP address string (IPv4 or IPv6, possibly bracketed).

    Returns:
        True if the IP is non-routable, private, loopback, or reserved; False otherwise.
    """
    clean = ip_str.strip("[]").split("%")[0].strip()
    try:
        ip = ipaddress.ip_address(clean)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_reserved
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_unspecified
        )
    except ValueError:
        return False


def strip_url_query_and_fragment(raw_url: str) -> str:
    """Strip query strings and fragments from URL for privacy protection.

    Args:
        raw_url: URL to strip.

    Returns:
        URL with only scheme, netloc, and path.
    """
    try:
        parsed = urllib.parse.urlsplit(raw_url)
        path = parsed.path if parsed.path else "/"
        return f"{parsed.scheme}://{parsed.netloc}{path}"
    except Exception:
        return raw_url


def select_indicators(
    parsed: ParsedEmail,
    *,
    max_indicators: int = 5,
    send_full_urls: bool = False,
) -> list[Indicator]:
    """Pure function selecting and prioritizing indicators from ParsedEmail.

    Per Amendment 2:
      - Pure function of ParsedEmail.
      - Uses ExtractedURL flags, shortener and TLD lists, and attachment hashes.
      - Priority:
        1. Attachment SHA-256 hashes (FR-ATT-3).
        2. Flagged URLs (link-mismatches, typosquats, homographs, shorteners, suspicious TLDs).
        3. Remaining unique registered domains.
      - Drops private/reserved/loopback IPs (Amendment 6).
      - Strips query and fragment by default unless send_full_urls=True.
      - Capped at max_indicators.

    Args:
        parsed: Ingested ParsedEmail instance.
        max_indicators: Maximum total indicators to return.
        send_full_urls: If True, keep query and fragment; if False, strip them.

    Returns:
        Prioritized list of unique Indicator objects.
    """
    shorteners = load_shorteners()
    suspicious_tlds = load_suspicious_tlds()

    selected: list[Indicator] = []
    seen_hashes: set[str] = set()

    def add_indicator(ind: Indicator) -> None:
        if ind.value.lower() in seen_hashes:
            return
        # Drop private/reserved IPs per Amendment 6
        if ind.type == "ip" and is_private_or_reserved_ip(ind.value):
            return
        if ind.type == "url":
            try:
                host = urllib.parse.urlsplit(ind.value).netloc.split(":")[0]
                if is_private_or_reserved_ip(host):
                    return
            except Exception:
                return

        seen_hashes.add(ind.value.lower())
        selected.append(ind)

    # 1. Attachment SHA-256 hashes first (FR-ATT-3)
    for att in parsed.attachments:
        if att.sha256:
            add_indicator(
                Indicator(
                    type="sha256",
                    value=att.sha256.lower().strip(),
                    is_flagged=True,
                )
            )
            if len(selected) >= max_indicators:
                return selected

    # 2. Flagged URLs
    for ext_url in parsed.extracted_urls:
        norm = ext_url.normalized_url
        is_flagged = (
            ext_url.link_text_mismatch
            or norm.is_idn
            or norm.has_punycode
            or norm.ip_obfuscated
            or norm.has_userinfo
            or norm.registered_domain.lower() in shorteners
            or norm.suffix.lower() in suspicious_tlds
        )

        if is_flagged:
            val = ext_url.raw_url if send_full_urls else strip_url_query_and_fragment(norm.url)
            add_indicator(
                Indicator(
                    type="url",
                    value=val,
                    is_flagged=True,
                )
            )
            if len(selected) >= max_indicators:
                return selected

    # 3. Remaining URLs and registered domains
    for ext_url in parsed.extracted_urls:
        norm = ext_url.normalized_url
        # If IP literal
        if norm.is_ip_literal:
            add_indicator(Indicator(type="ip", value=norm.host, is_flagged=False))
        elif norm.registered_domain:
            add_indicator(Indicator(type="domain", value=norm.registered_domain, is_flagged=False))

        if len(selected) >= max_indicators:
            return selected

    return selected[:max_indicators]
