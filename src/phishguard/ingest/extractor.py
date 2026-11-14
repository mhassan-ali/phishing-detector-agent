"""URL extraction from plain text and HTML with link-text mismatch detection."""

import re

from bs4 import BeautifulSoup

from phishguard.core.schemas import ExtractedURL, ParsedEmail, ParseWarning
from phishguard.ingest.limits import (
    MAX_BODY_CHARS_RETAINED,
    MAX_URL_LENGTH,
    MAX_URLS_PER_MESSAGE,
)
from phishguard.ingest.normalizer import TLD_EXTRACTOR, normalize_url

# Regex finding URLs and candidate scheme-less www links
PLAIN_URL_PATTERN = re.compile(
    r"""(?xi)
    \b
    (?:
      https?://[^\s<>"]+
      |
      www\.[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}(?:/[^\s<>"]*)?
    )
    """
)

# Markdown link pattern [visible text](url)
MARKDOWN_LINK_PATTERN = re.compile(
    r"\[([^\]]+)\]\((https?://[^\s\)]+|www\.[^\s\)]+)\)",
    re.IGNORECASE,
)

# Domain detection in visible text for link-text mismatch detection (linear O(n), ReDoS-safe)
VISIBLE_DOMAIN_PATTERN = re.compile(
    r"(?:https?://)?([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})",
    re.IGNORECASE,
)

NON_HTTP_SCHEME_PATTERN = re.compile(
    r"^(javascript|data|file|vbscript|about|blob):",
    re.IGNORECASE,
)


def html_to_text(html: str) -> str:
    """Safely convert HTML to plain text, stripping scripts, styles, and tags.

    Args:
        html: Raw or partial HTML markup string.

    Returns:
        Extracted human-readable plain text.
    """
    if not html:
        return ""

    truncated = html[:MAX_BODY_CHARS_RETAINED]
    try:
        soup = BeautifulSoup(truncated, "html.parser")
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        return soup.get_text(separator=" ", strip=True)
    except (RecursionError, Exception):
        # Fallback to regex stripping if HTML parsing encounters recursion or fatal errors
        return re.sub(r"<[^>]+>", " ", truncated).strip()


def extract_registered_domain(host: str) -> str:
    """Extract registered domain from host with RFC 2606 fallback (.test, .invalid).

    Args:
        host: Hostname string.

    Returns:
        Registered domain string (e.g. 'example.com' or 'acme.test').
    """
    clean_host = host.lower().strip()
    extracted = TLD_EXTRACTOR(clean_host)
    if extracted.suffix:
        if hasattr(extracted, "top_domain_under_public_suffix"):
            return str(extracted.top_domain_under_public_suffix)
        return str(extracted.registered_domain)

    labels = [lbl for lbl in clean_host.split(".") if lbl]
    if len(labels) >= 2:
        return f"{labels[-2]}.{labels[-1]}"
    return clean_host


def detect_link_mismatch(visible_text: str | None, destination_registered_domain: str) -> bool:
    """Determine whether visible anchor text displays a domain different from href destination.

    Args:
        visible_text: The anchor tag's visible string.
        destination_registered_domain: The registered domain of the normalized href target.

    Returns:
        True if visible text looks like a domain and differs from destination registered domain.
    """
    if not visible_text:
        return False

    match = VISIBLE_DOMAIN_PATTERN.search(visible_text)
    if not match:
        return False

    visible_host = match.group(1).lower().strip()
    visible_reg_domain = extract_registered_domain(visible_host)

    if not visible_reg_domain or not destination_registered_domain:
        return False

    return visible_reg_domain != destination_registered_domain.lower()


def trim_url_punctuation(raw_url: str) -> str:
    """Trim surrounding angle brackets, markdown parentheses, and trailing punctuation.

    Args:
        raw_url: Raw candidate URL.

    Returns:
        Trimmed URL string.
    """
    url = raw_url.strip()
    if url.startswith("<") and url.endswith(">"):
        url = url[1:-1].strip()

    # Strip trailing sentence punctuation
    trailing_chars = ".,;:!?)'\""
    while url and url[-1] in trailing_chars:
        # Avoid stripping closing parenthesis if it matches an opening one in the URL
        if url[-1] == ")" and url.count("(") >= url.count(")"):
            break
        url = url[:-1]

    return url.strip()


def extract_urls_from_content(
    body_plain: str = "",
    body_html: str = "",
) -> tuple[list[ExtractedURL], list[str], list[ParseWarning]]:
    """Extract, deduplicate, and classify URLs from plain text and sanitized HTML.

    Args:
        body_plain: Plain text message content.
        body_html: HTML message content.

    Returns:
        Tuple of (extracted_urls, other_schemes, parse_warnings).
    """
    extracted_map: dict[str, ExtractedURL] = {}
    other_schemes_set: set[str] = set()
    warnings: list[ParseWarning] = []

    def record_url(raw_url: str, location: str, visible: str | None = None) -> None:
        trimmed = trim_url_punctuation(raw_url)
        if not trimmed:
            return

        # Check for non-http(s) schemes
        scheme_match = NON_HTTP_SCHEME_PATTERN.match(trimmed)
        if scheme_match:
            truncated_other = trimmed[:MAX_URL_LENGTH]
            other_schemes_set.add(truncated_other)
            return

        if len(extracted_map) >= MAX_URLS_PER_MESSAGE:
            if ParseWarning.MAX_URLS_EXCEEDED not in warnings:
                warnings.append(ParseWarning.MAX_URLS_EXCEEDED)
            return

        try:
            norm = normalize_url(trimmed)
        except ValueError:
            return

        mismatch = detect_link_mismatch(visible, norm.registered_domain)

        canonical_key = norm.url
        if canonical_key in extracted_map:
            existing = extracted_map[canonical_key]
            if location not in existing.source_locations:
                existing.source_locations.append(location)
            if visible and not existing.visible_text:
                existing.visible_text = visible[:200]
            if mismatch:
                existing.link_text_mismatch = True
        else:
            extracted_map[canonical_key] = ExtractedURL(
                raw_url=trimmed[:MAX_URL_LENGTH],
                normalized_url=norm,
                visible_text=visible[:200] if visible else None,
                link_text_mismatch=mismatch,
                source_locations=[location],
            )

    # 1. Extract from plain text markdown links first: [text](url)
    if body_plain:
        for match in MARKDOWN_LINK_PATTERN.finditer(body_plain):
            visible_text = match.group(1).strip()
            link_url = match.group(2).strip()
            record_url(link_url, "body_plain", visible_text)

        # Standard plain text URLs
        for match in PLAIN_URL_PATTERN.finditer(body_plain):
            record_url(match.group(0), "body_plain")

    # 2. Extract from HTML
    if body_html:
        truncated_html = body_html[:MAX_BODY_CHARS_RETAINED]
        try:
            soup = BeautifulSoup(truncated_html, "html.parser")
            # Decompose scripts and styles immediately
            for tag in soup(["script", "style", "noscript"]):
                tag.decompose()

            # Anchors <a href="...">
            for a in soup.find_all("a", href=True):
                href = str(a.get("href", "")).strip()
                visible = a.get_text(separator=" ", strip=True) or None
                record_url(href, "html_anchor", visible)

            # Images <img src="...">
            for img in soup.find_all("img", src=True):
                src = str(img.get("src", "")).strip()
                record_url(src, "html_img")

            # Forms <form action="...">
            for form in soup.find_all("form", action=True):
                action = str(form.get("action", "")).strip()
                record_url(action, "html_form")

        except (RecursionError, Exception):
            if ParseWarning.HTML_PARSE_ERROR not in warnings:
                warnings.append(ParseWarning.HTML_PARSE_ERROR)

    return list(extracted_map.values()), sorted(other_schemes_set), warnings


def extract_urls(parsed: ParsedEmail) -> list[ExtractedURL]:
    """Extract and categorize all URLs from a ParsedEmail instance.

    Updates the parsed instance's extracted_urls, other_schemes, and parse_warnings fields.

    Args:
        parsed: ParsedEmail object to process.

    Returns:
        List of structured ExtractedURL objects.
    """
    urls, other_schemes, warnings = extract_urls_from_content(
        body_plain=parsed.body_plain,
        body_html=parsed.body_html,
    )

    parsed.extracted_urls = urls
    for scheme in other_schemes:
        if scheme not in parsed.other_schemes:
            parsed.other_schemes.append(scheme)

    for w in warnings:
        if w not in parsed.parse_warnings:
            parsed.parse_warnings.append(w)

    return urls
