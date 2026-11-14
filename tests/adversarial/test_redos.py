"""Adversarial ReDoS testing for URL extraction and domain matching regex patterns."""

import time

from phishguard.ingest.extractor import (
    MARKDOWN_LINK_PATTERN,
    PLAIN_URL_PATTERN,
    VISIBLE_DOMAIN_PATTERN,
    extract_urls_from_content,
)


def test_redos_url_extraction_100k_chars() -> None:
    """Verify URL extraction patterns process crafted 100k input in under 1 second.

    Crafted patterns test:
      - Repeated incomplete scheme sequences ('http://http://http://...')
      - Long chains of subdomain dots and trailing punctuation
      - Deeply nested unclosed parentheses and brackets
      - Long alphanumeric strings without delimiters
    """
    crafted_50k = (
        ("http://" * 2000)
        + ("www." * 2000 + "example.test")
        + ("[" * 2000 + "text" + "]" * 2000)
        + ("https://example.test/" + "." * 10000)
        + ("a" * 20000)
    )
    crafted_100k = crafted_50k * 2

    # Verify individual compiled regexes on 100k input
    t0 = time.perf_counter()
    PLAIN_URL_PATTERN.findall(crafted_100k)
    MARKDOWN_LINK_PATTERN.findall(crafted_100k)
    VISIBLE_DOMAIN_PATTERN.findall(crafted_100k)
    regex_duration = time.perf_counter() - t0

    assert regex_duration < 1.0, f"Regex search exceeded 1.0s: {regex_duration:.4f}s"

    # Full extraction pipeline scaling test: 50k vs 100k
    t1 = time.perf_counter()
    extract_urls_from_content(body_plain=crafted_50k)
    duration_50k = time.perf_counter() - t1

    t2 = time.perf_counter()
    extract_urls_from_content(body_plain=crafted_100k)
    duration_100k = time.perf_counter() - t2

    assert duration_100k < 1.0, f"Extraction on 100k exceeded 1.0s: {duration_100k:.4f}s"

    # Verify roughly linear scaling (ratio < 4.0 to exclude O(n^2) or catastrophic backtracking)
    if duration_50k > 0.001:
        scaling_ratio = duration_100k / duration_50k
        assert scaling_ratio < 4.0, f"Non-linear scaling ratio: {scaling_ratio:.2f}"
