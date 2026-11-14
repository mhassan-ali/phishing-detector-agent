"""Email parsing, URL extraction, normalization, and ingestion dispatching."""

from phishguard.ingest.defang import defang, refang
from phishguard.ingest.extractor import extract_urls, html_to_text
from phishguard.ingest.limits import (
    MAX_ATTACHMENT_BYTES,
    MAX_ATTACHMENTS,
    MAX_BODY_CHARS_RETAINED,
    MAX_EMAIL_BYTES,
    MAX_HEADER_COUNT,
    MAX_HEADER_VALUE_CHARS,
    MAX_MIME_DEPTH,
    MAX_PARTS,
    MAX_RECEIVED_HOPS,
    MAX_URL_LENGTH,
    MAX_URLS_PER_MESSAGE,
)
from phishguard.ingest.normalizer import normalize_url
from phishguard.ingest.parser import ingest, is_rfc5322_text, parse_eml, parse_raw_text

__all__ = [
    "MAX_ATTACHMENT_BYTES",
    "MAX_ATTACHMENTS",
    "MAX_BODY_CHARS_RETAINED",
    "MAX_EMAIL_BYTES",
    "MAX_HEADER_COUNT",
    "MAX_HEADER_VALUE_CHARS",
    "MAX_MIME_DEPTH",
    "MAX_PARTS",
    "MAX_RECEIVED_HOPS",
    "MAX_URL_LENGTH",
    "MAX_URLS_PER_MESSAGE",
    "defang",
    "extract_urls",
    "html_to_text",
    "ingest",
    "is_rfc5322_text",
    "normalize_url",
    "parse_eml",
    "parse_raw_text",
    "refang",
]
