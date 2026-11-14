"""Integration tests for the ingestion pipeline across all synthetic and malformed fixtures."""

from pathlib import Path

from phishguard.core.schemas import ScanRequest
from phishguard.ingest.parser import ingest, parse_eml

FIXTURES_DIR = Path("tests/fixtures/emails")


def test_ingest_all_synthetic_fixtures() -> None:
    """End-to-end integration test verifying ingestion of all fixture files."""
    fixtures = [
        "legit_newsletter.eml",
        "legit_receipt.eml",
        "fake_bank.eml",
        "fake_delivery.eml",
        "display_name_spoof.eml",
        "link_mismatch.eml",
        "homograph_link.eml",
        "suspicious_attachment.eml",
        "truncated_mime.eml",
        "bad_charset.eml",
        "no_headers.eml",
    ]

    for fixture_name in fixtures:
        path = FIXTURES_DIR / fixture_name
        assert path.exists(), f"Missing fixture file: {fixture_name}"
        data = path.read_bytes()

        # Ingest directly via parse_eml
        parsed = parse_eml(data)
        assert parsed is not None
        assert parsed.sha256 != ""

        # Ingest via ScanRequest dispatcher
        text_content = data.decode("utf-8", errors="replace")
        req = ScanRequest(input_type="text", content=text_content)
        parsed_via_dispatcher = ingest(req)
        assert parsed_via_dispatcher is not None
        assert parsed_via_dispatcher.sha256 != ""
