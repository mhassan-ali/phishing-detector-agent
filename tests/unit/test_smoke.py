"""Smoke test verifying importability and core package metadata."""

import phishguard
from phishguard.core import (
    IOC,
    AnalyzerResult,
    ConfigurationError,
    Evidence,
    ParsedEmail,
    ScanRequest,
    Settings,
    Severity,
    Verdict,
    get_logger,
    new_scan_id,
)


def test_package_metadata() -> None:
    """Verify package version and export sanity."""
    assert phishguard.__version__ == "0.1.0"


def test_core_exports_present() -> None:
    """Verify all expected core exports can be instantiated or referenced."""
    assert Severity.HIGH == "high"
    assert issubclass(ConfigurationError, Exception)
    assert IOC is not None
    assert Evidence is not None
    assert AnalyzerResult is not None
    assert Verdict is not None
    assert ScanRequest is not None
    assert ParsedEmail is not None
    assert Settings is not None

    sid = new_scan_id()
    assert len(sid) == 32

    logger = get_logger("smoke_test")
    assert logger is not None
