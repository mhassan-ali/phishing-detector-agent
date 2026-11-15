"""Constants and thresholds for threat intelligence providers and scoring."""

# Named threshold: number of VirusTotal malicious engine detections required for
# file-hash confirmed malicious verdict (FR-ATT-3 / Amendment 4).
VT_MALICIOUS_THRESHOLD: int = 5

# Named threshold: number of VirusTotal detections for domain/IP suspicious verdict.
VT_HOST_SUSPICIOUS_THRESHOLD: int = 3

# Per-scan lookup caps per provider to conserve free-tier quota (Amendment 3).
VT_MAX_LOOKUPS_PER_SCAN: int = 2
URLSCAN_MAX_LOOKUPS_PER_SCAN: int = 3

# Cache TTL hours: negative, unknown, or clean results expire quickly to detect
# emergent threats, whereas confirmed findings persist longer.
NEGATIVE_CACHE_TTL_HOURS: int = 1

# Size and item caps for database caching (Amendment 1).
MAX_THREAT_TYPES_CACHED: int = 5
MAX_RAW_SUMMARY_BYTES: int = 2048

# Fixed evidence description templates (no raw untrusted content interpolated).
DESC_INTEL_CONFIRMED_MALICIOUS: str = (
    "Threat intelligence confirmed exact URL or attachment hash as malicious."
)
DESC_INTEL_SUSPICIOUS: str = "Threat intelligence flagged domain, host, or indicator as suspicious."
DESC_INTEL_NOT_LISTED: str = (
    "Threat intelligence providers report no malicious history for queried indicators."
)
