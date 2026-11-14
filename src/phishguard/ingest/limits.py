"""Constants enforcing structural, memory, and complexity limits during ingestion."""

# Upload and payload bounds
MAX_EMAIL_BYTES: int = 10 * 1024 * 1024  # 10 MB maximum total message payload
MAX_ATTACHMENT_BYTES: int = 25 * 1024 * 1024  # 25 MB max individual attachment size
MAX_ATTACHMENTS: int = 50  # Maximum number of attachments to enumerate

# MIME structure and recursion guards
MAX_MIME_DEPTH: int = 20  # Maximum MIME multipart recursion depth
MAX_PARTS: int = 100  # Maximum total MIME parts traversed

# Header constraints
MAX_HEADER_COUNT: int = 200  # Maximum total number of headers processed
MAX_HEADER_VALUE_CHARS: int = 10_000  # Maximum length of an individual header value
MAX_RECEIVED_HOPS: int = 50  # Maximum Received hops recorded

# Body and URL limits
MAX_BODY_CHARS_RETAINED: int = 500_000  # Maximum chars retained per body plain/html
MAX_URL_LENGTH: int = 2048  # Maximum length of an individual extracted URL
MAX_URLS_PER_MESSAGE: int = 200  # Maximum number of unique URLs retained per message
