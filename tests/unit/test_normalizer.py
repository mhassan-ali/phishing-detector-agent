"""Unit tests for URL normalization, tracking parameter stripping, and IP obfuscation handling."""

import ipaddress

import pytest

from phishguard.ingest.normalizer import TLD_EXTRACTOR, normalize_url


def test_basic_normalization_and_lowercasing() -> None:
    """Verify schemes, hosts, and paths are normalized to lowercase canonical form."""
    norm = normalize_url("HTTP://EXAMPLE.COM/Path/To/Page")
    assert norm.scheme == "http"
    assert norm.host == "example.com"
    assert norm.url == "http://example.com/Path/To/Page"
    assert norm.registered_domain == "example.com"
    assert norm.suffix == "com"
    assert norm.suffix_known is True


def test_tracking_params_stripped_and_query_sorted() -> None:
    """Verify analytics and marketing parameters are stripped and queries sorted."""
    url = (
        "https://example.com/product"
        "?utm_source=newsletter"
        "&b_param=second"
        "&utm_medium=email"
        "&a_param=first"
        "&fbclid=12345"
        "&mc_eid=abcde"
    )
    norm = normalize_url(url)
    assert norm.has_tracking_params is True
    assert "utm_source" not in norm.query
    assert "fbclid" not in norm.query
    assert "mc_eid" not in norm.query
    assert norm.query == "a_param=first&b_param=second"
    assert norm.url == "https://example.com/product?a_param=first&b_param=second"


def test_userinfo_stripped() -> None:
    """Verify credentials embedded in URLs are flagged and stripped from canonical form."""
    url = "https://admin:supersecret@portal.example.com/dashboard"
    norm = normalize_url(url)
    assert norm.has_userinfo is True
    assert "admin" not in norm.url
    assert "supersecret" not in norm.url
    assert norm.url == "https://portal.example.com/dashboard"
    assert norm.host == "portal.example.com"


def test_ip_obfuscation_decimal_octal_hex() -> None:
    """Verify decimal, octal, and hex IPv4 forms normalize to standard dotted-decimal."""
    # 32-bit decimal integer (2130706433 == 127.0.0.1)
    norm_dec = normalize_url("http://2130706433/")
    assert norm_dec.is_ip_literal is True
    assert norm_dec.ip_obfuscated is True
    assert norm_dec.host == "127.0.0.1"
    assert norm_dec.url == "http://127.0.0.1/"

    # Octal dotted quad (0177.0.0.1 == 127.0.0.1)
    norm_oct = normalize_url("http://0177.0.0.1/test")
    assert norm_oct.is_ip_literal is True
    assert norm_oct.ip_obfuscated is True
    assert norm_oct.host == "127.0.0.1"

    # Hex dotted quad (0x7f.0.0.1 == 127.0.0.1)
    norm_hex = normalize_url("http://0x7f.0.0.1/login")
    assert norm_hex.is_ip_literal is True
    assert norm_hex.ip_obfuscated is True
    assert norm_hex.host == "127.0.0.1"

    # Normal IPv4 is not flagged as obfuscated
    norm_std = normalize_url("http://192.168.1.1/")
    assert norm_std.is_ip_literal is True
    assert norm_std.ip_obfuscated is False
    assert norm_std.host == "192.168.1.1"


def test_rfc2606_reserved_domains_fallback() -> None:
    """Verify .test, .invalid, and .example domains without PSL entries are decomposed."""
    norm = normalize_url("https://secure.acmetrust.test/login")
    assert norm.suffix_known is False
    assert norm.domain == "acmetrust"
    assert norm.suffix == "test"
    assert norm.registered_domain == "acmetrust.test"
    assert norm.subdomain == "secure"


def test_idn_and_punycode_handling() -> None:
    """Verify bidirectional Unicode and Punycode normalization."""
    # Cyrillic 'а' in аcmetrust.test -> xn--cmetrust-06g.test
    url_unicode = "https://аcmetrust.test/verify"
    norm_uni = normalize_url(url_unicode)
    assert norm_uni.is_idn is True
    assert norm_uni.has_punycode is True
    assert norm_uni.host_punycode == "xn--cmetrust-06g.test"
    assert norm_uni.host_unicode == "аcmetrust.test"

    # Input already in Punycode format
    url_puny = "https://xn--cmetrust-06g.test/verify"
    norm_puny = normalize_url(url_puny)
    assert norm_puny.has_punycode is True
    assert norm_puny.host_unicode == "аcmetrust.test"


def test_control_character_and_backslash_sanitization() -> None:
    """Verify backslashes are converted to slashes and control characters removed."""
    dirty_url = "https:\\\\example.com\\path\\to\\page\r\n\t"
    norm = normalize_url(dirty_url)
    assert norm.host == "example.com"
    assert norm.path == "/path/to/page"


def test_unsupported_schemes_raise_value_error() -> None:
    """Verify non-http(s) schemes raise ValueError."""
    with pytest.raises(ValueError, match="Unsupported scheme"):
        normalize_url("javascript:alert(1)")

    with pytest.raises(ValueError, match="Unsupported scheme"):
        normalize_url("data:text/html,<b>hi</b>")


def test_tldextract_operates_strictly_offline() -> None:
    """Verify tldextract extracts components using bundled snapshot without socket calls."""
    res = TLD_EXTRACTOR("sub.example.co.uk")
    assert res.subdomain == "sub"
    assert res.domain == "example"
    assert res.suffix == "co.uk"
    if hasattr(res, "top_domain_under_public_suffix"):
        reg = res.top_domain_under_public_suffix
    else:
        reg = res.registered_domain
    assert reg == "example.co.uk"


def test_ports_fragments_and_ipv6() -> None:
    """Verify non-default ports, IPv6 literals, and fragment stripping."""
    # Non-default port
    norm_port = normalize_url("http://example.com:8080/test#section")
    assert norm_port.port == 8080
    assert norm_port.url == "http://example.com:8080/test"
    assert "#section" not in norm_port.url

    # Default port omitted
    norm_default = normalize_url("https://example.com:443/test")
    assert norm_default.port is None
    assert norm_default.url == "https://example.com/test"

    # IPv6 with port
    norm_ipv6 = normalize_url("http://[::1]:9000/api")
    assert norm_ipv6.is_ip_literal is True
    assert norm_ipv6.host == "[::1]"
    assert norm_ipv6.port == 9000

    # Pathless URL adds trailing slash
    norm_pathless = normalize_url("https://example.com")
    assert norm_pathless.path == "/"
    assert norm_pathless.url == "https://example.com/"

    # Single label host (e.g. intranet)
    norm_single = normalize_url("http://intranet/dashboard")
    assert norm_single.domain == "intranet"
    assert norm_single.suffix == ""
    assert norm_single.suffix_known is False


def test_normalizer_ip_and_scheme_edge_cases() -> None:
    """Verify IP obfuscation bounds and error handling in normalizer."""
    from phishguard.ingest.normalizer import parse_ipv4_obfuscation

    # Out of range hex
    ip, obf = parse_ipv4_obfuscation("0xFFFFFFFFFF")
    assert ip is None

    # Out of range octet
    ip2, obf2 = parse_ipv4_obfuscation("256.0.0.1")
    assert ip2 is None

    # Empty octet part
    ip3, obf3 = parse_ipv4_obfuscation("127..0.1")
    assert ip3 is None

    # Malformed URL triggering urlsplit ValueError
    with pytest.raises(ValueError, match="Malformed URL structure"):
        normalize_url("http://[invalid-ipv6")


def test_normalizer_idna_and_ip_coverage_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify branches for invalid bracketed host, IDNAError fallback, and empty label host."""
    import idna

    # 1. Bracketed host where IPv6Address raises ValueError on second check (hits line 205-206)
    calls = 0
    orig_ipv6 = ipaddress.IPv6Address

    def mock_ipv6(val: str | int) -> ipaddress.IPv6Address:
        nonlocal calls
        calls += 1
        if calls > 1:
            raise ValueError("Simulated IPv6 check failure")
        return orig_ipv6(val)

    monkeypatch.setattr("ipaddress.IPv6Address", mock_ipv6)
    norm_bracket = normalize_url("http://[::1]/path")
    assert norm_bracket.host == "[::1]"
    assert norm_bracket.is_ip_literal is False
    monkeypatch.undo()

    # 2. Host with only dots (hits line 280-283)
    norm_dots = normalize_url("http://.../path")
    assert norm_dots.domain == "..."

    # 3. idna.encode raising IDNAError (hits line 243-244)
    def mock_idna_encode(val: str) -> bytes:
        raise idna.IDNAError("Simulated IDNA failure")

    monkeypatch.setattr("idna.encode", mock_idna_encode)
    norm_idna = normalize_url("http://example.com/test")
    assert norm_idna.host_punycode == "example.com"
