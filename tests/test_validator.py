import pytest

from scanner.url_validator import InvalidURLError, validate_url


def test_adds_scheme_and_normalises():
    u = validate_url("  Example.COM/path#frag ")
    assert u.hostname == "example.com"
    assert u.scheme_assumed is True
    assert u.normalized == "http://example.com/path"


def test_registered_domain_and_subdomains():
    u = validate_url("https://a.b.shop.example.co.uk/x")
    assert u.registered_domain == "example.co.uk"
    assert u.subdomain_labels == ["a", "b", "shop"]


def test_ip_host_detected():
    assert validate_url("http://203.0.113.5/login").is_ip is True


@pytest.mark.parametrize("bad", [
    "", "   ", "javascript:alert(1)", "ftp://example.com", "http://localhost/",
    "http://192.168.1.1/", "http://127.0.0.1", "http://nodot", "http://exa mple.com",
    "http://example.com:99999", "http://-bad-.com", "a" * 2100,
])
def test_rejects_bad_input(bad):
    with pytest.raises(InvalidURLError):
        validate_url(bad)


def test_idn_converted_to_punycode():
    assert validate_url("https://bücher.de").hostname.startswith("xn--")