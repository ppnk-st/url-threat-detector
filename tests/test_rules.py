from scanner.rule_engine import analyze
from scanner.url_validator import validate_url


def ids(url):
    return {f.rule_id for f in analyze(validate_url(url))}


def test_clean_url_has_no_findings():
    assert ids("https://www.python.org/downloads/") == set()


def test_ip_and_http():
    assert {"ip_host", "no_https"} <= ids("http://203.0.113.5/")


def test_brand_impersonation_flagged():
    assert "brand_impersonation" in ids("https://paypal.secure-login.xyz/verify")


def test_real_brand_not_flagged():
    assert "brand_impersonation" not in ids("https://www.paypal.com/signin")


def test_userinfo_trick():
    assert "userinfo" in ids("https://google.com@evil-site.top/")


def test_shortener_tld_port_and_embedded_url():
    found = ids("https://bit.ly:8443/r?u=http://x.com")
    assert {"shortener", "odd_port", "embedded_url"} <= found


def test_findings_sorted_by_score():
    scores = [f.score for f in analyze(validate_url("http://paypal.login-a-b-c.xyz:81/"))]
    assert scores == sorted(scores, reverse=True)