"""Heuristic rules that score how phishing/malware-like a URL looks."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable
from urllib.parse import unquote

from .url_validator import ParsedURL

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click",
    "country", "work", "support", "rest", "icu", "buzz", "cam", "monster",
}
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
}
KEYWORDS = (
    "login", "signin", "verify", "account", "update", "secure", "banking",
    "password", "confirm", "wallet", "suspend", "billing", "recover",
    "unlock", "invoice",
)
# brand keyword -> domains that legitimately own it
BRANDS = {
    "paypal": {"paypal.com"},
    "apple": {"apple.com", "icloud.com"},
    "google": {"google.com", "gmail.com", "youtube.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.co.jp"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "dhl": {"dhl.com"},
    "binance": {"binance.com"},
}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    detail: str
    score: int
    severity: str  # low | medium | high


def _finding(rule_id: str, title: str, detail: str, score: int) -> Finding:
    severity = "high" if score >= 25 else "medium" if score >= 10 else "low"
    return Finding(rule_id, title, detail, score, severity)


Rule = Callable[[ParsedURL], "Finding | None"]
RULES: list[Rule] = []


def rule(fn: Rule) -> Rule:
    RULES.append(fn)
    return fn


@rule
def ip_host(u: ParsedURL):
    if u.is_ip:
        return _finding("ip_host", "IP address used as host",
                        "Legitimate sites rarely use a raw IP address in links.", 25)


@rule
def no_https(u: ParsedURL):
    if u.scheme == "http" and not u.scheme_assumed:
        return _finding("no_https", "Connection is not encrypted",
                        "The URL uses http:// instead of https://.", 10)


@rule
def userinfo(u: ParsedURL):
    if u.has_userinfo:
        return _finding("userinfo", "Credentials/'@' in URL",
                        "Text before '@' is ignored by browsers and often hides the real host.", 25)


@rule
def suspicious_tld(u: ParsedURL):
    if u.tld in SUSPICIOUS_TLDS:
        return _finding("suspicious_tld", "Suspicious top-level domain",
                        f".{u.tld} is frequently abused for throwaway sites.", 12)


@rule
def many_subdomains(u: ParsedURL):
    n = len(u.subdomain_labels)
    if n > 3:
        return _finding("many_subdomains", "Excessive subdomains",
                        f"{n} subdomain levels can be used to bury the real domain.", 12)


@rule
def long_url(u: ParsedURL):
    n = len(u.normalized)
    if n > 200:
        return _finding("long_url", "Very long URL", f"{n} characters long.", 10)
    if n > 100:
        return _finding("long_url", "Long URL", f"{n} characters long.", 5)


@rule
def punycode(u: ParsedURL):
    if any(label.startswith("xn--") for label in u.labels):
        return _finding("punycode", "Internationalised domain (punycode)",
                        "May be a look-alike (homograph) of a well-known domain.", 15)


@rule
def shortener(u: ParsedURL):
    if u.registered_domain in SHORTENERS:
        return _finding("shortener", "URL shortener",
                        "The real destination is hidden behind a short link.", 10)


@rule
def keywords(u: ParsedURL):
    text = " ".join(u.subdomain_labels + [u.path, u.query]).lower()
    hits = [k for k in KEYWORDS if k in text]
    if hits:
        return _finding("keywords", "Phishing-style keywords",
                        "Found: " + ", ".join(hits), min(5 * len(hits), 15))


@rule
def brand_impersonation(u: ParsedURL):
    if u.is_ip:
        return None
    for brand, legit in BRANDS.items():
        if brand in u.hostname and u.registered_domain not in legit:
            return _finding("brand_impersonation", f"Possible {brand.title()} impersonation",
                            f"Hostname mentions '{brand}' but belongs to {u.registered_domain}.", 30)


@rule
def many_hyphens(u: ParsedURL):
    if u.hostname.count("-") >= 3:
        return _finding("many_hyphens", "Many hyphens in hostname",
                        "Typical of auto-generated phishing domains.", 8)


@rule
def odd_port(u: ParsedURL):
    if u.port not in (None, 80, 443):
        return _finding("odd_port", "Non-standard port", f"Port {u.port} is unusual for websites.", 8)


@rule
def heavy_encoding(u: ParsedURL):
    tail = u.path + "?" + u.query
    if "%25" in tail:
        return _finding("heavy_encoding", "Double-encoded characters",
                        "Often used to evade filters.", 10)
    if tail.count("%") >= 5:
        return _finding("heavy_encoding", "Heavy percent-encoding",
                        "Many encoded characters in path/query.", 6)


@rule
def embedded_url(u: ParsedURL):
    if "://" in unquote(u.path + "?" + u.query):
        return _finding("embedded_url", "URL inside URL",
                        "Another link is embedded, which may be an open redirect.", 10)


def analyze(url: ParsedURL) -> list[Finding]:
    """Run every rule and return findings, highest score first."""
    findings = [f for r in RULES if (f := r(url)) is not None]
    return sorted(findings, key=lambda f: f.score, reverse=True)