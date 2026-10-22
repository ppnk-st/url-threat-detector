"""Validate and normalise user-supplied URLs before they are analysed."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse

MAX_URL_LENGTH = 2048
ALLOWED_SCHEMES = {"http", "https"}
BLOCKED_PREFIXES = ("javascript:", "data:", "vbscript:", "file:", "ftp:")
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_BAD_CHARS = re.compile(r"[\s\x00-\x1f\x7f]")
# Common two-part public suffixes (small list; swap in `tldextract` for full accuracy).
_SECOND_LEVEL = {
    "co.uk", "org.uk", "ac.uk", "com.au", "co.nz", "co.jp",
    "co.th", "com.br", "co.in", "com.sg",
}
_DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)


class InvalidURLError(ValueError):
    """Raised when the input cannot be treated as a scannable URL."""


@dataclass(frozen=True)
class ParsedURL:
    original: str
    normalized: str
    scheme: str
    hostname: str          # ASCII / punycode form, lower-case
    port: int | None
    path: str
    query: str
    has_userinfo: bool
    is_ip: bool
    scheme_assumed: bool   # True if the user typed no http(s):// prefix

    @property
    def labels(self) -> list[str]:
        return [] if self.is_ip else self.hostname.split(".")

    @property
    def tld(self) -> str:
        return self.labels[-1] if self.labels else ""

    @property
    def registered_domain(self) -> str:
        if self.is_ip:
            return self.hostname
        labels = self.labels
        if len(labels) >= 3 and ".".join(labels[-2:]) in _SECOND_LEVEL:
            return ".".join(labels[-3:])
        return ".".join(labels[-2:])

    @property
    def subdomain_labels(self) -> list[str]:
        if self.is_ip:
            return []
        n = len(self.registered_domain.split("."))
        return self.labels[:-n]


def validate_url(raw: str) -> ParsedURL:
    """Return a ParsedURL or raise InvalidURLError with a user-friendly message."""
    if not isinstance(raw, str) or not raw.strip():
        raise InvalidURLError("Please enter a URL.")
    text = raw.strip()

    if len(text) > MAX_URL_LENGTH:
        raise InvalidURLError(f"URL is too long (max {MAX_URL_LENGTH} characters).")
    if _BAD_CHARS.search(text):
        raise InvalidURLError("URL must not contain spaces or control characters.")
    if text.lower().startswith(BLOCKED_PREFIXES):
        raise InvalidURLError("Only http:// and https:// URLs can be scanned.")

    scheme_assumed = "://" not in text
    if scheme_assumed:
        text = "http://" + text

    parsed = urlparse(text)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise InvalidURLError("Only http:// and https:// URLs can be scanned.")

    try:
        port = parsed.port
    except ValueError:
        raise InvalidURLError("URL contains an invalid port.") from None

    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        raise InvalidURLError("URL has no hostname.")

    is_ip = False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        is_ip = True
        # Keep RFC 5737 example addresses usable in documentation and tests.
        is_documentation_address = any(ip in network for network in _DOCUMENTATION_NETWORKS)
        if ((ip.is_private and not is_documentation_address)
                or ip.is_loopback or ip.is_link_local
                or (ip.is_reserved and not is_documentation_address) or ip.is_multicast):
            raise InvalidURLError("Internal or reserved IP addresses can't be scanned.")

    if not is_ip:
        if host == "localhost" or host.endswith((".local", ".internal", ".localhost")):
            raise InvalidURLError("Internal hostnames can't be scanned.")
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            raise InvalidURLError("Hostname contains invalid characters.") from None
        labels = host.split(".")
        if len(labels) < 2:
            raise InvalidURLError("Hostname must include a domain and TLD (e.g. example.com).")
        if len(host) > 253 or not all(_LABEL_RE.match(label) for label in labels):
            raise InvalidURLError("Hostname is not valid.")

    netloc = f"[{host}]" if (is_ip and ":" in host) else host
    if port:
        netloc += f":{port}"
    if parsed.username is not None:
        netloc = f"{parsed.username}@{netloc}"
    normalized = urlunparse(
        (parsed.scheme.lower(), netloc, parsed.path or "/", parsed.params, parsed.query, "")
    )

    return ParsedURL(
        original=raw.strip(),
        normalized=normalized,
        scheme=parsed.scheme.lower(),
        hostname=host,
        port=port,
        path=parsed.path or "/",
        query=parsed.query,
        has_userinfo=parsed.username is not None,
        is_ip=is_ip,
        scheme_assumed=scheme_assumed,
    )
