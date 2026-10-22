"""Reputation lookups: local blocklist + optional Google Safe Browsing."""
from __future__ import annotations

import os
from dataclasses import dataclass, field

import requests

from .url_validator import ParsedURL

SAFE_BROWSING_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
TIMEOUT_SECONDS = 5

# Domains used in the project's own test data; extend via EXTRA_BLOCKED_DOMAINS.
LOCAL_BLOCKLIST = {"malware.testing.google.test"}


@dataclass
class ReputationResult:
    checked: bool = False          # at least one external/local source answered
    flagged: bool = False
    sources: list[str] = field(default_factory=list)
    threats: list[str] = field(default_factory=list)
    error: str | None = None


def _blocklist() -> set[str]:
    extra = os.getenv("EXTRA_BLOCKED_DOMAINS", "")
    return LOCAL_BLOCKLIST | {d.strip().lower() for d in extra.split(",") if d.strip()}


def _check_local(url: ParsedURL, result: ReputationResult) -> None:
    result.checked = True
    blocked = _blocklist()
    if url.hostname in blocked or url.registered_domain in blocked:
        result.flagged = True
        result.sources.append("local blocklist")
        result.threats.append("BLOCKLISTED_DOMAIN")


def _check_safe_browsing(url: ParsedURL, result: ReputationResult) -> None:
    key = os.getenv("SAFE_BROWSING_API_KEY")
    if not key:
        return
    body = {
        "client": {"clientId": "url-threat-detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING",
                            "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url.normalized}],
        },
    }
    try:
        resp = requests.post(SAFE_BROWSING_ENDPOINT, params={"key": key},
                             json=body, timeout=TIMEOUT_SECONDS)
        resp.raise_for_status()
        matches = resp.json().get("matches", [])
    except (requests.RequestException, ValueError) as exc:
        result.error = f"Safe Browsing lookup failed: {exc.__class__.__name__}"
        return
    result.checked = True
    if matches:
        result.flagged = True
        result.sources.append("Google Safe Browsing")
        result.threats.extend(sorted({m.get("threatType", "UNKNOWN") for m in matches}))


def check_reputation(url: ParsedURL) -> ReputationResult:
    result = ReputationResult()
    _check_local(url, result)
    _check_safe_browsing(url, result)
    return result