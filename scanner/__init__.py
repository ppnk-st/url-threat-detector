"""Public scanner API: `scan_url(raw)` -> RiskReport."""
from .reputation import ReputationResult, check_reputation
from .risk_report import RiskReport, build_report
from .rule_engine import Finding, analyze
from .url_validator import InvalidURLError, ParsedURL, validate_url


def scan_url(raw: str) -> RiskReport:
    """Validate, analyse and look up a URL. Raises InvalidURLError on bad input."""
    parsed = validate_url(raw)
    findings = analyze(parsed)
    reputation = check_reputation(parsed)
    return build_report(parsed, findings, reputation)


__all__ = [
    "scan_url", "InvalidURLError", "ParsedURL", "validate_url", "analyze",
    "check_reputation", "build_report", "RiskReport", "Finding", "ReputationResult",
]