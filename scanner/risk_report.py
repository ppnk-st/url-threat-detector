"""Combine rule findings and reputation data into one risk report."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from .reputation import ReputationResult
from .rule_engine import Finding
from .url_validator import ParsedURL

LEVELS = [  # (minimum score, level, recommendation)
    (70, "critical", "Do not visit this URL. It shows strong signs of being malicious."),
    (45, "high", "Avoid this URL unless you can verify it through another channel."),
    (20, "medium", "Be cautious. Check the domain carefully and don't enter credentials."),
    (0, "low", "No major warning signs found, but no scan can guarantee a site is safe."),
]


@dataclass
class RiskReport:
    url: str
    hostname: str
    score: int
    level: str
    recommendation: str
    findings: list[Finding] = field(default_factory=list)
    reputation: ReputationResult = field(default_factory=ReputationResult)
    scanned_at: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def score_to_level(score: int) -> tuple[str, str]:
    for minimum, level, advice in LEVELS:
        if score >= minimum:
            return level, advice
    return LEVELS[-1][1], LEVELS[-1][2]


def build_report(url: ParsedURL, findings: list[Finding],
                 reputation: ReputationResult) -> RiskReport:
    score = min(sum(f.score for f in findings), 100)
    if reputation.flagged:
        score = max(score + 40, 90)
    score = min(score, 100)
    level, advice = score_to_level(score)
    return RiskReport(
        url=url.normalized,
        hostname=url.hostname,
        score=score,
        level=level,
        recommendation=advice,
        findings=findings,
        reputation=reputation,
        scanned_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )