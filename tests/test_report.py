from scanner.reputation import ReputationResult
from scanner.risk_report import build_report, score_to_level
from scanner.rule_engine import Finding, analyze
from scanner.url_validator import validate_url


def test_clean_url_is_low():
    u = validate_url("https://www.python.org/")
    r = build_report(u, analyze(u), ReputationResult(checked=True))
    assert r.score == 0 and r.level == "low"


def test_score_is_capped_at_100():
    u = validate_url("https://example.com/")
    big = [Finding(f"r{i}", "t", "d", 30, "high") for i in range(6)]
    assert build_report(u, big, ReputationResult()).score == 100


def test_flagged_reputation_forces_critical():
    u = validate_url("https://example.com/")
    rep = ReputationResult(checked=True, flagged=True, sources=["x"], threats=["MALWARE"])
    r = build_report(u, [], rep)
    assert r.score >= 90 and r.level == "critical"


def test_level_thresholds():
    assert score_to_level(0)[0] == "low"
    assert score_to_level(20)[0] == "medium"
    assert score_to_level(45)[0] == "high"
    assert score_to_level(70)[0] == "critical"


def test_to_dict_is_json_friendly():
    import json
    u = validate_url("http://203.0.113.5/")
    json.dumps(build_report(u, analyze(u), ReputationResult()).to_dict())