"""Risk assessment for findings produced by the detector."""

from collections import defaultdict

from models.analysis import DetectionFinding, RiskBreakdown


def calculate_risk(findings: list[DetectionFinding]) -> tuple[int, str, list[RiskBreakdown]]:
    """Sum rule points, cap the score, and determine the risk level."""

    points_by_rule: dict[tuple[str, str], int] = defaultdict(int)
    for finding in findings:
        points_by_rule[(finding.rule_id, finding.title)] += finding.points

    breakdown = [
        RiskBreakdown(rule_id=rule_id, label=label, points=points)
        for (rule_id, label), points in sorted(points_by_rule.items())
    ]
    score = min(sum(item.points for item in breakdown), 100)

    if score >= 75:
        level = "KRITISCH"
    elif score >= 50:
        level = "HOCH"
    elif score >= 20:
        level = "MITTEL"
    else:
        level = "NIEDRIG"

    return score, level, breakdown
