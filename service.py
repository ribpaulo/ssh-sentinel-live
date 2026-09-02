"""Application service connecting parsing, detection, and scoring."""

from collections import defaultdict

from detector import detect_threats
from models.analysis import (
    AnalysisResult,
    EntitySummary,
    EventType,
    MarkedLogLine,
    SSHEvent,
)
from parser import parse_ssh_log
from scorer import calculate_risk


def _entity_summaries(
    events: list[SSHEvent],
    findings_by_value: dict[str, set[str]],
    attribute: str,
) -> list[EntitySummary]:
    summaries: list[EntitySummary] = []
    for value, reasons in findings_by_value.items():
        entity_events = [event for event in events if getattr(event, attribute) == value]
        summaries.append(
            EntitySummary(
                value=value,
                attempts=len(entity_events),
                failed_attempts=sum(
                    event.event_type == EventType.FAILED_LOGIN for event in entity_events
                ),
                successful_attempts=sum(
                    event.event_type == EventType.SUCCESSFUL_LOGIN for event in entity_events
                ),
                reasons=sorted(reasons),
            )
        )
    return sorted(summaries, key=lambda item: (-item.failed_attempts, item.value))


def analyze_log(content: str, filename: str) -> AnalysisResult:
    """Analyze log text and return a result suitable for HTML and JSON."""

    events = parse_ssh_log(content)
    findings = detect_threats(events)
    score, level, breakdown = calculate_risk(findings)

    ip_reasons: dict[str, set[str]] = defaultdict(set)
    user_reasons: dict[str, set[str]] = defaultdict(set)
    line_reasons: dict[int, set[str]] = defaultdict(set)
    for finding in findings:
        if finding.ip_address:
            ip_reasons[finding.ip_address].add(finding.title)
        if finding.username:
            user_reasons[finding.username].add(finding.title)
        for line_number in finding.line_numbers:
            line_reasons[line_number].add(finding.title)

    # Usernames from marked lines remain visible even when the original finding
    # was produced by an IP-based rule.
    marked_event_lines = {event.line_number: event for event in events if event.line_number in line_reasons}
    for line_number, event in marked_event_lines.items():
        if event.username:
            user_reasons[event.username].update(line_reasons[line_number])

    marked_lines = [
        MarkedLogLine(
            line_number=line_number,
            content=marked_event_lines[line_number].raw_line,
            reasons=sorted(reasons),
        )
        for line_number, reasons in sorted(line_reasons.items())
        if line_number in marked_event_lines
    ]

    return AnalysisResult(
        filename=filename,
        total_lines=len(content.splitlines()),
        parsed_events=len(events),
        failed_logins=sum(event.event_type == EventType.FAILED_LOGIN for event in events),
        successful_logins=sum(event.event_type == EventType.SUCCESSFUL_LOGIN for event in events),
        risk_score=score,
        risk_level=level,
        alert=bool(findings),
        suspicious_ips=_entity_summaries(events, ip_reasons, "ip_address"),
        suspicious_users=_entity_summaries(events, user_reasons, "username"),
        findings=findings,
        score_breakdown=breakdown,
        marked_lines=marked_lines,
    )
