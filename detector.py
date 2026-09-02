"""Rule-based detection of suspicious SSH login patterns."""

from collections import defaultdict

from models.analysis import DetectionFinding, EventType, SSHEvent


# Central thresholds keep the demo rules transparent and configurable.
FAILED_IP_THRESHOLD = 5
IP_ATTEMPT_THRESHOLD = 10
USER_ATTEMPT_THRESHOLD = 6
FAILURES_BEFORE_SUCCESS_THRESHOLD = 3


def _capped_points(base: int, count: int, threshold: int, factor: int, cap: int) -> int:
    """Calculate base points plus capped points above the threshold."""

    return min(base + max(0, count - threshold) * factor, cap)


def detect_threats(events: list[SSHEvent]) -> list[DetectionFinding]:
    """Apply all demo detection rules to the events."""

    findings: list[DetectionFinding] = []
    by_ip: dict[str, list[SSHEvent]] = defaultdict(list)
    by_user: dict[str, list[SSHEvent]] = defaultdict(list)

    for event in events:
        by_ip[event.ip_address].append(event)
        if event.username:
            by_user[event.username].append(event)

    for ip_address, ip_events in sorted(by_ip.items()):
        failures = [event for event in ip_events if event.event_type == EventType.FAILED_LOGIN]
        # Rule 1: repeated failed attempts.
        if len(failures) >= FAILED_IP_THRESHOLD:
            findings.append(
                DetectionFinding(
                    rule_id="FAILED_LOGINS_BY_IP",
                    title="Multiple failed logins",
                    description=(
                        f"{len(failures)} failed logins from {ip_address} "
                        f"(threshold: {FAILED_IP_THRESHOLD})."
                    ),
                    severity="hoch",
                    points=_capped_points(25, len(failures), FAILED_IP_THRESHOLD, 2, 40),
                    line_numbers=[event.line_number for event in failures],
                    ip_address=ip_address,
                )
            )

        # Rule 2: high event volume from one IP address.
        if len(ip_events) >= IP_ATTEMPT_THRESHOLD:
            findings.append(
                DetectionFinding(
                    rule_id="HIGH_IP_VOLUME",
                    title="High attempt volume from one IP",
                    description=(
                        f"{len(ip_events)} login events from {ip_address} "
                        f"(threshold: {IP_ATTEMPT_THRESHOLD})."
                    ),
                    severity="mittel",
                    points=_capped_points(15, len(ip_events), IP_ATTEMPT_THRESHOLD, 1, 25),
                    line_numbers=[event.line_number for event in ip_events],
                    ip_address=ip_address,
                )
            )

        # Rule 3: successful login after failed attempts.
        previous_failures: list[SSHEvent] = []
        for event in ip_events:
            if event.event_type == EventType.FAILED_LOGIN:
                previous_failures.append(event)
                continue
            if len(previous_failures) >= FAILURES_BEFORE_SUCCESS_THRESHOLD:
                related = [*previous_failures, event]
                findings.append(
                    DetectionFinding(
                        rule_id="SUCCESS_AFTER_FAILURES",
                        title="Successful login after failed attempts",
                        description=(
                            f"Successful login from {ip_address} after "
                            f"{len(previous_failures)} previous failed attempts."
                        ),
                        severity="kritisch",
                        points=30,
                        line_numbers=[item.line_number for item in related],
                        ip_address=ip_address,
                        username=event.username,
                    )
                )
                # A new sequence begins after a successful login.
                previous_failures = []

    for username, user_events in sorted(by_user.items()):
        # Rule 4: high attempt volume for one username.
        if len(user_events) < USER_ATTEMPT_THRESHOLD:
            continue
        failures = [event for event in user_events if event.event_type == EventType.FAILED_LOGIN]
        findings.append(
            DetectionFinding(
                rule_id="TARGETED_USER",
                title="High attempt volume for one username",
                description=(
                    f"{len(user_events)} login attempts for username {username} "
                    f"({len(failures)} failed; threshold: {USER_ATTEMPT_THRESHOLD})."
                ),
                severity="mittel",
                points=_capped_points(15, len(user_events), USER_ATTEMPT_THRESHOLD, 2, 25),
                line_numbers=[event.line_number for event in user_events],
                username=username,
            )
        )

    return findings
