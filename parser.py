"""Parser for common OpenSSH entries from ``auth.log`` files."""

import ipaddress
import re

from models.analysis import EventType, SSHEvent


# Syslog and ISO timestamps are supported. The message section is evaluated
# separately so that additional SSH patterns can be added easily.
LOG_PREFIX = re.compile(
    r"^(?P<timestamp>(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|"
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?))"
    r"\s+(?P<hostname>\S+)\s+sshd(?:\[\d+\])?:\s+(?P<message>.*)$",
    re.IGNORECASE,
)

FAILED_PASSWORD = re.compile(
    r"Failed password for (?:(?:invalid|illegal) user )?(?P<user>\S+) "
    r"from (?P<ip>\S+)(?: port \d+)?(?: ssh\d+)?",
    re.IGNORECASE,
)
INVALID_USER = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\S+)(?: port \d+)?",
    re.IGNORECASE,
)
ACCEPTED_LOGIN = re.compile(
    r"Accepted (?P<method>password|publickey|keyboard-interactive) for "
    r"(?P<user>\S+) from (?P<ip>\S+)(?: port \d+)?",
    re.IGNORECASE,
)
PAM_FAILURE = re.compile(
    r"authentication failure;.*?(?:rhost=(?P<ip>\S+)).*?(?:user=(?P<user>\S*))",
    re.IGNORECASE,
)


def _valid_ip(value: str) -> str | None:
    """Return a normalized IP address, or ``None`` for invalid text."""

    try:
        return str(ipaddress.ip_address(value.strip("[]")))
    except ValueError:
        return None


def parse_line(line: str, line_number: int) -> SSHEvent | None:
    """Parse one log line; unsupported lines are ignored."""

    raw_line = line.rstrip("\r\n")
    prefix = LOG_PREFIX.match(raw_line)
    if not prefix:
        return None

    message = prefix.group("message")
    match = ACCEPTED_LOGIN.search(message)
    if match:
        event_type = EventType.SUCCESSFUL_LOGIN
        method = match.group("method").lower()
    else:
        match = FAILED_PASSWORD.search(message) or INVALID_USER.search(message)
        method = "password" if FAILED_PASSWORD.search(message) else None
        if not match:
            match = PAM_FAILURE.search(message)
            method = "pam" if match else None
        if not match:
            return None
        event_type = EventType.FAILED_LOGIN

    ip_address = _valid_ip(match.group("ip"))
    if ip_address is None:
        return None

    username = match.groupdict().get("user") or None
    return SSHEvent(
        line_number=line_number,
        raw_line=raw_line,
        timestamp=prefix.group("timestamp"),
        hostname=prefix.group("hostname"),
        event_type=event_type,
        ip_address=ip_address,
        username=username,
        authentication_method=method,
    )


def parse_ssh_log(content: str) -> list[SSHEvent]:
    """Parse all recognized SSH authentication events from text."""

    events: list[SSHEvent] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        event = parse_line(line, line_number)
        if event is not None:
            events.append(event)
    return events
