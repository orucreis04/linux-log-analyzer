"""Parsers for Linux authentication and system log files."""

from pathlib import Path
import re

from linux_log_analyzer.models import LogEvent

SYSLOG_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<service>[\w.-]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.+)$"
)

SSH_FAILED_PATTERN = re.compile(
    r"^Failed password for (?:invalid user )?(?P<username>\S+) "
    r"from (?P<source_ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+ ssh2$"
)

SSH_ACCEPTED_PATTERN = re.compile(
    r"^Accepted password for (?P<username>\S+) "
    r"from (?P<source_ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+ ssh2$"
)

SUDO_PATTERN = re.compile(
    r"^(?P<username>\S+)\s+:\s+.*COMMAND=(?P<command>.+)$"
)


def parse_line(line: str) -> LogEvent | None:
    """Parse a supported Linux auth log line into a LogEvent."""

    raw_line = line.rstrip("\n")
    syslog_match = SYSLOG_PATTERN.match(raw_line)
    if syslog_match is None:
        return None

    message = syslog_match.group("message")
    service = syslog_match.group("service")

    if service == "sshd":
        return _parse_ssh_event(syslog_match, message, raw_line)
    if service == "sudo":
        return _parse_sudo_event(syslog_match, message, raw_line)
    return None


def _parse_ssh_event(
    syslog_match: re.Match[str], message: str, raw_line: str
) -> LogEvent | None:
    failed_match = SSH_FAILED_PATTERN.match(message)
    if failed_match is not None:
        username = failed_match.group("username")
        event_type = "root_login_attempt" if username == "root" else "ssh_failed_login"
        return _build_event(
            syslog_match=syslog_match,
            event_type=event_type,
            username=username,
            source_ip=failed_match.group("source_ip"),
            command=None,
            raw_line=raw_line,
        )

    accepted_match = SSH_ACCEPTED_PATTERN.match(message)
    if accepted_match is not None:
        return _build_event(
            syslog_match=syslog_match,
            event_type="ssh_successful_login",
            username=accepted_match.group("username"),
            source_ip=accepted_match.group("source_ip"),
            command=None,
            raw_line=raw_line,
        )

    return None


def _parse_sudo_event(
    syslog_match: re.Match[str], message: str, raw_line: str
) -> LogEvent | None:
    sudo_match = SUDO_PATTERN.match(message)
    if sudo_match is None:
        return None

    return _build_event(
        syslog_match=syslog_match,
        event_type="sudo_command",
        username=sudo_match.group("username"),
        source_ip=None,
        command=sudo_match.group("command"),
        raw_line=raw_line,
    )


def _build_event(
    syslog_match: re.Match[str],
    event_type: str,
    username: str | None,
    source_ip: str | None,
    command: str | None,
    raw_line: str,
) -> LogEvent:
    return LogEvent(
        timestamp_raw=syslog_match.group("timestamp"),
        hostname=syslog_match.group("hostname"),
        service=syslog_match.group("service"),
        pid=syslog_match.group("pid"),
        event_type=event_type,
        username=username,
        source_ip=source_ip,
        command=command,
        raw_line=raw_line,
    )


class LogParser:
    """Read log files and expose parsed security events."""

    def parse_lines(self, lines: list[str]) -> list[LogEvent]:
        """Parse a list of log lines and return recognized events."""

        events: list[LogEvent] = []
        for line in lines:
            event = parse_line(line)
            if event is not None:
                events.append(event)
        return events

    def parse_file(self, file_path: Path) -> list[LogEvent]:
        """Read a text log file and return recognized events."""

        path = file_path.expanduser()
        with path.open("r", encoding="utf-8", errors="replace") as log_file:
            return self.parse_lines(list(log_file))
