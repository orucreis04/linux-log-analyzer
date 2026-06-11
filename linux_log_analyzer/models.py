"""Data models used by the log analyzer."""

from dataclasses import dataclass


@dataclass(frozen=True)
class LogEntry:
    """A single raw log line with its source line number."""

    line_number: int
    raw: str


@dataclass(frozen=True)
class LogEvent:
    """A parsed security-relevant log event."""

    timestamp_raw: str
    hostname: str
    service: str
    pid: str | None
    event_type: str
    username: str | None
    source_ip: str | None
    command: str | None
    raw_line: str


@dataclass(frozen=True)
class Finding:
    """A security finding produced by analysis rules."""

    rule_id: str
    title: str
    severity: str
    description: str
    source_ip: str | None
    username: str | None
    evidence_count: int
    recommendation: str


@dataclass(frozen=True)
class IPStats:
    """Aggregated activity counters for a source IP address."""

    source_ip: str
    total_events: int
    failed_login_count: int
    accepted_login_count: int
    root_attempt_count: int
    invalid_user_attempt_count: int


@dataclass(frozen=True)
class AnalysisSummary:
    """High-level security analysis summary."""

    total_events: int
    unparsed_lines: int
    total_findings: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    risk_score: int
