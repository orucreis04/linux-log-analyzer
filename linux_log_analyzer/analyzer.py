"""Analysis orchestration for parsed log entries."""

from collections import Counter

from linux_log_analyzer.models import AnalysisSummary, Finding, IPStats, LogEvent
from linux_log_analyzer.rules import (
    INVALID_USER_ENUMERATION,
    ROOT_LOGIN_ATTEMPT,
    SEVERITY_ORDER,
    SSH_BRUTE_FORCE,
    SUDO_USAGE,
    Rule,
)

RISK_WEIGHTS: dict[str, int] = {
    "HIGH": 25,
    "MEDIUM": 15,
    "LOW": 8,
    "INFO": 2,
}


def analyze_events(events: list[LogEvent]) -> list[Finding]:
    """Analyze parsed events and return security findings."""

    findings: list[Finding] = []
    findings.extend(_find_ssh_brute_force(events))
    findings.extend(_find_root_login_attempts(events))
    findings.extend(_find_invalid_user_enumeration(events))
    findings.extend(_find_sudo_usage(events))
    return sorted(
        findings,
        key=lambda finding: (
            SEVERITY_ORDER.get(finding.severity, len(SEVERITY_ORDER)),
            finding.rule_id,
            finding.source_ip or "",
            finding.username or "",
        ),
    )


def calculate_risk_score(findings: list[Finding]) -> int:
    """Calculate a capped 0-100 risk score from finding severities."""

    score = sum(RISK_WEIGHTS.get(finding.severity, 0) for finding in findings)
    return min(score, 100)


def summarize_analysis(
    total_lines: int, events: list[LogEvent], findings: list[Finding]
) -> AnalysisSummary:
    """Build a high-level summary for parsed events and findings."""

    severity_counts = Counter(finding.severity for finding in findings)
    return AnalysisSummary(
        total_events=len(events),
        unparsed_lines=max(total_lines - len(events), 0),
        total_findings=len(findings),
        high_count=severity_counts["HIGH"],
        medium_count=severity_counts["MEDIUM"],
        low_count=severity_counts["LOW"],
        info_count=severity_counts["INFO"],
        risk_score=calculate_risk_score(findings),
    )


def get_top_source_ips(events: list[LogEvent], limit: int = 10) -> list[IPStats]:
    """Return per-IP activity counters ordered by total event volume."""

    stats_by_ip: dict[str, dict[str, int]] = {}
    for event in events:
        if event.source_ip is None:
            continue

        counters = stats_by_ip.setdefault(
            event.source_ip,
            {
                "total_events": 0,
                "failed_login_count": 0,
                "accepted_login_count": 0,
                "root_attempt_count": 0,
                "invalid_user_attempt_count": 0,
            },
        )
        counters["total_events"] += 1
        if event.event_type == "ssh_failed_login":
            counters["failed_login_count"] += 1
        if event.event_type == "ssh_successful_login":
            counters["accepted_login_count"] += 1
        if event.event_type == "root_login_attempt" or _is_root_failed_password(event):
            counters["root_attempt_count"] += 1
        if "Failed password for invalid user " in event.raw_line:
            counters["invalid_user_attempt_count"] += 1

    stats = [
        IPStats(
            source_ip=source_ip,
            total_events=counters["total_events"],
            failed_login_count=counters["failed_login_count"],
            accepted_login_count=counters["accepted_login_count"],
            root_attempt_count=counters["root_attempt_count"],
            invalid_user_attempt_count=counters["invalid_user_attempt_count"],
        )
        for source_ip, counters in stats_by_ip.items()
    ]
    return sorted(stats, key=lambda item: (-item.total_events, item.source_ip))[:limit]


class LogAnalyzer:
    """Analyze parsed Linux log entries."""

    def summarize(
        self, total_lines: int, events: list[LogEvent], findings: list[Finding]
    ) -> AnalysisSummary:
        """Return the high-level analysis summary."""

        return summarize_analysis(total_lines, events, findings)

    def analyze_events(self, events: list[LogEvent]) -> list[Finding]:
        """Analyze parsed events and return security findings."""

        return analyze_events(events)

    def get_top_source_ips(
        self, events: list[LogEvent], limit: int = 10
    ) -> list[IPStats]:
        """Return per-IP activity counters ordered by total event volume."""

        return get_top_source_ips(events, limit)


def _find_ssh_brute_force(events: list[LogEvent]) -> list[Finding]:
    failed_by_ip = Counter(
        event.source_ip
        for event in events
        if _is_failed_ssh_event(event) and event.source_ip is not None
    )
    return [
        _build_finding(
            rule=SSH_BRUTE_FORCE,
            evidence_count=count,
            source_ip=source_ip,
            username=None,
        )
        for source_ip, count in failed_by_ip.items()
        if count >= SSH_BRUTE_FORCE.threshold
    ]


def _find_root_login_attempts(events: list[LogEvent]) -> list[Finding]:
    root_attempts = [
        event
        for event in events
        if event.event_type == "root_login_attempt" or _is_root_failed_password(event)
    ]
    if not root_attempts:
        return []

    source_ips = {
        event.source_ip
        for event in root_attempts
        if event.source_ip is not None
    }
    return [
        _build_finding(
            rule=ROOT_LOGIN_ATTEMPT,
            evidence_count=len(root_attempts),
            source_ip=_single_value_or_none(source_ips),
            username="root",
        )
    ]


def _find_invalid_user_enumeration(events: list[LogEvent]) -> list[Finding]:
    invalid_user_events = [
        event
        for event in events
        if "Failed password for invalid user " in event.raw_line
    ]
    if len(invalid_user_events) < INVALID_USER_ENUMERATION.threshold:
        return []

    source_ips = {
        event.source_ip for event in invalid_user_events if event.source_ip is not None
    }
    return [
        _build_finding(
            rule=INVALID_USER_ENUMERATION,
            evidence_count=len(invalid_user_events),
            source_ip=_single_value_or_none(source_ips),
            username=None,
        )
    ]


def _find_sudo_usage(events: list[LogEvent]) -> list[Finding]:
    sudo_events = [event for event in events if event.event_type == "sudo_command"]
    return [
        _build_finding(
            rule=SUDO_USAGE,
            evidence_count=1,
            source_ip=None,
            username=event.username,
            description=f"{SUDO_USAGE.description} Command: {event.command}",
        )
        for event in sudo_events
    ]


def _is_failed_ssh_event(event: LogEvent) -> bool:
    return event.service == "sshd" and event.event_type in {
        "ssh_failed_login",
        "root_login_attempt",
    }


def _is_root_failed_password(event: LogEvent) -> bool:
    return (
        event.service == "sshd"
        and event.username == "root"
        and "Failed password for root " in event.raw_line
    )


def _build_finding(
    rule: Rule,
    evidence_count: int,
    source_ip: str | None,
    username: str | None,
    description: str | None = None,
) -> Finding:
    return Finding(
        rule_id=rule.rule_id,
        title=rule.title,
        severity=rule.severity,
        description=description or rule.description,
        source_ip=source_ip,
        username=username,
        evidence_count=evidence_count,
        recommendation=rule.recommendation,
    )


def _single_value_or_none(values: set[str]) -> str | None:
    if len(values) == 1:
        return next(iter(values))
    return None
