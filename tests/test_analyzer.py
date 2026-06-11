from linux_log_analyzer.analyzer import (
    LogAnalyzer,
    analyze_events,
    calculate_risk_score,
    get_top_source_ips,
    summarize_analysis,
)
from linux_log_analyzer.models import Finding, LogEvent


def test_summarize_counts_entries() -> None:
    entries = [
        _event(event_type="ssh_failed_login", source_ip="192.168.1.50"),
    ]
    findings = [_finding(severity="MEDIUM")]

    summary = LogAnalyzer().summarize(2, entries, findings)

    assert summary.total_events == 1
    assert summary.unparsed_lines == 1
    assert summary.total_findings == 1
    assert summary.medium_count == 1
    assert summary.risk_score == 15


def test_analyze_events_detects_ssh_brute_force() -> None:
    events = [
        _event(event_type="ssh_failed_login", source_ip="203.0.113.10")
        for _ in range(5)
    ]

    findings = analyze_events(events)

    assert len(findings) == 1
    assert findings[0].rule_id == "SSH_BRUTE_FORCE"
    assert findings[0].severity == "HIGH"
    assert findings[0].source_ip == "203.0.113.10"
    assert findings[0].evidence_count == 5


def test_analyze_events_detects_root_login_attempt() -> None:
    events = [
        _event(
            event_type="root_login_attempt",
            username="root",
            source_ip="203.0.113.10",
            raw_line=(
                "May 26 12:47:33 fedora sshd[1500]: Failed password for root "
                "from 203.0.113.10 port 41231 ssh2"
            ),
        )
    ]

    findings = analyze_events(events)

    assert len(findings) == 1
    assert findings[0].rule_id == "ROOT_LOGIN_ATTEMPT"
    assert findings[0].severity == "MEDIUM"
    assert findings[0].username == "root"


def test_analyze_events_detects_sudo_usage() -> None:
    events = [
        _event(
            service="sudo",
            pid=None,
            event_type="sudo_command",
            username="orucreis",
            command="/usr/bin/dnf update",
        )
    ]

    findings = analyze_events(events)

    assert len(findings) == 1
    assert findings[0].rule_id == "SUDO_USAGE"
    assert findings[0].severity == "INFO"
    assert findings[0].username == "orucreis"
    assert findings[0].evidence_count == 1


def test_analyze_events_detects_invalid_user_enumeration() -> None:
    events = [
        _event(
            username=username,
            source_ip="192.168.1.50",
            raw_line=(
                "May 26 12:44:03 fedora sshd[1423]: Failed password for invalid "
                f"user {username} from 192.168.1.50 port 55322 ssh2"
            ),
        )
        for username in ("admin", "test", "oracle")
    ]

    findings = analyze_events(events)

    assert len(findings) == 1
    assert findings[0].rule_id == "INVALID_USER_ENUMERATION"
    assert findings[0].severity == "MEDIUM"
    assert findings[0].source_ip == "192.168.1.50"
    assert findings[0].evidence_count == 3


def test_analyze_events_sorts_findings_by_severity() -> None:
    events = [
        _event(service="sudo", event_type="sudo_command", command="/usr/bin/id"),
        *[
            _event(event_type="ssh_failed_login", source_ip="203.0.113.10")
            for _ in range(5)
        ],
        _event(event_type="root_login_attempt", username="root"),
    ]

    findings = analyze_events(events)

    assert [finding.severity for finding in findings] == ["HIGH", "MEDIUM", "INFO"]


def test_calculate_risk_score_uses_severity_weights() -> None:
    findings = [
        _finding(severity="HIGH"),
        _finding(severity="MEDIUM"),
        _finding(severity="LOW"),
        _finding(severity="INFO"),
    ]

    assert calculate_risk_score(findings) == 50


def test_calculate_risk_score_is_capped_at_100() -> None:
    findings = [_finding(severity="HIGH") for _ in range(5)]

    assert calculate_risk_score(findings) == 100


def test_summarize_analysis_counts_severities() -> None:
    events = [_event(), _event(event_type="sudo_command")]
    findings = [
        _finding(severity="HIGH"),
        _finding(severity="MEDIUM"),
        _finding(severity="LOW"),
        _finding(severity="INFO"),
        _finding(severity="INFO"),
    ]

    summary = summarize_analysis(4, events, findings)

    assert summary.total_events == 2
    assert summary.unparsed_lines == 2
    assert summary.total_findings == 5
    assert summary.high_count == 1
    assert summary.medium_count == 1
    assert summary.low_count == 1
    assert summary.info_count == 2
    assert summary.risk_score == 52


def test_get_top_source_ips_counts_login_activity() -> None:
    events = [
        _event(event_type="ssh_failed_login", source_ip="203.0.113.10"),
        _event(
            event_type="root_login_attempt",
            username="root",
            source_ip="203.0.113.10",
            raw_line=(
                "May 26 12:47:33 fedora sshd[1500]: Failed password for root "
                "from 203.0.113.10 port 41231 ssh2"
            ),
        ),
        _event(
            event_type="ssh_failed_login",
            username="admin",
            source_ip="203.0.113.10",
            raw_line=(
                "May 26 12:44:03 fedora sshd[1423]: Failed password for invalid "
                "user admin from 203.0.113.10 port 55322 ssh2"
            ),
        ),
        _event(event_type="ssh_successful_login", source_ip="192.168.1.20"),
        _event(event_type="ssh_successful_login", source_ip="192.168.1.20"),
        _event(service="sudo", event_type="sudo_command", source_ip=None),
    ]

    stats = get_top_source_ips(events)

    assert len(stats) == 2
    assert stats[0].source_ip == "203.0.113.10"
    assert stats[0].total_events == 3
    assert stats[0].failed_login_count == 2
    assert stats[0].accepted_login_count == 0
    assert stats[0].root_attempt_count == 1
    assert stats[0].invalid_user_attempt_count == 1
    assert stats[1].source_ip == "192.168.1.20"
    assert stats[1].accepted_login_count == 2


def test_get_top_source_ips_respects_limit() -> None:
    events = [
        _event(source_ip="203.0.113.10"),
        _event(source_ip="192.168.1.20"),
    ]

    stats = get_top_source_ips(events, limit=1)

    assert len(stats) == 1


def _event(
    event_type: str = "ssh_failed_login",
    service: str = "sshd",
    pid: str | None = "1423",
    username: str | None = "admin",
    source_ip: str | None = "192.168.1.50",
    command: str | None = None,
    raw_line: str | None = None,
) -> LogEvent:
    return LogEvent(
        timestamp_raw="May 26 12:44:03",
        hostname="fedora",
        service=service,
        pid=pid,
        event_type=event_type,
        username=username,
        source_ip=source_ip,
        command=command,
        raw_line=raw_line or "May 26 12:44:03 fedora sshd[1423]: Failed password",
    )


def _finding(severity: str) -> Finding:
    return Finding(
        rule_id=f"{severity}_RULE",
        title=f"{severity} Finding",
        severity=severity,
        description="description",
        source_ip=None,
        username=None,
        evidence_count=1,
        recommendation="recommendation",
    )
