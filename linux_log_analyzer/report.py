"""Report rendering and persistence helpers."""

from dataclasses import asdict
import json
from pathlib import Path

from linux_log_analyzer.models import AnalysisSummary, Finding, IPStats, LogEvent


def format_summary(summary: AnalysisSummary) -> str:
    """Format the high-level analysis summary."""

    return (
        "Linux Log Analyzer Summary\n"
        f"Total Events: {summary.total_events}\n"
        f"Unparsed Lines: {summary.unparsed_lines}\n"
        f"Findings: {summary.total_findings}\n"
        f"Risk Score: {summary.risk_score}/100"
    )


def format_events_table(events: list[LogEvent]) -> str:
    """Format parsed events as a compact terminal table."""

    if not events:
        return "No supported log events found."

    headers = ["timestamp", "host", "service", "pid", "type", "user", "ip", "command"]
    rows = [_event_to_row(event) for event in events]
    widths = _column_widths(headers, rows)
    lines = [_format_row(headers, widths), _format_separator(widths)]
    lines.extend(_format_row(row, widths) for row in rows)
    return "\n".join(lines)


def _event_to_row(event: LogEvent) -> list[str]:
    return [
        event.timestamp_raw,
        event.hostname,
        event.service,
        event.pid or "-",
        event.event_type,
        event.username or "-",
        event.source_ip or "-",
        event.command or "-",
    ]


def _column_widths(headers: list[str], rows: list[list[str]]) -> list[int]:
    return [
        max(len(headers[index]), *(len(row[index]) for row in rows))
        for index in range(len(headers))
    ]


def _format_row(values: list[str], widths: list[int]) -> str:
    return " | ".join(value.ljust(widths[index]) for index, value in enumerate(values))


def _format_separator(widths: list[int]) -> str:
    return "-+-".join("-" * width for width in widths)


def format_findings(findings: list[Finding]) -> str:
    """Format findings as readable terminal blocks."""

    return render_txt(findings)


def render_table(findings: list[Finding]) -> str:
    """Render findings as a compact table."""

    if not findings:
        return "No security findings detected."

    headers = ["severity", "rule", "title", "ip", "user", "count"]
    rows = [
        [
            finding.severity,
            finding.rule_id,
            finding.title,
            finding.source_ip or "-",
            finding.username or "-",
            str(finding.evidence_count),
        ]
        for finding in findings
    ]
    widths = _column_widths(headers, rows)
    lines = [_format_row(headers, widths), _format_separator(widths)]
    lines.extend(_format_row(row, widths) for row in rows)
    return "\n".join(lines)


def render_top_source_ips(top_source_ips: list[IPStats]) -> str:
    """Render top source IP statistics as readable lines."""

    if not top_source_ips:
        return "Top Source IPs\nNo source IP activity found."

    lines = ["Top Source IPs"]
    lines.extend(_format_ip_stats(stats) for stats in top_source_ips)
    return "\n".join(lines)


def render_json(
    findings: list[Finding],
    summary: AnalysisSummary | None = None,
    top_source_ips: list[IPStats] | None = None,
) -> str:
    """Render findings as pretty JSON."""

    if summary is not None:
        data = {
            "summary": asdict(summary),
            "findings": [asdict(finding) for finding in findings],
        }
        if top_source_ips is not None:
            data["top_source_ips"] = [asdict(stats) for stats in top_source_ips]
        return json.dumps(data, ensure_ascii=False, indent=2)

    return json.dumps(
        [asdict(finding) for finding in findings],
        ensure_ascii=False,
        indent=2,
    )


def render_txt(
    findings: list[Finding],
    summary: AnalysisSummary | None = None,
    top_source_ips: list[IPStats] | None = None,
) -> str:
    """Render findings as readable text blocks."""

    sections = [_render_txt_findings(findings)]
    if top_source_ips is not None:
        sections.append(render_top_source_ips(top_source_ips))
    body = "\n\n".join(sections)
    if summary is not None:
        return f"{format_summary(summary)}\n\n{body}"
    return body


def _render_txt_findings(findings: list[Finding]) -> str:
    if not findings:
        return "No security findings detected."

    return "\n\n".join(_format_finding(finding) for finding in findings)


def _format_ip_stats(stats: IPStats) -> str:
    parts = [
        stats.source_ip,
        f"total={stats.total_events}",
    ]
    if stats.failed_login_count:
        parts.append(f"failed={stats.failed_login_count}")
    if stats.accepted_login_count:
        parts.append(f"accepted={stats.accepted_login_count}")
    if stats.root_attempt_count:
        parts.append(f"root={stats.root_attempt_count}")
    if stats.invalid_user_attempt_count:
        parts.append(f"invalid_user={stats.invalid_user_attempt_count}")
    return " | ".join(parts)


def save_report(content: str, output_path: Path) -> Path:
    """Save rendered report content and create parent directories as needed."""

    path = output_path.expanduser()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    except OSError as exc:
        raise OSError(f"Could not save report to {path}: {exc}") from exc
    return path


def _format_finding(finding: Finding) -> str:
    lines = [
        f"[{finding.severity}] {finding.title}",
        f"Rule: {finding.rule_id}",
    ]
    if finding.source_ip is not None:
        lines.append(f"IP: {finding.source_ip}")
    if finding.username is not None:
        lines.append(f"User: {finding.username}")
    lines.extend(
        [
            f"Evidence Count: {finding.evidence_count}",
            f"Description: {finding.description}",
            f"Recommendation: {finding.recommendation}",
        ]
    )
    return "\n".join(lines)
