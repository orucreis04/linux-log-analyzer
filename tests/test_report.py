import json

from linux_log_analyzer.models import AnalysisSummary, Finding, IPStats
from linux_log_analyzer.report import (
    render_json,
    render_table,
    render_top_source_ips,
    render_txt,
    save_report,
)


def test_render_json_serializes_findings() -> None:
    content = render_json([_finding()])

    data = json.loads(content)

    assert data[0]["rule_id"] == "SSH_BRUTE_FORCE"
    assert data[0]["evidence_count"] == 5


def test_render_json_includes_summary_when_provided() -> None:
    content = render_json([_finding()], _summary())

    data = json.loads(content)

    assert data["summary"]["total_events"] == 10
    assert data["summary"]["risk_score"] == 25
    assert data["findings"][0]["rule_id"] == "SSH_BRUTE_FORCE"


def test_render_json_includes_top_source_ips_when_provided() -> None:
    content = render_json([_finding()], _summary(), [_ip_stats()])

    data = json.loads(content)

    assert data["top_source_ips"][0]["source_ip"] == "203.0.113.10"
    assert data["top_source_ips"][0]["failed_login_count"] == 10


def test_render_table_includes_key_columns() -> None:
    content = render_table([_finding()])

    assert "severity" in content
    assert "SSH_BRUTE_FORCE" in content
    assert "203.0.113.10" in content


def test_render_txt_uses_finding_block_format() -> None:
    content = render_txt([_finding()])

    assert "[HIGH] SSH Brute Force Detected" in content
    assert "Recommendation: Block the IP temporarily." in content


def test_render_txt_includes_summary_when_provided() -> None:
    content = render_txt([_finding()], _summary())

    assert "Linux Log Analyzer Summary" in content
    assert "Total Events: 10" in content
    assert "Risk Score: 25/100" in content
    assert "[HIGH] SSH Brute Force Detected" in content


def test_render_txt_includes_top_source_ips_when_provided() -> None:
    content = render_txt([_finding()], _summary(), [_ip_stats()])

    assert "Top Source IPs" in content
    assert "203.0.113.10 | total=12 | failed=10 | root=2 | invalid_user=4" in content


def test_render_top_source_ips_shows_accepted_activity() -> None:
    content = render_top_source_ips(
        [
            IPStats(
                source_ip="192.168.1.20",
                total_events=2,
                failed_login_count=0,
                accepted_login_count=2,
                root_attempt_count=0,
                invalid_user_attempt_count=0,
            )
        ]
    )

    assert "192.168.1.20 | total=2 | accepted=2" in content


def test_save_report_creates_parent_directory(tmp_path) -> None:
    output_path = tmp_path / "reports" / "report.txt"

    saved_path = save_report("hello", output_path)

    assert saved_path == output_path
    assert output_path.read_text(encoding="utf-8") == "hello"


def _finding() -> Finding:
    return Finding(
        rule_id="SSH_BRUTE_FORCE",
        title="SSH Brute Force Detected",
        severity="HIGH",
        description="Multiple failed SSH password attempts.",
        source_ip="203.0.113.10",
        username=None,
        evidence_count=5,
        recommendation="Block the IP temporarily.",
    )


def _summary() -> AnalysisSummary:
    return AnalysisSummary(
        total_events=10,
        unparsed_lines=3,
        total_findings=1,
        high_count=1,
        medium_count=0,
        low_count=0,
        info_count=0,
        risk_score=25,
    )


def _ip_stats() -> IPStats:
    return IPStats(
        source_ip="203.0.113.10",
        total_events=12,
        failed_login_count=10,
        accepted_login_count=0,
        root_attempt_count=2,
        invalid_user_attempt_count=4,
    )
