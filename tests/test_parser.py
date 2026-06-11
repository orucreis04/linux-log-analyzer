from pathlib import Path

from linux_log_analyzer.parser import LogParser, parse_line


def test_parse_line_failed_ssh_invalid_user() -> None:
    line = (
        "May 26 12:44:03 fedora sshd[1423]: Failed password for invalid user "
        "admin from 192.168.1.50 port 55322 ssh2"
    )

    event = parse_line(line)

    assert event is not None
    assert event.timestamp_raw == "May 26 12:44:03"
    assert event.hostname == "fedora"
    assert event.service == "sshd"
    assert event.pid == "1423"
    assert event.event_type == "ssh_failed_login"
    assert event.username == "admin"
    assert event.source_ip == "192.168.1.50"
    assert event.command is None
    assert event.raw_line == line


def test_parse_line_successful_ssh_login() -> None:
    event = parse_line(
        "May 26 12:45:10 fedora sshd[1423]: Accepted password for "
        "orucreis from 192.168.1.20 port 49812 ssh2"
    )

    assert event is not None
    assert event.event_type == "ssh_successful_login"
    assert event.username == "orucreis"
    assert event.source_ip == "192.168.1.20"


def test_parse_line_sudo_command() -> None:
    event = parse_line(
        "May 26 12:46:01 fedora sudo: orucreis : TTY=pts/0 ; "
        "PWD=/home/orucreis ; USER=root ; COMMAND=/usr/bin/dnf update"
    )

    assert event is not None
    assert event.service == "sudo"
    assert event.pid is None
    assert event.event_type == "sudo_command"
    assert event.username == "orucreis"
    assert event.command == "/usr/bin/dnf update"


def test_parse_line_root_login_attempt() -> None:
    event = parse_line(
        "May 26 12:47:33 fedora sshd[1500]: Failed password for root "
        "from 203.0.113.10 port 41231 ssh2"
    )

    assert event is not None
    assert event.event_type == "root_login_attempt"
    assert event.username == "root"
    assert event.source_ip == "203.0.113.10"


def test_parse_line_unknown_returns_none() -> None:
    event = parse_line("May 26 12:48:01 fedora systemd[1]: Started unrelated service.")

    assert event is None


def test_parse_file_returns_supported_events_only() -> None:
    sample = Path("tests/sample_logs/auth_sample.log")

    events = LogParser().parse_file(sample)

    assert len(events) == 4
    assert [event.event_type for event in events] == [
        "ssh_failed_login",
        "ssh_successful_login",
        "sudo_command",
        "root_login_attempt",
    ]
