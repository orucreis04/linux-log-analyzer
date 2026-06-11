import subprocess

import pytest

from linux_log_analyzer import utils


def test_run_journalctl_builds_safe_argument_list(monkeypatch) -> None:
    captured_command: list[str] = []

    def fake_run(command, capture_output, check, text):
        captured_command.extend(command)
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout="May 26 12:44:03 fedora sshd[1]: message\n",
            stderr="",
        )

    monkeypatch.setattr(utils.subprocess, "run", fake_run)

    lines = utils.run_journalctl(since="1 hour ago", unit="sshd")

    assert captured_command == [
        "journalctl",
        "--no-pager",
        "--since",
        "1 hour ago",
        "--unit",
        "sshd",
    ]
    assert lines == ["May 26 12:44:03 fedora sshd[1]: message"]


def test_run_journalctl_missing_binary_has_clear_error(monkeypatch) -> None:
    def fake_run(command, capture_output, check, text):
        raise FileNotFoundError

    monkeypatch.setattr(utils.subprocess, "run", fake_run)

    with pytest.raises(RuntimeError, match="journalctl was not found"):
        utils.run_journalctl(since=None, unit=None)


def test_run_journalctl_permission_error_has_clear_error(monkeypatch) -> None:
    def fake_run(command, capture_output, check, text):
        return subprocess.CompletedProcess(
            args=command,
            returncode=1,
            stdout="",
            stderr="Permission denied",
        )

    monkeypatch.setattr(utils.subprocess, "run", fake_run)

    with pytest.raises(RuntimeError, match="Permission denied"):
        utils.run_journalctl(since=None, unit=None)


def test_run_journalctl_subprocess_error_has_clear_error(monkeypatch) -> None:
    def fake_run(command, capture_output, check, text):
        raise subprocess.SubprocessError("boom")

    monkeypatch.setattr(utils.subprocess, "run", fake_run)

    with pytest.raises(RuntimeError, match="journalctl execution failed"):
        utils.run_journalctl(since=None, unit=None)
