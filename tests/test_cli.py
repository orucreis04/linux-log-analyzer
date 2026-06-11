import pytest

from linux_log_analyzer import cli
from linux_log_analyzer.cli import main


def test_cli_rejects_file_and_journal_together(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--file", "tests/sample_logs/auth_sample.log", "--journal"])

    captured = capsys.readouterr()

    assert exc_info.value.code == 2
    assert "Use either --file or --journal" in captured.err


def test_cli_requires_file_or_journal(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main([])

    captured = capsys.readouterr()

    assert exc_info.value.code == 2
    assert "One input source is required" in captured.err


def test_cli_rejects_journal_filters_without_journal(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--file", "tests/sample_logs/auth_sample.log", "--since", "today"])

    captured = capsys.readouterr()

    assert exc_info.value.code == 2
    assert "--since and --unit can only be used with --journal" in captured.err


def test_cli_missing_file_has_friendly_error() -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--file", "tests/sample_logs/missing.log"])

    assert "Log file not found" in str(exc_info.value)


def test_cli_handles_empty_log_file(tmp_path, capsys) -> None:
    empty_log = tmp_path / "empty.log"
    empty_log.write_text("", encoding="utf-8")

    exit_code = main(["--file", str(empty_log), "--format", "table"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Total Events: 0" in captured.out
    assert "Unparsed Lines: 0" in captured.out
    assert "No security findings detected." in captured.out


def test_cli_reports_unparsed_lines(tmp_path, capsys) -> None:
    log_file = tmp_path / "unknown.log"
    log_file.write_text("not a supported log line\n", encoding="utf-8")

    exit_code = main(["--file", str(log_file), "--format", "table"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Total Events: 0" in captured.out
    assert "Unparsed Lines: 1" in captured.out


def test_cli_keyboard_interrupt_has_clear_message(monkeypatch) -> None:
    def fake_run(args):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "run", fake_run)

    with pytest.raises(SystemExit) as exc_info:
        main(["--file", "tests/sample_logs/auth_sample.log"])

    assert str(exc_info.value) == "Operation cancelled by user."
