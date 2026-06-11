"""Utility helpers for filesystem validation and system commands."""

from pathlib import Path
import subprocess


def ensure_readable_file(file_path: Path) -> Path:
    """Validate that a path points to an existing regular file."""

    path = file_path.expanduser()
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")
    if not path.is_file():
        raise IsADirectoryError(f"Expected a log file, got directory: {path}")
    return path


def run_journalctl(since: str | None, unit: str | None) -> list[str]:
    """Run journalctl safely and return output lines."""

    command = ["journalctl", "--no-pager"]
    if since is not None:
        command.extend(["--since", since])
    if unit is not None:
        command.extend(["--unit", unit])

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            check=False,
            text=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            "journalctl was not found. This feature requires systemd journalctl."
        ) from exc
    except PermissionError as exc:
        raise RuntimeError(
            "Permission denied while running journalctl. Try a user with journal "
            "access or run with sudo."
        ) from exc
    except subprocess.SubprocessError as exc:
        raise RuntimeError(f"journalctl execution failed: {exc}") from exc
    except OSError as exc:
        raise RuntimeError(f"Unable to run journalctl: {exc}") from exc

    if result.returncode != 0:
        raise RuntimeError(_journalctl_error_message(result.stderr))

    return result.stdout.splitlines()


def _journalctl_error_message(stderr: str) -> str:
    message = stderr.strip()
    lower_message = message.lower()
    if "permission denied" in lower_message or "access denied" in lower_message:
        return (
            "Permission denied while reading the systemd journal. Try a user with "
            "journal access or run with sudo."
        )
    if message:
        return f"journalctl failed: {message}"
    return "journalctl failed with an unknown error."
