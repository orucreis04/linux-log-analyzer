"""Command-line interface for linux-log-analyzer."""

import argparse
from pathlib import Path
import textwrap

from linux_log_analyzer.analyzer import (
    LogAnalyzer,
    analyze_events,
    get_top_source_ips,
)
from linux_log_analyzer.models import AnalysisSummary, Finding, IPStats, LogEvent
from linux_log_analyzer.parser import LogParser
from linux_log_analyzer.report import (
    format_summary,
    render_json,
    render_table,
    render_txt,
    render_top_source_ips,
    save_report,
)
from linux_log_analyzer.utils import ensure_readable_file, run_journalctl

SUPPORTED_FORMATS = {"table", "json", "txt"}


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level CLI argument parser."""

    parser = argparse.ArgumentParser(
        prog="linux-log-analyzer",
        description=(
            "Analyze Linux authentication logs and systemd journal output for "
            "security-relevant activity."
        ),
        epilog=textwrap.dedent(
            """\
            examples:
              python main.py --file tests/sample_logs/auth_sample.log --format table
              python main.py --journal --unit sshd --since today
              python main.py --file /var/log/secure --format json \\
                --output reports/report.json

            input source:
              Use exactly one source: --file or --journal.
            """
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--file",
        type=Path,
        metavar="PATH",
        help="Path to an auth.log, secure, or journalctl text export.",
    )
    parser.add_argument(
        "--journal",
        action="store_true",
        help="Read logs from systemd journalctl instead of a file.",
    )
    parser.add_argument(
        "--since",
        metavar="WHEN",
        help='Optional journalctl --since value, for example "1 hour ago" or today.',
    )
    parser.add_argument(
        "--unit",
        metavar="UNIT",
        help="Optional systemd unit filter for journalctl, for example sshd.",
    )
    parser.add_argument(
        "--format",
        default="table",
        metavar="FORMAT",
        help="Report output format: table, json, or txt.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        metavar="PATH",
        help="Optional path where the rendered report will be saved.",
    )
    return parser


def run(args: argparse.Namespace) -> int:
    """Run the CLI workflow for parsed arguments."""

    report_format = _normalize_format(args.format)
    total_lines, events, _source = _load_events(args)
    findings = analyze_events(events)
    summary = LogAnalyzer().summarize(total_lines, events, findings)
    top_source_ips = get_top_source_ips(events)
    content = _render_report(report_format, findings, summary, top_source_ips)
    if args.output is not None:
        saved_path = save_report(content, args.output)
        print(f"Report saved to {saved_path}")
        return 0

    print(format_summary(summary))
    print()
    print(content)
    return 0


def _load_events(args: argparse.Namespace) -> tuple[int, list[LogEvent], str]:
    parser = LogParser()
    if args.journal:
        lines = run_journalctl(since=args.since, unit=args.unit)
        return len(lines), parser.parse_lines(lines), _journal_source(args)

    log_path = ensure_readable_file(args.file)
    return _count_lines(log_path), parser.parse_file(log_path), str(log_path)


def _journal_source(args: argparse.Namespace) -> str:
    parts = ["journalctl"]
    if args.unit is not None:
        parts.extend(["--unit", args.unit])
    if args.since is not None:
        parts.extend(["--since", args.since])
    return " ".join(parts)


def _normalize_format(report_format: str) -> str:
    normalized = report_format.lower()
    if normalized not in SUPPORTED_FORMATS:
        formats = ", ".join(sorted(SUPPORTED_FORMATS))
        raise SystemExit(
            f"Unsupported format '{report_format}'. Please use one of: {formats}."
        )
    return normalized


def _render_report(
    report_format: str,
    findings: list[Finding],
    summary: AnalysisSummary,
    top_source_ips: list[IPStats],
) -> str:
    if report_format == "json":
        return render_json(findings, summary, top_source_ips)
    if report_format == "txt":
        return render_txt(findings, summary, top_source_ips)
    return f"{render_table(findings)}\n\n{render_top_source_ips(top_source_ips)}"


def _count_lines(file_path: Path) -> int:
    with file_path.open("r", encoding="utf-8", errors="replace") as log_file:
        return sum(1 for _ in log_file)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""

    parser = build_parser()
    args = parser.parse_args(argv)
    _validate_source_args(parser, args)
    try:
        return run(args)
    except KeyboardInterrupt as exc:
        raise SystemExit("Operation cancelled by user.") from exc
    except (FileNotFoundError, IsADirectoryError, RuntimeError) as exc:
        raise SystemExit(str(exc)) from exc
    except OSError as exc:
        raise SystemExit(f"File operation failed: {exc}") from exc


def _validate_source_args(
    parser: argparse.ArgumentParser, args: argparse.Namespace
) -> None:
    if args.file is not None and args.journal:
        parser.error("Use either --file or --journal, not both.")
    if args.file is None and not args.journal:
        parser.error("One input source is required: use --file <path> or --journal.")
    if not args.journal and (args.since is not None or args.unit is not None):
        parser.error("--since and --unit can only be used with --journal.")
