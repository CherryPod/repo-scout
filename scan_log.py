"""Append-only scan log: one-liner per scan in scan-log.md."""

from pathlib import Path

from config import SCAN_LOG_PATH
from patterns import RED_FLAG, WARNING, INFO
from scanner import ScanResult
from report import compute_verdict


def update_scan_log(result: ScanResult, report_path: str):
    """Append a one-line entry to the scan log.

    Format:
        | date | owner/repo | verdict | 2R/3W/5I | report path |
    """
    log_path = Path(SCAN_LOG_PATH)

    # Create header if the file doesn't exist
    if not log_path.exists():
        header = (
            "# repo-scout Scan Log\n\n"
            "| Date | Repository | Verdict | Findings | Report |\n"
            "| --- | --- | --- | --- | --- |\n"
        )
        log_path.write_text(header)

    verdict = compute_verdict(result)
    counts = result.count_by_severity()
    date_str = result.scan_time.strftime("%Y-%m-%d %H:%M")
    repo_str = f"{result.owner}/{result.repo}"

    # Format findings count: "2R/3W/5I"
    findings_str = (
        f"{counts.get(RED_FLAG, 0)}R/"
        f"{counts.get(WARNING, 0)}W/"
        f"{counts.get(INFO, 0)}I"
    )

    # Make report path relative to home for readability
    try:
        display_path = str(Path(report_path).relative_to(Path.home()))
        display_path = f"~/{display_path}"
    except ValueError:
        display_path = report_path

    entry = f"| {date_str} | {repo_str} | {verdict} | {findings_str} | `{display_path}` |\n"

    with open(log_path, "a") as f:
        f.write(entry)
