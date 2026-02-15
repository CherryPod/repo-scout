"""CLI entry point for repo-scout."""

import sys
import argparse
from pathlib import Path

from config import DEFAULT_REPORTS_DIR
from utils import parse_repo_input, sanitize_filename
from scanner import run_scan
from report import generate_report, compute_verdict
from scan_log import update_scan_log
from patterns import RED_FLAG


def main():
    parser = argparse.ArgumentParser(
        prog="repo-scout",
        description="Scan GitHub repos for suspicious code before cloning.",
    )
    parser.add_argument(
        "repo",
        help="Repository to scan: 'owner/repo' or full GitHub URL",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="API-only scan (no tarball download)",
    )
    parser.add_argument(
        "--output", "-o",
        help="Output directory for the report (default: ~/git-audits/reports/)",
    )
    parser.add_argument(
        "--token",
        help="GitHub token (overrides ~/.secrets/repo-scout.env)",
    )

    args = parser.parse_args()

    # Parse repo input
    try:
        owner, repo = parse_repo_input(args.repo)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    # Determine output directory
    if args.output:
        reports_dir = Path(args.output).expanduser().resolve() / "reports"
    else:
        reports_dir = DEFAULT_REPORTS_DIR

    reports_dir.mkdir(parents=True, exist_ok=True)

    # Run scan
    try:
        result = run_scan(owner, repo, quick=args.quick, token=args.token)
    except Exception as e:
        print(f"Error during scan: {e}", file=sys.stderr)
        sys.exit(1)

    # Check if we got metadata (if not, scan failed early)
    if not result.metadata:
        print("Scan failed — no data collected.", file=sys.stderr)
        sys.exit(1)

    # Generate report
    report_text = generate_report(result)
    verdict = compute_verdict(result)

    # Write report
    date_str = result.scan_time.strftime("%Y-%m-%d")
    safe_name = sanitize_filename(f"{owner}_{repo}")
    report_filename = f"{date_str}_{safe_name}.md"
    report_path = reports_dir / report_filename

    report_path.write_text(report_text)
    print(f"\n  Report saved to: {report_path}")

    # Update scan log
    try:
        update_scan_log(result, str(report_path))
    except OSError as e:
        print(f"  Warning: Could not update scan log: {e}", file=sys.stderr)

    # Print verdict
    print(f"\n  === {verdict} ===\n")

    # Exit code based on findings
    counts = result.count_by_severity()
    if counts.get(RED_FLAG, 0) > 0:
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
