"""Markdown report generation from scan results."""

from datetime import datetime, timezone

from patterns import RED_FLAG, WARNING, INFO
from scanner import ScanResult
from utils import format_size


# Verdict thresholds
def compute_verdict(result: ScanResult) -> str:
    """Compute a risk verdict based on findings.

    Verdict scale:
        HIGH RISK       — any red flags
        ELEVATED RISK   — 5+ warnings, no red flags
        MODERATE RISK   — 1-4 warnings, no red flags
        LOW RISK        — info findings only (3+)
        MINIMAL RISK    — 0-2 info findings only
    """
    counts = result.count_by_severity()
    red = counts.get(RED_FLAG, 0)
    warn = counts.get(WARNING, 0)
    info = counts.get(INFO, 0)

    if red > 0:
        return "HIGH RISK"
    elif warn >= 5:
        return "ELEVATED RISK"
    elif warn >= 1:
        return "MODERATE RISK"
    elif info >= 3:
        return "LOW RISK"
    else:
        return "MINIMAL RISK"


def generate_report(result: ScanResult) -> str:
    """Generate a full markdown report from scan results."""
    verdict = compute_verdict(result)
    counts = result.count_by_severity()
    meta = result.metadata

    lines = []

    # -- Header --
    lines.append(f"# repo-scout Report: {result.owner}/{result.repo}")
    lines.append("")
    lines.append(f"**Scan date:** {result.scan_time.strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append(f"**Scan type:** {result.scan_type}")
    lines.append("")

    # -- Verdict --
    lines.append(f"## Verdict: {verdict}")
    lines.append("")
    lines.append(
        f"| Red Flags | Warnings | Info |"
    )
    lines.append("| --- | --- | --- |")
    lines.append(
        f"| {counts.get(RED_FLAG, 0)} | {counts.get(WARNING, 0)} | {counts.get(INFO, 0)} |"
    )
    lines.append("")

    # -- Repo metadata --
    lines.append("## Repository Metadata")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("| --- | --- |")

    if meta:
        lines.append(f"| Name | [{meta.get('full_name', 'N/A')}]({meta.get('html_url', '')}) |")
        lines.append(f"| Description | {meta.get('description') or 'None'} |")
        lines.append(f"| Stars | {meta.get('stargazers_count', 'N/A'):,} |")
        lines.append(f"| Forks | {meta.get('forks_count', 'N/A'):,} |")
        lines.append(f"| Open Issues | {meta.get('open_issues_count', 'N/A'):,} |")
        lines.append(f"| Language | {meta.get('language') or 'N/A'} |")
        license_info = meta.get("license")
        license_name = license_info.get("spdx_id", "N/A") if isinstance(license_info, dict) else "None"
        lines.append(f"| License | {license_name} |")
        lines.append(f"| Created | {_format_date(meta.get('created_at', ''))} |")
        lines.append(f"| Last push | {_format_date(meta.get('pushed_at', ''))} |")
        lines.append(f"| Size | {format_size(meta.get('size', 0) * 1024)} |")
        lines.append(f"| Default branch | {meta.get('default_branch', 'N/A')} |")
        lines.append(f"| Archived | {'Yes' if meta.get('archived') else 'No'} |")

        # Contributors summary
        if result.contributors:
            count = len(result.contributors)
            top = ", ".join(
                c.get("login", "?") for c in result.contributors[:5]
            )
            if count > 5:
                top += f" (+{count - 5} more)"
            lines.append(f"| Contributors | {count}: {top} |")
    lines.append("")

    # -- File tree summary --
    if result.file_tree:
        total_files = sum(1 for e in result.file_tree if e.get("type") == "blob")
        total_dirs = sum(1 for e in result.file_tree if e.get("type") == "tree")
        lines.append("## File Tree Summary")
        lines.append("")
        lines.append(f"- **{total_files}** files, **{total_dirs}** directories")
        lines.append(f"- **{result.files_scanned}** files scanned, **{result.files_skipped}** skipped")
        lines.append("")

    # -- Findings --
    if result.findings:
        lines.append("## Findings")
        lines.append("")

        # Group and sort by severity
        for severity in [RED_FLAG, WARNING, INFO]:
            severity_findings = [f for f in result.findings if f.severity == severity]
            if not severity_findings:
                continue

            severity_label = {RED_FLAG: "Red Flags", WARNING: "Warnings", INFO: "Info"}[severity]
            severity_icon = {RED_FLAG: "🔴", WARNING: "🟡", INFO: "🔵"}[severity]
            lines.append(f"### {severity_icon} {severity_label} ({len(severity_findings)})")
            lines.append("")

            for finding in severity_findings:
                location = ""
                if finding.file_path:
                    location = f" — `{finding.file_path}`"
                    if finding.line_number:
                        location += f":{finding.line_number}"

                lines.append(f"- **{finding.name}**{location}")
                lines.append(f"  - {finding.description}")
                if finding.matched_text:
                    # Escape backticks in matched text
                    escaped = finding.matched_text.replace("`", "\\`")
                    lines.append(f"  - Match: `{escaped}`")

            lines.append("")
    else:
        lines.append("## Findings")
        lines.append("")
        lines.append("No findings.")
        lines.append("")

    # -- Errors --
    if result.errors:
        lines.append("## Scan Errors")
        lines.append("")
        for error in result.errors:
            lines.append(f"- {error}")
        lines.append("")

    # -- Footer --
    lines.append("---")
    lines.append(f"*Generated by repo-scout ({result.scan_type} scan)*")

    return "\n".join(lines)


def _format_date(iso_str: str) -> str:
    """Format an ISO date string into a readable format."""
    if not iso_str:
        return "N/A"
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d")
    except (ValueError, TypeError):
        return iso_str
