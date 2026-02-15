"""Scanning engine: orchestrates quick and deep scans."""

import os
import sys
import tarfile
import tempfile
import shutil
from datetime import datetime, timezone
from pathlib import Path

from config import MAX_FILE_SIZE, MAX_REPO_SIZE, PRIORITY_FILES
from github_api import GitHubClient, GitHubAPIError
from patterns import (
    ALL_CONTENT_PATTERNS,
    SUSPICIOUS_FILENAMES,
    REPO_HEALTH_CHECKS,
    RED_FLAG,
    WARNING,
    INFO,
)
from utils import is_binary_file, should_scan_file, format_size


class Finding:
    """A single finding from a scan."""

    def __init__(self, name: str, severity: str, description: str,
                 file_path: str = None, line_number: int = None,
                 matched_text: str = None, category: str = None):
        self.name = name
        self.severity = severity
        self.description = description
        self.file_path = file_path
        self.line_number = line_number
        self.matched_text = matched_text
        self.category = category

    def __repr__(self):
        loc = f" @ {self.file_path}" if self.file_path else ""
        if self.line_number:
            loc += f":{self.line_number}"
        return f"[{self.severity}] {self.name}{loc}"


class ScanResult:
    """Holds all data from a completed scan."""

    def __init__(self, owner: str, repo: str, scan_type: str):
        self.owner = owner
        self.repo = repo
        self.scan_type = scan_type  # "quick" or "deep"
        self.metadata = {}
        self.contributors = []
        self.file_tree = []
        self.findings: list[Finding] = []
        self.scan_time = datetime.now(timezone.utc)
        self.files_scanned = 0
        self.files_skipped = 0
        self.errors: list[str] = []

    def add_finding(self, finding: Finding):
        self.findings.append(finding)

    def count_by_severity(self) -> dict[str, int]:
        counts = {RED_FLAG: 0, WARNING: 0, INFO: 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


def run_scan(owner: str, repo: str, quick: bool = False,
             token: str = None) -> ScanResult:
    """Main scan entry point.

    Args:
        owner: GitHub repo owner
        repo: GitHub repo name
        quick: If True, API-only scan. If False (default), full deep scan.
        token: Optional GitHub token override

    Returns:
        ScanResult with all findings
    """
    scan_type = "quick" if quick else "deep"
    result = ScanResult(owner, repo, scan_type)
    client = GitHubClient(token=token)

    print(f"Scanning {owner}/{repo} ({scan_type} scan)...")

    # -- Phase 1: Repo metadata --
    print("  Fetching repo metadata...")
    try:
        result.metadata = client.get_repo_metadata(owner, repo)
    except GitHubAPIError as e:
        print(f"  ERROR: {e}", file=sys.stderr)
        result.errors.append(str(e))
        return result

    _check_repo_health(result)

    # -- Phase 2: Contributors --
    print("  Fetching contributors...")
    try:
        result.contributors = client.get_contributors(owner, repo)
    except GitHubAPIError:
        result.errors.append("Could not fetch contributors")

    _check_contributor_health(result)

    # -- Phase 3: File tree --
    print("  Fetching file tree...")
    try:
        result.file_tree = client.get_file_tree(owner, repo)
    except GitHubAPIError as e:
        result.errors.append(f"Could not fetch file tree: {e}")

    _check_suspicious_filenames(result)

    # -- Phase 4: Priority file reads (quick scan) --
    print("  Reading priority files...")
    _scan_priority_files(client, owner, repo, result)

    if quick:
        _print_summary(result)
        return result

    # -- Phase 5: Deep scan — tarball download and full scan --
    repo_size = result.metadata.get("size", 0) * 1024  # API returns KB
    if repo_size > MAX_REPO_SIZE:
        print(
            f"  WARNING: Repo is {format_size(repo_size)} — "
            f"exceeds {format_size(MAX_REPO_SIZE)} limit. "
            "Skipping deep scan, using quick scan results only.",
            file=sys.stderr,
        )
        result.scan_type = "quick (deep skipped — repo too large)"
        _print_summary(result)
        return result

    print("  Downloading tarball for deep scan...")
    try:
        tarball_path = client.download_tarball(owner, repo)
    except GitHubAPIError as e:
        result.errors.append(f"Could not download tarball: {e}")
        print(f"  ERROR: {e}", file=sys.stderr)
        _print_summary(result)
        return result

    # Extract and scan
    tmp_dir = tempfile.mkdtemp(prefix="repo-scout-scan-")
    try:
        _extract_and_scan(tarball_path, tmp_dir, result)
    finally:
        # Always clean up
        shutil.rmtree(tmp_dir, ignore_errors=True)
        tarball_path.unlink(missing_ok=True)
        print("  Cleaned up temporary files.")

    _print_summary(result)
    return result


def _check_repo_health(result: ScanResult):
    """Assess repo health from metadata."""
    meta = result.metadata

    # Archived
    if meta.get("archived"):
        check = REPO_HEALTH_CHECKS["archived"]
        result.add_finding(Finding(
            check["name"], check["severity"], check["description"],
            category="repo_health",
        ))

    # No license
    if not meta.get("license"):
        check = REPO_HEALTH_CHECKS["no_license"]
        result.add_finding(Finding(
            check["name"], check["severity"], check["description"],
            category="repo_health",
        ))

    # No description
    if not meta.get("description"):
        check = REPO_HEALTH_CHECKS["no_description"]
        result.add_finding(Finding(
            check["name"], check["severity"], check["description"],
            category="repo_health",
        ))

    # Low stars
    if meta.get("stargazers_count", 0) < 10:
        check = REPO_HEALTH_CHECKS["low_stars"]
        result.add_finding(Finding(
            check["name"], check["severity"], check["description"],
            category="repo_health",
        ))

    # Very new (created less than 30 days ago)
    created_str = meta.get("created_at", "")
    if created_str:
        try:
            created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - created).days
            if age_days < 30:
                check = REPO_HEALTH_CHECKS["very_new"]
                result.add_finding(Finding(
                    check["name"], check["severity"],
                    f"{check['description']} ({age_days} days old)",
                    category="repo_health",
                ))
        except (ValueError, TypeError):
            pass

    # Stale (no push in 2 years)
    pushed_str = meta.get("pushed_at", "")
    if pushed_str:
        try:
            pushed = datetime.fromisoformat(pushed_str.replace("Z", "+00:00"))
            stale_days = (datetime.now(timezone.utc) - pushed).days
            if stale_days > 730:
                check = REPO_HEALTH_CHECKS["stale"]
                result.add_finding(Finding(
                    check["name"], check["severity"],
                    f"{check['description']} (last push {stale_days} days ago)",
                    category="repo_health",
                ))
        except (ValueError, TypeError):
            pass


def _check_contributor_health(result: ScanResult):
    """Check contributor count."""
    if isinstance(result.contributors, list) and len(result.contributors) <= 1:
        check = REPO_HEALTH_CHECKS["single_contributor"]
        result.add_finding(Finding(
            check["name"], check["severity"], check["description"],
            category="repo_health",
        ))


def _check_suspicious_filenames(result: ScanResult):
    """Scan the file tree for suspicious filenames."""
    for entry in result.file_tree:
        path = entry.get("path", "")
        for rule in SUSPICIOUS_FILENAMES:
            if rule["pattern"].search(path):
                # Check exclude pattern if present
                exclude = rule.get("exclude_pattern")
                if exclude and exclude.search(path):
                    continue
                result.add_finding(Finding(
                    rule["name"], rule["severity"], rule["description"],
                    file_path=path, category="filename",
                ))


def _scan_priority_files(client: GitHubClient, owner: str, repo: str,
                         result: ScanResult):
    """Read and scan priority files via the API (used in both quick and deep)."""
    # Build a set of paths that exist in the tree for quick lookup
    tree_paths = {e.get("path", "") for e in result.file_tree}

    for priority_path in PRIORITY_FILES:
        if priority_path not in tree_paths:
            continue

        try:
            content = client.get_file_content(owner, repo, priority_path)
            if content:
                _scan_content(content, priority_path, result)
                result.files_scanned += 1
        except GitHubAPIError:
            result.errors.append(f"Could not read {priority_path}")


def _scan_content(content: str, file_path: str, result: ScanResult):
    """Run all content patterns against a file's text."""
    # Determine file extension for filtering
    filename = file_path.rsplit("/", 1)[-1] if "/" in file_path else file_path
    dot_pos = filename.rfind(".")
    ext = filename[dot_pos:].lower() if dot_pos != -1 else ""

    lines = content.split("\n")

    for pattern_rule in ALL_CONTENT_PATTERNS:
        # Check if this rule applies to this file type
        file_types = pattern_rule.get("file_types")
        if file_types and ext not in file_types:
            continue

        # Check target_files constraint
        target_files = pattern_rule.get("target_files")
        if target_files:
            basename = file_path.rsplit("/", 1)[-1] if "/" in file_path else file_path
            if basename not in target_files:
                continue

        # Scan line by line for line number context
        for line_num, line in enumerate(lines, start=1):
            match = pattern_rule["pattern"].search(line)
            if not match:
                continue

            # Check exclude pattern
            exclude = pattern_rule.get("exclude_pattern")
            if exclude and exclude.search(line):
                continue

            # Truncate matched text for display
            matched = match.group(0)
            if len(matched) > 200:
                matched = matched[:200] + "..."

            result.add_finding(Finding(
                name=pattern_rule["name"],
                severity=pattern_rule["severity"],
                description=pattern_rule["description"],
                file_path=file_path,
                line_number=line_num,
                matched_text=matched,
                category="content",
            ))

            # Only report the first match per pattern per file to avoid spam
            break


def _extract_and_scan(tarball_path: Path, tmp_dir: str, result: ScanResult):
    """Extract tarball and scan all files."""
    print("  Extracting tarball...")
    try:
        with tarfile.open(tarball_path, "r:gz") as tar:
            # Safety: use data filter (Python 3.12+) to prevent path traversal
            try:
                tar.extractall(path=tmp_dir, filter="data")
            except TypeError:
                # Python < 3.12 — manual safety check
                for member in tar.getmembers():
                    # Block path traversal
                    if ".." in member.name or member.name.startswith("/"):
                        result.add_finding(Finding(
                            "Path traversal in tarball",
                            RED_FLAG,
                            f"Tarball contains suspicious path: {member.name}",
                            file_path=member.name,
                            category="archive",
                        ))
                        continue
                    tar.extract(member, path=tmp_dir)
    except (tarfile.TarError, OSError) as e:
        result.errors.append(f"Failed to extract tarball: {e}")
        print(f"  ERROR: Failed to extract tarball: {e}", file=sys.stderr)
        return

    # Walk extracted files and scan
    print("  Scanning files...")
    for root, _dirs, files in os.walk(tmp_dir):
        for filename in files:
            full_path = os.path.join(root, filename)

            # Build a relative path for reporting (strip the temp dir + GitHub prefix)
            rel_path = os.path.relpath(full_path, tmp_dir)
            # GitHub tarballs have a prefix dir like "owner-repo-sha/"
            parts = rel_path.split(os.sep, 1)
            display_path = parts[1] if len(parts) > 1 else rel_path

            # Skip if not worth scanning
            if not should_scan_file(display_path):
                result.files_skipped += 1
                continue

            # Skip binary files
            if is_binary_file(full_path):
                result.files_skipped += 1
                continue

            # Skip oversized files
            try:
                size = os.path.getsize(full_path)
                if size > MAX_FILE_SIZE:
                    result.files_skipped += 1
                    continue
            except OSError:
                result.files_skipped += 1
                continue

            # Read and scan
            try:
                with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                _scan_content(content, display_path, result)
                result.files_scanned += 1
            except (OSError, UnicodeDecodeError) as e:
                result.errors.append(f"Could not read {display_path}: {e}")
                result.files_skipped += 1


def _print_summary(result: ScanResult):
    """Print a brief summary to stdout after scanning."""
    counts = result.count_by_severity()
    print(
        f"\n  Done. Scanned {result.files_scanned} files, "
        f"skipped {result.files_skipped}."
    )
    print(
        f"  Findings: {counts[RED_FLAG]} red flags, "
        f"{counts[WARNING]} warnings, {counts[INFO]} info"
    )
    if result.errors:
        print(f"  Errors: {len(result.errors)}")
