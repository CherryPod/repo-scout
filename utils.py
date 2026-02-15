"""Utility functions: URL parsing, file helpers, formatting."""

import re
from urllib.parse import urlparse


def parse_repo_input(repo_input: str) -> tuple[str, str]:
    """Parse 'owner/repo' or a full GitHub URL into (owner, repo).

    Accepts:
        owner/repo
        https://github.com/owner/repo
        https://github.com/owner/repo/tree/main/...
        github.com/owner/repo

    Returns:
        (owner, repo) tuple

    Raises:
        ValueError if the input can't be parsed into owner/repo.
    """
    repo_input = repo_input.strip().rstrip("/")

    # Full URL
    if "github.com" in repo_input:
        # Handle URLs missing the scheme
        if not repo_input.startswith("http"):
            repo_input = "https://" + repo_input
        parsed = urlparse(repo_input)
        parts = [p for p in parsed.path.split("/") if p]
        if len(parts) >= 2:
            owner, repo = parts[0], parts[1]
            # Strip .git suffix if present
            repo = re.sub(r"\.git$", "", repo)
            return owner, repo
        raise ValueError(
            f"Could not extract owner/repo from URL: {repo_input}"
        )

    # owner/repo shorthand
    if "/" in repo_input:
        parts = repo_input.split("/")
        if len(parts) == 2 and parts[0] and parts[1]:
            return parts[0], parts[1]

    raise ValueError(
        f"Invalid repo format: '{repo_input}'. "
        "Use 'owner/repo' or 'https://github.com/owner/repo'"
    )


def is_binary_file(filepath: str, chunk_size: int = 8192) -> bool:
    """Check if a file is binary by looking for null bytes in the first chunk."""
    try:
        with open(filepath, "rb") as f:
            chunk = f.read(chunk_size)
            return b"\x00" in chunk
    except (OSError, IOError):
        return True  # If we can't read it, treat as binary (skip it)


def format_size(size_bytes: int) -> str:
    """Format byte count into human-readable string."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"


def sanitize_filename(name: str) -> str:
    """Convert a string into a safe filename component.

    Replaces / and other unsafe chars with underscores.
    """
    return re.sub(r"[^\w\-.]", "_", name)


def should_scan_file(filepath: str) -> bool:
    """Decide whether a file path is worth scanning based on extension/name.

    Uses SCANNABLE_EXTENSIONS and SCANNABLE_FILENAMES from config.
    """
    from config import SCANNABLE_EXTENSIONS, SCANNABLE_FILENAMES

    # Check by filename (case-insensitive)
    filename = filepath.rsplit("/", 1)[-1] if "/" in filepath else filepath
    if filename.lower() in SCANNABLE_FILENAMES:
        return True

    # Check by extension
    dot_pos = filename.rfind(".")
    if dot_pos != -1:
        ext = filename[dot_pos:].lower()
        return ext in SCANNABLE_EXTENSIONS

    # No extension — scan it anyway (could be a script without extension)
    return True
