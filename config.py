"""Configuration: token loading, paths, and constants."""

import os
from pathlib import Path

# Try to load token from ~/.secrets/repo-scout.env
GITHUB_TOKEN = None
_token_path = Path.home() / ".secrets" / "repo-scout.env"
if _token_path.exists():
    try:
        from dotenv import dotenv_values
        _values = dotenv_values(_token_path)
        GITHUB_TOKEN = _values.get("GITHUB_TOKEN")
    except ImportError:
        # Fall back to manual parsing if python-dotenv not available
        with open(_token_path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("GITHUB_TOKEN="):
                    GITHUB_TOKEN = line.split("=", 1)[1].strip().strip("\"'")
                    break

# GitHub API
API_BASE_URL = "https://api.github.com"

# Scanning limits
MAX_FILE_SIZE = 1_000_000      # 1MB — skip files larger than this
MAX_REPO_SIZE = 500_000_000    # 500MB — refuse to deep scan repos larger than this

# File extensions worth scanning for patterns
SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".sh", ".bash", ".zsh", ".fish",
    ".rb", ".pl", ".php",
    ".go", ".rs", ".c", ".cpp", ".h", ".hpp",
    ".java", ".kt", ".scala", ".groovy",
    ".cs", ".fs",
    ".lua", ".r", ".jl",
    ".yml", ".yaml", ".toml", ".json", ".xml",
    ".cfg", ".ini", ".conf",
    ".dockerfile", ".containerfile",
    ".ps1", ".bat", ".cmd",
    ".makefile", ".cmake",
}

# Filenames always worth scanning (case-insensitive match)
SCANNABLE_FILENAMES = {
    "makefile", "dockerfile", "containerfile",
    "rakefile", "gemfile", "procfile",
    "cmakelists.txt", "justfile", "taskfile",
}

# Files to read during quick scan (checked via API, path relative to repo root)
PRIORITY_FILES = [
    "package.json",
    "setup.py",
    "setup.cfg",
    "pyproject.toml",
    "Makefile",
    "Dockerfile",
    "Containerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "Cargo.toml",
    "build.rs",
    "Gemfile",
    "Rakefile",
    ".github/workflows",
    "install.sh",
    "postinstall.sh",
    ".npmrc",
    ".husky/pre-commit",
    ".husky/post-checkout",
]

# Paths
PROJECT_DIR = Path(__file__).parent.resolve()
DEFAULT_REPORTS_DIR = PROJECT_DIR / "reports"
SCAN_LOG_PATH = PROJECT_DIR / "scan-log.md"
