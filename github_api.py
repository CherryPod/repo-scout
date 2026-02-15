"""GitHub REST API client for repo metadata, file tree, and content retrieval."""

import sys
import time
import base64
import tempfile
from pathlib import Path

import requests

from config import API_BASE_URL, GITHUB_TOKEN, MAX_FILE_SIZE


class GitHubAPIError(Exception):
    """Raised when a GitHub API call fails."""
    pass


class GitHubClient:
    """Thin wrapper around the GitHub REST API.

    Works without authentication (60 requests/hour) but warns about limits.
    With a token, the limit is 5,000 requests/hour.
    """

    def __init__(self, token: str | None = None):
        self.session = requests.Session()
        self.token = token or GITHUB_TOKEN
        self.session.headers["Accept"] = "application/vnd.github.v3+json"
        self.session.headers["User-Agent"] = "repo-scout"
        if self.token:
            self.session.headers["Authorization"] = f"token {self.token}"
        else:
            print(
                "WARNING: No GitHub token configured. "
                "Rate limited to 60 requests/hour.\n"
                "  Set GITHUB_TOKEN in ~/.secrets/repo-scout.env for 5,000/hr.",
                file=sys.stderr,
            )

    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Make an API request with rate limit awareness and error handling."""
        resp = self.session.request(method, url, **kwargs)

        # Check rate limit headers
        remaining = resp.headers.get("X-RateLimit-Remaining")
        if remaining is not None and int(remaining) < 10:
            reset_time = int(resp.headers.get("X-RateLimit-Reset", 0))
            wait_seconds = max(0, reset_time - int(time.time()))
            print(
                f"WARNING: Only {remaining} API requests remaining. "
                f"Resets in {wait_seconds}s.",
                file=sys.stderr,
            )

        if resp.status_code == 401:
            raise GitHubAPIError(
                "Authentication failed. Check your GitHub token."
            )
        elif resp.status_code == 403:
            if "rate limit" in resp.text.lower():
                reset_time = int(resp.headers.get("X-RateLimit-Reset", 0))
                wait_seconds = max(0, reset_time - int(time.time()))
                raise GitHubAPIError(
                    f"Rate limit exceeded. Resets in {wait_seconds}s. "
                    "Add a GitHub token to increase your limit."
                )
            raise GitHubAPIError(f"Access forbidden: {resp.text}")
        elif resp.status_code == 404:
            raise GitHubAPIError(
                "Repository not found. Check the owner/repo name, "
                "or it may be private (token required)."
            )
        elif resp.status_code >= 400:
            raise GitHubAPIError(
                f"GitHub API error {resp.status_code}: {resp.text[:200]}"
            )

        return resp

    def get_repo_metadata(self, owner: str, repo: str) -> dict:
        """Fetch repo metadata (stars, forks, dates, size, etc.)."""
        url = f"{API_BASE_URL}/repos/{owner}/{repo}"
        resp = self._request("GET", url)
        return resp.json()

    def get_contributors(self, owner: str, repo: str, limit: int = 30) -> list[dict]:
        """Fetch top contributors."""
        url = f"{API_BASE_URL}/repos/{owner}/{repo}/contributors"
        resp = self._request("GET", url, params={"per_page": limit})
        return resp.json()

    def get_file_tree(self, owner: str, repo: str, branch: str = None) -> list[dict]:
        """Fetch the full recursive file tree.

        Returns a list of tree entries with 'path', 'type', 'size' keys.
        Uses the Git Trees API with recursive=1 for efficiency (single request).
        """
        # Use the default branch if none specified
        if not branch:
            meta = self.get_repo_metadata(owner, repo)
            branch = meta.get("default_branch", "main")

        url = f"{API_BASE_URL}/repos/{owner}/{repo}/git/trees/{branch}"
        resp = self._request("GET", url, params={"recursive": "1"})
        data = resp.json()

        if data.get("truncated"):
            print(
                "WARNING: File tree was truncated (very large repo). "
                "Some files may be missed in quick scan.",
                file=sys.stderr,
            )

        return data.get("tree", [])

    def get_file_content(self, owner: str, repo: str, path: str) -> str | None:
        """Fetch a single file's content via the Contents API.

        Returns decoded text content, or None if the file is too large
        or not a regular file.
        """
        url = f"{API_BASE_URL}/repos/{owner}/{repo}/contents/{path}"
        resp = self._request("GET", url)
        data = resp.json()

        # The Contents API returns a list for directories — skip those
        if isinstance(data, list):
            return None

        # The Contents API returns base64-encoded content for files under 1MB
        if data.get("encoding") == "base64" and data.get("content"):
            size = data.get("size", 0)
            if size > MAX_FILE_SIZE:
                return None
            try:
                return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
            except Exception:
                return None

        return None

    def download_tarball(self, owner: str, repo: str) -> Path:
        """Download the default branch tarball to a temp file.

        Returns the Path to the downloaded .tar.gz file.
        Caller is responsible for cleanup.
        """
        url = f"{API_BASE_URL}/repos/{owner}/{repo}/tarball"
        resp = self._request("GET", url, stream=True)

        # Write to a temp file
        tmp = tempfile.NamedTemporaryFile(
            suffix=".tar.gz", prefix=f"repo-scout-{owner}-{repo}-", delete=False
        )
        try:
            for chunk in resp.iter_content(chunk_size=65536):
                tmp.write(chunk)
            tmp.close()
            return Path(tmp.name)
        except Exception:
            tmp.close()
            Path(tmp.name).unlink(missing_ok=True)
            raise

    def check_rate_limit(self) -> dict:
        """Check current rate limit status."""
        url = f"{API_BASE_URL}/rate_limit"
        resp = self._request("GET", url)
        return resp.json().get("rate", {})
