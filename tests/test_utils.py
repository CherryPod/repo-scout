"""Tests for utility functions in utils.py."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from utils import parse_repo_input, should_scan_file, format_size, sanitize_filename


# ============================================================
# parse_repo_input
# ============================================================

class TestParseRepoInput:

    @pytest.mark.parametrize("input_str, expected", [
        ("owner/repo", ("owner", "repo")),
        ("octocat/hello-world", ("octocat", "hello-world")),
    ])
    def test_owner_repo_shorthand(self, input_str, expected):
        assert parse_repo_input(input_str) == expected

    @pytest.mark.parametrize("input_str, expected", [
        ("https://github.com/owner/repo", ("owner", "repo")),
        ("https://github.com/owner/repo/", ("owner", "repo")),
        ("http://github.com/owner/repo", ("owner", "repo")),
    ])
    def test_full_url(self, input_str, expected):
        assert parse_repo_input(input_str) == expected

    def test_url_with_tree_path(self):
        """URLs with /tree/main/... should still extract owner/repo."""
        result = parse_repo_input("https://github.com/owner/repo/tree/main/src")
        assert result == ("owner", "repo")

    def test_url_with_git_suffix(self):
        result = parse_repo_input("https://github.com/owner/repo.git")
        assert result == ("owner", "repo")

    def test_url_missing_scheme(self):
        """github.com/owner/repo without https:// should still work."""
        result = parse_repo_input("github.com/owner/repo")
        assert result == ("owner", "repo")

    @pytest.mark.parametrize("input_str", [
        "just-a-name",
        "",
        "   ",
        "/",
        "owner/",
        "/repo",
    ])
    def test_invalid_inputs_raise(self, input_str):
        with pytest.raises(ValueError):
            parse_repo_input(input_str)

    def test_strips_whitespace(self):
        assert parse_repo_input("  owner/repo  ") == ("owner", "repo")

    def test_strips_trailing_slash(self):
        assert parse_repo_input("owner/repo/") == ("owner", "repo")


# ============================================================
# should_scan_file
# ============================================================

class TestShouldScanFile:

    @pytest.mark.parametrize("filepath", [
        "main.py",
        "src/app.js",
        "lib/utils.ts",
        "deploy.sh",
        "config.yml",
        "data.json",
        "build.rs",
    ])
    def test_scannable_extensions(self, filepath):
        assert should_scan_file(filepath) is True

    @pytest.mark.parametrize("filepath", [
        "image.png",
        "photo.jpg",
        "icon.ico",
        "font.woff",
        "archive.zip",
        "binary.o",
    ])
    def test_non_scannable_extensions(self, filepath):
        assert should_scan_file(filepath) is False

    @pytest.mark.parametrize("filepath", [
        "Makefile",
        "Dockerfile",
        "Gemfile",
        "Rakefile",
    ])
    def test_scannable_filenames(self, filepath):
        assert should_scan_file(filepath) is True

    def test_no_extension_scanned(self):
        """Files without extensions should be scanned (could be scripts)."""
        assert should_scan_file("somescript") is True

    def test_nested_path(self):
        assert should_scan_file("src/deep/nested/module.py") is True


# ============================================================
# format_size
# ============================================================

class TestFormatSize:

    @pytest.mark.parametrize("size_bytes, expected", [
        (0, "0 B"),
        (500, "500 B"),
        (1023, "1023 B"),
        (1024, "1.0 KB"),
        (1536, "1.5 KB"),
        (1048576, "1.0 MB"),
        (1073741824, "1.0 GB"),
        (1610612736, "1.5 GB"),
    ])
    def test_formatting(self, size_bytes, expected):
        assert format_size(size_bytes) == expected


# ============================================================
# sanitize_filename
# ============================================================

class TestSanitizeFilename:

    def test_replaces_slash(self):
        assert sanitize_filename("owner/repo") == "owner_repo"

    def test_replaces_spaces(self):
        assert sanitize_filename("my repo name") == "my_repo_name"

    def test_preserves_safe_chars(self):
        result = sanitize_filename("my-repo_v1.0")
        assert result == "my-repo_v1.0"

    def test_replaces_special_chars(self):
        result = sanitize_filename("repo@v2!beta#1")
        assert result == "repo_v2_beta_1"
