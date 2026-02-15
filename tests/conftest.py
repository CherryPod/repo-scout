"""Shared test fixtures for repo-scout tests."""

import sys
from pathlib import Path

import pytest

# Add project root to sys.path so tests can import the flat modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from scanner import Finding, ScanResult
from patterns import RED_FLAG, WARNING, INFO


@pytest.fixture
def make_finding():
    """Factory fixture for creating Finding objects with sensible defaults."""
    def _make(severity=INFO, name="Test finding", description="Test description",
              file_path=None, line_number=None, matched_text=None, category=None):
        return Finding(
            name=name,
            severity=severity,
            description=description,
            file_path=file_path,
            line_number=line_number,
            matched_text=matched_text,
            category=category,
        )
    return _make


@pytest.fixture
def make_scan_result():
    """Factory fixture for creating ScanResult objects."""
    def _make(owner="test-owner", repo="test-repo", scan_type="quick"):
        return ScanResult(owner, repo, scan_type)
    return _make
