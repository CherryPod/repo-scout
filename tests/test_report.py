"""Tests for verdict computation in report.py."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from patterns import RED_FLAG, WARNING, INFO
from report import compute_verdict


class TestComputeVerdict:
    """Test the verdict threshold logic.

    Verdict scale:
        HIGH RISK       — any red flags
        ELEVATED RISK   — 5+ warnings, no red flags
        MODERATE RISK   — 1-4 warnings, no red flags
        LOW RISK        — info findings only (3+)
        MINIMAL RISK    — 0-2 info findings only
    """

    def test_no_findings_is_minimal(self, make_scan_result):
        result = make_scan_result()
        assert compute_verdict(result) == "MINIMAL RISK"

    def test_one_info_is_minimal(self, make_scan_result, make_finding):
        result = make_scan_result()
        result.add_finding(make_finding(severity=INFO))
        assert compute_verdict(result) == "MINIMAL RISK"

    def test_two_info_is_minimal(self, make_scan_result, make_finding):
        result = make_scan_result()
        for _ in range(2):
            result.add_finding(make_finding(severity=INFO))
        assert compute_verdict(result) == "MINIMAL RISK"

    def test_three_info_is_low(self, make_scan_result, make_finding):
        result = make_scan_result()
        for _ in range(3):
            result.add_finding(make_finding(severity=INFO))
        assert compute_verdict(result) == "LOW RISK"

    def test_one_warning_is_moderate(self, make_scan_result, make_finding):
        result = make_scan_result()
        result.add_finding(make_finding(severity=WARNING))
        assert compute_verdict(result) == "MODERATE RISK"

    def test_four_warnings_is_moderate(self, make_scan_result, make_finding):
        result = make_scan_result()
        for _ in range(4):
            result.add_finding(make_finding(severity=WARNING))
        assert compute_verdict(result) == "MODERATE RISK"

    def test_five_warnings_is_elevated(self, make_scan_result, make_finding):
        result = make_scan_result()
        for _ in range(5):
            result.add_finding(make_finding(severity=WARNING))
        assert compute_verdict(result) == "ELEVATED RISK"

    def test_one_red_flag_is_high(self, make_scan_result, make_finding):
        result = make_scan_result()
        result.add_finding(make_finding(severity=RED_FLAG))
        assert compute_verdict(result) == "HIGH RISK"

    def test_red_flag_overrides_warnings(self, make_scan_result, make_finding):
        """RED_FLAG takes precedence regardless of warning count."""
        result = make_scan_result()
        result.add_finding(make_finding(severity=RED_FLAG))
        for _ in range(10):
            result.add_finding(make_finding(severity=WARNING))
        assert compute_verdict(result) == "HIGH RISK"

    def test_warnings_with_info_still_moderate(self, make_scan_result, make_finding):
        """Warnings take precedence over info count."""
        result = make_scan_result()
        result.add_finding(make_finding(severity=WARNING))
        for _ in range(10):
            result.add_finding(make_finding(severity=INFO))
        assert compute_verdict(result) == "MODERATE RISK"
