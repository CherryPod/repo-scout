"""Detection patterns for suspicious code scanning.

Each pattern is a dict with:
    name:            Human-readable description
    severity:        RED_FLAG, WARNING, or INFO
    pattern:         Compiled regex to match against file content
    file_types:      Set of extensions to check (None = all scannable files)
    exclude_pattern: Optional compiled regex — match suppresses the finding
    description:     Explanation of why this is suspicious
    target_files:    Optional list of specific filenames this applies to
"""

import re

# -- Severity levels --
RED_FLAG = "RED_FLAG"
WARNING = "WARNING"
INFO = "INFO"

# ============================================================
# Network patterns — hardcoded IPs, outbound requests
# ============================================================
NETWORK_PATTERNS = [
    {
        "name": "Hardcoded IP address",
        "severity": WARNING,
        "pattern": re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ),
        "file_types": None,
        # Exclude common non-suspicious IPs (localhost, example ranges, test nets)
        "exclude_pattern": re.compile(
            r"\b(?:127\.0\.0\.1|0\.0\.0\.0|255\.255\.255\.\d+|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)\b"
        ),
        "description": "Hardcoded public IP could indicate C2 server or data exfiltration target",
    },
    {
        "name": "Curl/wget to external URL",
        "severity": WARNING,
        "pattern": re.compile(
            r"\b(?:curl|wget)\s+(?:-[a-zA-Z\s]+)*\s*['\"]?https?://",
            re.IGNORECASE,
        ),
        "file_types": {".sh", ".bash", ".zsh", ".fish", ".py", ".rb", ".pl"},
        "description": "Script downloads content from an external URL",
    },
    {
        "name": "Python requests to non-standard URL",
        "severity": INFO,
        "pattern": re.compile(
            r"requests\.(?:get|post|put|delete|patch)\s*\(\s*['\"]https?://(?!(?:api\.github\.com|pypi\.org|registry\.npmjs\.org))",
        ),
        "file_types": {".py"},
        "description": "HTTP request to a non-standard URL in Python code",
    },
    {
        "name": "Node fetch/axios to non-standard URL",
        "severity": INFO,
        "pattern": re.compile(
            r"(?:fetch|axios\.(?:get|post|put|delete))\s*\(\s*['\"`]https?://(?!(?:api\.github\.com|registry\.npmjs\.org|cdn\.jsdelivr\.net))",
        ),
        "file_types": {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"},
        "description": "HTTP request to a non-standard URL in JavaScript/TypeScript",
    },
    {
        "name": "DNS lookup / resolution",
        "severity": INFO,
        "pattern": re.compile(
            r"(?:dns\.resolve|dns\.lookup|getaddrinfo|nslookup|dig\s+)",
        ),
        "file_types": None,
        "description": "DNS resolution could be used for data exfiltration via DNS queries",
    },
]

# ============================================================
# Install hook patterns — package manager hooks that auto-execute
# ============================================================
INSTALL_HOOK_PATTERNS = [
    {
        "name": "npm preinstall/postinstall script",
        "severity": RED_FLAG,
        "pattern": re.compile(
            r'"(?:pre|post)?install"\s*:\s*"[^"]*(?:node|sh|bash|python|curl|wget|rm\s)',
        ),
        "file_types": {".json"},
        "target_files": ["package.json"],
        "description": "npm install hooks run automatically — common malware vector",
    },
    {
        "name": "npm lifecycle script with network access",
        "severity": RED_FLAG,
        "pattern": re.compile(
            r'"(?:pre|post)?(?:install|build|test|publish)"\s*:\s*"[^"]*(?:curl|wget|fetch|http)',
        ),
        "file_types": {".json"},
        "target_files": ["package.json"],
        "description": "npm lifecycle script makes network requests",
    },
    {
        "name": "Python setup.py cmdclass override",
        "severity": WARNING,
        "pattern": re.compile(
            r"cmdclass\s*=\s*\{[^}]*(?:install|develop|build)",
        ),
        "file_types": {".py"},
        "target_files": ["setup.py"],
        "description": "Custom setup.py install command — code runs during pip install",
    },
    {
        "name": "Python setup.py with subprocess/os.system",
        "severity": RED_FLAG,
        "pattern": re.compile(
            r"(?:subprocess\.|os\.system|os\.popen|Popen)\s*\(",
        ),
        "file_types": {".py"},
        "target_files": ["setup.py", "setup.cfg"],
        "description": "setup.py executes system commands during install",
    },
    {
        "name": "Cargo build script",
        "severity": INFO,
        "pattern": re.compile(r'build\s*=\s*"build\.rs"'),
        "file_types": {".toml"},
        "target_files": ["Cargo.toml"],
        "description": "Rust build script (build.rs) runs at compile time — review its contents",
    },
    {
        "name": "Makefile install target with network",
        "severity": WARNING,
        "pattern": re.compile(
            r"^install\s*:.*\n(?:\t.*\n)*\t.*(?:curl|wget|git\s+clone)",
            re.MULTILINE,
        ),
        "file_types": None,
        "target_files": ["Makefile", "makefile"],
        "description": "Makefile install target downloads from the network",
    },
    {
        "name": "GitHub Actions workflow with dangerous permissions",
        "severity": WARNING,
        "pattern": re.compile(
            r"permissions\s*:\s*\n\s*(?:contents|issues|pull-requests|packages)\s*:\s*write",
        ),
        "file_types": {".yml", ".yaml"},
        "description": "GitHub Actions workflow requests write permissions",
    },
]

# ============================================================
# Credential patterns — secrets, tokens, key access
# ============================================================
CREDENTIAL_PATTERNS = [
    {
        "name": "SSH key file access",
        "severity": RED_FLAG,
        "pattern": re.compile(
            r"(?:~|/home/\w+|/root)/\.ssh/(?:id_rsa|id_ed25519|id_ecdsa|authorized_keys|known_hosts|config)",
        ),
        "file_types": None,
        "description": "Code accesses SSH key files",
    },
    {
        "name": "AWS credential patterns",
        "severity": RED_FLAG,
        "pattern": re.compile(
            r"(?:AKIA[0-9A-Z]{16}|aws_secret_access_key|aws_access_key_id)\s*[=:]",
            re.IGNORECASE,
        ),
        "file_types": None,
        "description": "AWS credentials found or accessed in code",
    },
    {
        "name": "Hardcoded API token/key pattern",
        "severity": WARNING,
        "pattern": re.compile(
            r"""(?:api[_-]?key|api[_-]?secret|auth[_-]?token|access[_-]?token|secret[_-]?key)\s*[=:]\s*['"][a-zA-Z0-9_\-]{20,}['"]""",
            re.IGNORECASE,
        ),
        "file_types": None,
        "exclude_pattern": re.compile(
            r"(?:example|placeholder|your[_-]|xxx|test|dummy|fake|sample)",
            re.IGNORECASE,
        ),
        "description": "Hardcoded API key or token (not a placeholder)",
    },
    {
        "name": "Environment variable with secret-like name",
        "severity": INFO,
        "pattern": re.compile(
            r"os\.environ\.get\(\s*['\"](?:.*(?:SECRET|TOKEN|PASSWORD|KEY|CREDENTIAL|API_KEY))['\"]\s*\)",
            re.IGNORECASE,
        ),
        "file_types": {".py"},
        "description": "Reads a secret-like environment variable (normal for config, flag for review)",
    },
    {
        "name": "Private key block",
        "severity": RED_FLAG,
        "pattern": re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        ),
        "file_types": None,
        "description": "Private key embedded in source code",
    },
    {
        "name": "Password in connection string",
        "severity": WARNING,
        "pattern": re.compile(
            r"(?:mysql|postgres|mongodb|redis|amqp)://\w+:[^@\s]+@",
            re.IGNORECASE,
        ),
        "file_types": None,
        "exclude_pattern": re.compile(
            r"(?:localhost|127\.0\.0\.1|example\.com|password|your_)",
            re.IGNORECASE,
        ),
        "description": "Database connection string with embedded password",
    },
]

# ============================================================
# Obfuscation patterns — code hiding techniques
# ============================================================
OBFUSCATION_PATTERNS = [
    {
        "name": "Long base64 string",
        "severity": WARNING,
        "pattern": re.compile(
            r"['\"][A-Za-z0-9+/]{100,}={0,2}['\"]",
        ),
        "file_types": None,
        "exclude_pattern": re.compile(
            r"(?:\.(?:png|jpg|gif|ico|svg|woff|ttf|eot)|data:image|test_|fixture)",
            re.IGNORECASE,
        ),
        "description": "Long base64-encoded string — may hide malicious payload",
    },
    {
        "name": "Python eval/exec with string construction",
        "severity": RED_FLAG,
        "pattern": re.compile(
            r"(?:eval|exec)\s*\(\s*(?:base64\.b64decode|bytes\.fromhex|codecs\.decode|compile\(|''.join|chr\()",
        ),
        "file_types": {".py"},
        "description": "eval/exec on decoded or constructed strings — classic obfuscation",
    },
    {
        "name": "JavaScript eval with string manipulation",
        "severity": RED_FLAG,
        "pattern": re.compile(
            r"eval\s*\(\s*(?:atob|Buffer\.from|String\.fromCharCode|unescape|decodeURIComponent)\s*\(",
        ),
        "file_types": {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"},
        "description": "eval on decoded strings — classic JS obfuscation",
    },
    {
        "name": "Character code string building",
        "severity": WARNING,
        "pattern": re.compile(
            r"(?:String\.fromCharCode|chr)\s*\(\s*\d+\s*(?:,\s*\d+\s*){5,}",
        ),
        "file_types": None,
        "description": "Building strings from character codes — common obfuscation technique",
    },
    {
        "name": "Hex-encoded string execution",
        "severity": WARNING,
        "pattern": re.compile(
            r"(?:bytes\.fromhex|Buffer\.from)\s*\(['\"][0-9a-fA-F]{40,}['\"]\s*(?:,\s*['\"]hex['\"])?\)",
        ),
        "file_types": None,
        "description": "Hex-encoded payload being decoded",
    },
    {
        "name": "Extremely long single line in source",
        "severity": INFO,
        "pattern": re.compile(r".{1000,}"),
        "file_types": {".py", ".js", ".ts", ".rb", ".sh", ".go", ".rs", ".java"},
        "exclude_pattern": re.compile(
            r"(?://\s*eslint|/\*|\.min\.|\.bundle\.)",
            re.IGNORECASE,
        ),
        "description": "Very long line in source file — could be minified/obfuscated code",
    },
]

# ============================================================
# Privilege escalation patterns
# ============================================================
PRIVILEGE_PATTERNS = [
    {
        "name": "Sudo in script",
        "severity": WARNING,
        "pattern": re.compile(r"\bsudo\s+"),
        "file_types": {".sh", ".bash", ".zsh", ".fish"},
        "description": "Script uses sudo — requests elevated privileges",
    },
    {
        "name": "Setuid/setgid calls",
        "severity": RED_FLAG,
        "pattern": re.compile(r"\b(?:setuid|setgid|seteuid|setegid)\s*\("),
        "file_types": {".c", ".cpp", ".h", ".hpp", ".rs", ".go"},
        "description": "Code manipulates process UID/GID — privilege escalation",
    },
    {
        "name": "Chmod with setuid bit",
        "severity": RED_FLAG,
        "pattern": re.compile(r"chmod\s+[ugo]*\+s\b|chmod\s+[42][0-7]{3}\b"),
        "file_types": None,
        "description": "Setting setuid/setgid bits on files",
    },
    {
        "name": "Linux capability manipulation",
        "severity": WARNING,
        "pattern": re.compile(r"\b(?:setcap|getcap|capsh)\b"),
        "file_types": None,
        "description": "Linux capability manipulation",
    },
    {
        "name": "Kernel module operations",
        "severity": RED_FLAG,
        "pattern": re.compile(r"\b(?:insmod|modprobe|rmmod)\s+"),
        "file_types": {".sh", ".bash", ".zsh"},
        "description": "Loading/unloading kernel modules",
    },
]

# ============================================================
# Data exfiltration patterns
# ============================================================
EXFILTRATION_PATTERNS = [
    {
        "name": "File read piped to network tool",
        "severity": RED_FLAG,
        "pattern": re.compile(
            r"cat\s+.+\|\s*(?:curl|wget|nc|ncat|netcat)\b",
        ),
        "file_types": {".sh", ".bash", ".zsh", ".fish"},
        "description": "File content piped to a network tool — data exfiltration pattern",
    },
    {
        "name": "Netcat listener or reverse shell",
        "severity": RED_FLAG,
        "pattern": re.compile(
            r"\b(?:nc|ncat|netcat)\s+(?:-[a-z]*\s+)*(?:-l|-e\s+/bin/)",
        ),
        "file_types": None,
        "description": "Netcat in listen/exec mode — possible reverse shell",
    },
    {
        "name": "Bash reverse shell pattern",
        "severity": RED_FLAG,
        "pattern": re.compile(
            r"(?:bash\s+-i\s+>&|/dev/tcp/|mkfifo\s+/tmp/)",
        ),
        "file_types": None,
        "description": "Classic bash reverse shell pattern",
    },
    {
        "name": "DNS exfiltration pattern",
        "severity": RED_FLAG,
        "pattern": re.compile(
            r"(?:\$\(|`).+(?:base64|xxd|od\s).+\.[\w-]+\.\w{2,}",
        ),
        "file_types": {".sh", ".bash", ".zsh"},
        "description": "Encoding data into DNS queries for exfiltration",
    },
    {
        "name": "Tar/zip and send",
        "severity": WARNING,
        "pattern": re.compile(
            r"(?:tar\s+[a-z]*c|zip\s+).*(?:curl|wget|scp|rsync)\b",
        ),
        "file_types": {".sh", ".bash", ".zsh", ".fish"},
        "description": "Archiving and sending data — possible exfiltration",
    },
    {
        "name": "Clipboard access",
        "severity": INFO,
        "pattern": re.compile(
            r"\b(?:xclip|xsel|pbcopy|pbpaste|wl-copy|wl-paste|clipboard)\b",
        ),
        "file_types": None,
        "description": "Clipboard access — review in context",
    },
]

# ============================================================
# Suspicious filenames — checked against the file tree
# ============================================================
SUSPICIOUS_FILENAMES = [
    {
        "name": "Binary executable in source repo",
        "severity": WARNING,
        "pattern": re.compile(
            r"(?:^|/)(?!\.git/).*\.(?:exe|dll|so|dylib|bin|elf|msi|deb|rpm)$",
            re.IGNORECASE,
        ),
        "description": "Compiled binary checked into source — unusual and worth reviewing",
    },
    {
        "name": "Hidden directory with scripts",
        "severity": WARNING,
        "pattern": re.compile(
            r"(?:^|/)\.[a-z]+/.*\.(?:sh|py|js|rb|pl)$",
            re.IGNORECASE,
        ),
        "exclude_pattern": re.compile(
            r"(?:^|/)\.(?:github|gitlab|circleci|vscode|husky|config|devcontainer)/",
        ),
        "description": "Script in a hidden directory (not a common CI/editor config dir)",
    },
    {
        "name": "Keylogger/backdoor filename",
        "severity": RED_FLAG,
        "pattern": re.compile(
            r"(?:^|/)(?:keylog|backdoor|rootkit|trojan|payload|exploit|webshell|c2server|rat[_.\-/]|stealer)",
            re.IGNORECASE,
        ),
        "description": "Filename suggests malicious intent",
    },
    {
        "name": "Cryptocurrency miner indicators",
        "severity": RED_FLAG,
        "pattern": re.compile(
            r"(?:^|/)(?:xmrig|minerd|cgminer|bfgminer|cpuminer|cryptonight)",
            re.IGNORECASE,
        ),
        "description": "Filename suggests cryptocurrency miner",
    },
    {
        "name": "Environment file checked in",
        "severity": WARNING,
        "pattern": re.compile(
            r"(?:^|/)\.env(?:\.(?:local|production|staging|development))?$",
        ),
        "description": ".env file in repo — may contain secrets",
    },
]

# ============================================================
# Repo health checks — assessed from metadata, not file content
# ============================================================
REPO_HEALTH_CHECKS = {
    "single_contributor": {
        "name": "Single contributor",
        "severity": INFO,
        "description": "Repo has only one contributor — less peer review",
    },
    "no_license": {
        "name": "No license",
        "severity": INFO,
        "description": "No license file — unclear usage terms",
    },
    "very_new": {
        "name": "Very new repository",
        "severity": INFO,
        "description": "Repository created less than 30 days ago",
    },
    "stale": {
        "name": "Stale repository",
        "severity": WARNING,
        "description": "No commits in the last 2 years",
    },
    "low_stars": {
        "name": "Low community adoption",
        "severity": INFO,
        "description": "Fewer than 10 stars — limited community validation",
    },
    "archived": {
        "name": "Archived repository",
        "severity": INFO,
        "description": "Repository is archived (read-only, no longer maintained)",
    },
    "no_description": {
        "name": "No description",
        "severity": INFO,
        "description": "Repository has no description — minimal documentation effort",
    },
}

# ============================================================
# Aggregate all content patterns for easy iteration
# ============================================================
ALL_CONTENT_PATTERNS = (
    NETWORK_PATTERNS
    + INSTALL_HOOK_PATTERNS
    + CREDENTIAL_PATTERNS
    + OBFUSCATION_PATTERNS
    + PRIVILEGE_PATTERNS
    + EXFILTRATION_PATTERNS
)
