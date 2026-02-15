# repo-scout

Scan GitHub repositories for suspicious code patterns before cloning them.

repo-scout checks for supply chain attack indicators — install hooks, hardcoded credentials, obfuscated payloads, reverse shells, privilege escalation, and data exfiltration patterns. It flags what looks suspicious; you make the final call.

## Why

Every `git clone` and `pip install` is a trust decision. Malicious packages on npm, PyPI, and other registries have used install hooks to steal credentials, exfiltrate data, and install backdoors. repo-scout automates the boring parts of auditing a repo before you bring it onto your machine.

## Installation

```bash
git clone https://github.com/cherrypod/repo-scout.git
cd repo-scout
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Requires Python 3.10+.

## Usage

```bash
# Quick scan — API only, no downloads (~4-5 API calls)
repo-scout owner/repo --quick

# Deep scan — downloads tarball, scans all files, deletes after
repo-scout owner/repo

# Save report to a different directory
repo-scout owner/repo --output ~/projects/myapp
```

Full GitHub URLs also work:

```bash
repo-scout https://github.com/owner/repo
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Clean scan |
| 1 | Error (API failure, bad input) |
| 2 | RED_FLAGs found |

Use exit codes for scripting — see the `safeclone` alias below.

## What it checks

| Category | Examples | Severity |
|----------|----------|----------|
| **Install hooks** | npm postinstall, setup.py cmdclass, Cargo build scripts | RED_FLAG |
| **Credentials** | SSH key access, AWS keys (AKIA*), private key blocks, DB connection strings | RED_FLAG / WARNING |
| **Obfuscation** | eval/exec + base64, char code building, hex payloads, long base64 strings | RED_FLAG / WARNING |
| **Exfiltration** | File piped to curl/nc, reverse shells, bash /dev/tcp, DNS exfil | RED_FLAG |
| **Privilege escalation** | setuid/setgid, chmod +s, kernel modules, sudo in scripts | RED_FLAG / WARNING |
| **Network** | Hardcoded public IPs, curl/wget in scripts, requests to non-standard URLs | WARNING / INFO |
| **Suspicious filenames** | Binaries in source, hidden dir scripts, backdoor/keylogger names, .env files | RED_FLAG / WARNING |
| **Repo health** | Single contributor, no license, very new, stale, low stars | INFO |

### Verdict scale

| Verdict | Criteria |
|---------|----------|
| HIGH RISK | Any red flags |
| ELEVATED RISK | 5+ warnings, no red flags |
| MODERATE RISK | 1-4 warnings |
| LOW RISK | 3+ info findings only |
| MINIMAL RISK | 0-2 info findings |

### False positives

False positives are expected and not bugs. The scanner flags patterns that *could* be suspicious — the human reviewer makes the final call. Common examples: hardcoded IPs in test data, base64-encoded public keys, version numbers matching the IP regex.

## GitHub token

A token is optional but strongly recommended. Without one you get 60 API requests/hour; with one, 5,000/hour.

```bash
# Create the token file
mkdir -p ~/.secrets
echo "GITHUB_TOKEN=ghp_your_token_here" > ~/.secrets/repo-scout.env
chmod 600 ~/.secrets/repo-scout.env
```

No special scopes needed — public repo access only.

## safeclone alias

Add this to your shell config to scan before every clone:

```bash
safeclone() {
    if [ -z "$1" ]; then
        echo "Usage: safeclone <owner/repo or GitHub URL> [git clone args...]"
        return 1
    fi
    local repo_input="$1"
    shift
    echo "Running repo-scout scan..."
    repo-scout "$repo_input" --quick
    local exit_code=$?
    if [ $exit_code -eq 2 ]; then
        echo ""
        echo "RED FLAGS detected. Clone at your own risk."
        read -rp "Continue with clone? [y/N] " confirm
        [[ "$confirm" =~ ^[Yy]$ ]] || { echo "Clone aborted."; return 2; }
    elif [ $exit_code -eq 1 ]; then
        echo ""
        echo "Scan failed. Check the error above."
        read -rp "Continue with clone anyway? [y/N] " confirm
        [[ "$confirm" =~ ^[Yy]$ ]] || { echo "Clone aborted."; return 1; }
    fi
    local clone_url="$repo_input"
    if [[ ! "$clone_url" =~ ^https?:// ]] && [[ ! "$clone_url" =~ ^git@ ]]; then
        clone_url="https://github.com/$repo_input.git"
    fi
    echo ""
    echo "Cloning $clone_url ..."
    git clone "$clone_url" "$@"
}
```

## Development

```bash
git clone https://github.com/cherrypod/repo-scout.git
cd repo-scout
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest -v
```

## License

MIT
