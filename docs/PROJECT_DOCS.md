# repo-scout — Project Documentation

## Overview

repo-scout is a CLI tool that scans GitHub repositories for suspicious code patterns before they're cloned to the machine. It checks for red flags like install hooks, hardcoded credentials, obfuscated code, privilege escalation, and data exfiltration patterns.

Neither scan tier clones the repo. Quick scan uses the GitHub API only. Deep scan downloads a tarball to a temp directory, scans it, then deletes everything.

## Architecture

### Two-Tier Scanning

| Tier | Method | What It Catches |
|------|--------|-----------------|
| **Quick** (`--quick`) | GitHub REST API only — metadata, file tree, targeted file reads | Repo health signals, suspicious filenames, install hooks in priority files (package.json, setup.py, Makefile, etc.) |
| **Deep** (default) | Everything from quick + downloads tarball to temp dir, scans all files, deletes after | Hardcoded URLs/IPs, eval/exec, base64 blobs, credential patterns, exfiltration patterns, reverse shells |

### Scan Flow

```
CLI (cli.py)
  → parse_repo_input (utils.py)
  → run_scan (scanner.py)
      → Phase 1: get_repo_metadata → health checks
      → Phase 2: get_contributors → contributor checks
      → Phase 3: get_file_tree → suspicious filename checks
      → Phase 4: read priority files → content pattern matching
      → Phase 5 (deep only): download_tarball → extract to tmpdir → walk all files → pattern match → cleanup
  → generate_report (report.py) → write markdown
  → update_scan_log (scan_log.py) → append one-liner
  → exit code (0=clean, 1=error, 2=red flags)
```

## Module Reference

### cli.py — Entry Point
Argparse CLI. Parses repo input (owner/repo or full URL), determines output directory, calls `run_scan()`, writes report, updates scan log, sets exit code.

**Arguments:**
- `repo` (positional) — `owner/repo` or `https://github.com/owner/repo`
- `--quick` — API-only scan, no tarball download
- `--output / -o` — Report output base directory (report goes to `<dir>/reports/`)
- `--token` — Override the token from `~/.secrets/repo-scout.env`

### config.py — Configuration
Loads GitHub token from `~/.secrets/repo-scout.env` using python-dotenv (falls back to manual parsing if dotenv unavailable).

**Key constants:**
- `MAX_FILE_SIZE` — 1MB, files larger than this are skipped
- `MAX_REPO_SIZE` — 500MB, repos larger than this skip deep scan automatically
- `SCANNABLE_EXTENSIONS` — Set of ~40 extensions worth scanning
- `SCANNABLE_FILENAMES` — Extensionless filenames to scan (Makefile, Dockerfile, etc.)
- `PRIORITY_FILES` — Files read during quick scan via API (package.json, setup.py, Cargo.toml, build.rs, Dockerfiles, CI workflows, install scripts)

### github_api.py — GitHub REST API Client
`GitHubClient` class using `requests.Session` with token auth headers.

**Methods:**
- `get_repo_metadata(owner, repo)` — Stars, forks, dates, size, license, etc.
- `get_contributors(owner, repo)` — Top 30 contributors
- `get_file_tree(owner, repo)` — Full recursive tree via Git Trees API (single request)
- `get_file_content(owner, repo, path)` — Single file via Contents API (base64 decoded). Returns None for directories or oversized files
- `download_tarball(owner, repo)` — Downloads default branch tarball to temp file
- `check_rate_limit()` — Current rate limit status

**Rate limiting:** Checks `X-RateLimit-Remaining` on every response. Warns at <10 remaining. Without a token: 60 req/hr. With token: 5,000 req/hr.

**Error handling:** Custom `GitHubAPIError` for 401 (bad token), 403 (rate limit), 404 (not found), and other 4xx/5xx.

### scanner.py — Scan Orchestrator
Core engine. `run_scan()` is the main entry point called by CLI.

**Classes:**
- `Finding` — Single finding with name, severity, description, file_path, line_number, matched_text, category
- `ScanResult` — Holds all scan data: metadata, contributors, file tree, findings list, scan stats, errors

**Internal functions:**
- `_check_repo_health()` — Assesses metadata (archived, no license, low stars, new, stale)
- `_check_contributor_health()` — Flags single-contributor repos
- `_check_suspicious_filenames()` — Runs filename patterns against file tree
- `_scan_priority_files()` — Reads priority files via API and runs content patterns
- `_scan_content()` — Runs all content patterns against a file's text, line by line
- `_extract_and_scan()` — Tarball extraction (uses `filter="data"` for path traversal protection on Python 3.12+) and full file walk

**Safety:**
- Tarball extracted to `tempfile.mkdtemp()`, always cleaned up in `finally` block
- Binary files detected via null byte check, skipped
- Files over 1MB skipped
- Repos over 500MB skip deep scan automatically
- One match per pattern per file (prevents spam on repetitive code)

### patterns.py — Detection Rules
All patterns as plain dicts with compiled regexes. Each dict has: `name`, `severity` (RED_FLAG/WARNING/INFO), `pattern`, `file_types`, optional `exclude_pattern`, `description`, optional `target_files`.

**Pattern categories:**

| Category | Count | What It Detects |
|----------|-------|-----------------|
| `NETWORK_PATTERNS` | 5 | Hardcoded IPs, curl/wget, requests/fetch to non-standard URLs, DNS lookups |
| `INSTALL_HOOK_PATTERNS` | 7 | npm pre/postinstall, setup.py cmdclass, Cargo build scripts, Makefile install targets, CI write permissions |
| `CREDENTIAL_PATTERNS` | 6 | SSH key access, AWS creds, hardcoded tokens, env vars with secret names, private key blocks, DB connection strings |
| `OBFUSCATION_PATTERNS` | 6 | Long base64 strings, eval/exec with decoding, char code building, hex payloads, extremely long lines |
| `PRIVILEGE_PATTERNS` | 5 | sudo, setuid/setgid, chmod +s, Linux capabilities, kernel modules |
| `EXFILTRATION_PATTERNS` | 6 | File piped to curl/nc, reverse shells, bash /dev/tcp, DNS exfil, tar+send, clipboard access |
| `SUSPICIOUS_FILENAMES` | 5 | Binaries in source, hidden dir scripts, backdoor names, crypto miners, .env files |
| `REPO_HEALTH_CHECKS` | 7 | Single contributor, no license, very new, stale, low stars, archived, no description |

**Exclude patterns** reduce false positives:
- IPs: Excludes private ranges (127.x, 192.168.x, 10.x, 172.16-31.x)
- Tokens: Excludes placeholder names (example, test, dummy, fake)
- Base64: Excludes image data, test fixtures
- Hidden dirs: Excludes `.github/`, `.vscode/`, `.devcontainer/`, etc.
- Filenames: `webshell` instead of `shell`, `rat` requires separator after it

### report.py — Markdown Report Generator

**Verdict scale:**
| Verdict | Criteria |
|---------|----------|
| HIGH RISK | Any red flags |
| ELEVATED RISK | 5+ warnings, no red flags |
| MODERATE RISK | 1-4 warnings, no red flags |
| LOW RISK | 3+ info findings only |
| MINIMAL RISK | 0-2 info findings |

**Report sections:** Header → Verdict table → Repo metadata table → File tree summary → Findings grouped by severity (red flags first) with file location and matched text → Errors → Footer.

### scan_log.py — Append-Only Log
Writes one-liner per scan to `scan-log.md` (in the project directory) in markdown table format:
```
| date | owner/repo | verdict | 2R/3W/5I | report path |
```
Creates the file with headers on first use.

### utils.py — Helpers
- `parse_repo_input()` — Accepts `owner/repo`, full GitHub URLs (with or without scheme), strips `.git` suffix
- `is_binary_file()` — Null byte check in first 8KB
- `should_scan_file()` — Checks against SCANNABLE_EXTENSIONS and SCANNABLE_FILENAMES
- `format_size()` — Bytes to human-readable (B/KB/MB/GB)
- `sanitize_filename()` — Safe filename for report output

## Configuration

### GitHub Token
**Location:** `~/.secrets/repo-scout.env`
**Format:** `GITHUB_TOKEN=ghp_...`
**Required:** No, but strongly recommended. Without token: 60 API requests/hour. With token: 5,000/hour.
**Scopes needed:** None (public repo access only)

A quick scan uses ~4-5 API calls per repo (metadata, contributors, tree, plus priority file reads). A deep scan adds 1 more for the tarball download.

### Report Output
- Default: `./reports/YYYY-MM-DD_owner_repo.md` (relative to where repo-scout is installed)
- Custom: `repo-scout owner/repo --output ~/myproject/` writes to `~/myproject/reports/YYYY-MM-DD_owner_repo.md`
- Scan log always writes to `scan-log.md` in the project directory regardless of output dir

### safeclone Alias
**Setup:** Add the function from README.md to your shell config (e.g. `.bashrc` or `.bash_aliases`)
**Usage:** `safeclone owner/repo [git clone args...]`

Workflow:
1. Runs `repo-scout --quick` on the target
2. If RED_FLAGs found (exit 2): shows warning, asks for confirmation
3. If scan error (exit 1): shows warning, asks for confirmation
4. If clean (exit 0): proceeds directly to `git clone`

## Known False Positive Patterns

These are expected and not bugs — the scanner correctly flags patterns that *could* be suspicious, but in context are benign. The human reviewer makes the final call.

| Pattern | Common False Positive | Example |
|---------|----------------------|---------|
| Hardcoded IP | Test data, example configs, CGNAT ranges (100.64.x.x), DNS servers (1.1.1.1, 8.8.8.8) | headscale uses 100.64.0.0/10 throughout tests |
| Long base64 | Crypto public keys, test fixtures, embedded certificates | signal-cli embeds Signal server public keys |
| Version numbers | Semver in TOML/YAML matching IP regex | `3.51.2.0` in gradle version catalogs |
| DNS lookup | Networking tools that legitimately use DNS | headscale integration tests use `dig` |

## Troubleshooting

**"Rate limit exceeded"** — Add a GitHub token to `~/.secrets/repo-scout.env`. Without one you only get 60 requests per hour.

**"Repository not found"** — Check spelling. If it's a private repo, you need a token with `repo` scope (not just the default no-scope token).

**"Repo too large, skipping deep scan"** — Repos over 500MB skip tarball download automatically and fall back to quick scan results. Adjust `MAX_REPO_SIZE` in config.py if needed.

**No findings on quick scan but findings on deep scan** — Quick scan only reads priority files (package.json, setup.py, etc.). Deep scan reads every file. This is expected.

**ModuleNotFoundError** — Make sure the venv is activated (`source .venv/bin/activate`) or use the full path to the `repo-scout` entry point in your venv.
