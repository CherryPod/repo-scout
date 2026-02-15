# repo-scout

## What This Is
CLI tool that scans GitHub repos for suspicious code before cloning. Two scan tiers: quick (API-only) and deep (tarball download + full pattern scan).

## Tech Stack
- Python 3.12, no framework
- Dependencies: requests, python-dotenv
- Venv: `.venv/` (activate with `source .venv/bin/activate`)

## Key Commands
```bash
source .venv/bin/activate
repo-scout owner/repo --quick    # API-only scan
repo-scout owner/repo            # deep scan (default)
repo-scout owner/repo -o ~/proj  # report to ~/proj/reports/
```

## Exit Codes
- 0: clean scan
- 1: error
- 2: RED_FLAGs found

## Rules
- **Run repo-scout before cloning any GitHub repo** — this is the whole point
- Token lives in `~/.secrets/repo-scout.env` — never store it in this project
- Reports go to `reports/` (gitignored) or `--output` dir
- Scan log at `scan-log.md` tracks all scans
- Never commit reports, scan-log.md, or .env files to git
- Deep scan never clones — downloads tarball to temp dir, scans, deletes
- `safeclone` alias in `~/.bash_aliases` wraps quick scan + git clone
- Pattern false positives are expected — scanner flags, human reviews

## File Layout
- `cli.py` — entry point (argparse)
- `config.py` — token loading, constants
- `github_api.py` — GitHub REST API client
- `scanner.py` — scan orchestrator (quick/deep)
- `patterns.py` — all detection regexes
- `report.py` — markdown report generator
- `scan_log.py` — append-only scan log
- `utils.py` — URL parsing, helpers
