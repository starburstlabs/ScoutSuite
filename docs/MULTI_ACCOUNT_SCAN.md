# Multi-Account ScoutSuite Scanner

A tool for running ScoutSuite security audits across multiple Wealthbox AWS accounts in parallel.

## Prerequisites

### 1. Python Virtual Environment & Dependencies

ScoutSuite requires a Python virtual environment with its dependencies installed:

```bash
cd /path/to/ScoutSuite

# Create a virtual environment
python3 -m venv .venv

# Activate it
source .venv/bin/activate

# Install ScoutSuite dependencies
pip install -r requirements.txt
```

> **Note:** On macOS with Homebrew Python, you cannot install packages globally (`pip install` will fail with PEP 668). The virtual environment is required.

> **Python 3.14 compatibility:** This fork includes a fix for `asyncio.get_event_loop()` which was removed in Python 3.14. If you encounter `RuntimeError: There is no current event loop in thread 'MainThread'`, ensure you are running from this repo (not an older upstream version).

### 2. GitHub CLI (`gh`)

The tool fetches account data from the `starburstlabs/terraform-modules` repo at runtime. This requires the GitHub CLI.

```bash
# Install (macOS)
brew install gh

# Authenticate
gh auth login
```

The tool checks `gh auth status` on startup and will prompt you to log in if not authenticated.

**What it fetches:** The file `org-data/config/accounts.json` from the `v1` branch of `starburstlabs/terraform-modules`. This JSON file defines all AWS account names, IDs, and their level groupings (dev, stg, prod, shared). By fetching at runtime, account data is always up to date without maintaining a local copy.

### 3. AWS SSO

All Wealthbox AWS accounts use a shared AWS SSO session. The tool uses AWS CLI profiles named `<account-name>-admin` (e.g., `prod-admin`, `legacy-prod-admin`).

```bash
# Ensure your ~/.aws/config has SSO profiles configured
# The tool will check your SSO session and prompt login if expired:
aws sso login --profile prod-admin
```

The tool validates the SSO token in `~/.aws/sso/cache/` before starting scans. If the token is expired or missing, it runs `aws sso login` interactively.

## Usage

Run the tool from the ScoutSuite repo root:

```bash
python3 tools/multi_account_scan.py [selection] [options] [-- extra_scout_args...]
```

### Account Selection (one required)

| Flag | Description |
|------|-------------|
| `--accounts NAME [NAME ...]` | Scan specific accounts by name |
| `--levels LEVEL [LEVEL ...]` | Scan all accounts at a given level: `dev`, `stg`, `prod`, `shared` |
| `--all` | Scan all accounts in the org |

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--parallel N` | 4 | Max concurrent scans |
| `--output-dir DIR` | `./scoutsuite-reports` | Base report directory |
| `--accounts-file PATH` | *(fetch from GitHub)* | Use a local `accounts.json` instead of fetching from GitHub |
| `--services SVC [SVC ...]` | *(all)* | Limit to specific ScoutSuite services (e.g., `iam s3 ec2`) |
| `--regions REGION [REGION ...]` | *(all)* | Limit to specific AWS regions |
| `--dry-run` | | Print commands without executing |
| `--skip-sso-check` | | Skip SSO session validation |

Anything after `--` is passed through verbatim to every ScoutSuite invocation.

### Examples

```bash
# Scan all production accounts
python3 tools/multi_account_scan.py --levels prod

# Scan specific accounts with higher parallelism
python3 tools/multi_account_scan.py --accounts prod legacy-prod dev --parallel 6

# Scan all accounts, limited to IAM and S3
python3 tools/multi_account_scan.py --all --services iam s3

# Preview what would run without executing
python3 tools/multi_account_scan.py --all --dry-run

# Scan dev and staging with extra ScoutSuite flags
python3 tools/multi_account_scan.py --levels dev stg -- --max-rate 5 --debug

# Use a local accounts file instead of fetching from GitHub
python3 tools/multi_account_scan.py --all --accounts-file ~/code/terraform-modules/org-data/config/accounts.json
```

## Output

Reports are organized by date, level, and account:

```
scoutsuite-reports/
  2026-04-09/
    shared/
      aws-alerts/
      audit/
      ...
    dev/
      dev/
      legacy-dev/
      ops-dev/
    stg/
      ca-stg/
      legacy-stg/
      qa/
      stg1/
    prod/
      legacy-prod/
      prod/
      prod-ca/
      support-ops/
```

Each account directory contains:
- The ScoutSuite HTML report and results data
- `scan.log` — full stdout/stderr from the scan (useful for debugging failures)

## Progress & Summary

During execution, the tool displays a live status line:

```
[3/20 done, 1 failed, 12.3m elapsed] Running: prod, legacy-prod, dev
```

When complete, a summary table is printed:

```
======================================================================
ScoutSuite Multi-Account Scan Summary
======================================================================

  Account              Level      Status   Duration     Details
  -------------------- ---------- -------- ------------ -------------------
  legacy-prod          prod       PASS     1m 23s       ./scoutsuite-reports/...
  prod                 prod       PASS     1m 14s       ./scoutsuite-reports/...
  prod-ca              prod       PASS     1m 02s       ./scoutsuite-reports/...

  Total: 3 passed, 0 failed
  CPU time: 3m 39s, Wall time: 1m 23s
```

## Exit Codes

The tool exits with `0` if all scans pass, or `1` if any fail.

ScoutSuite exit code `200` ("Completed with errors") is treated as a pass — this indicates the scan completed successfully but encountered non-fatal API errors during data gathering (common with restricted permissions).

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `ModuleNotFoundError: No module named 'asyncio_throttle'` | Activate the venv: `source .venv/bin/activate`, or the tool auto-detects `.venv/bin/python` |
| `RuntimeError: There is no current event loop` | You're on Python 3.14+; this repo includes the fix in `ScoutSuite/__main__.py` |
| `gh: command not found` | Install GitHub CLI: `brew install gh` |
| `ERROR: Failed to fetch accounts from GitHub` | Run `gh auth login` to authenticate |
| `AWS SSO session is expired` | The tool will prompt you automatically; or run `aws sso login --profile prod-admin` |
| All scans fail with exit code 101 | SSO token expired mid-run; re-authenticate and retry |
| High memory usage | Reduce `--parallel` (each scan can consume significant memory) |

## Dependencies Summary

| Dependency | Purpose | Install |
|------------|---------|---------|
| Python 3.x | Runtime | `brew install python` |
| ScoutSuite requirements | ScoutSuite libraries | `pip install -r requirements.txt` (in venv) |
| GitHub CLI (`gh`) | Fetch account data from `starburstlabs/terraform-modules` | `brew install gh` |
| AWS CLI v2 | SSO authentication | `brew install awscli` |
| AWS SSO profiles | Per-account access (`<name>-admin`) | Configured in `~/.aws/config` |
