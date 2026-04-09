#!/usr/bin/env python3
"""
Multi-Account ScoutSuite Runner

Runs ScoutSuite security audits across multiple AWS accounts in parallel.
Account data is fetched live from the starburstlabs/terraform-modules repo.

Usage:
    python tools/multi_account_scan.py --levels prod --parallel 4
    python tools/multi_account_scan.py --accounts prod legacy-prod dev
    python tools/multi_account_scan.py --all --services iam s3 -- --max-rate 5
    python tools/multi_account_scan.py --all --dry-run
"""

import argparse
import base64
import dataclasses
import datetime
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from glob import glob
from pathlib import Path

# --- Constants ---

GITHUB_REPO = "starburstlabs/terraform-modules"
GITHUB_BRANCH = "v1"
ACCOUNTS_PATH = "org-data/config/accounts.json"

SSO_START_URL = "https://wealthbox.awsapps.com/start"
PROFILE_SUFFIX = "-admin"

VALID_LEVELS = {"dev", "stg", "prod", "shared"}

SCOUT_EXIT_CODES = {
    0: "Success",
    101: "Authentication failure",
    102: "Initialization failure",
    103: "Report init failure",
    104: "Data gathering failure",
    105: "Pre-processing failure",
    106: "Rule engine failure",
    107: "Display filter failure",
    108: "Post-processing failure",
    109: "Report generation failure",
    130: "Cancelled by user",
    200: "Completed with errors",
}

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent


# --- Data classes ---


@dataclasses.dataclass
class ScanResult:
    account_name: str
    account_id: str
    level: str
    profile: str
    exit_code: int
    start_time: float
    end_time: float
    report_dir: str
    log_file: str

    @property
    def success(self) -> bool:
        return self.exit_code in (0, 200)

    @property
    def duration_seconds(self) -> float:
        return self.end_time - self.start_time

    @property
    def exit_message(self) -> str:
        return SCOUT_EXIT_CODES.get(self.exit_code, f"Unknown exit code {self.exit_code}")


# --- Progress tracking ---


class ProgressTracker:
    def __init__(self, total: int):
        self.total = total
        self.completed = 0
        self.failed = 0
        self.in_progress: list[str] = []
        self.start_time = time.time()
        self.lock = threading.Lock()

    def start(self, account_name: str):
        with self.lock:
            self.in_progress.append(account_name)
            self._print_status()

    def finish(self, account_name: str, result: ScanResult):
        with self.lock:
            self.in_progress.remove(account_name)
            self.completed += 1
            if not result.success:
                self.failed += 1

            status = "PASS" if result.success else "FAIL"
            duration = format_duration(result.duration_seconds)
            line = f"  {status}  {result.account_name:<20} ({duration})"
            if not result.success:
                line += f"  [{result.exit_message}] see {result.log_file}"
            print(f"\r\033[K{line}")
            self._print_status()

    def _print_status(self):
        elapsed = format_duration(time.time() - self.start_time)
        running = ", ".join(self.in_progress) if self.in_progress else "none"
        status = f"[{self.completed}/{self.total} done"
        if self.failed:
            status += f", {self.failed} failed"
        status += f", {elapsed} elapsed] Running: {running}"
        print(f"\r\033[K{status}", end="", flush=True)


# --- Helper functions ---


def format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.0f}s"
    minutes = int(seconds // 60)
    secs = int(seconds % 60)
    if minutes < 60:
        return f"{minutes}m {secs:02d}s"
    hours = int(minutes // 60)
    mins = minutes % 60
    return f"{hours}h {mins:02d}m"


def check_gh_auth() -> bool:
    """Check if GitHub CLI is authenticated."""
    result = subprocess.run(
        ["gh", "auth", "status"],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def login_gh():
    """Force interactive GitHub CLI login."""
    print("GitHub CLI is not authenticated. Starting login...")
    result = subprocess.run(["gh", "auth", "login"])
    if result.returncode != 0:
        print("ERROR: GitHub CLI login failed.", file=sys.stderr)
        sys.exit(1)
    print("GitHub CLI authenticated successfully.")


def fetch_accounts_from_github() -> dict:
    """Fetch accounts.json from GitHub via gh CLI."""
    result = subprocess.run(
        [
            "gh", "api",
            f"repos/{GITHUB_REPO}/contents/{ACCOUNTS_PATH}?ref={GITHUB_BRANCH}",
            "--jq", ".content",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"ERROR: Failed to fetch accounts from GitHub: {result.stderr.strip()}", file=sys.stderr)
        sys.exit(1)

    content = base64.b64decode(result.stdout.strip()).decode("utf-8")
    return json.loads(content)


def load_accounts(accounts_file: str | None = None) -> dict:
    """Load account data from local file or GitHub."""
    if accounts_file:
        with open(accounts_file) as f:
            return json.load(f)
    return fetch_accounts_from_github()


def check_sso_session() -> bool:
    """Check if AWS SSO session is still valid."""
    sso_cache_dir = Path.home() / ".aws" / "sso" / "cache"
    if not sso_cache_dir.exists():
        return False

    for cache_file in sso_cache_dir.glob("*.json"):
        try:
            with open(cache_file) as f:
                data = json.load(f)
            if data.get("startUrl") != SSO_START_URL:
                continue
            expires_at = data.get("expiresAt", "")
            # Handle both formats: with and without Z suffix
            expires_at = expires_at.replace("Z", "+00:00")
            expiry = datetime.datetime.fromisoformat(expires_at)
            now = datetime.datetime.now(datetime.timezone.utc)
            # Valid if more than 5 minutes remain
            return (expiry - now).total_seconds() > 300
        except (json.JSONDecodeError, ValueError, KeyError):
            continue

    return False


def login_sso(profile: str):
    """Force interactive AWS SSO login."""
    print("AWS SSO session is expired or missing. Starting login...")
    result = subprocess.run(["aws", "sso", "login", "--profile", profile])
    if result.returncode != 0:
        print("ERROR: AWS SSO login failed.", file=sys.stderr)
        sys.exit(1)
    print("AWS SSO authenticated successfully.")


def resolve_accounts(args, accounts_data: dict) -> list[dict]:
    """Resolve CLI arguments to a list of account dicts."""
    accounts = []

    if args.all:
        selected_names = sorted(accounts_data.keys())
    elif args.levels:
        invalid = set(args.levels) - VALID_LEVELS
        if invalid:
            print(f"ERROR: Unknown levels: {', '.join(sorted(invalid))}. Valid: {', '.join(sorted(VALID_LEVELS))}", file=sys.stderr)
            sys.exit(1)
        selected_names = sorted(
            name for name, info in accounts_data.items()
            if info["level"] in args.levels
        )
    elif args.accounts:
        unknown = [name for name in args.accounts if name not in accounts_data]
        if unknown:
            print(f"ERROR: Unknown accounts: {', '.join(unknown)}", file=sys.stderr)
            print(f"Valid accounts: {', '.join(sorted(accounts_data.keys()))}", file=sys.stderr)
            sys.exit(1)
        selected_names = args.accounts
    else:
        print("ERROR: Must specify --accounts, --levels, or --all", file=sys.stderr)
        sys.exit(1)

    for name in selected_names:
        info = accounts_data[name]
        accounts.append({
            "name": name,
            "id": info["id"],
            "level": info["level"],
            "profile": f"{name}{PROFILE_SUFFIX}",
        })

    return accounts


def find_scout_command() -> list[str]:
    """Find the scout command to use."""
    scout_path = shutil.which("scout")
    if scout_path:
        return [scout_path]
    # Fall back to running scout.py from the repo with the venv python
    scout_py = REPO_ROOT / "scout.py"
    if scout_py.exists():
        venv_python = REPO_ROOT / ".venv" / "bin" / "python"
        python = str(venv_python) if venv_python.exists() else sys.executable
        return [python, str(scout_py)]
    print("ERROR: Cannot find 'scout' command or scout.py in repo root.", file=sys.stderr)
    sys.exit(1)


def run_scout_for_account(
    account: dict,
    output_dir: str,
    date_str: str,
    scout_command: list[str],
    scout_args: list[str],
    extra_args: list[str],
) -> ScanResult:
    """Run ScoutSuite for a single account."""
    report_dir = os.path.join(output_dir, date_str, account["level"], account["name"])
    os.makedirs(report_dir, exist_ok=True)

    log_file = os.path.join(report_dir, "scan.log")
    report_name = f"aws-{account['profile']}"

    cmd = [
        *scout_command,
        "aws",
        "--profile", account["profile"],
        "--no-browser",
        "--force",
        "--report-dir", report_dir,
        "--report-name", report_name,
        *scout_args,
        *extra_args,
    ]

    start_time = time.time()
    with open(log_file, "w") as lf:
        lf.write(f"Command: {' '.join(cmd)}\n")
        lf.write(f"Started: {datetime.datetime.now().isoformat()}\n")
        lf.write("-" * 60 + "\n")
        lf.flush()
        result = subprocess.run(cmd, stdout=lf, stderr=subprocess.STDOUT)
    end_time = time.time()

    return ScanResult(
        account_name=account["name"],
        account_id=account["id"],
        level=account["level"],
        profile=account["profile"],
        exit_code=result.returncode,
        start_time=start_time,
        end_time=end_time,
        report_dir=report_dir,
        log_file=log_file,
    )


def print_summary(results: list[ScanResult], wall_start: float):
    """Print final summary table."""
    wall_elapsed = time.time() - wall_start
    passed = sum(1 for r in results if r.success)
    failed = sum(1 for r in results if not r.success)
    total_cpu = sum(r.duration_seconds for r in results)

    print("\n" + "=" * 70)
    print("ScoutSuite Multi-Account Scan Summary")
    print("=" * 70)
    print()
    print(f"  {'Account':<20} {'Level':<10} {'Status':<8} {'Duration':<12} {'Details'}")
    print(f"  {'-'*20} {'-'*10} {'-'*8} {'-'*12} {'-'*30}")

    # Sort by level then name
    level_order = {"shared": 0, "dev": 1, "stg": 2, "prod": 3}
    for r in sorted(results, key=lambda x: (level_order.get(x.level, 99), x.account_name)):
        status = "PASS" if r.success else "FAIL"
        duration = format_duration(r.duration_seconds)
        details = r.report_dir if r.success else f"{r.exit_message} - see {r.log_file}"
        print(f"  {r.account_name:<20} {r.level:<10} {status:<8} {duration:<12} {details}")

    print()
    print(f"  Total: {passed} passed, {failed} failed")
    print(f"  CPU time: {format_duration(total_cpu)}, Wall time: {format_duration(wall_elapsed)}")
    print()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run ScoutSuite across multiple AWS accounts in parallel.",
        epilog="Extra arguments after -- are passed through to ScoutSuite.",
    )

    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument(
        "--accounts", nargs="+", metavar="NAME",
        help="Specific account names to scan",
    )
    selection.add_argument(
        "--levels", nargs="+", metavar="LEVEL",
        help="Scan all accounts at given levels (dev, stg, prod, shared)",
    )
    selection.add_argument(
        "--all", action="store_true",
        help="Scan all accounts",
    )

    parser.add_argument(
        "--parallel", type=int, default=4,
        help="Max concurrent scans (default: 4)",
    )
    parser.add_argument(
        "--output-dir", default="./scoutsuite-reports",
        help="Base report directory (default: ./scoutsuite-reports)",
    )
    parser.add_argument(
        "--accounts-file", metavar="PATH",
        help="Local accounts.json file (default: fetch from GitHub)",
    )
    parser.add_argument(
        "--services", nargs="+", metavar="SVC",
        help="ScoutSuite services to scan (passed through to --services)",
    )
    parser.add_argument(
        "--regions", nargs="+", metavar="REGION",
        help="AWS regions to scan (passed through to --regions)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print commands without executing",
    )
    parser.add_argument(
        "--skip-sso-check", action="store_true",
        help="Skip AWS SSO session validation",
    )

    return parser


def main():
    # Split args on -- to separate our args from ScoutSuite passthrough args
    argv = sys.argv[1:]
    extra_args = []
    if "--" in argv:
        split_idx = argv.index("--")
        extra_args = argv[split_idx + 1:]
        argv = argv[:split_idx]

    parser = build_parser()
    args = parser.parse_args(argv)

    # --- Preflight: GH auth ---
    if not args.accounts_file:
        if not check_gh_auth():
            login_gh()

    # --- Fetch account data ---
    print("Loading account data...")
    accounts_data = load_accounts(args.accounts_file)
    print(f"  Loaded {len(accounts_data)} accounts")

    # --- Preflight: SSO ---
    if not args.skip_sso_check and not args.dry_run:
        if not check_sso_session():
            # Use the first resolved account's profile for SSO login
            first_profile = f"{next(iter(accounts_data))}{PROFILE_SUFFIX}"
            login_sso(first_profile)

    # --- Resolve accounts ---
    accounts = resolve_accounts(args, accounts_data)
    if not accounts:
        print("No accounts matched the selection.")
        sys.exit(0)

    # --- Build ScoutSuite args ---
    scout_args = []
    if args.services:
        scout_args.extend(["--services"] + args.services)
    if args.regions:
        scout_args.extend(["--regions"] + args.regions)

    scout_command = find_scout_command()
    date_str = datetime.date.today().isoformat()

    # --- Print plan ---
    print(f"\nAccounts to scan ({len(accounts)}):")
    for level in ["shared", "dev", "stg", "prod"]:
        level_accounts = [a for a in accounts if a["level"] == level]
        if level_accounts:
            names = ", ".join(a["name"] for a in level_accounts)
            print(f"  {level}: {names}")
    print(f"\nParallelism: {args.parallel}")
    print(f"Output: {args.output_dir}/{date_str}/")
    if scout_args or extra_args:
        print(f"Extra args: {' '.join(scout_args + extra_args)}")
    print()

    # --- Dry run ---
    if args.dry_run:
        print("[DRY RUN] Commands that would be executed:\n")
        for i, account in enumerate(accounts, 1):
            report_dir = os.path.join(args.output_dir, date_str, account["level"], account["name"])
            report_name = f"aws-{account['profile']}"
            cmd = [
                *scout_command, "aws",
                "--profile", account["profile"],
                "--no-browser", "--force",
                "--report-dir", report_dir,
                "--report-name", report_name,
                *scout_args,
                *extra_args,
            ]
            print(f"  {i}. {' '.join(cmd)}\n")
        return

    # --- Signal handling ---
    shutting_down = threading.Event()

    def handle_sigint(signum, frame):
        if shutting_down.is_set():
            print("\n\nForce quitting...")
            sys.exit(130)
        shutting_down.set()
        print("\n\nShutting down... waiting for in-progress scans to finish.")

    signal.signal(signal.SIGINT, handle_sigint)

    # --- Execute scans ---
    wall_start = time.time()
    tracker = ProgressTracker(len(accounts))
    results: list[ScanResult] = []

    print("Starting scans...\n")

    with ThreadPoolExecutor(max_workers=args.parallel) as executor:
        futures = {}
        for account in accounts:
            if shutting_down.is_set():
                break
            future = executor.submit(
                run_scout_for_account,
                account=account,
                output_dir=args.output_dir,
                date_str=date_str,
                scout_command=scout_command,
                scout_args=scout_args,
                extra_args=extra_args,
            )
            futures[future] = account
            tracker.start(account["name"])

        for future in as_completed(futures):
            account = futures[future]
            try:
                result = future.result()
            except Exception as e:
                result = ScanResult(
                    account_name=account["name"],
                    account_id=account["id"],
                    level=account["level"],
                    profile=account["profile"],
                    exit_code=-1,
                    start_time=time.time(),
                    end_time=time.time(),
                    report_dir="",
                    log_file="",
                )
                print(f"\r\033[KERROR running scan for {account['name']}: {e}")
            results.append(result)
            tracker.finish(account["name"], result)

    # --- Summary ---
    print_summary(results, wall_start)

    # Exit with 1 if any scan failed
    if any(not r.success for r in results):
        sys.exit(1)


if __name__ == "__main__":
    main()
