#!/usr/bin/env python3
"""
SSH Log Brute-Force Analysis

Modes:
  demo    — Generate 1000 fake SSH logs and analyze them
  real    — Parse a real log file (e.g. OpenSSH_2k.log from loghub)
  live    — Tail /var/log/auth.log (or custom path) and detect attacks in real time

Usage:
  python scripts/run_analysis.py demo
  python scripts/run_analysis.py real data/OpenSSH_2k.log
  python scripts/run_analysis.py real /var/log/auth.log --year 2024
  python scripts/run_analysis.py live
  python scripts/run_analysis.py live /var/log/auth.log
  python scripts/run_analysis.py live --threshold 3 --window 5
"""

import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services.log_generator import generate_logs
from app.services.log_parser import parse_logs, detect_bruteforce
from app.services.live_monitor import start_live_monitor
from app.models.database import get_connection, init_db, save_alerts
from app.services.reporter import print_report


def cmd_demo(args):
    """Generate fake logs and analyze them."""
    print("\n  Generating 1000 SSH log entries...")
    log_lines = generate_logs(count=1000, brute_force_ips=8, attempts_per_bf=15)

    logs_path = Path(__file__).resolve().parent.parent / "data" / "ssh_auth.log"
    logs_path.parent.mkdir(exist_ok=True)
    logs_path.write_text("\n".join(log_lines) + "\n")
    print(f"  Saved raw logs to {logs_path.relative_to(logs_path.parent.parent)}")

    parsed = parse_logs(log_lines)
    alerts = detect_bruteforce(parsed, threshold=args.threshold, window_minutes=args.window)

    conn = get_connection()
    init_db(conn)
    rows = save_alerts(conn, alerts)
    conn.close()

    print_report(parsed, alerts, rows)


def cmd_real(args):
    """Parse a real log file and analyze it."""
    log_path = Path(args.file)
    if not log_path.exists():
        print(f"\n  Error: File not found: {log_path}")
        sys.exit(1)

    print(f"\n  Reading {log_path}...")
    log_lines = log_path.read_text().splitlines()
    print(f"  Loaded {len(log_lines):,} lines")

    print("  Parsing logs and detecting brute-force patterns...")
    parsed = parse_logs(log_lines, year=args.year)
    print(f"  Parsed {len(parsed):,} SSH events")

    alerts = detect_bruteforce(parsed, threshold=args.threshold, window_minutes=args.window)

    conn = get_connection()
    init_db(conn)
    rows = save_alerts(conn, alerts)
    conn.close()

    print_report(parsed, alerts, rows)


def cmd_live(args):
    """Tail a log file and detect attacks in real time."""
    start_live_monitor(
        log_path=args.file,
        threshold=args.threshold,
        window_minutes=args.window,
    )


def main():
    parser = argparse.ArgumentParser(
        description="SSH Log Brute-Force Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command")

    # -- demo --
    p_demo = sub.add_parser("demo", help="Generate fake logs and analyze")
    p_demo.add_argument("--threshold", type=int, default=5, help="Min failures to trigger alert (default: 5)")
    p_demo.add_argument("--window", type=int, default=10, help="Sliding window in minutes (default: 10)")

    # -- real --
    p_real = sub.add_parser("real", help="Analyze a real log file")
    p_real.add_argument("file", help="Path to SSH log file")
    p_real.add_argument("--year", type=int, default=None, help="Year for log timestamps (default: current)")
    p_real.add_argument("--threshold", type=int, default=5, help="Min failures to trigger alert (default: 5)")
    p_real.add_argument("--window", type=int, default=10, help="Sliding window in minutes (default: 10)")

    # -- live --
    p_live = sub.add_parser("live", help="Monitor a log file in real time")
    p_live.add_argument("file", nargs="?", default=None, help="Log file path (auto-detects OS default)")
    p_live.add_argument("--threshold", type=int, default=5, help="Min failures to trigger alert (default: 5)")
    p_live.add_argument("--window", type=int, default=10, help="Sliding window in minutes (default: 10)")

    args = parser.parse_args()

    if args.command == "demo":
        cmd_demo(args)
    elif args.command == "real":
        cmd_real(args)
    elif args.command == "live":
        cmd_live(args)
    else:
        parser.print_help()
        print("\n  Example: python scripts/run_analysis.py demo")


if __name__ == "__main__":
    main()
