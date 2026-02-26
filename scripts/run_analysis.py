#!/usr/bin/env python3
"""
SSH Log Brute-Force Analysis — Entry Point

Generates fake SSH logs, parses them, detects brute-force patterns,
saves alerts to SQLite, and prints a colorful terminal report.

Usage:
    python scripts/run_analysis.py
"""

import sys
from pathlib import Path

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services.log_generator import generate_logs
from app.services.log_parser import parse_logs, detect_bruteforce
from app.models.database import get_connection, init_db, save_alerts
from app.services.reporter import print_report


def main():
    # 1. Generate fake SSH logs
    print("\n  Generating 1000 SSH log entries...")
    log_lines = generate_logs(count=1000, brute_force_ips=8, attempts_per_bf=15)

    # Save raw logs to file for inspection
    logs_path = Path(__file__).resolve().parent.parent / "data" / "ssh_auth.log"
    logs_path.parent.mkdir(exist_ok=True)
    logs_path.write_text("\n".join(log_lines) + "\n")
    print(f"  Saved raw logs to {logs_path.relative_to(logs_path.parent.parent)}")

    # 2. Parse & detect
    print("  Parsing logs and detecting brute-force patterns...")
    parsed = parse_logs(log_lines)
    alerts = detect_bruteforce(parsed, threshold=5, window_minutes=10)

    # 3. Persist to SQLite
    conn = get_connection()
    init_db(conn)
    rows = save_alerts(conn, alerts)
    conn.close()

    # 4. Terminal report
    print_report(parsed, alerts, rows)


if __name__ == "__main__":
    main()
