"""Live SSH log monitor — tails auth.log and detects brute-force in real time."""

import os
import sys
import time
import platform
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path

from app.services.log_parser import parse_line, _FAILURE_EVENTS
from app.models.database import get_connection, init_db, save_alerts


# ANSI codes
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BG_RED = "\033[41m"


SEVERITY_STYLE = {
    "critical": f"{C.BOLD}{C.BG_RED}{C.WHITE}",
    "high": f"{C.BOLD}{C.RED}",
    "medium": f"{C.YELLOW}",
    "low": f"{C.DIM}{C.WHITE}",
}


def _detect_log_path():
    """Auto-detect the SSH auth log path based on the OS."""
    system = platform.system()
    candidates = []

    if system == "Darwin":
        # macOS: unified log, but some setups write to these
        candidates = [
            "/var/log/auth.log",
            "/var/log/secure",
            "/var/log/system.log",
        ]
    elif system == "Linux":
        candidates = [
            "/var/log/auth.log",       # Debian/Ubuntu
            "/var/log/secure",         # RHEL/CentOS/Fedora
            "/var/log/messages",       # Fallback
        ]
    else:
        candidates = ["/var/log/auth.log"]

    for path in candidates:
        if os.path.exists(path):
            return path

    return None


def _tail_file(path, poll_interval=0.5):
    """Generator that yields new lines appended to a file (like tail -f)."""
    with open(path, "r") as f:
        # Seek to end of file
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                yield line.rstrip("\n")
            else:
                time.sleep(poll_interval)


def _classify_severity(count, users):
    if count >= 50:
        severity = "critical"
    elif count >= 20:
        severity = "high"
    elif count >= 10:
        severity = "medium"
    else:
        severity = "low"
    if "root" in users and severity in ("low", "medium"):
        severity = "high" if severity == "medium" else "medium"
    return severity


def start_live_monitor(log_path=None, threshold=5, window_minutes=10):
    """Monitor SSH log in real time and alert on brute-force patterns.

    Tails the log file, maintains a sliding window of failures per IP,
    and prints alerts + saves to SQLite when thresholds are exceeded.
    """
    if log_path is None:
        log_path = _detect_log_path()

    if log_path is None or not os.path.exists(log_path):
        print(f"\n  {C.RED}Error:{C.RESET} No SSH log file found.")
        print(f"  Searched: /var/log/auth.log, /var/log/secure")
        print()
        print(f"  {C.BOLD}Options:{C.RESET}")
        print(f"    1. Run with a specific file:  python scripts/run_analysis.py live /path/to/auth.log")
        print(f"    2. Use demo mode:             python scripts/run_analysis.py demo")
        print(f"    3. Simulate live monitoring:   python scripts/simulate_live.py")
        print()
        if platform.system() == "Darwin":
            print(f"  {C.DIM}Note: macOS uses unified logging. SSH logs may not be in a flat file.")
            print(f"  You can redirect: log stream --predicate 'process == \"sshd\"' > /tmp/ssh.log &")
            print(f"  Then: python scripts/run_analysis.py live /tmp/ssh.log{C.RESET}")
            print()
        sys.exit(1)

    # Check read permission
    if not os.access(log_path, os.R_OK):
        print(f"\n  {C.RED}Error:{C.RESET} Permission denied: {log_path}")
        print(f"  Try: sudo python scripts/run_analysis.py live {log_path}")
        print()
        sys.exit(1)

    # Init DB
    conn = get_connection()
    init_db(conn)

    # State: sliding window of failures per IP
    failures = defaultdict(list)  # ip -> [timestamp, ...]
    alerted_ips = set()  # IPs we already alerted on this session
    users_by_ip = defaultdict(set)
    window = timedelta(minutes=window_minutes)

    event_count = 0
    fail_count = 0
    alert_count = 0

    # Header
    print()
    print(f"  {C.BOLD}{C.CYAN}╔══════════════════════════════════════════════════════╗{C.RESET}")
    print(f"  {C.BOLD}{C.CYAN}║          SSH LIVE MONITOR — REAL-TIME MODE           ║{C.RESET}")
    print(f"  {C.BOLD}{C.CYAN}╚══════════════════════════════════════════════════════╝{C.RESET}")
    print()
    print(f"  {C.WHITE}Watching:{C.RESET}  {log_path}")
    print(f"  {C.WHITE}Threshold:{C.RESET} {threshold} failures in {window_minutes} min")
    print(f"  {C.WHITE}Started:{C.RESET}   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  {C.DIM}  Press Ctrl+C to stop{C.RESET}")
    print()
    print(f"  {C.DIM}{'─' * 54}{C.RESET}")
    print()

    try:
        for line in _tail_file(log_path):
            entry = parse_line(line)
            if entry is None:
                continue

            event_count += 1
            ip = entry.get("ip", "")
            user = entry.get("user", "")
            ts = entry["timestamp"]
            event = entry["event"]

            # Show accepted logins
            if event == "accepted":
                print(
                    f"  {C.GREEN}✓ LOGIN{C.RESET}  "
                    f"{C.WHITE}{ip:<18}{C.RESET} "
                    f"user={C.CYAN}{user}{C.RESET}  "
                    f"{C.DIM}{ts.strftime('%H:%M:%S')}{C.RESET}"
                )
                continue

            # Track failures
            if event in _FAILURE_EVENTS and ip:
                fail_count += 1
                failures[ip].append(ts)
                if user:
                    users_by_ip[ip].add(user)

                # Prune old entries outside the window
                cutoff = ts - window
                failures[ip] = [t for t in failures[ip] if t > cutoff]

                count = len(failures[ip])

                # Show individual failure
                sev_indicator = C.DIM
                if count >= threshold:
                    sev_indicator = C.RED
                elif count >= threshold // 2:
                    sev_indicator = C.YELLOW

                print(
                    f"  {sev_indicator}✗ FAIL {C.RESET}  "
                    f"{C.WHITE}{ip:<18}{C.RESET} "
                    f"user={user:<12} "
                    f"({count}/{threshold} in window)  "
                    f"{C.DIM}{ts.strftime('%H:%M:%S')}{C.RESET}"
                )

                # Alert if threshold crossed and not yet alerted
                if count >= threshold and ip not in alerted_ips:
                    alerted_ips.add(ip)
                    alert_count += 1

                    users = list(users_by_ip[ip])
                    severity = _classify_severity(count, users)
                    style = SEVERITY_STYLE[severity]

                    alert_data = [{
                        "ip": ip,
                        "total_failures": count,
                        "max_in_window": count,
                        "window_start": failures[ip][0],
                        "window_end": ts,
                        "severity": severity,
                        "users_targeted": users,
                        "attack_type": "ssh_bruteforce",
                    }]
                    save_alerts(conn, alert_data)

                    print()
                    print(f"  {C.BOLD}{C.RED}{'━' * 54}{C.RESET}")
                    print(
                        f"  {style} ⚠ ALERT #{alert_count} {C.RESET}  "
                        f"Brute-force detected from {C.BOLD}{C.WHITE}{ip}{C.RESET}"
                    )
                    print(
                        f"           {style}{severity.upper()}{C.RESET} — "
                        f"{count} failures in {window_minutes} min — "
                        f"targeting: {', '.join(users[:5])}"
                    )
                    print(f"           {C.DIM}Alert saved to security.db{C.RESET}")
                    print(f"  {C.BOLD}{C.RED}{'━' * 54}{C.RESET}")
                    print()

                # Re-alert on escalation (double the threshold)
                elif count >= threshold * 2 and f"{ip}_escalated" not in alerted_ips:
                    alerted_ips.add(f"{ip}_escalated")
                    users = list(users_by_ip[ip])
                    severity = _classify_severity(count, users)
                    style = SEVERITY_STYLE[severity]

                    alert_data = [{
                        "ip": ip,
                        "total_failures": count,
                        "max_in_window": count,
                        "window_start": failures[ip][0],
                        "window_end": ts,
                        "severity": severity,
                        "users_targeted": users,
                        "attack_type": "ssh_bruteforce",
                    }]
                    save_alerts(conn, alert_data)

                    print()
                    print(f"  {C.BOLD}{C.BG_RED} ⚠ ESCALATION {C.RESET}  {ip} now at {count} failures — {style}{severity.upper()}{C.RESET}")
                    print()

    except KeyboardInterrupt:
        conn.close()
        print()
        print(f"  {C.BOLD}{C.CYAN}{'═' * 54}{C.RESET}")
        print(f"  {C.WHITE}  Live monitor stopped.{C.RESET}")
        print(f"    Events processed: {event_count}")
        print(f"    Failures seen:    {fail_count}")
        print(f"    Alerts triggered: {alert_count}")
        print(f"  {C.BOLD}{C.CYAN}{'═' * 54}{C.RESET}")
        print()
