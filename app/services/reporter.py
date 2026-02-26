"""Colorful terminal report for SSH brute-force analysis."""


# ANSI color codes
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
    BG_YELLOW = "\033[43m"


SEVERITY_STYLE = {
    "critical": f"{C.BOLD}{C.BG_RED}{C.WHITE}",
    "high": f"{C.BOLD}{C.RED}",
    "medium": f"{C.YELLOW}",
    "low": f"{C.DIM}{C.WHITE}",
}


def _bar(value, max_value, width=30):
    filled = int((value / max(max_value, 1)) * width)
    return f"{C.RED}{'█' * filled}{C.DIM}{'░' * (width - filled)}{C.RESET}"


def print_report(parsed_entries, alerts, db_rows_inserted):
    """Print a colorful terminal summary of the analysis."""

    total_lines = len(parsed_entries)
    accepted = sum(1 for e in parsed_entries if e["event"] == "accepted")
    failed = sum(1 for e in parsed_entries if e["event"] in ("failed", "invalid_user"))
    unique_ips = len({e["ip"] for e in parsed_entries})
    suspicious_ips = len(alerts)

    # Header
    print()
    print(f"  {C.BOLD}{C.CYAN}╔══════════════════════════════════════════════════════╗{C.RESET}")
    print(f"  {C.BOLD}{C.CYAN}║     SSH BRUTE-FORCE DETECTION — ANALYSIS REPORT      ║{C.RESET}")
    print(f"  {C.BOLD}{C.CYAN}╚══════════════════════════════════════════════════════╝{C.RESET}")
    print()

    # Overview
    print(f"  {C.BOLD}{C.WHITE}▸ LOG OVERVIEW{C.RESET}")
    print(f"  {C.DIM}{'─' * 54}{C.RESET}")
    print(f"    Total log entries parsed    {C.BOLD}{C.WHITE}{total_lines:>8,}{C.RESET}")
    print(f"    Successful logins           {C.GREEN}{accepted:>8,}{C.RESET}")
    print(f"    Failed attempts             {C.RED}{failed:>8,}{C.RESET}")
    print(f"    Unique IPs seen             {C.BLUE}{unique_ips:>8,}{C.RESET}")
    print(f"    Suspicious IPs detected     {C.BOLD}{C.RED}{suspicious_ips:>8,}{C.RESET}")
    print(f"    Alerts saved to database    {C.MAGENTA}{db_rows_inserted:>8,}{C.RESET}")
    print()

    if not alerts:
        print(f"  {C.GREEN}  ✓ No brute-force patterns detected.{C.RESET}\n")
        return

    # Severity breakdown
    sev_counts = {}
    for a in alerts:
        sev_counts[a["severity"]] = sev_counts.get(a["severity"], 0) + 1

    print(f"  {C.BOLD}{C.WHITE}▸ SEVERITY BREAKDOWN{C.RESET}")
    print(f"  {C.DIM}{'─' * 54}{C.RESET}")
    for sev in ("critical", "high", "medium", "low"):
        cnt = sev_counts.get(sev, 0)
        style = SEVERITY_STYLE[sev]
        label = f"{style} {sev.upper():>8} {C.RESET}"
        print(f"    {label}  {cnt}")
    print()

    # Top 5 attackers
    top5 = alerts[:5]
    max_attempts = top5[0]["max_in_window"] if top5 else 1

    print(f"  {C.BOLD}{C.WHITE}▸ TOP 5 ATTACKERS{C.RESET}")
    print(f"  {C.DIM}{'─' * 54}{C.RESET}")
    print(f"    {'IP':<18} {'Severity':<10} {'Peak':>5}  {'Bar'}")
    print(f"  {C.DIM}{'─' * 54}{C.RESET}")

    for a in top5:
        style = SEVERITY_STYLE[a["severity"]]
        sev_label = f"{style}{a['severity'].upper():<10}{C.RESET}"
        bar = _bar(a["max_in_window"], max_attempts, 20)
        print(f"    {C.WHITE}{a['ip']:<18}{C.RESET} {sev_label} {a['max_in_window']:>5}  {bar}")

    print()

    # Detail table
    print(f"  {C.BOLD}{C.WHITE}▸ ALL ALERTS DETAIL{C.RESET}")
    print(f"  {C.DIM}{'─' * 54}{C.RESET}")
    for i, a in enumerate(alerts, 1):
        style = SEVERITY_STYLE[a["severity"]]
        print(
            f"    {C.DIM}{i:>2}.{C.RESET} {C.WHITE}{a['ip']:<18}{C.RESET}"
            f" {style}{a['severity'].upper():<8}{C.RESET}"
            f"  {a['max_in_window']:>3} in window / {a['total_failures']} total"
        )
        users_str = ", ".join(a["users_targeted"][:5])
        if len(a["users_targeted"]) > 5:
            users_str += f" (+{len(a['users_targeted']) - 5} more)"
        print(f"        {C.DIM}users: {users_str}{C.RESET}")

    print()
    print(f"  {C.BOLD}{C.CYAN}{'═' * 54}{C.RESET}")
    print(f"  {C.DIM}  Analysis complete. Alerts persisted in security.db{C.RESET}")
    print()
