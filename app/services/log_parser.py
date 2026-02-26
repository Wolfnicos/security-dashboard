"""Parse SSH log lines and detect brute-force attack patterns."""

import re
from datetime import datetime, timedelta
from collections import defaultdict

# Matches standard sshd auth log lines
_LOG_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+"
    r"(?P<message>.+)$"
)

_ACCEPTED_RE = re.compile(r"Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)")
_FAILED_RE = re.compile(r"Failed password for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)")


def parse_line(line, year=None):
    """Parse a single SSH log line into a structured dict.

    Returns None for lines that don't match the expected format.
    """
    m = _LOG_RE.match(line.strip())
    if not m:
        return None

    year = year or datetime.now().year
    ts = datetime.strptime(f"{year} {m.group('timestamp')}", "%Y %b %d %H:%M:%S")

    result = {
        "timestamp": ts,
        "host": m.group("host"),
        "pid": int(m.group("pid")),
        "raw": line.strip(),
    }

    msg = m.group("message")

    am = _ACCEPTED_RE.search(msg)
    if am:
        result["event"] = "accepted"
        result["method"] = am.group(1)
        result["user"] = am.group(2)
        result["ip"] = am.group(3)
        result["port"] = int(am.group(4))
        return result

    fm = _FAILED_RE.search(msg)
    if fm:
        result["event"] = "invalid_user" if "invalid user" in msg else "failed"
        result["user"] = fm.group(1)
        result["ip"] = fm.group(2)
        result["port"] = int(fm.group(3))
        return result

    return None


def parse_logs(lines, year=None):
    """Parse multiple log lines, skipping unparseable ones."""
    parsed = []
    for line in lines:
        entry = parse_line(line, year)
        if entry:
            parsed.append(entry)
    return parsed


def detect_bruteforce(parsed_entries, threshold=5, window_minutes=10):
    """Detect brute-force attacks: IPs with >= threshold failures within a sliding window.

    Returns a list of alert dicts with IP, attempt count, time window, and severity.
    """
    # Group failed attempts by IP
    failures_by_ip = defaultdict(list)
    for entry in parsed_entries:
        if entry["event"] in ("failed", "invalid_user"):
            failures_by_ip[entry["ip"]].append(entry)

    window = timedelta(minutes=window_minutes)
    alerts = []

    for ip, attempts in failures_by_ip.items():
        attempts.sort(key=lambda e: e["timestamp"])

        # Sliding window: for each attempt, count how many fall within the window
        max_in_window = 0
        window_start_ts = None
        window_end_ts = None

        for i, entry in enumerate(attempts):
            count = 0
            for j in range(i, len(attempts)):
                if attempts[j]["timestamp"] - entry["timestamp"] <= window:
                    count += 1
                else:
                    break
            if count > max_in_window:
                max_in_window = count
                window_start_ts = entry["timestamp"]
                window_end_ts = attempts[min(i + count - 1, len(attempts) - 1)]["timestamp"]

        if max_in_window >= threshold:
            # Determine targeted users
            users_targeted = list({a["user"] for a in attempts})

            # Severity based on attempt volume
            if max_in_window >= 50:
                severity = "critical"
            elif max_in_window >= 20:
                severity = "high"
            elif max_in_window >= 10:
                severity = "medium"
            else:
                severity = "low"

            # Escalate if root was targeted
            if "root" in users_targeted and severity in ("low", "medium"):
                severity = "high" if severity == "medium" else "medium"

            alerts.append({
                "ip": ip,
                "total_failures": len(attempts),
                "max_in_window": max_in_window,
                "window_start": window_start_ts,
                "window_end": window_end_ts,
                "severity": severity,
                "users_targeted": users_targeted,
                "attack_type": "ssh_bruteforce",
            })

    alerts.sort(key=lambda a: a["max_in_window"], reverse=True)
    return alerts
