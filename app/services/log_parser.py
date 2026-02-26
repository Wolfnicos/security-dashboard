"""Parse SSH log lines and detect brute-force attack patterns.

Supports both generated (fake) and real-world SSH logs, including
the OpenSSH dataset from logpai/loghub and standard /var/log/auth.log.
"""

import re
from datetime import datetime, timedelta
from collections import defaultdict

# ── Base sshd line pattern ──────────────────────────────────────────────
_LOG_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+"
    r"(?P<message>.+)$"
)

# ── Event-specific patterns ─────────────────────────────────────────────
# Accepted password/publickey for user from IP port PORT ssh2
_ACCEPTED_RE = re.compile(
    r"Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)"
)

# Failed password for [invalid user] USER from IP port PORT ssh2
_FAILED_RE = re.compile(
    r"Failed password for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)"
)

# Invalid user USER from IP  (no port — real-world format)
_INVALID_USER_RE = re.compile(
    r"Invalid user\s+(\S+)\s+from\s+(\S+)"
)

# reverse mapping checking getaddrinfo for HOSTNAME [IP] failed
_REVERSE_MAP_RE = re.compile(
    r"reverse mapping checking getaddrinfo for\s+\S+\s+\[(\S+)\]"
)

# Connection closed by IP [preauth]
_CONN_CLOSED_RE = re.compile(
    r"Connection closed by\s+(\S+)"
)

# Received disconnect from IP: ...
_RECV_DISCONNECT_RE = re.compile(
    r"Received disconnect from\s+(\S+):"
)

# Disconnecting: Too many authentication failures for USER [preauth]
_TOO_MANY_RE = re.compile(
    r"Disconnecting:.*authentication failures for\s+(\S+)"
)

# pam_unix(sshd:auth): authentication failure; ... rhost=IP [user=USER]
_PAM_AUTH_FAIL_RE = re.compile(
    r"pam_unix\(sshd:auth\): authentication failure;.*rhost=(\S+)(?:.*user=(\S+))?"
)

# message repeated N times: [ Failed password for USER from IP port PORT ssh2]
_MSG_REPEATED_RE = re.compile(
    r"message repeated\s+(\d+)\s+times:\s+\[\s*Failed password for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+)"
)

# pam_unix(sshd:session): session opened for user USER
_SESSION_OPEN_RE = re.compile(
    r"pam_unix\(sshd:session\): session opened for user\s+(\S+)"
)

# pam_unix(sshd:session): session closed for user USER
_SESSION_CLOSE_RE = re.compile(
    r"pam_unix\(sshd:session\): session closed for user\s+(\S+)"
)

# IP address validation (basic — filters out hostnames)
_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _is_ip(value):
    return bool(_IP_RE.match(value))


def parse_line(line, year=None):
    """Parse a single SSH log line into a structured dict.

    Handles all common sshd event types found in real-world logs.
    Returns None for lines that don't match sshd format.
    """
    m = _LOG_RE.match(line.strip())
    if not m:
        return None

    year = year or datetime.now().year
    try:
        ts = datetime.strptime(f"{year} {m.group('timestamp')}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None

    result = {
        "timestamp": ts,
        "host": m.group("host"),
        "pid": int(m.group("pid")),
        "raw": line.strip(),
    }

    msg = m.group("message")

    # ── "message repeated N times" (expands into N synthetic entries) ──
    rm = _MSG_REPEATED_RE.search(msg)
    if rm:
        result["event"] = "invalid_user" if "invalid user" in msg else "failed"
        result["repeat_count"] = int(rm.group(1))
        result["user"] = rm.group(2)
        result["ip"] = rm.group(3)
        result["port"] = int(rm.group(4))
        return result

    # ── Accepted login ──
    am = _ACCEPTED_RE.search(msg)
    if am:
        result["event"] = "accepted"
        result["method"] = am.group(1)
        result["user"] = am.group(2)
        result["ip"] = am.group(3)
        result["port"] = int(am.group(4))
        return result

    # ── Failed password ──
    fm = _FAILED_RE.search(msg)
    if fm:
        result["event"] = "invalid_user" if "invalid user" in msg else "failed"
        result["user"] = fm.group(1)
        result["ip"] = fm.group(2)
        result["port"] = int(fm.group(3))
        return result

    # ── Invalid user (no port) ──
    iu = _INVALID_USER_RE.search(msg)
    if iu:
        result["event"] = "invalid_user"
        result["user"] = iu.group(1)
        result["ip"] = iu.group(2)
        result["port"] = 0
        return result

    # ── Too many auth failures ──
    tm = _TOO_MANY_RE.search(msg)
    if tm:
        result["event"] = "too_many_failures"
        result["user"] = tm.group(1)
        result["ip"] = ""
        result["port"] = 0
        return result

    # ── PAM auth failure (has rhost=IP) ──
    pam = _PAM_AUTH_FAIL_RE.search(msg)
    if pam:
        rhost = pam.group(1)
        result["event"] = "pam_auth_failure"
        result["ip"] = rhost if _is_ip(rhost) else ""
        result["user"] = pam.group(2) or ""
        result["port"] = 0
        return result

    # ── Reverse mapping failure (recon indicator) ──
    rv = _REVERSE_MAP_RE.search(msg)
    if rv:
        result["event"] = "reverse_mapping_failed"
        result["ip"] = rv.group(1)
        result["user"] = ""
        result["port"] = 0
        return result

    # ── Connection closed ──
    cc = _CONN_CLOSED_RE.search(msg)
    if cc and _is_ip(cc.group(1)):
        result["event"] = "connection_closed"
        result["ip"] = cc.group(1)
        result["user"] = ""
        result["port"] = 0
        return result

    # ── Received disconnect ──
    rd = _RECV_DISCONNECT_RE.search(msg)
    if rd and _is_ip(rd.group(1)):
        result["event"] = "disconnect"
        result["ip"] = rd.group(1)
        result["user"] = ""
        result["port"] = 0
        return result

    # ── Session opened ──
    so = _SESSION_OPEN_RE.search(msg)
    if so:
        result["event"] = "session_opened"
        result["user"] = so.group(1)
        result["ip"] = ""
        result["port"] = 0
        return result

    # ── Session closed ──
    sc = _SESSION_CLOSE_RE.search(msg)
    if sc:
        result["event"] = "session_closed"
        result["user"] = sc.group(1)
        result["ip"] = ""
        result["port"] = 0
        return result

    # ── Unrecognized sshd line — still return base info ──
    result["event"] = "other"
    result["ip"] = ""
    result["user"] = ""
    result["port"] = 0
    return result


# Events that count as authentication failures for brute-force detection
_FAILURE_EVENTS = {"failed", "invalid_user", "pam_auth_failure", "too_many_failures"}


def parse_logs(lines, year=None):
    """Parse multiple log lines.

    Expands 'message repeated N times' entries into N individual entries.
    """
    parsed = []
    for line in lines:
        entry = parse_line(line, year)
        if entry is None:
            continue
        repeat = entry.pop("repeat_count", 1)
        for _ in range(repeat):
            parsed.append(entry if repeat == 1 else dict(entry))
    return parsed


def detect_bruteforce(parsed_entries, threshold=5, window_minutes=10):
    """Detect brute-force attacks: IPs with >= threshold failures within a sliding window.

    Returns a list of alert dicts with IP, attempt count, time window, and severity.
    """
    failures_by_ip = defaultdict(list)
    for entry in parsed_entries:
        if entry["event"] in _FAILURE_EVENTS and entry.get("ip"):
            failures_by_ip[entry["ip"]].append(entry)

    window = timedelta(minutes=window_minutes)
    alerts = []

    for ip, attempts in failures_by_ip.items():
        attempts.sort(key=lambda e: e["timestamp"])

        # Sliding window
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
            users_targeted = list({a.get("user", "") for a in attempts} - {""})

            if max_in_window >= 50:
                severity = "critical"
            elif max_in_window >= 20:
                severity = "high"
            elif max_in_window >= 10:
                severity = "medium"
            else:
                severity = "low"

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
