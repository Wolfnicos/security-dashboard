"""Generate realistic fake SSH auth logs with brute-force patterns."""

import random
from datetime import datetime, timedelta

REAL_USERNAMES = [
    "root", "admin", "ubuntu", "deploy", "git", "jenkins", "postgres",
    "mysql", "www-data", "nginx", "ftpuser", "test", "user", "oracle",
    "pi", "vagrant", "ansible", "docker", "backup", "mail",
]

FAKE_USERNAMES = [
    "admin123", "support", "guest", "info", "a]dmin", "ubuntuuser",
    "testuser", "ftp", "scanner", "default", "supervisor", "operator",
]

HOSTNAMES = [
    "web-prod-01", "db-master", "app-server-03", "bastion-host",
    "gateway-eu", "monitor-node", "ci-runner-07",
]

# Weighted pools: /24 subnets that will be reused for brute-force clusters
BRUTE_SUBNETS = ["185.220.101", "45.133.1", "103.99.0", "193.56.29", "91.240.118"]
NORMAL_SUBNETS = [f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}" for _ in range(60)]


def _random_ip(subnet_pool):
    subnet = random.choice(subnet_pool)
    return f"{subnet}.{random.randint(1, 254)}"


def _ssh_log_line(ts, hostname, event_type, user, ip, port):
    ts_str = ts.strftime("%b %d %H:%M:%S")
    pid = random.randint(10000, 65000)

    if event_type == "accepted":
        method = random.choice(["publickey", "password"])
        return f"{ts_str} {hostname} sshd[{pid}]: Accepted {method} for {user} from {ip} port {port} ssh2"
    elif event_type == "failed":
        return f"{ts_str} {hostname} sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2"
    else:  # invalid user
        return f"{ts_str} {hostname} sshd[{pid}]: Failed password for invalid user {user} from {ip} port {port} ssh2"


def generate_logs(count=1000, brute_force_ips=8, attempts_per_bf=15):
    """Generate SSH log lines with embedded brute-force patterns.

    Args:
        count: Total number of log lines to generate.
        brute_force_ips: How many distinct IPs perform brute-force attacks.
        attempts_per_bf: Average failed attempts per brute-force IP.

    Returns:
        List of log line strings sorted by timestamp.
    """
    lines = []
    base_time = datetime.now() - timedelta(hours=2)
    hostname = random.choice(HOSTNAMES)

    # --- Brute-force clusters ---------------------------------------------------
    bf_ips = [_random_ip(BRUTE_SUBNETS) for _ in range(brute_force_ips)]
    for ip in bf_ips:
        cluster_start = base_time + timedelta(minutes=random.randint(0, 90))
        n_attempts = attempts_per_bf + random.randint(-5, 10)
        for i in range(max(5, n_attempts)):
            ts = cluster_start + timedelta(seconds=random.randint(0, 540))  # within ~9 min
            user = random.choice(REAL_USERNAMES + FAKE_USERNAMES)
            port = random.randint(40000, 65535)
            etype = "invalid_user" if user in FAKE_USERNAMES else "failed"
            lines.append((ts, _ssh_log_line(ts, hostname, etype, user, ip, port)))

        # Some brute-force IPs eventually succeed (compromised account)
        if random.random() < 0.2:
            ts = cluster_start + timedelta(seconds=random.randint(550, 600))
            lines.append((ts, _ssh_log_line(ts, hostname, "accepted", "root", ip, random.randint(40000, 65535))))

    # --- Normal traffic ---------------------------------------------------------
    remaining = count - len(lines)
    for _ in range(max(0, remaining)):
        ts = base_time + timedelta(seconds=random.randint(0, 7200))
        ip = _random_ip(NORMAL_SUBNETS)
        user = random.choice(REAL_USERNAMES)
        port = random.randint(40000, 65535)

        roll = random.random()
        if roll < 0.70:
            etype = "accepted"
        elif roll < 0.90:
            etype = "failed"
        else:
            user = random.choice(FAKE_USERNAMES)
            etype = "invalid_user"

        lines.append((ts, _ssh_log_line(ts, hostname, etype, user, ip, port)))

    lines.sort(key=lambda x: x[0])
    return [line for _, line in lines]
