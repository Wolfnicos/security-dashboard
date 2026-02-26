# Security Dashboard

Security Log Analyzer & Dashboard — Real-time monitoring of SSH/Apache logs, brute-force detection, IP geolocation & threat visualization.

![Security Dashboard](docs/dashboard_screenshot.png)

## Features

- **Real SSH Log Support** — Parses real-world OpenSSH logs (loghub dataset, auth.log, secure)
- **Brute-Force Detection** — Sliding-window algorithm with configurable threshold and window
- **Live Monitoring** — Tail mode watches auth.log in real time, alerts on attacks as they happen
- **Web Dashboard** — Dark SOC-style interface with charts, threat map, and attacker table
- **IP Geolocation** — Maps attacker IPs to countries/cities using ip-api.com
- **SQLite Persistence** — All alerts stored and queryable
- **Demo Mode** — Generate fake logs to test without a real server

## Quick Start

```bash
git clone https://github.com/Wolfnicos/security-dashboard.git
cd security-dashboard
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 1. Demo Mode (generated logs)

```bash
python scripts/run_analysis.py demo
```

Generates 1000 fake SSH logs with embedded brute-force patterns, runs detection, saves alerts to `security.db`, and prints a terminal report.

### 2. Real Logs (loghub dataset)

```bash
# Download the OpenSSH 2k sample from logpai/loghub
python scripts/download_dataset.py

# Analyze it
python scripts/run_analysis.py real data/OpenSSH_2k.log --year 2017

# Or download the full 655K-line dataset
python scripts/download_dataset.py --full
python scripts/run_analysis.py real data/SSH.log --year 2017
```

### 3. Your Own Logs

```bash
# Analyze any SSH auth log
python scripts/run_analysis.py real /var/log/auth.log
python scripts/run_analysis.py real /var/log/secure --year 2024

# Adjust detection sensitivity
python scripts/run_analysis.py real /path/to/auth.log --threshold 3 --window 5
```

### 4. Live Monitoring

```bash
# Monitor the system auth log in real time (auto-detects OS)
sudo python scripts/run_analysis.py live

# Monitor a specific file
sudo python scripts/run_analysis.py live /var/log/auth.log

# Adjust sensitivity
sudo python scripts/run_analysis.py live --threshold 3 --window 5
```

**On macOS** (which uses unified logging for SSH):

```bash
# Option A: Redirect SSH logs to a file, then monitor
log stream --predicate 'process == "sshd"' > /tmp/ssh.log &
python scripts/run_analysis.py live /tmp/ssh.log

# Option B: Simulate live traffic for testing
python scripts/simulate_live.py              # Terminal 1: writes logs
python scripts/run_analysis.py live /tmp/ssh_live_sim.log  # Terminal 2: monitors
```

### 5. Web Dashboard

```bash
# After running any analysis mode (demo/real), launch the dashboard
python run.py
# Open http://localhost:5000
```

## Supported Log Formats

The parser handles all standard `sshd` log events:

| Event | Example |
|---|---|
| Failed password | `Failed password for root from 1.2.3.4 port 22 ssh2` |
| Failed (invalid user) | `Failed password for invalid user admin from 1.2.3.4 port 22 ssh2` |
| Invalid user | `Invalid user test from 1.2.3.4` |
| Accepted login | `Accepted password for user from 1.2.3.4 port 22 ssh2` |
| PAM auth failure | `pam_unix(sshd:auth): authentication failure; ... rhost=1.2.3.4` |
| Reverse mapping | `reverse mapping checking getaddrinfo for host [1.2.3.4] failed` |
| Connection closed | `Connection closed by 1.2.3.4 [preauth]` |
| Disconnect | `Received disconnect from 1.2.3.4: 11: Bye Bye` |
| Too many failures | `Disconnecting: Too many authentication failures for root` |
| Message repeated | `message repeated 5 times: [ Failed password for root ... ]` |
| Session open/close | `pam_unix(sshd:session): session opened/closed for user` |

## Detection Engine

1. **Sliding Window** — Configurable time window (default: 10 min) tracks failures per IP
2. **Threshold** — Alert when failures reach the threshold (default: 5) within the window
3. **Severity Classification**:
   - `low` — 5-9 failures in window
   - `medium` — 10-19 failures (or `low` + root targeted)
   - `high` — 20-49 failures (or `medium` + root targeted)
   - `critical` — 50+ failures
4. **Live Escalation** — Re-alerts when an IP doubles the threshold

## Project Structure

```
security-dashboard/
├── app/
│   ├── routes/
│   │   └── dashboard.py          # Flask routes + API
│   ├── models/
│   │   └── database.py           # SQLite persistence
│   ├── services/
│   │   ├── log_generator.py      # Fake SSH log generator
│   │   ├── log_parser.py         # Multi-format parser + detector
│   │   ├── live_monitor.py       # Real-time tail + alerting
│   │   ├── geolocation.py        # IP geolocation (ip-api.com)
│   │   └── reporter.py           # Terminal color reports
│   └── templates/
│       └── index.html            # Dashboard UI
├── scripts/
│   ├── run_analysis.py           # CLI: demo / real / live modes
│   ├── download_dataset.py       # Download loghub OpenSSH dataset
│   └── simulate_live.py          # Simulate live traffic for testing
├── data/                         # Log files (gitignored)
├── config/
│   └── settings.py
├── requirements.txt
└── run.py                        # Flask entry point
```

## Tech Stack

- **Python 3.11+** / **Flask** — Backend
- **Chart.js 4.x** — Visualizations
- **Leaflet.js** + CARTO dark tiles — Threat map
- **SQLite** — Alert storage
- **ip-api.com** — IP geolocation

## License

MIT
