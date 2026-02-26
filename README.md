# Security Dashboard

Security Log Analyzer & Dashboard — Real-time monitoring of SSH/Apache logs, brute-force detection, IP geolocation & threat visualization.

## SSH Brute-Force Detection Module

The core analysis module generates realistic SSH authentication logs and detects brute-force attack patterns using a sliding-window algorithm.

### How It Works

1. **Log Generation** (`app/services/log_generator.py`)
   - Generates 1000 realistic `sshd` log entries (configurable)
   - Mixes normal traffic (~70% accepted, ~20% occasional failures) with brute-force clusters
   - 8 attacker IPs each produce 10-25 rapid failed attempts within a ~9 minute window
   - Uses realistic usernames, subnets, ports, and timestamps

2. **Log Parsing & Detection** (`app/services/log_parser.py`)
   - Regex-based parser extracts timestamp, IP, username, event type from each line
   - Sliding-window brute-force detector: flags IPs with **5+ failed attempts within 10 minutes**
   - Severity classification based on volume:
     - `low` — 5-9 failures in window
     - `medium` — 10-19 failures
     - `high` — 20-49 failures (or root targeted)
     - `critical` — 50+ failures

3. **SQLite Persistence** (`app/models/database.py`)
   - Alerts stored with: timestamp, IP, attack type, severity, details
   - Indexed on IP and severity for fast lookups

4. **Terminal Report** (`app/services/reporter.py`)
   - Color-coded severity breakdown
   - Top 5 attackers with visual bar chart
   - Full alert detail table

### Quick Start

```bash
cd security-dashboard
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run the SSH log analysis
python scripts/run_analysis.py
```

### Example Output

```
  ╔══════════════════════════════════════════════════════╗
  ║     SSH BRUTE-FORCE DETECTION — ANALYSIS REPORT      ║
  ╚══════════════════════════════════════════════════════╝

  ▸ LOG OVERVIEW
    Total log entries parsed        1,000
    Successful logins                 xxx
    Failed attempts                   xxx
    Unique IPs seen                   xxx
    Suspicious IPs detected             8

  ▸ TOP 5 ATTACKERS
    IP                 Severity   Peak  Bar
    185.220.101.42     CRITICAL     23  ██████████████████░░
    45.133.1.87        HIGH         18  ████████████████░░░░
    ...
```

## Project Structure

```
security-dashboard/
├── app/
│   ├── routes/            # Flask route blueprints
│   ├── models/
│   │   └── database.py    # SQLite alert persistence
│   ├── services/
│   │   ├── log_generator.py   # Fake SSH log generator
│   │   ├── log_parser.py      # Parser + brute-force detector
│   │   └── reporter.py        # Colorful terminal reports
│   ├── templates/
│   └── static/
├── scripts/
│   └── run_analysis.py    # Main entry point for analysis
├── data/                  # Generated log files (gitignored)
├── tests/
├── config/
├── requirements.txt
└── run.py                 # Flask web app entry point
```

## Tech Stack

- **Python 3.11+**
- **Flask** — Web dashboard
- **Pandas** — Data analysis and aggregation
- **SQLite** — Alert storage
- **Requests** — External threat feed integration (planned)

## License

MIT
