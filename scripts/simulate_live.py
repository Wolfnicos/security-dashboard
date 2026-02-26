#!/usr/bin/env python3
"""
Simulate live log monitoring by writing generated logs to a temp file
line by line, as if they were being appended to /var/log/auth.log.

Usage:
    # Terminal 1: start the simulator (writes logs)
    python scripts/simulate_live.py

    # Terminal 2: start the live monitor (reads logs)
    python scripts/run_analysis.py live /tmp/ssh_live_sim.log
"""

import sys
import time
import random
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services.log_generator import generate_logs

OUTFILE = "/tmp/ssh_live_sim.log"


def main():
    print(f"\n  Generating simulated SSH traffic to: {OUTFILE}")
    print(f"  In another terminal, run:")
    print(f"    python scripts/run_analysis.py live {OUTFILE}")
    print(f"\n  Press Ctrl+C to stop.\n")

    log_lines = generate_logs(count=500, brute_force_ips=5, attempts_per_bf=12)

    # Create/truncate the output file
    Path(OUTFILE).write_text("")

    try:
        with open(OUTFILE, "a") as f:
            for line in log_lines:
                f.write(line + "\n")
                f.flush()
                # Random delay: fast for brute-force clusters, slower for normal traffic
                if "Failed password" in line:
                    time.sleep(random.uniform(0.05, 0.3))
                else:
                    time.sleep(random.uniform(0.2, 1.0))
    except KeyboardInterrupt:
        print(f"\n  Simulation stopped. {OUTFILE} contains the logs.\n")


if __name__ == "__main__":
    main()
