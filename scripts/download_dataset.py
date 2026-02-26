#!/usr/bin/env python3
"""
Download the OpenSSH log dataset from logpai/loghub.

Downloads the 2k sample by default. Use --full for the complete 655K-line dataset.

Usage:
    python scripts/download_dataset.py          # 2k sample (~200KB)
    python scripts/download_dataset.py --full    # Full dataset (~70MB)
"""

import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

SAMPLE_URL = "https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/OpenSSH_2k.log"
FULL_URL = "https://zenodo.org/records/8196385/files/SSH.tar.gz?download=1"
DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def download_sample():
    import requests

    DATA_DIR.mkdir(exist_ok=True)
    dest = DATA_DIR / "OpenSSH_2k.log"

    if dest.exists():
        print(f"  Already exists: {dest}")
        return dest

    print(f"  Downloading OpenSSH 2k sample...")
    resp = requests.get(SAMPLE_URL, timeout=30)
    resp.raise_for_status()
    dest.write_text(resp.text)
    lines = len(resp.text.splitlines())
    print(f"  Saved {lines:,} lines to {dest.relative_to(dest.parent.parent)}")
    return dest


def download_full():
    import requests
    import tarfile
    import io

    DATA_DIR.mkdir(exist_ok=True)
    dest = DATA_DIR / "SSH.log"

    if dest.exists():
        print(f"  Already exists: {dest}")
        return dest

    print(f"  Downloading full OpenSSH dataset (~70MB)...")
    resp = requests.get(FULL_URL, timeout=120, stream=True)
    resp.raise_for_status()

    content = resp.content
    print(f"  Downloaded {len(content) / 1024 / 1024:.1f} MB, extracting...")

    with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as tar:
        for member in tar.getmembers():
            if member.name.endswith(".log") and member.isfile():
                f = tar.extractfile(member)
                if f:
                    dest.write_bytes(f.read())
                    lines = len(dest.read_text().splitlines())
                    print(f"  Extracted {lines:,} lines to {dest.relative_to(dest.parent.parent)}")
                    return dest

    print("  Warning: Could not find .log file in archive")
    return None


def main():
    parser = argparse.ArgumentParser(description="Download OpenSSH log dataset")
    parser.add_argument("--full", action="store_true", help="Download full 655K-line dataset")
    args = parser.parse_args()

    if args.full:
        download_full()
    else:
        download_sample()


if __name__ == "__main__":
    main()
