#!/usr/bin/env python3
# anti_cheat.py
# Javelin Project - Python self-integrity check via SHA-256
#
# Usage:
#   python anti_cheat.py
#
# Environment variables:
#   JAVELIN_EXPECTED_SHA256  - expected SHA-256 hex digest of this script file (64 hex chars)
#                              If not set or empty, the check is skipped.
#
# Exit codes:
#   0   - check passed or skipped
#   0x256 (598) - SHA-256 mismatch (tampering detected)
#   1   - file read error

import os
import sys
import hashlib

TAG = "[Javelin AntiCheat] "

EXPECTED_SHA256_ENV = "JAVELIN_EXPECTED_SHA256"


def sha256_file(path: str) -> str:
    """Compute SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    expected = os.environ.get(EXPECTED_SHA256_ENV, "").strip().lower()

    if not expected:
        print(f"{TAG}JAVELIN_EXPECTED_SHA256 not set, skipping integrity check.")
        return 0

    if len(expected) != 64:
        print(f"{TAG}JAVELIN_EXPECTED_SHA256 must be 64 hex characters.")
        return 1

    script_path = os.path.abspath(__file__)

    try:
        actual = sha256_file(script_path)
    except OSError as e:
        print(f"{TAG}Failed to read script file: {e}", file=sys.stderr)
        return 1

    if actual != expected:
        print(f"{TAG}Integrity check failed (SHA-256 mismatch). Exiting.", file=sys.stderr)
        print(f"  Expected: {expected}", file=sys.stderr)
        print(f"  Actual:   {actual}", file=sys.stderr)
        return 0x256  # 598

    print(f"{TAG}SHA-256 integrity OK.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
