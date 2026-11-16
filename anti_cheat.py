#!/usr/bin/env python3
"""anti_cheat.py — Javelin Project: minimal anti-cheat guards (Python).

Features:
  - SHA-256 self-integrity check of this script file.
  - Opt-in via the JAVELIN_EXPECTED_SHA256 environment variable.

Usage:
  1. Compute the expected hash of this script:
       sha256sum anti_cheat.py          # Linux / macOS
       Get-FileHash anti_cheat.py -Algorithm SHA256   # Windows PowerShell

  2. Export the hash before running:
       export JAVELIN_EXPECTED_SHA256=<64-char-hex>

  3. Run:
       python3 anti_cheat.py

If JAVELIN_EXPECTED_SHA256 is unset or empty the integrity check is skipped.
If the hash does not match, the script prints a diagnostic and exits with
status 0x104 (260).
"""

import hashlib
import hmac
import os
import sys

TAG = "[Javelin AntiCheat] "


def sha256_file(path: str) -> str:
    """Return the lowercase hex SHA-256 digest of the file at *path*."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def check_self_integrity() -> bool:
    """Compare this script's SHA-256 to JAVELIN_EXPECTED_SHA256.

    Returns True when the check passes or is disabled.
    """
    expected = os.environ.get("JAVELIN_EXPECTED_SHA256", "").strip().lower()
    if not expected:
        print(f"{TAG}JAVELIN_EXPECTED_SHA256 not set — integrity check skipped.")
        return True

    script_path = os.path.abspath(__file__)
    actual = sha256_file(script_path)

    if not hmac.compare_digest(actual, expected):
        print(f"{TAG}Integrity check failed (SHA-256 mismatch).")
        print(f"{TAG}  expected: {expected}")
        print(f"{TAG}  actual:   {actual}")
        print(f"{TAG}  file:     {script_path}")
        return False

    print(f"{TAG}Integrity check passed.")
    return True


def main() -> int:
    print(f"{TAG}starting checks...")

    if not check_self_integrity():
        print(f"{TAG}Exiting.")
        return 0x104  # guarded exit: SHA-256 integrity failure

    print(f"{TAG}All clear. Continue.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
