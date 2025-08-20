"""
Javelin Integrity Check (Python)

- Computes SHA-256 of the current script file (__file__) and compares to
  the value in environment variable JAVELIN_EXPECTED_SHA256.
- Exits with non-zero code on mismatch.

Usage:
  - Set env var JAVELIN_EXPECTED_SHA256 to the expected 64-hex digest.
  - Run this script normally; it will guard-exit if tampered.
"""
from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

TAG = "[Javelin Py Integrity] "

EXIT_INTEGRITY_SHA = 0x05A6


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    expected = os.environ.get("JAVELIN_EXPECTED_SHA256", "").strip().lower()
    if not expected:
        print(TAG + "No expected SHA-256 set; skipping integrity check.")
        return 0

    script_path = Path(__file__).resolve()
    try:
        got = sha256_file(script_path)
    except Exception as e:
        print(TAG + f"Failed to read script: {e}")
        return EXIT_INTEGRITY_SHA

    if got.lower() != expected.lower():
        print(TAG + "Integrity check failed (SHA-256 mismatch). Exiting.")
        return EXIT_INTEGRITY_SHA

    print(TAG + "Integrity OK.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
