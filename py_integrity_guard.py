#!/usr/bin/env python3
"""
Javelin AntiCheat - Python integrity guard

- Computes SHA-256 of this script (__file__) at runtime
- If env var JAVELIN_EXPECTED_SHA256 is set, compares against it (case-insensitive, hex)
- On mismatch: prints an error and exits with a guarded non-zero code (0x1C7)
- If the env var is not set: integrity check is skipped
"""

import hashlib
import os
import sys
from typing import Optional

TAG = "[Javelin AntiCheat] "
INTEGRITY_EXIT_CODE = 0x1C7  # 455


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def normalize_hex(s: str) -> str:
    s = s.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    return s


def check_integrity(expected_hex: Optional[str]) -> bool:
    if not expected_hex:
        # Nothing to enforce -> pass
        return True
    current = sha256_file(os.path.abspath(__file__))
    return normalize_hex(current) == normalize_hex(expected_hex)


def main() -> int:
    print(f"{TAG}starting checks...")

    expected = os.environ.get("JAVELIN_EXPECTED_SHA256", "")

    if expected:
        ok = check_integrity(expected)
        if not ok:
            print(f"{TAG}Integrity check failed (SHA-256 mismatch). Exiting.", file=sys.stderr)
            return INTEGRITY_EXIT_CODE

    print(f"{TAG}All clear. Continue.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
