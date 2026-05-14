#!/usr/bin/env python3
"""Minimal Python anti-cheat guard with optional script integrity verification.

Set JAVELIN_EXPECTED_SHA256 to the expected SHA-256 digest of this script to
enable tamper detection. If the variable is unset, the integrity check is
skipped so development builds remain easy to run.
"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

TAG = "[Javelin AntiCheat] "
EXPECTED_SHA256_ENV = "JAVELIN_EXPECTED_SHA256"
INTEGRITY_FAILURE_EXIT_CODE = 0xC7C


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_script_integrity(script_path: Path | None = None) -> bool:
    expected = os.getenv(EXPECTED_SHA256_ENV)
    if not expected:
        return True

    normalized_expected = expected.strip().lower()
    if len(normalized_expected) != 64:
        print(f"{TAG}{EXPECTED_SHA256_ENV} must be a 64-character SHA-256 hex digest.", file=sys.stderr)
        return False

    path = script_path or Path(__file__).resolve()
    try:
        current = sha256_file(path)
    except OSError as exc:
        print(f"{TAG}Unable to read script for integrity check: {exc}", file=sys.stderr)
        return False

    if current != normalized_expected:
        print(f"{TAG}Integrity check failed (SHA-256 mismatch). Exiting.", file=sys.stderr)
        return False

    return True


def main() -> int:
    print(f"{TAG}starting checks...")
    if not check_script_integrity():
        return INTEGRITY_FAILURE_EXIT_CODE
    print(f"{TAG}All clear. Continue.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
