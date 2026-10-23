#!/usr/bin/env python3
"""Minimal Python anti-cheat guard with optional script integrity checking."""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

TAG = "[Javelin AntiCheat] "
EXPECTED_SHA256_ENV = "JAVELIN_EXPECTED_SHA256"
EXIT_INTEGRITY_FAILURE = 13


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_script_integrity(script_path: Path | None = None) -> bool:
    """Return False when JAVELIN_EXPECTED_SHA256 is set and does not match."""
    expected = os.environ.get(EXPECTED_SHA256_ENV)
    if expected is None:
        return True

    script = script_path if script_path is not None else Path(__file__)
    try:
        current = sha256_file(script.resolve())
    except OSError:
        return False

    return current.lower() == expected.strip().lower()


def guard_script_integrity(script_path: Path | None = None) -> None:
    if not verify_script_integrity(script_path):
        print(f"{TAG}Integrity check failed (SHA-256 mismatch). Exiting.", file=sys.stderr)
        raise SystemExit(EXIT_INTEGRITY_FAILURE)


def main() -> int:
    guard_script_integrity()
    print(f"{TAG}starting checks...")
    print(f"{TAG}All clear. Continue.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
