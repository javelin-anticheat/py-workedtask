#!/usr/bin/env python3
"""Minimal Python anti-cheat guard with optional script integrity checking."""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path


TAG = "[Javelin AntiCheat] "
EXPECTED_SHA256_ENV = "JAVELIN_EXPECTED_SHA256"
EXIT_INTEGRITY = 0x0C0D


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def current_script_path() -> Path:
    return Path(__file__).resolve()


def check_script_integrity(expected_sha256: str) -> bool:
    expected = expected_sha256.strip().lower()
    if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        print(f"{TAG}{EXPECTED_SHA256_ENV} must be a 64-character SHA-256 hex digest.", file=sys.stderr)
        return False

    current = sha256_file(current_script_path())
    if current != expected:
        print(f"{TAG}Integrity check failed (SHA-256 mismatch). Exiting.", file=sys.stderr)
        return False

    return True


def main(argv: list[str]) -> int:
    if len(argv) > 1 and argv[1] == "--print-integrity-sha256":
        print(sha256_file(current_script_path()))
        return 0

    print(f"{TAG}starting checks...")

    expected_sha256 = os.environ.get(EXPECTED_SHA256_ENV)
    if expected_sha256:
        if not check_script_integrity(expected_sha256):
            return EXIT_INTEGRITY

    print(f"{TAG}All clear. Continue.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
