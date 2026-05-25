"""Minimal Python anti-cheat guard with optional script integrity checking."""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path


TAG = "[Javelin AntiCheat] "
EXPECTED_SHA256_ENV = "JAVELIN_EXPECTED_SHA256"
EXIT_INTEGRITY_FAILED = 0xC0C


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_script_integrity(path: Path | None = None) -> bool:
    """Return True when no expected hash is configured or the script matches it."""
    expected = os.environ.get(EXPECTED_SHA256_ENV, "").strip().lower()
    if not expected:
        return True

    script_path = path or Path(__file__).resolve()
    current = sha256_file(script_path)
    return current == expected


def main() -> int:
    print(f"{TAG}starting checks...")

    if not check_script_integrity():
        print(f"{TAG}Integrity check failed (SHA-256 mismatch). Exiting.", file=sys.stderr)
        return EXIT_INTEGRITY_FAILED

    print(f"{TAG}All clear. Continue.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
