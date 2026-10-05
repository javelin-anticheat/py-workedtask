#!/usr/bin/env python3
"""Javelin minimal anti-cheat helpers (Python).

Integrity: SHA-256 of this script file vs env JAVELIN_EXPECTED_SHA256.
On mismatch, exits with a guarded non-zero code.
"""
from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

TAG = "[Javelin AntiCheat] "
EXIT_INTEGRITY = 0xA56  # 2646


def script_path() -> Path:
    return Path(__file__).resolve()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def check_integrity() -> None:
    expected = os.environ.get("JAVELIN_EXPECTED_SHA256", "").strip().lower()
    if not expected:
        print(f"{TAG}integrity skipped (JAVELIN_EXPECTED_SHA256 unset)")
        return
    got = sha256_file(script_path())
    if got != expected:
        print(
            f"{TAG}Integrity check failed (SHA-256 mismatch). "
            f"expected={expected} got={got}",
            file=sys.stderr,
        )
        raise SystemExit(EXIT_INTEGRITY)
    print(f"{TAG}integrity ok")


def main() -> int:
    print(f"{TAG}starting checks...")
    check_integrity()
    print(f"{TAG}All clear. Continue.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
