"""Minimal Python anti-cheat guards for py-workedtask.

Optional integrity verification compares this script file's SHA-256 hash against
JAVELIN_EXPECTED_SHA256. Leave the environment variable unset to disable the
check during development.
"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

TAG = "[Javelin AntiCheat] "
EXPECTED_SHA256_ENV = "JAVELIN_EXPECTED_SHA256"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_script_integrity(script_path: Path | None = None) -> bool:
    expected = os.environ.get(EXPECTED_SHA256_ENV)
    if not expected:
        return True

    target = script_path or Path(__file__).resolve()
    current = sha256_file(target)
    return current.lower() == expected.strip().lower()


def main() -> int:
    print(f"{TAG}starting Python checks...")
    if not check_script_integrity():
        print(f"{TAG}Integrity check failed (SHA-256 mismatch). Exiting.", file=sys.stderr)
        return 0x51
    print(f"{TAG}All clear. Continue.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
