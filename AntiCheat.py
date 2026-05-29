"""Minimal Javelin anti-cheat guards for Python scripts."""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path


TAG = "[Javelin AntiCheat] "
EXPECTED_SHA256_ENV = "JAVELIN_EXPECTED_SHA256"
EXIT_INTEGRITY_FAILURE = 0x1A


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_sha256(value: str) -> str:
    return value.strip().lower()


def check_script_integrity(
    script_path: Path | None = None,
    expected_sha256: str | None = None,
) -> bool:
    expected = expected_sha256 if expected_sha256 is not None else os.getenv(EXPECTED_SHA256_ENV)
    if not expected:
        return True

    path = (script_path or Path(__file__)).resolve()
    current = sha256_file(path)
    return current == normalize_sha256(expected)


def run_integrity_guard(script_path: Path | None = None) -> None:
    if check_script_integrity(script_path):
        return

    print(f"{TAG}Integrity check failed (SHA-256 mismatch). Exiting.", file=sys.stderr)
    raise SystemExit(EXIT_INTEGRITY_FAILURE)


def main() -> int:
    print(f"{TAG}starting checks...")
    run_integrity_guard(Path(__file__))
    print(f"{TAG}All clear. Continue.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
