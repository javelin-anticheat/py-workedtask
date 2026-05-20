"""Minimal Python-side Javelin anti-cheat guards."""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

TAG = "[Javelin AntiCheat] "
EXPECTED_SHA256_ENV = "JAVELIN_EXPECTED_SHA256"
EXIT_INTEGRITY_FAILURE = 0xC7C


def file_sha256(path: str | os.PathLike[str]) -> str:
    """Return the SHA-256 hex digest for a file."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def expected_sha256_from_env() -> str | None:
    expected = os.environ.get(EXPECTED_SHA256_ENV)
    if expected is None:
        return None

    expected = expected.strip().lower()
    if not expected:
        return None
    return expected


def check_script_integrity(
    script_path: str | os.PathLike[str] | None = None,
    expected_sha256: str | None = None,
) -> bool:
    """Compare the current script hash with the expected SHA-256 value.

    The check is disabled when no expected hash is supplied.
    """
    expected_sha256 = expected_sha256 or expected_sha256_from_env()
    if expected_sha256 is None:
        return True

    path = Path(script_path) if script_path is not None else Path(__file__)
    current_sha256 = file_sha256(path)
    return current_sha256 == expected_sha256.lower()


def guarded_exit_if_tampered(
    script_path: str | os.PathLike[str] | None = None,
    expected_sha256: str | None = None,
) -> None:
    if not check_script_integrity(script_path, expected_sha256):
        print(f"{TAG}Integrity check failed (SHA-256 mismatch). Exiting.", file=sys.stderr)
        raise SystemExit(EXIT_INTEGRITY_FAILURE)


def main() -> int:
    print(f"{TAG}starting checks...")
    guarded_exit_if_tampered()
    print(f"{TAG}All clear. Continue.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
