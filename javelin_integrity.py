"""Optional SHA-256 integrity verification for Python entrypoints.

Set JAVELIN_EXPECTED_SHA256 to the lowercase hex digest of the script that
should be allowed to run. Leave it unset to disable the guard.
"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path


EXPECTED_SHA256_ENV = "JAVELIN_EXPECTED_SHA256"
EXIT_CODE_INTEGRITY_FAILURE = 0x71


def sha256_file(path: str | os.PathLike[str]) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_script_integrity(
    script_path: str | os.PathLike[str] | None = None,
    expected_sha256: str | None = None,
) -> bool:
    expected = expected_sha256 or os.getenv(EXPECTED_SHA256_ENV)
    if not expected:
        return True

    path = Path(script_path or sys.argv[0]).resolve()
    current = sha256_file(path)
    return current.lower() == expected.strip().lower()


def guard_script_integrity(
    script_path: str | os.PathLike[str] | None = None,
    expected_sha256: str | None = None,
) -> None:
    if verify_script_integrity(script_path, expected_sha256):
        return

    print(
        "[Javelin AntiCheat] Integrity check failed (SHA-256 mismatch). "
        "Exiting.",
        file=sys.stderr,
    )
    raise SystemExit(EXIT_CODE_INTEGRITY_FAILURE)


if __name__ == "__main__":
    guard_script_integrity()
    print("[Javelin AntiCheat] Integrity check passed.")
