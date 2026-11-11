"""Javelin Anti-Cheat — Python Script Integrity & Environment Guard (#4).

Computes the SHA-256 hash of the running Python script file and compares it
against the `JAVELIN_EXPECTED_SHA256` environment variable, performing a
guarded exit (`sys.exit(1)`) on mismatch.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import sys
import zlib
from pathlib import Path
from typing import Optional

TAG = "[Javelin AntiCheat] "
ENV_EXPECTED_SHA256 = "JAVELIN_EXPECTED_SHA256"


def compute_file_sha256(file_path: str | Path) -> str:
    """Compute the lowercase hex SHA-256 digest of a file on disk."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest().lower()


def compute_file_crc32(file_path: str | Path) -> int:
    """Compute the unsigned 32-bit CRC32 checksum of a file on disk."""
    crc = 0
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            crc = zlib.crc32(chunk, crc)
    return crc & 0xFFFFFFFF


def resolve_running_script_path(explicit_path: Optional[str | Path] = None) -> Path:
    """Resolve the path to the currently executing Python script."""
    if explicit_path is not None:
        return Path(explicit_path).resolve()
    if sys.argv and sys.argv[0] and os.path.isfile(sys.argv[0]):
        return Path(sys.argv[0]).resolve()
    return Path(__file__).resolve()


def verify_script_integrity(
    script_path: Optional[str | Path] = None,
    expected_sha256: Optional[str] = None,
    exit_on_mismatch: bool = True,
) -> bool:
    """Verify the SHA-256 hash of the script file against `JAVELIN_EXPECTED_SHA256`.

    - If `expected_sha256` (or `JAVELIN_EXPECTED_SHA256` in `os.environ`) is empty/unset,
      the integrity check is treated as optional and returns `True`.
    - If set and the computed SHA-256 does not match, logs a warning to `stderr` and
      performs a guarded exit (`sys.exit(1)`) when `exit_on_mismatch=True`.
    """
    expected = (
        expected_sha256
        if expected_sha256 is not None
        else os.environ.get(ENV_EXPECTED_SHA256, "")
    ).strip().lower()

    if not expected:
        return True

    target_path = resolve_running_script_path(script_path)
    if not target_path.is_file():
        sys.stderr.write(f"{TAG}Integrity check failed (script file not found: {target_path}). Exiting.\n")
        if exit_on_mismatch:
            sys.exit(1)
        return False

    actual = compute_file_sha256(target_path)
    if not hmac.compare_digest(actual, expected):
        sys.stderr.write(
            f"{TAG}Integrity check failed (SHA-256 mismatch: expected {expected}, got {actual}). Exiting.\n"
        )
        if exit_on_mismatch:
            sys.exit(1)
        return False

    return True


def main() -> int:
    print(f"{TAG}starting checks...")
    verify_script_integrity(script_path=__file__, exit_on_mismatch=True)
    print(f"{TAG}All clear. Continue.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
