"""Javelin Python anti-cheat integrity guard.

Set JAVELIN_EXPECTED_SHA256 to the SHA-256 hash of this script to enable
tamper detection. Leaving the variable unset keeps the check disabled.
"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path


TAG = "[Javelin AntiCheat] "
EXIT_INTEGRITY = 13
SHA256_HEX_LENGTH = 64


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_expected_sha256(value: str | None) -> str | None:
    if value is None:
        return None

    normalized = value.strip().lower()
    if not normalized:
        return None

    if len(normalized) != SHA256_HEX_LENGTH:
        raise ValueError("expected SHA-256 must be 64 hex characters")

    try:
        bytes.fromhex(normalized)
    except ValueError as exc:
        raise ValueError("expected SHA-256 must be hexadecimal") from exc

    return normalized


def check_self_integrity(expected_sha256: str | None = None, script_path: Path | None = None) -> bool:
    expected = normalize_expected_sha256(
        expected_sha256 if expected_sha256 is not None else os.environ.get("JAVELIN_EXPECTED_SHA256")
    )
    if expected is None:
        return True

    path = script_path or Path(__file__)
    return sha256_file(path) == expected


def main() -> int:
    try:
        ok = check_self_integrity()
    except (OSError, ValueError) as exc:
        print(f"{TAG}Integrity configuration failed: {exc}", file=sys.stderr)
        return EXIT_INTEGRITY

    if not ok:
        print(f"{TAG}Integrity check failed (SHA-256 mismatch). Exiting.", file=sys.stderr)
        return EXIT_INTEGRITY

    print(f"{TAG}All clear. Continue.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
