"""Python self-integrity guard for the Javelin Project.

Set JAVELIN_EXPECTED_SHA256 to the SHA-256 hash of this script to enable
tamper detection. Leaving it unset keeps the check disabled for development.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from pathlib import Path


TAG = "[Javelin AntiCheat] "
EXIT_INTEGRITY = 0xC0
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


def expected_sha256_from_env() -> str | None:
    return normalize_expected_sha256(os.environ.get("JAVELIN_EXPECTED_SHA256"))


def check_self_integrity(expected_sha256: str | None = None, script_path: Path | None = None) -> bool:
    expected = (
        normalize_expected_sha256(expected_sha256)
        if expected_sha256 is not None
        else expected_sha256_from_env()
    )
    if expected is None:
        return True

    target = script_path if script_path is not None else Path(__file__)
    return sha256_file(target) == expected


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Javelin Python anti-cheat integrity guard")
    parser.add_argument(
        "--print-integrity-sha256",
        action="store_true",
        help="print the SHA-256 value to use for JAVELIN_EXPECTED_SHA256",
    )
    args = parser.parse_args(argv)

    if args.print_integrity_sha256:
        print(sha256_file(Path(__file__)))
        return 0

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
