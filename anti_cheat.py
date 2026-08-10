#!/usr/bin/env python3
"""Minimal Python integrity guard for Javelin."""

import argparse
import hashlib
import hmac
import os
import string
import sys
from pathlib import Path
from typing import Mapping, Optional, Sequence


TAG = "[Javelin AntiCheat] "
EXPECTED_HASH_ENV = "JAVELIN_EXPECTED_SHA256"
INTEGRITY_FAILURE_EXIT_CODE = 0xC0C


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(128 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def expected_script_sha256(
    environ: Mapping[str, str] = os.environ,
) -> Optional[str]:
    value = environ.get(EXPECTED_HASH_ENV)
    if value is None or not value.strip():
        return None

    value = value.strip().lower()
    if len(value) != 64 or any(char not in string.hexdigits for char in value):
        raise ValueError(f"{EXPECTED_HASH_ENV} must contain exactly 64 hex characters")
    return value


def check_script_integrity(path: Path, expected_sha256: str) -> bool:
    return hmac.compare_digest(sha256_file(path), expected_sha256)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run Javelin's Python integrity guard")
    parser.add_argument(
        "--print-sha256",
        action="store_true",
        help="print this script's SHA-256 and exit",
    )
    args = parser.parse_args(argv)
    script_path = Path(__file__).resolve()

    if args.print_sha256:
        print(sha256_file(script_path))
        return 0

    try:
        expected_sha256 = expected_script_sha256()
    except ValueError as error:
        print(f"{TAG}{error}. Exiting.", file=sys.stderr)
        return INTEGRITY_FAILURE_EXIT_CODE

    if expected_sha256 is not None:
        try:
            matches = check_script_integrity(script_path, expected_sha256)
        except OSError as error:
            print(
                f"{TAG}Unable to read script for integrity check: {error}. Exiting.",
                file=sys.stderr,
            )
            return INTEGRITY_FAILURE_EXIT_CODE

        if not matches:
            print(
                f"{TAG}Integrity check failed (SHA-256 mismatch). Exiting.",
                file=sys.stderr,
            )
            return INTEGRITY_FAILURE_EXIT_CODE

    print(f"{TAG}All clear. Continue.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
