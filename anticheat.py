# -*- coding: utf-8 -*-
"""
Javelin Anti-Cheat — Python Implementation with Script Integrity Verification (Issue #4)
Computes SHA-256 of the running script file and compares against the
`JAVELIN_EXPECTED_SHA256` environment variable, performing a guarded exit on mismatch.
"""
import argparse
import hashlib
import os
import sys
from pathlib import Path
from typing import Optional

TAG = "[Javelin AntiCheat] "
EXIT_INTEGRITY_FAILED = 3
ENV_EXPECTED_SHA256 = "JAVELIN_EXPECTED_SHA256"


def compute_file_sha256(file_path: Optional[Path] = None) -> str:
    target = Path(file_path) if file_path is not None else Path(__file__).resolve()
    digest = hashlib.sha256()
    with open(target, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest().lower()


def verify_script_integrity(
    script_path: Optional[Path] = None,
    expected_sha256: Optional[str] = None,
) -> bool:
    expected = (
        expected_sha256
        if expected_sha256 is not None
        else os.environ.get(ENV_EXPECTED_SHA256, "")
    ).strip().lower()

    # Optional check: if no expected hash is configured, allow execution
    if not expected:
        return True

    try:
        actual = compute_file_sha256(script_path)
    except OSError:
        return False

    return actual == expected


def guarded_integrity_check(
    script_path: Optional[Path] = None,
    expected_sha256: Optional[str] = None,
) -> None:
    if not verify_script_integrity(script_path=script_path, expected_sha256=expected_sha256):
        sys.stderr.write(
            f"{TAG}Integrity check failed (SHA-256 mismatch for {ENV_EXPECTED_SHA256}). Guarded exit.\n"
        )
        raise SystemExit(EXIT_INTEGRITY_FAILED)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Javelin Anti-Cheat Python Guard")
    parser.add_argument(
        "--print-hash",
        action="store_true",
        help="Print the SHA-256 hash of this script and exit",
    )
    args = parser.parse_args(argv)

    if args.print_hash:
        print(compute_file_sha256())
        return 0

    print(f"{TAG}starting checks...")
    guarded_integrity_check()
    print(f"{TAG}All clear. Continue.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
