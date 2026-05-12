#!/usr/bin/env python3
"""Javelin Anti-Cheat - Python Integrity Verification Module.

Computes SHA-256 of the running script and compares to an expected
hash from the JAVELIN_EXPECTED_SHA256 environment variable.
Non-matching hash results in guarded exit.
"""

import hashlib
import os
import sys


def compute_script_hash(script_path: str) -> str:
    """Compute SHA-256 hash of the given file."""
    sha256 = hashlib.sha256()
    with open(script_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def verify_integrity(script_path: str | None = None) -> bool:
    """Verify script integrity against JAVELIN_EXPECTED_SHA256 env var.

    Args:
        script_path: Path to the script to verify. Defaults to the calling script.

    Returns:
        True if verification passes or is not configured.
        Exits with code 1 if hash mismatch detected.
    """
    expected_hash = os.environ.get("JAVELIN_EXPECTED_SHA256")

    if not expected_hash:
        # Integrity check not configured - skip
        return True

    if script_path is None:
        script_path = os.path.abspath(sys.argv[0])

    if not os.path.isfile(script_path):
        print(f"[Javelin] ERROR: Script file not found: {script_path}", file=sys.stderr)
        sys.exit(1)

    actual_hash = compute_script_hash(script_path)

    if actual_hash != expected_hash.lower().strip():
        print(f"[Javelin] INTEGRITY VIOLATION DETECTED", file=sys.stderr)
        print(f"[Javelin] Expected: {expected_hash}", file=sys.stderr)
        print(f"[Javelin] Actual:   {actual_hash}", file=sys.stderr)
        print(f"[Javelin] Script may have been tampered with. Exiting.", file=sys.stderr)
        sys.exit(1)

    return True


if __name__ == "__main__":
    # When run directly, print the hash of the specified file
    if len(sys.argv) > 1:
        target = sys.argv[1]
        print(f"{compute_script_hash(target)}  {target}")
    else:
        print("Usage: python integrity.py <file>")
        print("  Prints SHA-256 hash of the file.")
        print("")
        print("As a module:")
        print("  from integrity import verify_integrity")
        print("  verify_integrity()  # checks JAVELIN_EXPECTED_SHA256 env var")
