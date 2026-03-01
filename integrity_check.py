#!/usr/bin/env python3
"""
Javelin Anti-Cheat — Python Integrity Verification

Computes SHA-256 of the script file and compares to an expected hash
set via the JAVELIN_EXPECTED_SHA256 environment variable.

Usage:
    # First, compute the hash of your script:
    python integrity_check.py --compute-hash

    # Then set it and run with verification:
    export JAVELIN_EXPECTED_SHA256="<hash_from_above>"
    python integrity_check.py
"""

import hashlib
import os
import sys
import logging

# Configure logging
logger = logging.getLogger("javelin")
logger.setLevel(logging.INFO)
_handler = logging.StreamHandler()
_handler.setFormatter(logging.Formatter("[Javelin AntiCheat] %(message)s"))
logger.addHandler(_handler)

ENV_VAR_NAME = "JAVELIN_EXPECTED_SHA256"


def compute_file_sha256(filepath: str) -> str:
    """Compute SHA-256 hash of a file.

    Args:
        filepath: Path to the file to hash.

    Returns:
        Hex-encoded SHA-256 digest.

    Raises:
        FileNotFoundError: If the file does not exist.
        IOError: If the file cannot be read.
    """
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()


def verify_integrity(script_path: str | None = None) -> bool:
    """Verify the integrity of the script file.

    Computes SHA-256 of the script and compares against the expected
    hash from the JAVELIN_EXPECTED_SHA256 environment variable.

    Args:
        script_path: Optional override for the script path.
                     Defaults to the path of *this* file (__file__).

    Returns:
        True if the hash matches or if verification is skipped
        (env var not set). False if mismatch detected.
    """
    if script_path is None:
        script_path = os.path.abspath(__file__)

    expected_hash = os.environ.get(ENV_VAR_NAME)

    if expected_hash is None:
        logger.warning(
            "Integrity check SKIPPED: %s not set. "
            "Set it to enable tamper detection.",
            ENV_VAR_NAME,
        )
        return True  # No expected hash → skip verification

    expected_hash = expected_hash.strip().lower()

    try:
        actual_hash = compute_file_sha256(script_path)
    except FileNotFoundError:
        logger.error("Integrity check FAILED: script file not found at %s", script_path)
        return False
    except IOError as e:
        logger.error("Integrity check FAILED: cannot read script file: %s", e)
        return False

    if actual_hash == expected_hash:
        logger.info("Integrity check PASSED (SHA-256: %s)", actual_hash[:16] + "...")
        return True
    else:
        logger.error(
            "Integrity check FAILED: hash mismatch!\n"
            "  Expected: %s\n"
            "  Actual:   %s\n"
            "Possible tampering detected. Exiting.",
            expected_hash,
            actual_hash,
        )
        return False


def guarded_main():
    """Entry point that exits on integrity failure."""
    if "--compute-hash" in sys.argv:
        # Utility mode: print the hash so the user can set the env var
        script_path = os.path.abspath(__file__)
        file_hash = compute_file_sha256(script_path)
        print(f"SHA-256 of {script_path}:")
        print(f"  {file_hash}")
        print(f"\nTo enable integrity verification, run:")
        print(f'  export {ENV_VAR_NAME}="{file_hash}"')
        return

    if not verify_integrity():
        logger.error("GUARDED EXIT: Integrity verification failed.")
        sys.exit(1)

    logger.info("All checks passed. Application may proceed.")


if __name__ == "__main__":
    guarded_main()
