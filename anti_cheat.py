#!/usr/bin/env python3
"""
Javelin Project - Python Anti-Cheat: Integrity Verification
Computes SHA-256 of this script and compares to JAVELIN_EXPECTED_SHA256 env var.
"""

import os
import sys
import hashlib

TAG = "[Javelin AntiCheat] "


def compute_file_sha256(filepath: str) -> str:
    """Compute SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def check_integrity() -> bool:
    """
    Check script integrity by comparing SHA-256 to JAVELIN_EXPECTED_SHA256 env var.
    Returns True if integrity check passes, False otherwise.
    """
    expected_sha256 = os.environ.get("JAVELIN_EXPECTED_SHA256", "").strip()
    
    if not expected_sha256:
        # No expected hash set - skip check (same as C++ behavior with JAVELIN_EXPECTED_CRC32=0)
        print(f"{TAG}JAVELIN_EXPECTED_SHA256 not set, skipping integrity check.")
        return True
    
    # Get this script's path
    script_path = os.path.abspath(__file__)
    
    if not os.path.exists(script_path):
        print(f"{TAG}Error: Cannot find script file at {script_path}")
        return False
    
    current_sha256 = compute_file_sha256(script_path)
    
    if current_sha256 == expected_sha256:
        print(f"{TAG}Integrity check passed (SHA-256 match).")
        return True
    else:
        print(f"{TAG}Integrity check FAILED!")
        print(f"  Expected: {expected_sha256}")
        print(f"  Current:  {current_sha256}")
        return False


def main():
    print(f"{TAG}Starting Python integrity check...")
    
    if not check_integrity():
        print(f"{TAG}Integrity violation detected. Exiting.")
        sys.exit(1)
    
    print(f"{TAG}All clear. Continue.")
    sys.exit(0)


if __name__ == "__main__":
    main()
