#!/usr/bin/env python3
"""
Javelin Project - Minimal Anti-Cheat guards (Python implementation)
Features: basic self-integrity verification via SHA-256

Integrity Verification Setup:
=============================
1. First, compute the SHA-256 hash of this script:
   
   Linux/macOS:
     sha256sum anticheat.py
   
   Windows (PowerShell):
     Get-FileHash anticheat.py -Algorithm SHA256
   
   Python:
     python -c "import hashlib; print(hashlib.sha256(open('anticheat.py','rb').read()).hexdigest())"

2. Set the expected hash as an environment variable before running:
   
   Linux/macOS:
     export JAVELIN_EXPECTED_SHA256="<hash_from_step_1>"
   
   Windows (PowerShell):
     $env:JAVELIN_EXPECTED_SHA256="<hash_from_step_1>"
   
   Windows (CMD):
     set JAVELIN_EXPECTED_SHA256=<hash_from_step_1>

3. Run the script - it will verify its own integrity before proceeding.
   If JAVELIN_EXPECTED_SHA256 is not set, the integrity check is skipped.
"""

import hashlib
import os
import sys

TAG = "[Javelin AntiCheat] "

# Exit codes
EXIT_OK = 0
EXIT_INTEGRITY_FAIL = 0xCRC  # 3276 - matches C++ implementation convention


def compute_script_sha256() -> str:
    """Compute SHA-256 hash of this script file."""
    script_path = os.path.abspath(__file__)
    try:
        with open(script_path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except (IOError, OSError) as e:
        print(f"{TAG}Error reading script file: {e}", file=sys.stderr)
        return ""


def check_self_integrity() -> bool:
    """
    Verify script integrity against JAVELIN_EXPECTED_SHA256 env var.
    Returns True if check passes or is skipped (env var not set).
    Returns False if hash mismatch detected.
    """
    expected_hash = os.environ.get("JAVELIN_EXPECTED_SHA256", "").strip().lower()
    
    if not expected_hash:
        print(f"{TAG}Integrity check skipped (JAVELIN_EXPECTED_SHA256 not set)")
        return True
    
    current_hash = compute_script_sha256()
    if not current_hash:
        return False
    
    if current_hash != expected_hash:
        print(f"{TAG}Integrity check FAILED (SHA-256 mismatch). Exiting.", file=sys.stderr)
        return False
    
    print(f"{TAG}Integrity check passed")
    return True


if __name__ == "__main__":
    print(f"{TAG}Starting checks...")
    
    if not check_self_integrity():
        sys.exit(EXIT_INTEGRITY_FAIL)
    
    print(f"{TAG}All clear. Continue.")
    sys.exit(EXIT_OK)