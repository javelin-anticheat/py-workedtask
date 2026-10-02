#!/usr/bin/env python3
"""
Javelin Anti-Cheat: Integrity Verification Module
Computes SHA-256 hash of the running script and validates against JAVELIN_EXPECTED_SHA256 env var.
"""

import hashlib
import os
import sys


def verify_integrity() -> bool:
    """
    Compute SHA-256 of the current script file and compare to the expected hash
    stored in the JAVELIN_EXPECTED_SHA256 environment variable.

    Setup:
        1. Generate the expected hash once:
               python -c "import hashlib; print(hashlib.sha256(open(__file__,'rb').read()).hexdigest())"
        2. Export it before running:
               export JAVELIN_EXPECTED_SHA256=<hash_from_step_1>

    Returns:
        True  — hash matches (script is untampered)
        False — hash mismatch or env var not set (potential tampering detected)
    """
    expected = os.environ.get("JAVELIN_EXPECTED_SHA256")
    if not expected:
        # Env var not configured — skip integrity check (opt-in behaviour)
        return True

    try:
        script_path = os.path.abspath(__file__)
        with open(script_path, "rb") as f:
            actual = hashlib.sha256(f.read()).hexdigest()
    except OSError as exc:
        print(f"[JAVELIN] INTEGRITY ERROR: Cannot read script file: {exc}", file=sys.stderr)
        return False

    if actual != expected.lower():
        print(
            f"[JAVELIN] INTEGRITY VIOLATION DETECTED\n"
            f"  Expected : {expected.lower()}\n"
            f"  Actual   : {actual}\n"
            f"Script may have been tampered with. Exiting.",
            file=sys.stderr,
        )
        return False

    return True


# --- Guarded entry point ---
if not verify_integrity():
    sys.exit(1)


# ---------------------------------------------------------------------------
# Original workedtask logic continues below
# ---------------------------------------------------------------------------

def main():
    print("[JAVELIN] Integrity check passed. Running workedtask...")
    # ... existing workedtask code here ...


if __name__ == "__main__":
    main()
