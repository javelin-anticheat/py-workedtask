"""
anti_cheat.py
Javelin Project - Anti-Cheat guards (Python edition)
Features: SHA-256 self-integrity verification, suspicious process detection, debugger check
"""

import hashlib
import os
import sys


# --- Suspicious process list (mirrors C++ version) ---
SUSPICIOUS_PROCESSES = [
    "cheatengine.exe",
    "ollydbg.exe",
    "x64dbg.exe",
    "httpdebuggerui.exe",
    "ida.exe",
    "ida64.exe",
    "scylla.exe",
    "processhacker.exe",
]


def detect_suspicious_processes():
    """Check for known cheat/debug tools in the process list.

    Returns True if a suspicious process is found, False otherwise.
    On non-Windows or if the check cannot run, returns False.
    """
    try:
        import subprocess
        output = subprocess.check_output("tasklist", shell=True, text=True).lower()
        for proc in SUSPICIOUS_PROCESSES:
            if proc.lower() in output:
                return True
    except Exception:
        pass
    return False


def is_debugger_present():
    """Best-effort debugger detection.

    Returns True if a debugger is likely attached, False otherwise.
    """
    # Check the sys.gettrace() hook (set by debuggers like pdb, pydevd)
    if sys.gettrace() is not None:
        return True

    # On Windows, check via ctypes IsDebuggerPresent
    try:
        import ctypes
        if ctypes.windll.kernel32.IsDebuggerPresent():
            return True
    except Exception:
        pass

    return False


def compute_sha256(filepath):
    """Compute the SHA-256 hex digest of a file.

    Args:
        filepath: Path to the file to hash.

    Returns:
        Lowercase hex string of the SHA-256 hash.
    """
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_integrity(filepath=None, expected_hash=None):
    """Verify SHA-256 integrity of a file.

    Args:
        filepath: Path to verify. Defaults to this script (__file__).
        expected_hash: Expected SHA-256 hex string. Defaults to the
                       JAVELIN_EXPECTED_SHA256 environment variable.

    Returns:
        True if verification passed or was skipped (no expected hash set).
        False if the hash does not match.
    """
    if filepath is None:
        filepath = os.path.abspath(__file__)

    if expected_hash is None:
        expected_hash = os.environ.get("JAVELIN_EXPECTED_SHA256", "")

    if not expected_hash:
        return True  # No expected hash configured; skip check

    actual = compute_sha256(filepath)
    return actual == expected_hash.lower()


def main():
    """Run all anti-cheat checks."""
    tag = "[Javelin AntiCheat] "

    print(f"{tag}starting checks...")

    if is_debugger_present():
        print(f"{tag}Debugger detected. Exiting.", file=sys.stderr)
        sys.exit(0xDEB)

    if detect_suspicious_processes():
        print(f"{tag}Suspicious process detected. Exiting.", file=sys.stderr)
        sys.exit(0xBAD)

    if not verify_integrity():
        print(f"{tag}Integrity check failed (SHA-256 mismatch). Exiting.", file=sys.stderr)
        sys.exit(1)

    print(f"{tag}All clear. Continue.")


if __name__ == "__main__":
    main()
