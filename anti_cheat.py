#!/usr/bin/env python3
"""
AntiCheat.py - Javelin Project - Minimal Anti-Cheat guards (Python implementation)
Features: debugger detection, suspicious process scan, script integrity verification (SHA-256)

Integrity Verification:
  Set the JAVELIN_EXPECTED_SHA256 environment variable to the expected SHA-256
  hash of this script file. On startup, the script computes its own SHA-256
  and compares it against the expected value. If they mismatch, the script
  exits with an error.

  To generate the expected hash, run:
    python3 -c "import hashlib; print(hashlib.sha256(open('anti_cheat.py','rb').read()).hexdigest())"

  Then set it as an environment variable:
    export JAVELIN_EXPECTED_SHA256=<the_hash_above>

  Or inline:
    JAVELIN_EXPECTED_SHA256=<hash> python3 anti_cheat.py
"""

import hashlib
import os
import platform
import signal
import sys
import threading
from pathlib import Path

TAG = "[Javelin AntiCheat] "

# --- Configurable lists ---
SUSPICIOUS_PROCESSES = [
    "cheatengine",
    "ollydbg",
    "x64dbg",
    "httpdebuggerui",
    "ida",
    "ida64",
    "scylla",
    "processhacker",
]


# --- Integrity Check ---
def compute_script_hash(script_path: str) -> str:
    """Compute SHA-256 of the given file."""
    sha256 = hashlib.sha256()
    with open(script_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def check_script_integrity(script_path: str, expected_sha256: str) -> bool:
    """
    Verify the running script's SHA-256 against an expected value.

    Args:
        script_path: Path to the script file to verify.
        expected_sha256: The expected SHA-256 hex digest.

    Returns:
        True if the hash matches, False otherwise.
    """
    if not expected_sha256:
        # No expected hash configured; skip check
        return True

    actual = compute_script_hash(script_path)
    return actual.lower() == expected_sha256.lower()


# --- Debugger Detection ---
def check_debugger() -> bool:
    """Check if a debugger is attached to the current process."""
    # Cross-platform: sys.gettrace() detects Python debuggers
    if sys.gettrace() is not None:
        return True

    # Unix-specific: check TracerPid in /proc/self/status
    if platform.system() == "Linux":
        try:
            with open("/proc/self/status", "r") as f:
                for line in f:
                    if line.startswith("TracerPid:"):
                        pid = int(line.split(":")[1].strip())
                        if pid != 0:
                            return True
                        break
        except (FileNotFoundError, ValueError):
            pass

    # macOS: sysctl check for P_TRACED flag
    if platform.system() == "Darwin":
        try:
            import ctypes
            import ctypes.util

            libc = ctypes.CDLL(ctypes.util.find_library("c"))
            # P_TRACED = 0x00000800
            MIB_KERN_PROC = 14  # KERN_PROC
            KERN_PROC_PID = 1
            # Use ptrace-based check as a simpler alternative
            # PTRACE_DENY_ATTACH = 31 (macOS)
            try:
                libc.ptrace(31, 0, 0, 0)  # PT_DENY_ATTACH
                # If ptrace succeeds, we're not being debugged by an allowed tracer
                # But PT_DENY_ATTACH itself will kill the process if being traced
                return False
            except Exception:
                pass
        except Exception:
            pass

    # Windows: IsDebuggerPresent equivalent
    if platform.system() == "Windows":
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            if kernel32.IsDebuggerPresent():
                return True
        except Exception:
            pass

    return False


# --- Suspicious Process Detection ---
def check_suspicious_processes() -> bool:
    """Scan running processes for known suspicious tools."""
    system = platform.system()

    if system == "Linux" or system == "Darwin":
        try:
            import subprocess

            result = subprocess.run(
                ["ps", "aux"], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                for line in result.stdout.lower().split("\n"):
                    for suspicious in SUSPICIOUS_PROCESSES:
                        if suspicious in line:
                            return True
        except Exception:
            pass

    elif system == "Windows":
        try:
            import ctypes
            import ctypes.wintypes

            # Use WMI query via subprocess for simplicity
            import subprocess

            result = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                for line in result.stdout.lower().split("\n"):
                    for suspicious in SUSPICIOUS_PROCESSES:
                        if suspicious in line:
                            return True
        except Exception:
            pass

    return False


# --- Anti-Debug: Timer check ---
def check_timing() -> bool:
    """
    Check if execution timing is suspiciously slow (common with single-step debugging).
    This is a heuristic and may have false positives on slow systems.
    """
    import time

    start = time.perf_counter_ns()
    # Perform a small computation
    _ = sum(range(1000))
    elapsed = time.perf_counter_ns() - start

    # Normal execution should take < 1ms for this
    # If someone is single-stepping, it would take much longer
    return elapsed > 50_000_000  # 50ms threshold


# --- Main ---
def main() -> int:
    script_path = os.path.abspath(__file__)

    print(f"{TAG}starting checks...")

    # Integrity check (SHA-256)
    expected_sha256 = os.environ.get("JAVELIN_EXPECTED_SHA256", "")
    if expected_sha256:
        print(f"{TAG}verifying script integrity (SHA-256)...")
        if not check_script_integrity(script_path, expected_sha256):
            actual = compute_script_hash(script_path)
            sys.stderr.write(
                f"{TAG}Integrity check FAILED. "
                f"Expected: {expected_sha256}, Got: {actual}. Exiting.\n"
            )
            return 0x1  # integrity failure code
        print(f"{TAG}integrity check passed.")
    else:
        print(
            f"{TAG}JAVELIN_EXPECTED_SHA256 not set, skipping integrity check. "
            f"To enable, set it to the SHA-256 of this script.\n"
            f"  Generate: python3 -c \"import hashlib; "
            f"print(hashlib.sha256(open('{script_path}','rb').read()).hexdigest())\""
        )

    # Debugger check
    if check_debugger():
        sys.stderr.write(f"{TAG}Debugger detected. Exiting.\n")
        return 0xDEB

    # Suspicious process check
    if check_suspicious_processes():
        sys.stderr.write(f"{TAG}Suspicious process detected. Exiting.\n")
        return 0xBAD

    # Timing check
    if check_timing():
        sys.stderr.write(
            f"{TAG}Timing anomaly detected (possible single-step debugging). Exiting.\n"
        )
        return 3  # timing anomaly

    print(f"{TAG}All clear. Continue.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
