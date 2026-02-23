#!/usr/bin/env python3
"""
Javelin Anti-Cheat Python Module
Provides basic anti-cheat checks: debugger detection, suspicious process scan,
and script integrity verification via SHA-256 hash.
"""

import sys
import os
import hashlib
import subprocess
import warnings

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    warnings.warn("psutil not installed; suspicious process detection disabled.")

try:
    import ctypes
    HAS_CTYPES = True
except ImportError:
    HAS_CTYPES = False
    warnings.warn("ctypes not available; debugger detection disabled.")

# Platform‑specific availability
HAS_WIN = HAS_CTYPES and sys.platform == 'win32'

# Environment variable for expected SHA-256 hash of the script
HASH_ENV_VAR = "JAVELIN_EXPECTED_SHA256"

# List of suspicious process names (lowercase)
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

def compute_sha256(filepath: str) -> str:
    """Compute SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            sha256.update(chunk)
    return sha256.hexdigest()

def verify_script_integrity(script_path: str, expected_hash: str) -> bool:
    """Verify the integrity of a script file against expected SHA-256 hash."""
    actual = compute_sha256(script_path)
    return actual.lower() == expected_hash.lower()

def verify_self_integrity() -> bool:
    """
    Verify integrity of this script (anti_cheat.py) using environment variable.
    Returns True if integrity passes or no expected hash is set.
    """
    expected_hash = os.environ.get(HASH_ENV_VAR)
    if not expected_hash:
        # No expected hash set; skip integrity check
        return True
    script_path = os.path.abspath(__file__)
    return verify_script_integrity(script_path, expected_hash)

def is_debugger_present() -> bool:
    """Check if a debugger is attached (Windows only)."""
    if not HAS_CTYPES:
        return False
    if sys.platform != 'win32':
        return False
    try:
        # Call IsDebuggerPresent from kernel32
        return ctypes.windll.kernel32.IsDebuggerPresent() != 0
    except Exception:
        return False

def detect_suspicious_processes() -> str | None:
    """
    Scan running processes for known cheating tools.
    Returns the name of the first suspicious process found, or None.
    """
    if not HAS_PSUTIL:
        return None
    try:
        for proc in psutil.process_iter(['name']):
            proc_name = proc.info['name']
            if proc_name is None:
                continue
            proc_name_lower = proc_name.lower()
            for bad in SUSPICIOUS_PROCESSES:
                if bad in proc_name_lower:
                    return proc_name
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    return None

def run_checks() -> int:
    """
    Run all anti-cheat checks and return an exit code.
    0 = all checks passed
    0xDEB = debugger detected
    0xBAD = suspicious process found
    0xCRC = integrity check failed (hash mismatch)
    """
    # Integrity check
    if not verify_self_integrity():
        print(f"[Javelin AntiCheat] Integrity check failed (SHA‑256 mismatch). Exiting.", file=sys.stderr)
        return 0x1CE  # consistent with C++ return code

    # Debugger detection
    if is_debugger_present():
        print(f"[Javelin AntiCheat] Debugger detected. Exiting.", file=sys.stderr)
        return 0xDEB

    # Suspicious process detection
    bad_proc = detect_suspicious_processes()
    if bad_proc is not None:
        print(f"[Javelin AntiCheat] Suspicious process detected: {bad_proc}. Exiting.", file=sys.stderr)
        return 0xBAD

    print(f"[Javelin AntiCheat] All clear. Continue.")
    return 0

def main() -> None:
    """Entry point for command-line usage."""
    exit_code = run_checks()
    sys.exit(exit_code)

if __name__ == "__main__":
    main()