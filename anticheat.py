#!/usr/bin/env python3
"""
Javelin Anti-Cheat (Python Implementation)
Includes debugger detection, suspicious process check, and SHA-256 script integrity verification
against the JAVELIN_EXPECTED_SHA256 environment variable.
"""
import ctypes
import hashlib
import os
import subprocess
import sys
from pathlib import Path

TAG = "[Javelin AntiCheat] "

SUSPICIOUS_PROCESSES = {
    "cheatengine.exe",
    "ollydbg.exe",
    "x64dbg.exe",
    "httpdebuggerui.exe",
    "ida.exe",
    "ida64.exe",
    "scylla.exe",
    "processhacker.exe",
}


def compute_script_sha256(script_path: Path | None = None) -> str:
    """Compute the lowercase SHA-256 hex digest of the running Python script."""
    target = script_path or Path(__file__).resolve()
    hasher = hashlib.sha256()
    with open(target, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest().lower()


def verify_script_integrity() -> bool:
    """
    Compare SHA-256 of the running script against JAVELIN_EXPECTED_SHA256 env var.
    If JAVELIN_EXPECTED_SHA256 is unset or empty, check is skipped (optional check).
    Returns True if valid or unset, False if tampered.
    """
    expected = os.environ.get("JAVELIN_EXPECTED_SHA256", "").strip().lower()
    if not expected:
        return True
    actual = compute_script_sha256()
    return actual == expected


def check_debugger() -> bool:
    if sys.gettrace() is not None:
        return True
    if os.name == "nt":
        try:
            return bool(ctypes.windll.kernel32.IsDebuggerPresent())
        except Exception:
            pass
    return False


def check_suspicious_processes() -> bool:
    if os.name == "nt":
        try:
            out = subprocess.check_output(["tasklist", "/FO", "CSV", "/NH"], text=True, errors="ignore")
            for line in out.splitlines():
                parts = line.split(",")
                if parts:
                    proc_name = parts[0].strip('"').lower()
                    if proc_name in SUSPICIOUS_PROCESSES:
                        return True
        except Exception:
            pass
    return False


def main() -> int:
    if "--print-hash" in sys.argv:
        print(compute_script_sha256())
        return 0

    print(f"{TAG}starting checks...")

    if not verify_script_integrity():
        sys.stderr.write(f"{TAG}Integrity check failed (SHA-256 mismatch with JAVELIN_EXPECTED_SHA256). Guarded exit.\n")
        return 0x5A2

    if check_debugger():
        sys.stderr.write(f"{TAG}Debugger detected. Exiting.\n")
        return 0xDEB

    if check_suspicious_processes():
        sys.stderr.write(f"{TAG}Suspicious process detected. Exiting.\n")
        return 0xBAD

    print(f"{TAG}All clear. Continue.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
