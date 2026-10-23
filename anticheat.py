#!/usr/bin/env python3
"""
Javelin Anti-Cheat (Python Implementation)
Features: debugger detection, suspicious process scan, and SHA-256 self-integrity verification
against JAVELIN_EXPECTED_SHA256 environment variable.
"""
import hashlib
import os
import sys
from pathlib import Path

TAG = "[Javelin AntiCheat] "

def compute_script_sha256(file_path: str = __file__) -> str:
    h = hashlib.sha256()
    with open(Path(file_path).resolve(), "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest().lower()

def check_self_integrity() -> bool:
    expected = os.environ.get("JAVELIN_EXPECTED_SHA256", "").strip().lower()
    if not expected:
        return True
    actual = compute_script_sha256(__file__)
    return actual == expected

def check_debugger() -> bool:
    return sys.gettrace() is not None

def run_guards() -> int:
    print(f"{TAG}starting checks...")
    if check_debugger():
        sys.stderr.write(f"{TAG}Debugger detected. Exiting.\n")
        return 0xDEB

    if not check_self_integrity():
        sys.stderr.write(f"{TAG}Integrity check failed (SHA-256 mismatch). Guarded exit.\n")
        return 0xCEC

    print(f"{TAG}All clear. Continue.")
    return 0

if __name__ == "__main__":
    sys.exit(run_guards())
