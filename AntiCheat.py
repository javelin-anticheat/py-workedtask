#!/usr/bin/env python3
import os
import sys
import hashlib
import subprocess

TAG = "[Javelin AntiCheat]"

# --- Configurable lists ---
SUSPICIOUS_PROCESSES = [
    "cheatengine.exe",
    "ollydbg.exe",
    "x64dbg.exe",
    "httpdebuggerui.exe",
    "ida.exe",
    "ida64.exe",
    "scylla.exe",
    "processhacker.exe"
]

def check_debugger():
    """Detects if a debugger is attached."""
    # sys.gettrace() returns the trace function, which is usually set by debuggers
    if sys.gettrace() is not None:
        return True
    return False

def check_suspicious_processes():
    """Scans for suspicious processes using tasklist (Windows)."""
    if sys.platform != "win32":
        return False
    
    try:
        output = subprocess.check_output("tasklist", shell=True).decode('utf-8', 'ignore').lower()
        for proc in SUSPICIOUS_PROCESSES:
            if proc.lower() in output:
                return True
    except Exception:
        pass
    return False

def check_self_integrity(expected_sha256):
    """Computes SHA-256 of the current script and compares with expected value."""
    if not expected_sha256:
        return True
    
    try:
        script_path = os.path.abspath(__file__)
        with open(script_path, "rb") as f:
            file_data = f.read()
            current_sha256 = hashlib.sha256(file_data).hexdigest()
        
        return current_sha256.lower() == expected_sha256.lower()
    except Exception as e:
        print(f"{TAG} Integrity check error: {e}")
        return False

def main():
    print(f"{TAG} starting checks...")

    if check_debugger():
        print(f"{TAG} Debugger detected. Exiting.")
        sys.exit(0xDEB)

    if check_suspicious_processes():
        print(f"{TAG} Suspicious process detected. Exiting.")
        sys.exit(0xBAD)

    expected_sha256 = os.environ.get("JAVELIN_EXPECTED_SHA256")
    if expected_sha256:
        if not check_self_integrity(expected_sha256):
            print(f"{TAG} Integrity check failed (SHA-256 mismatch). Exiting.")
            sys.exit(0xCEC) # Code for integrity failure

    print(f"{TAG} All clear. Continue.")

if __name__ == "__main__":
    # If run with --print-integrity, print the current SHA-256 and exit
    if len(sys.argv) > 1 and sys.argv[1] == "--print-integrity":
        script_path = os.path.abspath(__file__)
        with open(script_path, "rb") as f:
            print(hashlib.sha256(f.read()).hexdigest())
        sys.exit(0)
        
    main()
