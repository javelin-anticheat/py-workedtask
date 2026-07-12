#!/usr/bin/env python3
"""
Javelin AntiCheat - Python Implementation
Features: Debugger detection, suspicious process scan, self-integrity (SHA-256)
"""

import os
import sys
import hashlib
import subprocess
import platform
from pathlib import Path

TAG = "[Javelin AntiCheat] "

# Configurable list of suspicious processes
SUSPICIOUS_PROCESSES = [
    "cheatengine.exe",
    "ollydbg.exe",
    "x64dbg.exe",
    "httpdebuggerui.exe",
    "ida.exe",
    "ida64.exe",
    "scylla.exe",
    "processhacker.exe",
    "wireshark.exe",
    "fiddler.exe",
]


def log(message: str) -> None:
    """Print tagged log message."""
    print(f"{TAG}{message}")


def check_debugger() -> bool:
    """Check if a debugger is attached."""
    # Check 1: Platform-specific debugger detection
    if platform.system() == "Windows":
        try:
            import ctypes
            if ctypes.windll.kernel32.IsDebuggerPresent():
                return True
        except Exception:
            pass
    
    # Check 2: Python-specific debugger detection
    if hasattr(sys, "gettrace") and sys.gettrace() is not None:
        return True
    
    # Check 3: Environment variable check (common for debugging)
    if os.environ.get("PYTHONDONTWRITEBYTECODE") == "1":
        # This is suspicious in production
        pass
    
    return False


def check_suspicious_processes() -> bool:
    """Check for running suspicious processes."""
    system = platform.system()
    
    try:
        if system == "Windows":
            # Use tasklist on Windows
            result = subprocess.run(
                ["tasklist", "/FO", "CSV"],
                capture_output=True,
                text=True,
                timeout=5
            )
            running = result.stdout.lower()
        elif system == "Linux":
            # Use ps on Linux
            result = subprocess.run(
                ["ps", "aux"],
                capture_output=True,
                text=True,
                timeout=5
            )
            running = result.stdout.lower()
        elif system == "Darwin":
            # Use ps on macOS
            result = subprocess.run(
                ["ps", "aux"],
                capture_output=True,
                text=True,
                timeout=5
            )
            running = result.stdout.lower()
        else:
            return False
        
        for process in SUSPICIOUS_PROCESSES:
            if process.lower() in running:
                log(f"Suspicious process detected: {process}")
                return True
                
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    
    return False


def compute_sha256(file_path: str) -> str:
    """Compute SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    
    try:
        with open(file_path, "rb") as f:
            # Read in chunks to handle large files
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (IOError, OSError):
        return ""


def check_self_integrity(expected_hash: str) -> bool:
    """Verify the script file hasn't been tampered with."""
    try:
        # Get the path of this script
        script_path = os.path.abspath(__file__)
        
        # Compute current hash
        current_hash = compute_sha256(script_path)
        
        if not current_hash:
            log("Failed to compute script hash")
            return False
        
        if current_hash != expected_hash:
            log(f"Integrity check failed!")
            log(f"Expected: {expected_hash}")
            log(f"Got:      {current_hash}")
            return False
        
        return True
        
    except Exception as e:
        log(f"Integrity check error: {e}")
        return False


def get_expected_hash() -> str:
    """Get expected hash from environment variable."""
    return os.environ.get("JAVELIN_EXPECTED_SHA256", "")


def main() -> int:
    """Main entry point."""
    log("starting checks...")
    
    # Check 1: Debugger detection
    if check_debugger():
        log("Debugger detected. Exiting.")
        return 0xDEB  # Same exit code as C++ version
    
    # Check 2: Suspicious processes
    if check_suspicious_processes():
        log("Suspicious process detected. Exiting.")
        return 0xBAD  # Same exit code as C++ version
    
    # Check 3: Self-integrity (if expected hash is set)
    expected_hash = get_expected_hash()
    if expected_hash:
        if not check_self_integrity(expected_hash):
            log("Integrity check failed (SHA-256 mismatch). Exiting.")
            return 0xCRC  # Same exit code as C++ version
    
    log("All clear. Continue.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
