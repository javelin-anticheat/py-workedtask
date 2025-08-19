#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# anti_cheat.py
# Javelin Project - Python version of anti-cheat protection
# Features: debugger detection, suspicious process scan, basic self-integrity

import os
import sys
import platform
import psutil
import hashlib

# Windows-specific imports
if platform.system() == "Windows":
    import ctypes
    import ctypes.wintypes
else:
    print("Warning: This anti-cheat system is designed for Windows systems.")
    print("Some features may not work on non-Windows platforms.")

# --- Configurable lists ---
kTag = "[Javelin AntiCheat] "
kSuspiciousProcesses = [
    "cheatengine.exe",
    "ollydbg.exe",
    "x64dbg.exe",
    "httpdebuggerui.exe",
    "ida.exe",
    "ida64.exe",
    "scylla.exe",
    "processhacker.exe"
]

# --- Checks ---
def checkDebugger():
    """
    Detect if a debugger is attached to the current process
    
    Returns:
        bool: True if debugger detected, False otherwise
    """
    if platform.system() != "Windows":
        print(f"{kTag}Debugger detection not available on non-Windows systems")
        return False
        
    try:
        # Method 1: IsDebuggerPresent API
        if ctypes.windll.kernel32.IsDebuggerPresent():
            print(f"{kTag}Debugger detected via IsDebuggerPresent")
            return True
        
        # Method 2: CheckRemoteDebuggerPresent
        is_debugger_present = ctypes.wintypes.BOOL()
        current_process = ctypes.windll.kernel32.GetCurrentProcess()
        
        if ctypes.windll.kernel32.CheckRemoteDebuggerPresent(current_process, ctypes.byref(is_debugger_present)):
            if is_debugger_present.value:
                print(f"{kTag}Debugger detected via CheckRemoteDebuggerPresent")
                return True
                
    except Exception as e:
        print(f"{kTag}Error during debugger detection: {e}")
        # If we can't detect, assume no debugger for safety
        
    return False
    
# --- Utils ---
def toLower(s):
    return s.lower()

# Simple hash calculation 
def sha256Hash(data):
    return hashlib.sha256(data).hexdigest()

def checkSuspiciousProcesses():
    """
    Scan for suspicious processes that might be cheat tools
    
    Returns:
        bool: True if suspicious process found, False otherwise
    """
    try:
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                proc_name = proc.info['name'].lower()
                
                # Check against our suspicious process list
                for suspicious in kSuspiciousProcesses:
                    if toLower(suspicious) == proc_name:  # exact match
                        print(f"{kTag}Suspicious process detected: {proc_name} (PID: {proc.info['pid']})")
                        return True
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # Skip processes we can't access
                continue
                
    except Exception as e:
        print(f"{kTag}Error during process scanning: {e}")
        # If we can't scan, assume no suspicious processes for safety
        
    return False
    
def checkSelfIntegrity(expected_hash):
    """
    Check the integrity of the current Python script
    
    Args:
        expected_hash: Expected SHA-256 hash of the script file
        
    Returns:
        bool: True if integrity check passes, False otherwise
    """
    if not expected_hash:
        return True  # Skip if no expected hash provided
        
    try:
        # Get the path to the current script
        script_path = os.path.abspath(__file__)
        
        # Read and hash the file
        with open(script_path, 'rb') as f:
            file_content = f.read()
            current_hash = sha256Hash(file_content)
        
        if current_hash != expected_hash:
            print(f"{kTag}Integrity check failed - hash mismatch")
            return False
            
    except Exception as e:
        print(f"{kTag}Error during integrity check: {e}")
        return False
        
    return True
    
# --- Entry helper (embed a baseline hash once you ship a build) ---
JAVELIN_EXPECTED_HASH = os.environ.get('JAVELIN_EXPECTED_HASH', None)

def main():
    print(f"{kTag}starting checks...")

    if checkDebugger():
        print(f"{kTag}Debugger detected. Exiting.")
        return 0xDEB  # code for debugger

    if checkSuspiciousProcesses():
        print(f"{kTag}Suspicious process detected. Exiting.")
        return 0xBAD  # code for bad process

    if JAVELIN_EXPECTED_HASH is not None:
        if not checkSelfIntegrity(JAVELIN_EXPECTED_HASH):
            print(f"{kTag}Integrity check failed (hash mismatch). Exiting.")
            return 0x12C  # custom code

    print(f"{kTag}All clear. Continue.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
