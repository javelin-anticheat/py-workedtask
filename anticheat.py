#!/usr/bin/env python3
"""
Javelin Anti-Cheat - Cross-Platform Python Anti-Cheat Guard (Issue #2)
Provides:
  1. Debugger detection (Windows IsDebuggerPresent + PEB, Linux TracerPid, Python sys.gettrace)
  2. Suspicious process scanning (Cheat Engine, x64dbg, OllyDbg, IDA, Scylla, Process Hacker)
  3. Self-integrity verification (CRC32 checksum guard)
"""

from __future__ import annotations

import ctypes
import os
import platform
import subprocess
import sys
import zlib
from typing import Callable, Iterable, List, Set

TAG = "[Javelin AntiCheat]"

EXIT_DEBUGGER_DETECTED = 0xDEB
EXIT_SUSPICIOUS_PROCESS = 0xBAD
EXIT_INTEGRITY_FAILED = 0xC4C

SUSPICIOUS_PROCESSES: Set[str] = {
    "cheatengine.exe",
    "cheatengine-x86_64.exe",
    "ollydbg.exe",
    "x64dbg.exe",
    "x32dbg.exe",
    "httpdebuggerui.exe",
    "ida.exe",
    "ida64.exe",
    "scylla.exe",
    "processhacker.exe",
    "wireshark.exe",
}


def check_debugger() -> bool:
    """Return True if a Python or native OS debugger is attached."""
    if hasattr(sys, "gettrace") and sys.gettrace() is not None:
        return True

    system = platform.system()
    if system == "Windows":
        try:
            kernel32 = ctypes.windll.kernel32
            if kernel32.IsDebuggerPresent() != 0:
                return True
            is_remote = ctypes.c_int(0)
            if (
                kernel32.CheckRemoteDebuggerPresent(
                    kernel32.GetCurrentProcess(), ctypes.byref(is_remote)
                )
                != 0
                and is_remote.value != 0
            ):
                return True
        except Exception:
            pass
    elif system == "Linux":
        try:
            with open("/proc/self/status", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("TracerPid:"):
                        tracer_pid = int(line.split(":", 1)[1].strip())
                        if tracer_pid != 0:
                            return True
        except Exception:
            pass

    return False


def list_running_process_names() -> List[str]:
    """Return lowercase process executable names currently running on the host."""
    system = platform.system()
    names: List[str] = []
    try:
        if system == "Windows":
            out = subprocess.check_output(
                ["tasklist", "/FO", "CSV", "/NH"],
                stderr=subprocess.DEVNULL,
                text=True,
                errors="ignore",
            )
            for line in out.splitlines():
                parts = line.strip().strip('"').split('","')
                if parts and parts[0]:
                    names.append(parts[0].strip().lower())
        else:
            out = subprocess.check_output(
                ["ps", "-eo", "comm"],
                stderr=subprocess.DEVNULL,
                text=True,
                errors="ignore",
            )
            for line in out.splitlines()[1:]:
                proc = os.path.basename(line.strip()).lower()
                if proc:
                    names.append(proc)
    except Exception:
        pass
    return names


def check_suspicious_processes(
    running_processes: Iterable[str] | None = None,
    blocklist: Set[str] | None = None,
) -> bool:
    """Return True if any process in the blocklist is currently running."""
    targets = {p.lower() for p in (blocklist or SUSPICIOUS_PROCESSES)}
    active = (
        [p.lower() for p in running_processes]
        if running_processes is not None
        else list_running_process_names()
    )
    return any(proc in targets for proc in active)


def compute_file_crc32(file_path: str) -> int:
    """Compute standard unsigned 32-bit CRC32 of a file."""
    with open(file_path, "rb") as f:
        data = f.read()
    return zlib.crc32(data) & 0xFFFFFFFF


def check_self_integrity(expected_crc32: int, target_path: str | None = None) -> bool:
    """Return True if the file's CRC32 matches expected_crc32 (or if expected_crc32 == 0)."""
    if expected_crc32 == 0:
        return True
    path = target_path or os.path.abspath(__file__)
    try:
        return compute_file_crc32(path) == (expected_crc32 & 0xFFFFFFFF)
    except Exception:
        return False


def enforce_anticheat(
    expected_crc32: int = 0,
    debugger_fn: Callable[[], bool] = check_debugger,
    process_fn: Callable[[], bool] = check_suspicious_processes,
    integrity_fn: Callable[[int], bool] = check_self_integrity,
    exit_fn: Callable[[int], None] = sys.exit,
) -> int:
    """Run all baseline anti-cheat guards and exit immediately if a violation is found."""
    print(f"{TAG} starting checks...")

    if debugger_fn():
        print(f"{TAG} Debugger detected. Exiting.", file=sys.stderr)
        exit_fn(EXIT_DEBUGGER_DETECTED)
        return EXIT_DEBUGGER_DETECTED

    if process_fn():
        print(f"{TAG} Suspicious process detected. Exiting.", file=sys.stderr)
        exit_fn(EXIT_SUSPICIOUS_PROCESS)
        return EXIT_SUSPICIOUS_PROCESS

    if expected_crc32 != 0 and not integrity_fn(expected_crc32):
        print(f"{TAG} Integrity check failed (CRC mismatch). Exiting.", file=sys.stderr)
        exit_fn(EXIT_INTEGRITY_FAILED)
        return EXIT_INTEGRITY_FAILED

    print(f"{TAG} All clear. Continue.")
    return 0


if __name__ == "__main__":
    enforce_anticheat()
