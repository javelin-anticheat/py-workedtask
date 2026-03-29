#!/usr/bin/env python3

import ctypes
import subprocess
import sys
from typing import Iterable, Optional

TAG = "[Javelin AntiCheat]"
DEBUGGER_EXIT_CODE = 0x6B
SUSPICIOUS_PROCESS_EXIT_CODE = 0x6C
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


def is_windows() -> bool:
    return sys.platform.startswith("win")


def debugger_attached(kernel32=None) -> bool:
    if not is_windows():
        return False

    kernel32 = kernel32 or ctypes.windll.kernel32
    return bool(kernel32.IsDebuggerPresent())


def list_process_names(tasklist_output: Optional[str] = None) -> list[str]:
    if not is_windows():
        return []

    if tasklist_output is None:
        result = subprocess.run(
            ["tasklist", "/fo", "csv", "/nh"],
            capture_output=True,
            check=True,
            text=True,
        )
        tasklist_output = result.stdout

    names: list[str] = []
    for raw_line in tasklist_output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith('"'):
            line = line[1:]
        name = line.split('","', 1)[0].strip('"').lower()
        if name:
            names.append(name)
    return names


def suspicious_process_found(
    process_names: Optional[Iterable[str]] = None,
) -> Optional[str]:
    if process_names is None:
        process_names = list_process_names()

    for name in process_names:
        lowered = name.lower()
        if lowered in SUSPICIOUS_PROCESSES:
            return lowered
    return None


def run_checks() -> int:
    print(f"{TAG} starting checks...")

    if debugger_attached():
        print(f"{TAG} Debugger detected. Exiting.")
        return DEBUGGER_EXIT_CODE

    bad_process = suspicious_process_found()
    if bad_process:
        print(f"{TAG} Suspicious process detected: {bad_process}. Exiting.")
        return SUSPICIOUS_PROCESS_EXIT_CODE

    print(f"{TAG} All clear. Continue.")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_checks())
