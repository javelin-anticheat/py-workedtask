"""Baseline anti-cheat monitor for the Javelin Project.

The module exposes testable functions and a small CLI entry point.  On Windows
it detects an attached debugger and enumerates running processes.  Unsupported
platforms fail open for the debugger check but still allow process enumeration
when psutil is unavailable by using platform commands only if present.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from typing import Iterable

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


def normalize_process_name(name: str) -> str:
    return os.path.basename(name.strip()).lower()


def is_debugger_attached() -> bool:
    """Return True when a debugger is attached to the current process."""
    if sys.platform != "win32":
        return bool(sys.gettrace())

    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    if kernel32.IsDebuggerPresent():
        return True

    remote = ctypes.c_int(0)
    ok = kernel32.CheckRemoteDebuggerPresent(
        kernel32.GetCurrentProcess(), ctypes.byref(remote)
    )
    return bool(ok and remote.value)


def iter_process_names() -> Iterable[str]:
    """Yield process image names without requiring third-party packages."""
    if sys.platform == "win32":
        completed = subprocess.run(
            ["tasklist", "/FO", "CSV", "/NH"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if completed.returncode != 0:
            return
        import csv
        from io import StringIO

        for row in csv.reader(StringIO(completed.stdout)):
            if row:
                yield row[0]
        return

    completed = subprocess.run(
        ["ps", "-A", "-o", "comm="],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if completed.returncode == 0:
        for line in completed.stdout.splitlines():
            if line.strip():
                yield line.strip()


def find_suspicious_process(
    process_names: Iterable[str] | None = None,
    suspicious: set[str] | None = None,
) -> str | None:
    suspicious_set = {normalize_process_name(x) for x in (suspicious or SUSPICIOUS_PROCESSES)}
    names = process_names if process_names is not None else iter_process_names()
    for name in names:
        normalized = normalize_process_name(name)
        if normalized in suspicious_set:
            return normalized
    return None


def run_checks(
    *,
    debugger_attached: bool | None = None,
    process_names: Iterable[str] | None = None,
) -> tuple[bool, str]:
    debugger = is_debugger_attached() if debugger_attached is None else debugger_attached
    if debugger:
        return False, "Debugger detected"

    bad = find_suspicious_process(process_names)
    if bad:
        return False, f"Suspicious process detected: {bad}"

    return True, "All clear"


def main() -> int:
    ok, message = run_checks()
    prefix = "[Javelin AntiCheat]"
    stream = sys.stdout if ok else sys.stderr
    print(f"{prefix} {message}", file=stream)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
