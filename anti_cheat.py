"""Baseline anti-cheat monitor for the Python runtime path."""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import PureWindowsPath
from typing import Iterable, Optional, Sequence


DEBUGGER_EXIT_CODE = 0xDE
SUSPICIOUS_PROCESS_EXIT_CODE = 0xAD

SUSPICIOUS_PROCESS_NAMES = frozenset(
    {
        "cheatengine.exe",
        "ollydbg.exe",
        "x64dbg.exe",
        "httpdebuggerui.exe",
        "ida.exe",
        "ida64.exe",
        "scylla.exe",
        "processhacker.exe",
    }
)


@dataclass(frozen=True)
class CheckResult:
    ok: bool
    reason: str
    exit_code: int


def normalize_process_name(process_name: str) -> str:
    """Return a case-insensitive executable basename."""
    stripped = process_name.strip().strip('"')
    if "\\" in stripped:
        stripped = PureWindowsPath(stripped).name
    else:
        stripped = os.path.basename(stripped)
    return stripped.casefold()


def is_debugger_attached() -> bool:
    if sys.gettrace() is not None:
        return True

    if os.name != "nt":
        return False

    kernel32 = ctypes.windll.kernel32
    if kernel32.IsDebuggerPresent():
        return True

    remote_debugger_present = ctypes.c_bool(False)
    current_process = kernel32.GetCurrentProcess()
    if kernel32.CheckRemoteDebuggerPresent(
        current_process,
        ctypes.byref(remote_debugger_present),
    ):
        return remote_debugger_present.value

    return False


def iter_process_names() -> list[str]:
    if os.name == "nt":
        command = ["tasklist", "/FO", "CSV", "/NH"]
    else:
        command = ["ps", "-axo", "comm="]

    output = subprocess.check_output(command, text=True, stderr=subprocess.DEVNULL)
    return [line.split(",", 1)[0].strip('"') for line in output.splitlines() if line.strip()]


def has_suspicious_process(
    process_names: Iterable[str],
    suspicious_processes: Sequence[str] = tuple(SUSPICIOUS_PROCESS_NAMES),
) -> bool:
    suspicious = {normalize_process_name(name) for name in suspicious_processes}
    return any(normalize_process_name(name) in suspicious for name in process_names)


def run_checks(
    process_names: Optional[Iterable[str]] = None,
    debugger_attached: Optional[bool] = None,
) -> CheckResult:
    if debugger_attached is None:
        debugger_attached = is_debugger_attached()

    if debugger_attached:
        return CheckResult(False, "Debugger detected", DEBUGGER_EXIT_CODE)

    if process_names is None:
        process_names = iter_process_names()

    if has_suspicious_process(process_names):
        return CheckResult(False, "Suspicious process detected", SUSPICIOUS_PROCESS_EXIT_CODE)

    return CheckResult(True, "All clear", 0)


def main() -> int:
    result = run_checks()
    stream = sys.stdout if result.ok else sys.stderr
    print(f"[Javelin AntiCheat] {result.reason}", file=stream)
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
