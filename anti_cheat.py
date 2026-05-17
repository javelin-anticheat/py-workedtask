"""Baseline Python anti-cheat monitor for the Javelin project."""

from __future__ import annotations

import csv
import os
import subprocess
import sys
from dataclasses import dataclass
from enum import IntEnum
from pathlib import PurePath
from typing import Iterable


class ExitCode(IntEnum):
    OK = 0
    DEBUGGER_DETECTED = 0xDEB
    SUSPICIOUS_PROCESS_DETECTED = 0xBAD


SUSPICIOUS_PROCESSES = frozenset(
    {
        "cheatengine.exe",
        "cheatengine",
        "ollydbg.exe",
        "ollydbg",
        "x64dbg.exe",
        "x64dbg",
        "x32dbg.exe",
        "x32dbg",
        "httpdebuggerui.exe",
        "httpdebuggerui",
        "ida.exe",
        "ida",
        "ida64.exe",
        "ida64",
        "scylla.exe",
        "scylla",
        "processhacker.exe",
        "processhacker",
        "frida-server",
        "frida-trace",
    }
)


@dataclass(frozen=True)
class CheckResult:
    ok: bool
    exit_code: ExitCode
    message: str


def _normalize_process_name(name: str) -> str:
    return PurePath(name.strip()).name.lower()


def is_debugger_attached() -> bool:
    if sys.gettrace() is not None:
        return True

    if os.name == "nt":
        try:
            import ctypes

            return bool(ctypes.windll.kernel32.IsDebuggerPresent())
        except (AttributeError, OSError):
            return False

    return False


def _windows_process_names() -> list[str]:
    completed = subprocess.run(
        ["tasklist", "/fo", "csv", "/nh"],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        return []

    return [row[0] for row in csv.reader(completed.stdout.splitlines()) if row]


def _posix_process_names() -> list[str]:
    completed = subprocess.run(
        ["ps", "-axo", "comm="],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        return []

    return [line.strip() for line in completed.stdout.splitlines() if line.strip()]


def iter_process_names() -> list[str]:
    if os.name == "nt":
        return _windows_process_names()
    return _posix_process_names()


def has_suspicious_process(process_names: Iterable[str] | None = None) -> bool:
    names = iter_process_names() if process_names is None else process_names
    return any(_normalize_process_name(name) in SUSPICIOUS_PROCESSES for name in names)


def run_checks(process_names: Iterable[str] | None = None) -> CheckResult:
    if is_debugger_attached():
        return CheckResult(False, ExitCode.DEBUGGER_DETECTED, "Debugger detected")

    if has_suspicious_process(process_names):
        return CheckResult(
            False,
            ExitCode.SUSPICIOUS_PROCESS_DETECTED,
            "Suspicious process detected",
        )

    return CheckResult(True, ExitCode.OK, "All clear")


def main() -> int:
    result = run_checks()
    stream = sys.stdout if result.ok else sys.stderr
    print(f"[Javelin AntiCheat] {result.message}", file=stream)
    return int(result.exit_code)


if __name__ == "__main__":
    raise SystemExit(main())
