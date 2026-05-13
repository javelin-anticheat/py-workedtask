"""Baseline anti-cheat monitor for the Javelin Python runtime."""

from __future__ import annotations

import argparse
import csv
import ctypes
import hashlib
import os
import platform
import subprocess
import sys
from dataclasses import dataclass
from typing import Iterable, Sequence


EXIT_OK = 0
EXIT_DEBUGGER = 0x0D
EXIT_SUSPICIOUS_PROCESS = 0x0B
EXIT_INTEGRITY = 0x0C
EXPECTED_SHA256_ENV = "JAVELIN_EXPECTED_SHA256"

DEFAULT_SUSPICIOUS_PROCESSES = frozenset(
    {
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
    }
)


@dataclass(frozen=True)
class CheckResult:
    ok: bool
    exit_code: int
    reason: str


def normalize_process_name(name: str) -> str:
    return name.strip().strip('"').lower()


def is_debugger_attached() -> bool:
    if sys.gettrace() is not None:
        return True

    if platform.system() != "Windows":
        return False

    try:
        return bool(ctypes.windll.kernel32.IsDebuggerPresent())
    except AttributeError:
        return False


def parse_tasklist_csv(output: str) -> list[str]:
    reader = csv.reader(output.splitlines())
    return [normalize_process_name(row[0]) for row in reader if row and row[0].strip()]


def iter_windows_process_names() -> list[str]:
    if platform.system() != "Windows":
        return []

    try:
        output = subprocess.check_output(
            ["tasklist", "/FO", "CSV", "/NH"],
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return []

    return parse_tasklist_csv(output)


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_script_integrity(
    script_path: str = __file__,
    expected_sha256: str | None = None,
) -> bool:
    expected = expected_sha256
    if expected is None:
        expected = os.environ.get(EXPECTED_SHA256_ENV)

    if not expected:
        return True

    expected = expected.strip().lower()
    if len(expected) != 64 or any(ch not in "0123456789abcdef" for ch in expected):
        return False

    try:
        return sha256_file(script_path).lower() == expected
    except OSError:
        return False


def has_suspicious_process(
    process_names: Iterable[str] | None = None,
    suspicious_names: Sequence[str] = tuple(DEFAULT_SUSPICIOUS_PROCESSES),
) -> bool:
    processes = (
        iter_windows_process_names()
        if process_names is None
        else [normalize_process_name(name) for name in process_names]
    )
    suspicious = {normalize_process_name(name) for name in suspicious_names}
    return any(name in suspicious for name in processes)


def run_checks(
    process_names: Iterable[str] | None = None,
    script_path: str = __file__,
    expected_sha256: str | None = None,
) -> CheckResult:
    if is_debugger_attached():
        return CheckResult(False, EXIT_DEBUGGER, "debugger detected")

    if has_suspicious_process(process_names):
        return CheckResult(False, EXIT_SUSPICIOUS_PROCESS, "suspicious process detected")

    if not check_script_integrity(script_path, expected_sha256):
        return CheckResult(False, EXIT_INTEGRITY, "script integrity check failed")

    return CheckResult(True, EXIT_OK, "all clear")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Javelin Python anti-cheat checks.")
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="print the check result before exiting",
    )
    args = parser.parse_args(argv)

    result = run_checks()
    if args.verbose:
        print(f"[Javelin AntiCheat] {result.reason}")
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
