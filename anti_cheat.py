"""Baseline Javelin anti-cheat monitor for Python clients.

The monitor mirrors the C++ guard surface: debugger detection, suspicious
process detection, and optional script integrity verification.
"""

from __future__ import annotations

import csv
import hashlib
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Iterable

TAG = "[Javelin AntiCheat]"

EXIT_DEBUGGER = 0x0DEB
EXIT_SUSPICIOUS_PROCESS = 0x0BAD
EXIT_INTEGRITY_FAILURE = 0x0C0C

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
    return name.strip().strip('"').lower()


def has_python_debugger() -> bool:
    return sys.gettrace() is not None


def has_windows_debugger() -> bool:
    if platform.system().lower() != "windows":
        return False

    try:
        import ctypes

        return bool(ctypes.windll.kernel32.IsDebuggerPresent())
    except Exception:
        return False


def is_debugger_present() -> bool:
    return has_python_debugger() or has_windows_debugger()


def parse_tasklist_csv(output: str) -> list[str]:
    rows = csv.reader(output.splitlines())
    names: list[str] = []
    for row in rows:
        if row:
            names.append(normalize_process_name(row[0]))
    return names


def list_windows_processes() -> list[str]:
    if platform.system().lower() != "windows":
        return []

    try:
        output = subprocess.check_output(
            ["tasklist", "/fo", "csv", "/nh"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError):
        return []

    return parse_tasklist_csv(output)


def find_suspicious_process(process_names: Iterable[str]) -> str | None:
    bad_names = {normalize_process_name(name) for name in SUSPICIOUS_PROCESSES}
    for process_name in process_names:
        normalized = normalize_process_name(process_name)
        if normalized in bad_names:
            return normalized
    return None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def expected_sha256() -> str | None:
    value = os.environ.get("JAVELIN_EXPECTED_SHA256")
    if value is None or not value.strip():
        return None
    return value.strip().lower()


def is_valid_sha256(value: str) -> bool:
    if len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def verify_script_integrity(script_path: Path | None = None, expected: str | None = None) -> bool:
    expected_hash = (expected or expected_sha256())
    if expected_hash is None:
        return True

    expected_hash = expected_hash.lower()
    if not is_valid_sha256(expected_hash):
        return False

    path = script_path or Path(__file__).resolve()
    if not path.exists() or not path.is_file():
        return False

    return sha256_file(path) == expected_hash


def run_checks(process_names: Iterable[str] | None = None, script_path: Path | None = None) -> int:
    if is_debugger_present():
        print(f"{TAG} Debugger detected. Exiting.", file=sys.stderr)
        return EXIT_DEBUGGER

    names = list(process_names) if process_names is not None else list_windows_processes()
    suspicious = find_suspicious_process(names)
    if suspicious:
        print(f"{TAG} Suspicious process detected: {suspicious}. Exiting.", file=sys.stderr)
        return EXIT_SUSPICIOUS_PROCESS

    if not verify_script_integrity(script_path=script_path):
        print(f"{TAG} Integrity check failed (SHA-256 mismatch). Exiting.", file=sys.stderr)
        return EXIT_INTEGRITY_FAILURE

    print(f"{TAG} All clear. Continue.")
    return 0


def main() -> int:
    return run_checks()


if __name__ == "__main__":
    raise SystemExit(main())
