from __future__ import annotations

import csv
import ctypes
import hashlib
import io
import os
import subprocess
import sys
from typing import Callable, Iterable, TextIO

EXIT_OK = 0
EXIT_DEBUGGER_DETECTED = 0xDEB
EXIT_SUSPICIOUS_PROCESS = 0xBAD
EXIT_INTEGRITY_FAILURE = 0x54A

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


def is_debugger_present() -> bool:
    if os.name != "nt":
        return False

    try:
        return bool(ctypes.windll.kernel32.IsDebuggerPresent())
    except (AttributeError, OSError):
        return False


def parse_tasklist_output(tasklist_output: str) -> list[str]:
    reader = csv.reader(io.StringIO(tasklist_output))
    names: list[str] = []
    for row in reader:
        if row:
            names.append(row[0].strip().lower())
    return names


def list_process_names() -> list[str]:
    if os.name != "nt":
        return []

    result = subprocess.run(
        ["tasklist", "/FO", "CSV", "/NH"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return []
    return parse_tasklist_output(result.stdout)


def has_suspicious_process(process_names: Iterable[str] | None = None) -> bool:
    candidates = process_names if process_names is not None else list_process_names()
    normalized = {name.strip().lower() for name in candidates}
    return any(proc in normalized for proc in SUSPICIOUS_PROCESSES)


def compute_sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_integrity(path: str, expected_hash: str | None = None) -> bool:
    expected_hash = expected_hash or os.environ.get("JAVELIN_EXPECTED_SHA256", "")
    if not expected_hash:
        return True
    return compute_sha256(path).lower() == expected_hash.strip().lower()


def run_checks(
    debugger_check: Callable[[], bool] | None = None,
    process_check: Callable[[], bool] | None = None,
    integrity_check: Callable[[], bool] | None = None,
    stderr: TextIO | None = None,
) -> int:
    debugger_check = debugger_check or is_debugger_present
    process_check = process_check or has_suspicious_process
    integrity_check = integrity_check or (lambda: verify_integrity(__file__))
    stderr = stderr or sys.stderr

    if debugger_check():
        print("[Javelin AntiCheat] Debugger detected. Exiting.", file=stderr)
        return EXIT_DEBUGGER_DETECTED

    if process_check():
        print("[Javelin AntiCheat] Suspicious process detected. Exiting.", file=stderr)
        return EXIT_SUSPICIOUS_PROCESS

    if not integrity_check():
        print("[Javelin AntiCheat] Integrity check failed. Exiting.", file=stderr)
        return EXIT_INTEGRITY_FAILURE

    print("[Javelin AntiCheat] All clear. Continue.", file=stderr)
    return EXIT_OK


def main() -> None:
    sys.exit(run_checks())


if __name__ == "__main__":
    main()
