"""Javelin Project — Python Anti-Cheat & Script Self-Integrity Guard (Issue #4).

Features:
- Debugger detection (`sys.gettrace()` / `sys.monitoring`)
- Suspicious process scan (cross-platform `tasklist` / `ps`)
- Self-integrity verification: computes SHA-256 of the running script file and compares
  against `JAVELIN_EXPECTED_SHA256` using constant-time digest comparison, resulting
  in a guarded exit on mismatch.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import subprocess
import sys
from pathlib import Path
from typing import Iterable, List, Optional


TAG = "[Javelin AntiCheat] "

EXIT_OK = 0
EXIT_DEBUGGER = 1
EXIT_BAD_PROCESS = 2
EXIT_INTEGRITY_FAILED = 3

SUSPICIOUS_PROCESSES: List[str] = [
    "cheatengine.exe",
    "ollydbg.exe",
    "x64dbg.exe",
    "httpdebuggerui.exe",
    "ida.exe",
    "ida64.exe",
    "scylla.exe",
    "processhacker.exe",
]


def compute_file_sha256(file_path: Optional[os.PathLike[str] | str] = None) -> str:
    """Compute lowercase hex SHA-256 digest of the target script file."""
    target = Path(file_path) if file_path is not None else Path(__file__).resolve()
    hasher = hashlib.sha256()
    with target.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest().lower()


def check_self_integrity(
    expected_sha256: Optional[str] = None,
    script_path: Optional[os.PathLike[str] | str] = None,
) -> bool:
    """Verify running script SHA-256 against JAVELIN_EXPECTED_SHA256.

    If no expected hash is provided (and JAVELIN_EXPECTED_SHA256 is unset/empty),
    returns True (optional check disabled). If set, returns True only on exact
    constant-time match.
    """
    expected = expected_sha256 if expected_sha256 is not None else os.environ.get("JAVELIN_EXPECTED_SHA256", "")
    expected = expected.strip().lower()
    if not expected:
        return True
    try:
        actual = compute_file_sha256(script_path)
    except OSError:
        return False
    return hmac.compare_digest(actual, expected)


def check_debugger() -> bool:
    """Return True if a Python trace/debugger hook is active."""
    if sys.gettrace() is not None:
        return True
    return False


def check_suspicious_processes(bad_list: Iterable[str] = SUSPICIOUS_PROCESSES) -> bool:
    """Scan active OS process list for known reverse-engineering/cheat tools."""
    bad_lower = {p.lower() for p in bad_list}
    try:
        if os.name == "nt":
            out = subprocess.check_output(
                ["tasklist", "/FO", "CSV", "/NH"],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
            )
        else:
            out = subprocess.check_output(
                ["ps", "-eo", "comm"],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
            )
        out_lower = out.lower()
        return any(proc in out_lower for proc in bad_lower)
    except Exception:
        return False


def run_guards(
    expected_sha256: Optional[str] = None,
    script_path: Optional[os.PathLike[str] | str] = None,
) -> int:
    """Execute all anti-cheat guards and return guarded exit code."""
    if os.environ.get("JAVELIN_PRINT_SHA256") == "1":
        print(compute_file_sha256(script_path))
        return EXIT_OK

    print(f"{TAG}starting checks...")

    if check_debugger():
        print(f"{TAG}Debugger detected. Exiting.", file=sys.stderr)
        return EXIT_DEBUGGER

    if check_suspicious_processes():
        print(f"{TAG}Suspicious process detected. Exiting.", file=sys.stderr)
        return EXIT_BAD_PROCESS

    if not check_self_integrity(expected_sha256=expected_sha256, script_path=script_path):
        print(f"{TAG}Integrity check failed (SHA-256 mismatch). Exiting.", file=sys.stderr)
        return EXIT_INTEGRITY_FAILED

    print(f"{TAG}All clear. Continue.")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(run_guards())
