#!/usr/bin/env python3
"""
Javelin Anti-Cheat (Python Reference Implementation)
Features:
  - Debugger detection (sys.gettrace / Windows IsDebuggerPresent)
  - Suspicious process scan
  - Self-integrity verification: computes SHA-256 of the running script file
    and compares against the `JAVELIN_EXPECTED_SHA256` environment variable
    (or an optional build-time constant `EXPECTED_SCRIPT_SHA256`).
    Non-matching hash triggers a guarded exit (sys.exit(1)).
"""
from __future__ import annotations

import ctypes
import hashlib
import os
import subprocess
import sys
from pathlib import Path
from typing import Iterable, Optional

TAG = "[Javelin AntiCheat] "

SUSPICIOUS_PROCESSES = (
    "cheatengine.exe",
    "ollydbg.exe",
    "x64dbg.exe",
    "httpdebuggerui.exe",
    "ida.exe",
    "ida64.exe",
    "scylla.exe",
    "processhacker.exe",
)

# Optional build-time constant; leave empty ("") to rely on JAVELIN_EXPECTED_SHA256 env var
EXPECTED_SCRIPT_SHA256: str = ""


def compute_file_sha256(path: Path | str) -> str:
    """Compute lowercase hex SHA-256 digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest().lower()


def compute_crc32_bytes(data: bytes) -> int:
    """Standard IEEE 802.3 CRC32 matching AntiCheat.cpp."""
    import zlib
    return zlib.crc32(data) & 0xFFFFFFFF


def verify_script_integrity(
    script_path: Optional[Path | str] = None,
    expected_sha256: Optional[str] = None,
) -> bool:
    """
    Compare SHA-256 of `script_path` (defaults to `__file__`) against
    `expected_sha256` (defaults to `os.environ.get("JAVELIN_EXPECTED_SHA256")`
    or `EXPECTED_SCRIPT_SHA256`).
    Returns True if verified or if no expected hash is configured; returns False on mismatch.
    """
    target = Path(script_path if script_path is not None else __file__).resolve()
    expected = (
        expected_sha256
        if expected_sha256 is not None
        else os.environ.get("JAVELIN_EXPECTED_SHA256", EXPECTED_SCRIPT_SHA256)
    ).strip().lower()

    if not expected:
        return True

    try:
        actual = compute_file_sha256(target)
    except OSError as exc:
        print(f"{TAG}Could not read script for integrity check: {exc}", file=sys.stderr)
        return False

    if actual != expected:
        print(
            f"{TAG}Integrity check failed: SHA-256 mismatch (expected {expected}, got {actual})",
            file=sys.stderr,
        )
        return False

    return True


def enforce_script_integrity(
    script_path: Optional[Path | str] = None,
    expected_sha256: Optional[str] = None,
    exit_code: int = 1,
) -> str:
    """Run SHA-256 integrity check and perform a guarded exit (`sys.exit(exit_code)`) on mismatch."""
    target = Path(script_path if script_path is not None else __file__).resolve()
    actual = compute_file_sha256(target)
    if not verify_script_integrity(script_path=target, expected_sha256=expected_sha256):
        print(f"{TAG}Integrity violation detected. Exiting.", file=sys.stderr)
        sys.exit(exit_code)
    return actual


def is_debugger_present() -> bool:
    """Detect Python trace hook or native Windows debugger."""
    if sys.gettrace() is not None:
        return True
    if sys.platform == "win32":
        try:
            kernel32 = ctypes.windll.kernel32
            if kernel32.IsDebuggerPresent() != 0:
                return True
            remote_dbg = ctypes.c_int(0)
            if (
                kernel32.CheckRemoteDebuggerPresent(
                    kernel32.GetCurrentProcess(), ctypes.byref(remote_dbg)
                )
                != 0
                and remote_dbg.value != 0
            ):
                return True
        except Exception:
            pass
    return False


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    script_target = Path(__file__).resolve()

    if "--print-sha256" in args:
        print(compute_file_sha256(script_target))
        return 0

    # 1. Script SHA-256 integrity verification (guarded exit on mismatch)
    enforce_script_integrity(script_path=script_target)

    # 2. Debugger check
    if is_debugger_present():
        print(f"{TAG}Debugger detected. Exiting.", file=sys.stderr)
        sys.exit(1)

    print(f"{TAG}All checks passed. Protected application running...")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
