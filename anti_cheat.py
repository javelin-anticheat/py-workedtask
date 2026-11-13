#!/usr/bin/env python3
"""Javelin Anti-Cheat Python guard with SHA-256 script integrity verification."""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import hmac
import os
import subprocess
import sys
from pathlib import Path
from typing import Iterable, Optional, Sequence

TAG = "[Javelin AntiCheat] "
EXIT_DEBUGGER = 10
EXIT_SUSPICIOUS_PROCESS = 11
EXIT_INTEGRITY_MISMATCH = 12

SUSPICIOUS_PROCESSES: tuple[str, ...] = (
    "cheatengine",
    "cheatengine.exe",
    "ollydbg",
    "ollydbg.exe",
    "x64dbg",
    "x64dbg.exe",
    "httpdebuggerui",
    "httpdebuggerui.exe",
    "ida",
    "ida.exe",
    "ida64",
    "ida64.exe",
    "scylla",
    "scylla.exe",
    "processhacker",
    "processhacker.exe",
)


def compute_file_sha256(file_path: Path | str) -> str:
    """Compute lowercase hexadecimal SHA-256 digest of a script or binary file."""
    path = Path(file_path).resolve()
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_valid_sha256_hex(value: str) -> bool:
    if len(value) != 64:
        return False
    return all(ch in "0123456789abcdef" for ch in value)


def verify_script_integrity(
    script_path: Path | str | None = None,
    expected_sha256: Optional[str] = None,
) -> bool:
    """Verify the SHA-256 hash of ``script_path`` against ``expected_sha256`` (or ``JAVELIN_EXPECTED_SHA256``).

    When no expected SHA-256 is configured (empty or unset), integrity verification is optional
    and returns ``True``. When set, malformed or non-matching hashes return ``False``.
    """
    raw_expected = (
        expected_sha256
        if expected_sha256 is not None
        else os.environ.get("JAVELIN_EXPECTED_SHA256", "")
    )
    normalized = raw_expected.strip().lower()
    if not normalized:
        return True
    if not _is_valid_sha256_hex(normalized):
        return False

    target = Path(script_path).resolve() if script_path is not None else Path(__file__).resolve()
    if not target.is_file():
        return False
    actual = compute_file_sha256(target)
    return hmac.compare_digest(actual, normalized)


def check_debugger() -> bool:
    """Detect attached Python or native OS debuggers."""
    if sys.gettrace() is not None:
        return True
    if sys.platform == "win32":
        try:
            kernel32 = ctypes.windll.kernel32
            if kernel32.IsDebuggerPresent():
                return True
            remote = ctypes.c_bool(False)
            if (
                kernel32.CheckRemoteDebuggerPresent(kernel32.GetCurrentProcess(), ctypes.byref(remote))
                and remote.value
            ):
                return True
        except Exception:
            pass
    elif sys.platform.startswith("linux"):
        status_file = Path("/proc/self/status")
        if status_file.is_file():
            for line in status_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                if line.startswith("TracerPid:"):
                    try:
                        return int(line.split(":", 1)[1].strip()) != 0
                    except ValueError:
                        return False
    return False


def check_suspicious_processes(blacklist: Iterable[str] = SUSPICIOUS_PROCESSES) -> bool:
    """Check running process names against known reverse-engineering/cheat tools."""
    lowered = {name.lower() for name in blacklist}
    try:
        if sys.platform == "win32":
            out = subprocess.check_output(["tasklist", "/FO", "CSV", "/NH"], text=True, stderr=subprocess.DEVNULL)
            names = [line.split(",")[0].strip('"').lower() for line in out.splitlines() if line.strip()]
        else:
            out = subprocess.check_output(["ps", "-eo", "comm="], text=True, stderr=subprocess.DEVNULL)
            names = [Path(line.strip()).name.lower() for line in out.splitlines() if line.strip()]
    except Exception:
        return False
    return any(proc in lowered for proc in names)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Javelin Anti-Cheat Monitor")
    parser.add_argument(
        "--print-sha256",
        action="store_true",
        help="Print the SHA-256 digest of this script for JAVELIN_EXPECTED_SHA256 and exit.",
    )
    args = parser.parse_args(argv)

    script_file = Path(__file__).resolve()
    if args.print_sha256:
        print(compute_file_sha256(script_file))
        return 0

    print(f"{TAG}starting checks...")

    if not verify_script_integrity(script_path=script_file):
        sys.stderr.write(f"{TAG}Integrity check failed (SHA-256 mismatch). Exiting.\n")
        return EXIT_INTEGRITY_MISMATCH

    if os.environ.get("JAVELIN_SKIP_RUNTIME_SCAN") != "1":
        if check_debugger():
            sys.stderr.write(f"{TAG}Debugger detected. Exiting.\n")
            return EXIT_DEBUGGER
        if check_suspicious_processes():
            sys.stderr.write(f"{TAG}Suspicious process detected. Exiting.\n")
            return EXIT_SUSPICIOUS_PROCESS

    print(f"{TAG}All clear. Continue.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
