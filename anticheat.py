#!/usr/bin/env python3
"""Javelin Anti-Cheat — Python guard and SHA-256 script integrity verifier.

Verifies the SHA-256 digest of the running Python script against the
``JAVELIN_EXPECTED_SHA256`` environment variable and exits with a non-zero
guarded exit status when a mismatch or tampering is detected.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Iterable, Optional, Sequence

TAG = "[Javelin AntiCheat] "

EXIT_OK = 0
EXIT_DEBUGGER_DETECTED = 0xDE
EXIT_SUSPICIOUS_PROCESS = 0xBA
EXIT_INTEGRITY_FAILED = 0xCF

ENV_EXPECTED_SHA256 = "JAVELIN_EXPECTED_SHA256"
ENV_STRICT_INTEGRITY = "JAVELIN_STRICT_INTEGRITY"

SUSPICIOUS_PROCESSES: tuple[str, ...] = (
    "cheatengine.exe",
    "ollydbg.exe",
    "x64dbg.exe",
    "httpdebuggerui.exe",
    "ida.exe",
    "ida64.exe",
    "scylla.exe",
    "processhacker.exe",
)

_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


def compute_file_sha256(file_path: os.PathLike[str] | str) -> str:
    """Compute the lowercase hexadecimal SHA-256 digest of ``file_path``."""
    resolved = Path(file_path).resolve()
    digest = hashlib.sha256()
    with resolved.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest().lower()


def normalize_expected_sha256(raw_value: Optional[str]) -> Optional[str]:
    """Normalize an expected SHA-256 hex string (supports optional ``sha256:`` prefix)."""
    if raw_value is None:
        return None
    cleaned = raw_value.strip().lower()
    if not cleaned:
        return None
    if cleaned.startswith("sha256:"):
        cleaned = cleaned[len("sha256:") :].strip()
    return cleaned


def verify_script_integrity(
    script_path: os.PathLike[str] | str | None = None,
    expected_sha256: Optional[str] = None,
    *,
    require_expected: bool = False,
) -> tuple[bool, str]:
    """Verify the SHA-256 hash of ``script_path`` against ``expected_sha256`` or ``JAVELIN_EXPECTED_SHA256``.

    Returns ``(ok, reason)``.
    """
    target = Path(script_path) if script_path is not None else Path(__file__)
    raw_expected = (
        expected_sha256
        if expected_sha256 is not None
        else os.environ.get(ENV_EXPECTED_SHA256)
    )
    normalized_expected = normalize_expected_sha256(raw_expected)

    if normalized_expected is None:
        if require_expected or os.environ.get(ENV_STRICT_INTEGRITY, "").strip() in ("1", "true", "TRUE", "yes"):
            return (
                False,
                f"{ENV_EXPECTED_SHA256} is not set while strict integrity verification is enabled.",
            )
        return True, "Integrity verification skipped (no expected SHA-256 configured)."

    if not _SHA256_HEX_RE.match(normalized_expected):
        return (
            False,
            f"Invalid {ENV_EXPECTED_SHA256} format (expected 64 hexadecimal characters).",
        )

    try:
        actual_sha256 = compute_file_sha256(target)
    except OSError as exc:
        return False, f"Unable to read script file '{target}': {exc}"

    if not hmac.compare_digest(actual_sha256, normalized_expected):
        return (
            False,
            f"SHA-256 mismatch for '{target.name}' (expected {normalized_expected}, got {actual_sha256}).",
        )

    return True, f"SHA-256 verified ({actual_sha256})."


def check_debugger() -> bool:
    """Return True if an active Python trace/debugger hook is attached."""
    return sys.gettrace() is not None


def check_suspicious_processes(
    suspicious_names: Iterable[str] = SUSPICIOUS_PROCESSES,
) -> bool:
    """Scan running process names on Windows/POSIX for known analysis tools."""
    lowered_targets = {name.lower() for name in suspicious_names}
    if not lowered_targets:
        return False

    try:
        if sys.platform.startswith("win"):
            proc = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            for line in proc.stdout.splitlines():
                parts = line.split(",")
                if parts:
                    exe_name = parts[0].strip().strip('"').lower()
                    if exe_name in lowered_targets:
                        return True
        else:
            proc = subprocess.run(
                ["ps", "-eo", "comm"],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            for line in proc.stdout.splitlines():
                exe_name = line.strip().lower()
                if exe_name in lowered_targets:
                    return True
    except Exception:
        return False

    return False


def run_guards(
    script_path: os.PathLike[str] | str | None = None,
    expected_sha256: Optional[str] = None,
    *,
    require_expected: bool = False,
) -> int:
    """Run all Javelin Anti-Cheat guards and return the appropriate exit code."""
    print(f"{TAG}starting checks...")

    if check_debugger():
        print(f"{TAG}Debugger detected. Exiting.", file=sys.stderr)
        return EXIT_DEBUGGER_DETECTED

    if check_suspicious_processes():
        print(f"{TAG}Suspicious process detected. Exiting.", file=sys.stderr)
        return EXIT_SUSPICIOUS_PROCESS

    ok, detail = verify_script_integrity(
        script_path=script_path,
        expected_sha256=expected_sha256,
        require_expected=require_expected,
    )
    if not ok:
        print(f"{TAG}Integrity check failed ({detail}) Exiting.", file=sys.stderr)
        return EXIT_INTEGRITY_FAILED

    print(f"{TAG}All clear. Continue.")
    return EXIT_OK


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Javelin Anti-Cheat guard with SHA-256 script integrity verification."
    )
    parser.add_argument(
        "--file",
        default=None,
        help="Path to script file to verify (defaults to this script).",
    )
    parser.add_argument(
        "--print-sha256",
        action="store_true",
        help="Print the SHA-256 hash of the target script and exit.",
    )
    parser.add_argument(
        "--require-sha256",
        action="store_true",
        help=f"Fail if {ENV_EXPECTED_SHA256} is not set.",
    )
    args = parser.parse_args(argv)

    target_file = Path(args.file) if args.file else Path(__file__)

    if args.print_sha256:
        try:
            print(compute_file_sha256(target_file))
            return EXIT_OK
        except OSError as exc:
            print(f"{TAG}Failed to compute SHA-256: {exc}", file=sys.stderr)
            return EXIT_INTEGRITY_FAILED

    return run_guards(
        script_path=target_file,
        require_expected=args.require_sha256,
    )


if __name__ == "__main__":
    sys.exit(main())
