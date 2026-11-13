"""Javelin AntiCheat - Python script integrity and runtime checks."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import hmac
import os
import re
import sys
from pathlib import Path
from typing import Optional

try:
    import psutil  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    psutil = None  # type: ignore

TAG = "[Javelin AntiCheat]"
ENV_EXPECTED_SHA256 = "JAVELIN_EXPECTED_SHA256"

EXIT_DEBUGGER_DETECTED = 2
EXIT_INTEGRITY_MISMATCH = 3
EXIT_SUSPICIOUS_PROCESS = 4

HAS_WIN = sys.platform == "win32"

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

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def compute_file_sha256(file_path: str | os.PathLike[str]) -> str:
    """Compute the lowercase hexadecimal SHA-256 digest of a file."""
    path = Path(file_path).resolve()
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def get_running_script_path(script_path: str | os.PathLike[str] | None = None) -> Path:
    """Resolve the path of the running script (or frozen executable)."""
    if script_path is not None:
        return Path(script_path).resolve()
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve()
    return Path(__file__).resolve()


def verify_script_integrity(
    script_path: str | os.PathLike[str] | None = None,
    expected_sha256: str | None = None,
) -> tuple[bool, str, Optional[str]]:
    """Verify the running script's SHA-256 against JAVELIN_EXPECTED_SHA256.

    Returns (passed, message, actual_sha256).
    When no expected hash is provided (and JAVELIN_EXPECTED_SHA256 is unset or empty),
    the check is treated as optional and passes.
    """
    raw_expected = (
        expected_sha256
        if expected_sha256 is not None
        else os.environ.get(ENV_EXPECTED_SHA256)
    )

    if raw_expected is None or raw_expected.strip() == "":
        return True, f"Integrity check skipped ({ENV_EXPECTED_SHA256} not set).", None

    expected = raw_expected.strip().lower()
    if not _SHA256_RE.match(expected):
        return (
            False,
            f"Integrity check failed: invalid {ENV_EXPECTED_SHA256} format (expected 64 hex characters).",
            None,
        )

    target = get_running_script_path(script_path)
    try:
        actual = compute_file_sha256(target)
    except OSError as exc:
        return (
            False,
            f"Integrity check failed: unable to read script '{target}': {exc}",
            None,
        )

    if not hmac.compare_digest(actual.lower(), expected):
        return (
            False,
            f"Integrity check failed (SHA-256 mismatch for '{target}': expected {expected}, got {actual}).",
            actual,
        )

    return True, f"Integrity check passed ({actual}).", actual


def enforce_script_integrity(
    script_path: str | os.PathLike[str] | None = None,
    expected_sha256: str | None = None,
) -> Optional[str]:
    """Enforce script SHA-256 integrity, exiting guardedly on mismatch."""
    ok, message, actual = verify_script_integrity(
        script_path=script_path,
        expected_sha256=expected_sha256,
    )
    if not ok:
        print(f"{TAG} {message} Exiting.", file=sys.stderr)
        sys.exit(EXIT_INTEGRITY_MISMATCH)
    return actual


def is_debugger_present() -> bool:
    """Return True if a Windows debugger is attached (best-effort)."""
    if not HAS_WIN:
        return False
    try:
        return bool(ctypes.windll.kernel32.IsDebuggerPresent())
    except Exception:
        return False


def detect_suspicious_processes() -> Optional[str]:
    """Return the name of the first suspicious process found, if psutil is available."""
    if psutil is None:
        return None
    try:
        for proc in psutil.process_iter(["name"]):
            name = (proc.info.get("name") or "").strip()
            if name.lower() in SUSPICIOUS_PROCESSES:
                return name
    except Exception:
        return None
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Javelin AntiCheat Python Guard")
    parser.add_argument(
        "--print-hash",
        action="store_true",
        help="Print the SHA-256 hash of the script and exit.",
    )
    parser.add_argument(
        "--script",
        default=None,
        help="Optional path to script file to verify (defaults to this script).",
    )
    args = parser.parse_args(argv)

    target = get_running_script_path(args.script)

    if args.print_hash:
        print(compute_file_sha256(target))
        return 0

    print(f"{TAG} starting checks...")

    enforce_script_integrity(script_path=target)

    if is_debugger_present():
        print(f"{TAG} Debugger detected. Exiting.", file=sys.stderr)
        return EXIT_DEBUGGER_DETECTED

    suspicious = detect_suspicious_processes()
    if suspicious:
        print(f"{TAG} Suspicious process detected ({suspicious}). Exiting.", file=sys.stderr)
        return EXIT_SUSPICIOUS_PROCESS

    print(f"{TAG} All clear. Continue.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
