"""Minimal Javelin anti-cheat guards for Python."""

from __future__ import annotations

import ctypes
import hashlib
import os
from pathlib import Path
import string
import sys

try:
    import psutil  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - depends on caller environment.
    psutil = None  # type: ignore[assignment]


TAG = "[Javelin AntiCheat] "
EXPECTED_SHA256_ENV = "JAVELIN_EXPECTED_SHA256"
EXIT_DEBUGGER = 0x0DEB
EXIT_SUSPICIOUS_PROCESS = 0x0BAD
EXIT_INTEGRITY = 0xC0DE
HAS_WIN = os.name == "nt"

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


def sha256_file(path: str | os.PathLike[str]) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normalize_sha256(value: str | None) -> str | None:
    if value is None:
        return None

    normalized = value.strip().lower()
    if normalized.startswith("sha256:"):
        normalized = normalized[len("sha256:") :]

    if len(normalized) != 64:
        return None
    if any(ch not in string.hexdigits.lower() for ch in normalized):
        return None
    return normalized


def check_script_integrity(
    script_path: str | os.PathLike[str] | None = None,
    expected_sha256: str | None = None,
) -> bool:
    raw_expected = (
        os.environ.get(EXPECTED_SHA256_ENV)
        if expected_sha256 is None
        else expected_sha256
    )
    if raw_expected is None or raw_expected.strip() == "":
        return True

    expected = _normalize_sha256(raw_expected)
    if expected is None:
        return False

    path = Path(script_path) if script_path is not None else Path(__file__)
    return sha256_file(path) == expected


def is_debugger_present() -> bool:
    if sys.gettrace() is not None:
        return True

    if not HAS_WIN:
        return False

    try:
        return bool(ctypes.windll.kernel32.IsDebuggerPresent())
    except (AttributeError, OSError):
        return False


def detect_suspicious_processes() -> str | None:
    if psutil is None:
        return None

    for process in psutil.process_iter(["name"]):
        try:
            name = (process.info.get("name") or "").lower()
        except (AttributeError, KeyError, TypeError):
            continue

        if name in SUSPICIOUS_PROCESSES:
            return name

    return None


def main(script_path: str | os.PathLike[str] | None = None) -> int:
    print(f"{TAG}starting checks...")

    if not check_script_integrity(script_path):
        print(f"{TAG}Integrity check failed (SHA-256 mismatch). Exiting.", file=sys.stderr)
        return EXIT_INTEGRITY

    if is_debugger_present():
        print(f"{TAG}Debugger detected. Exiting.", file=sys.stderr)
        return EXIT_DEBUGGER

    suspicious_process = detect_suspicious_processes()
    if suspicious_process is not None:
        print(
            f"{TAG}Suspicious process detected: {suspicious_process}. Exiting.",
            file=sys.stderr,
        )
        return EXIT_SUSPICIOUS_PROCESS

    print(f"{TAG}All clear. Continue.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
