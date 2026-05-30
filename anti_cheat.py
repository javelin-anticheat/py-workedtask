"""Baseline anti-cheat monitor for the Javelin Project.

The monitor intentionally avoids third-party dependencies so it can run beside
the C++ client in minimal environments.
"""

from __future__ import annotations

import csv
import ctypes
import hashlib
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Sequence


TAG = "[Javelin AntiCheat]"
EXIT_DEBUGGER = 0xDB
EXIT_SUSPICIOUS_PROCESS = 0xBA
EXIT_INTEGRITY = 0xC0

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


@dataclass(frozen=True)
class CheckResult:
    ok: bool
    exit_code: int
    message: str


ProcessRunner = Callable[..., subprocess.CompletedProcess[str]]


def _normalize_process_name(name: str) -> str:
    cleaned = name.strip().strip('"').replace("\\", "/")
    base = Path(cleaned).name.lower()
    if base.endswith(".exe"):
        base = base[:-4]
    return base


def is_suspicious_process_name(name: str, suspicious: Sequence[str] = SUSPICIOUS_PROCESSES) -> bool:
    normalized = _normalize_process_name(name)
    return normalized in {_normalize_process_name(candidate) for candidate in suspicious}


def _is_debugger_present_windows() -> bool:
    try:
        return bool(ctypes.windll.kernel32.IsDebuggerPresent())
    except (AttributeError, OSError):
        return False


def _tracer_pid_from_proc_status(status_path: Path = Path("/proc/self/status")) -> int:
    try:
        for line in status_path.read_text(encoding="utf-8").splitlines():
            if line.startswith("TracerPid:"):
                return int(line.split(":", 1)[1].strip())
    except (OSError, ValueError):
        return 0
    return 0


def is_debugger_attached() -> bool:
    if sys.gettrace() is not None:
        return True
    if os.name == "nt":
        return _is_debugger_present_windows()
    return _tracer_pid_from_proc_status() != 0


def _process_command() -> list[str]:
    if os.name == "nt":
        return ["tasklist", "/FO", "CSV", "/NH"]
    return ["ps", "-axo", "comm="]


def _parse_process_names(output: str) -> list[str]:
    if os.name == "nt":
        names: list[str] = []
        for row in csv.reader(output.splitlines()):
            if row:
                names.append(row[0])
        return names
    return [line.strip() for line in output.splitlines() if line.strip()]


def list_process_names(runner: ProcessRunner = subprocess.run) -> list[str]:
    try:
        completed = runner(
            _process_command(),
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if completed.returncode != 0:
        return []
    return _parse_process_names(completed.stdout)


def has_suspicious_process(
    process_names: Iterable[str] | None = None,
    suspicious: Sequence[str] = SUSPICIOUS_PROCESSES,
) -> bool:
    names = process_names if process_names is not None else list_process_names()
    return any(is_suspicious_process_name(name, suspicious) for name in names)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def expected_sha256_from_env() -> str | None:
    value = os.environ.get("JAVELIN_EXPECTED_SHA256")
    if value is None:
        return None
    value = value.strip().lower()
    return value or None


def check_self_integrity(expected_sha256: str | None = None, script_path: Path | None = None) -> bool:
    expected = expected_sha256 if expected_sha256 is not None else expected_sha256_from_env()
    if expected is None:
        return True
    if len(expected) != 64 or any(char not in "0123456789abcdef" for char in expected):
        return False
    target = script_path if script_path is not None else Path(__file__)
    try:
        return sha256_file(target) == expected
    except OSError:
        return False


def run_checks() -> CheckResult:
    if is_debugger_attached():
        return CheckResult(False, EXIT_DEBUGGER, "Debugger detected. Exiting.")
    if has_suspicious_process():
        return CheckResult(False, EXIT_SUSPICIOUS_PROCESS, "Suspicious process detected. Exiting.")
    if not check_self_integrity():
        return CheckResult(False, EXIT_INTEGRITY, "Integrity check failed (SHA-256 mismatch). Exiting.")
    return CheckResult(True, 0, "All clear. Continue.")


def main() -> int:
    print(f"{TAG} starting checks...")
    result = run_checks()
    stream = sys.stdout if result.ok else sys.stderr
    print(f"{TAG} {result.message}", file=stream)
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
