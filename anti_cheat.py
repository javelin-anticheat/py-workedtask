#!/usr/bin/env python3
"""Baseline anti-cheat monitor for the Javelin project.

The monitor intentionally stays dependency-free so it can run beside the
native client.  It provides the two checks required by issue #2:

* debugger detection
* suspicious process detection

The public helpers accept injected process/debugger providers, which keeps the
security behaviour testable without launching real debuggers or cheat tools.
"""

from __future__ import annotations

import argparse
import csv
import os
import platform
import subprocess
import sys
from pathlib import Path, PureWindowsPath
from typing import Callable, Iterable, Sequence

SUSPICIOUS_PROCESS_NAMES = frozenset(
    {
        "cheatengine.exe",
        "cheatengine-x86_64.exe",
        "cheat engine.exe",
        "x64dbg.exe",
        "x32dbg.exe",
        "ollydbg.exe",
        "ida.exe",
        "ida64.exe",
        "idaq.exe",
        "idaq64.exe",
        "scylla.exe",
        "scylla_x64.exe",
        "scylla_x86.exe",
        "processhacker.exe",
        "process hacker.exe",
        "httpdebuggerui.exe",
        "wireshark.exe",
        "fiddler.exe",
        "ghidra.exe",
    }
)

EXIT_OK = 0
EXIT_DEBUGGER = 17
EXIT_SUSPICIOUS_PROCESS = 18
EXIT_MONITOR_ERROR = 19


def normalize_process_name(name: str) -> str:
    """Return a comparable executable basename for Windows and POSIX paths."""

    raw = (name or "").strip().strip('"')
    if not raw:
        return ""

    windows_name = PureWindowsPath(raw).name
    posix_name = Path(windows_name).name
    return posix_name.lower()


def is_suspicious_process_name(name: str) -> bool:
    """Return True when *name* matches a known cheat/debugging tool."""

    normalized = normalize_process_name(name)
    if normalized in SUSPICIOUS_PROCESS_NAMES:
        return True

    # Some tools appear as launchers or renamed binaries while preserving a
    # recognizable prefix.  Keep this conservative to avoid blocking ordinary
    # developer tools such as python, lldb, or gdb by default.
    suspicious_prefixes = ("cheatengine", "x64dbg", "x32dbg", "ollydbg")
    return any(normalized.startswith(prefix) for prefix in suspicious_prefixes)


def iter_windows_process_names() -> list[str]:
    """List Windows process image names using tasklist's CSV output."""

    proc = subprocess.run(
        ["tasklist", "/fo", "csv", "/nh"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    rows = csv.reader(proc.stdout.splitlines())
    return [row[0] for row in rows if row]


def iter_posix_process_names() -> list[str]:
    """List POSIX process command names using ps."""

    proc = subprocess.run(
        ["ps", "-A", "-o", "comm="],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def iter_process_names() -> list[str]:
    """Return currently running process names for the active platform."""

    if platform.system().lower() == "windows":
        return iter_windows_process_names()
    return iter_posix_process_names()


def find_suspicious_process(
    process_names: Iterable[str] | None = None,
) -> str | None:
    """Return the first suspicious process name, or None when clear."""

    names = list(iter_process_names() if process_names is None else process_names)
    for name in names:
        if is_suspicious_process_name(name):
            return name
    return None


def _windows_debugger_attached() -> bool:
    if platform.system().lower() != "windows":
        return False

    try:
        import ctypes
    except Exception:
        return False

    try:
        return bool(ctypes.windll.kernel32.IsDebuggerPresent())
    except Exception:
        return False


def _linux_tracer_pid() -> int:
    status_path = Path("/proc/self/status")
    if not status_path.exists():
        return 0

    try:
        for line in status_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("TracerPid:"):
                return int(line.split(":", 1)[1].strip() or "0")
    except Exception:
        return 0
    return 0


def debugger_attached() -> bool:
    """Best-effort debugger detection for Python monitor runs."""

    # sys.gettrace() catches pdb/debugpy/PyCharm-style Python debuggers.
    if sys.gettrace() is not None:
        return True

    if _windows_debugger_attached():
        return True

    if _linux_tracer_pid() > 0:
        return True

    return False


def run_checks(
    *,
    process_names: Iterable[str] | None = None,
    debugger_probe: Callable[[], bool] = debugger_attached,
) -> tuple[int, str]:
    """Run all anti-cheat checks and return (exit_code, message)."""

    if debugger_probe():
        return EXIT_DEBUGGER, "Debugger detected; exiting."

    suspicious_process = find_suspicious_process(process_names)
    if suspicious_process:
        return (
            EXIT_SUSPICIOUS_PROCESS,
            f"Suspicious process detected: {normalize_process_name(suspicious_process)}; exiting.",
        )

    return EXIT_OK, "All anti-cheat checks passed."


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run Javelin baseline anti-cheat checks.")
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit a compact JSON result for external launchers",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        code, message = run_checks()
    except Exception as exc:  # defensive: fail closed if the monitor cannot run
        code, message = EXIT_MONITOR_ERROR, f"Anti-cheat monitor error: {exc}"

    if args.json:
        import json

        print(json.dumps({"ok": code == EXIT_OK, "exit_code": code, "message": message}))
    else:
        stream = sys.stdout if code == EXIT_OK else sys.stderr
        print(f"[Javelin AntiCheat] {message}", file=stream)

    return code


if __name__ == "__main__":
    raise SystemExit(main())
