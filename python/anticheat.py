"""Baseline Anti-Cheat Protection for Javelin Project (Debugger & Suspicious Process Detection)."""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from typing import Iterable, Sequence

EXIT_CODE_DEBUGGER = 0xDEB
EXIT_CODE_SUSPICIOUS_PROCESS = 0xBAD

DEFAULT_SUSPICIOUS_PROCESSES: tuple[str, ...] = (
    "cheatengine.exe",
    "cheatengine-x86_64.exe",
    "ollydbg.exe",
    "x64dbg.exe",
    "x32dbg.exe",
    "httpdebuggerui.exe",
    "ida.exe",
    "ida64.exe",
    "scylla.exe",
    "processhacker.exe",
    "wireshark.exe",
    "frida-server",
)


def _normalize_proc_name(name: str) -> str:
    cleaned = name.strip().lower()
    if cleaned.endswith(".exe"):
        return cleaned[:-4]
    return cleaned


def is_debugger_present() -> bool:
    """Return True if a Python or native OS debugger is currently attached."""
    if sys.gettrace() is not None:
        return True

    if sys.platform.startswith("win"):
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
    else:
        try:
            with open("/proc/self/status", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("TracerPid:"):
                        tracer_pid = int(line.split(":", 1)[1].strip())
                        if tracer_pid != 0:
                            return True
        except Exception:
            pass

    return False


def list_running_processes() -> list[str]:
    """Enumerate running process executable names on Windows or POSIX systems."""
    names: list[str] = []
    if sys.platform.startswith("win"):
        try:
            out = subprocess.check_output(
                ["tasklist", "/FO", "CSV", "/NH"],
                text=True,
                stderr=subprocess.DEVNULL,
            )
            for line in out.splitlines():
                parts = line.split(",")
                if parts:
                    names.append(parts[0].strip('" '))
        except Exception:
            pass
    elif os.path.isdir("/proc"):
        try:
            for entry in os.listdir("/proc"):
                if not entry.isdigit():
                    continue
                comm_path = os.path.join("/proc", entry, "comm")
                try:
                    with open(comm_path, "r", encoding="utf-8") as f:
                        names.append(f.read().strip())
                except Exception:
                    continue
        except Exception:
            pass
    return names


def detect_suspicious_process(
    running_processes: Iterable[str] | None = None,
    blacklist: Sequence[str] = DEFAULT_SUSPICIOUS_PROCESSES,
) -> str | None:
    """Return the first matching blacklisted cheat/debugger process name, or None."""
    procs = list_running_processes() if running_processes is None else list(running_processes)
    normalized_blacklist = {_normalize_proc_name(item) for item in blacklist}
    for proc in procs:
        if _normalize_proc_name(proc) in normalized_blacklist:
            return proc
    return None


def enforce_anticheat_guards(
    running_processes: Iterable[str] | None = None,
    blacklist: Sequence[str] = DEFAULT_SUSPICIOUS_PROCESSES,
) -> int:
    """Run anti-cheat checks and exit immediately if a debugger or cheat tool is detected."""
    if is_debugger_present():
        sys.stderr.write("[Javelin AntiCheat] Debugger detected. Exiting.\n")
        sys.exit(EXIT_CODE_DEBUGGER)

    matched = detect_suspicious_process(running_processes=running_processes, blacklist=blacklist)
    if matched is not None:
        sys.stderr.write(
            f"[Javelin AntiCheat] Suspicious process detected ({matched}). Exiting.\n"
        )
        sys.exit(EXIT_CODE_SUSPICIOUS_PROCESS)

    return 0
