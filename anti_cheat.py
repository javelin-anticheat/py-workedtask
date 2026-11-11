"""
anti_cheat.py - Javelin Project Python Anti-Cheat Monitor.

Provides baseline runtime anti-cheat protection:
- Debugger detection via Python trace hooks (`sys.gettrace()`), Windows Win32 APIs
  (`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`), Linux `/proc/self/status`
  `TracerPid`, and active Python debugger environment markers.
- Suspicious process detection across Windows (`tasklist`) and POSIX (`ps` / `/proc`)
  against known reverse-engineering and memory-tampering tools (Cheat Engine, x64dbg,
  x32dbg, OllyDbg, IDA, Scylla, Process Hacker, HTTPDebuggerUI, dnSpy, Ghidra).
- Immediate process exit on detection (`EXIT_DEBUGGER_DETECTED` or `EXIT_SUSPICIOUS_PROCESS`).
"""

from __future__ import annotations

import argparse
import ctypes
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Callable, Iterable, Sequence


TAG = "[Javelin AntiCheat]"
EXIT_DEBUGGER_DETECTED = 0xDEB
EXIT_SUSPICIOUS_PROCESS = 0xBAD

DEFAULT_SUSPICIOUS_PROCESSES: tuple[str, ...] = (
    "cheatengine.exe",
    "cheatengine-x86_64.exe",
    "cheatengine-i386.exe",
    "ollydbg.exe",
    "x64dbg.exe",
    "x32dbg.exe",
    "httpdebuggerui.exe",
    "ida.exe",
    "ida64.exe",
    "scylla.exe",
    "scylla_x64.exe",
    "processhacker.exe",
    "dnspy.exe",
    "ghidra.exe",
)


def normalize_process_name(name: str) -> str:
    """Return a lowercase basename without trailing `.exe` for cross-platform matching."""
    base = os.path.basename(str(name or "").strip().replace("\\", "/")).lower()
    if base.endswith(".exe"):
        return base[:-4]
    return base


def detect_debugger(
    *,
    trace_getter: Callable[[], object] | None = None,
    win32_checker: Callable[[], bool] | None = None,
    proc_status_text: str | None = None,
    environ: dict[str, str] | None = None,
) -> tuple[bool, str]:
    """
    Check whether a debugger is attached to the current process.
    Returns `(is_debugged, reason)`.
    """
    get_trace = trace_getter or getattr(sys, "gettrace", lambda: None)
    if get_trace() is not None:
        return True, "python_sys_gettrace"

    env = environ if environ is not None else os.environ
    for key in ("PYDEVD_LOAD_VALUES_ASYNC", "DEBUGPY_RUNNING"):
        if env.get(key):
            return True, f"env_{key.lower()}"

    if win32_checker is not None:
        if win32_checker():
            return True, "win32_debugger_api"
    elif platform.system() == "Windows":
        try:
            kernel32 = ctypes.windll.kernel32
            if kernel32.IsDebuggerPresent():
                return True, "win32_IsDebuggerPresent"
            remote_dbg = ctypes.c_int(0)
            if (
                kernel32.CheckRemoteDebuggerPresent(
                    kernel32.GetCurrentProcess(), ctypes.byref(remote_dbg)
                )
                and remote_dbg.value != 0
            ):
                return True, "win32_CheckRemoteDebuggerPresent"
        except Exception:
            pass

    status_content = proc_status_text
    if status_content is None and platform.system() == "Linux":
        status_path = Path("/proc/self/status")
        if status_path.exists():
            try:
                status_content = status_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                status_content = None

    if status_content:
        for line in status_content.splitlines():
            if line.lower().startswith("tracerpid:"):
                parts = line.split(":", 1)
                try:
                    tracer_pid = int(parts[1].strip())
                    if tracer_pid != 0:
                        return True, f"linux_tracer_pid_{tracer_pid}"
                except ValueError:
                    pass

    return False, "clean"


def list_running_processes() -> list[str]:
    """Return a list of running process executable names on the current host."""
    sys_name = platform.system()
    names: list[str] = []

    if sys_name == "Windows":
        try:
            out = subprocess.check_output(
                ["tasklist", "/FO", "CSV", "/NH"],
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="ignore",
            )
            for line in out.splitlines():
                line = line.strip()
                if not line:
                    continue
                first_col = line.split('","', 1)[0].strip('"').strip()
                if first_col:
                    names.append(first_col)
            return names
        except Exception:
            return []

    try:
        out = subprocess.check_output(
            ["ps", "-A", "-o", "comm="],
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="ignore",
        )
        for line in out.splitlines():
            cleaned = line.strip()
            if cleaned:
                names.append(os.path.basename(cleaned))
    except Exception:
        pass
    return names


def detect_suspicious_processes(
    *,
    running_processes: Iterable[str] | None = None,
    blacklist: Sequence[str] = DEFAULT_SUSPICIOUS_PROCESSES,
) -> list[str]:
    """Scan running processes against the blacklist and return matched process names."""
    active = list(running_processes) if running_processes is not None else list_running_processes()
    normalized_blacklist = {normalize_process_name(item) for item in blacklist if str(item).strip()}
    matched: list[str] = []

    for proc in active:
        norm = normalize_process_name(proc)
        if not norm:
            continue
        if norm in normalized_blacklist or "cheatengine" in norm:
            matched.append(str(proc).strip())

    return matched


def enforce_anti_cheat(
    *,
    running_processes: Iterable[str] | None = None,
    blacklist: Sequence[str] = DEFAULT_SUSPICIOUS_PROCESSES,
    trace_getter: Callable[[], object] | None = None,
    win32_checker: Callable[[], bool] | None = None,
    proc_status_text: str | None = None,
    environ: dict[str, str] | None = None,
    exit_fn: Callable[[int], None] | None = None,
) -> dict[str, object]:
    """
    Execute debugger and suspicious process checks.
    Invokes `exit_fn` (defaults to `sys.exit`) immediately when a check triggers.
    """
    terminator = exit_fn or sys.exit

    dbg_detected, dbg_reason = detect_debugger(
        trace_getter=trace_getter,
        win32_checker=win32_checker,
        proc_status_text=proc_status_text,
        environ=environ,
    )
    if dbg_detected:
        print(f"{TAG} Debugger detected ({dbg_reason}). Exiting.", file=sys.stderr)
        terminator(EXIT_DEBUGGER_DETECTED)
        return {
            "ok": False,
            "reason": "debugger_detected",
            "detail": dbg_reason,
            "exit_code": EXIT_DEBUGGER_DETECTED,
        }

    matched_procs = detect_suspicious_processes(
        running_processes=running_processes,
        blacklist=blacklist,
    )
    if matched_procs:
        joined = ", ".join(matched_procs)
        print(f"{TAG} Suspicious process detected ({joined}). Exiting.", file=sys.stderr)
        terminator(EXIT_SUSPICIOUS_PROCESS)
        return {
            "ok": False,
            "reason": "suspicious_process",
            "matched": matched_procs,
            "exit_code": EXIT_SUSPICIOUS_PROCESS,
        }

    print(f"{TAG} All clear. Continue.")
    return {
        "ok": True,
        "reason": "clean",
        "matched": [],
        "exit_code": 0,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Javelin Basic Anti-Cheat Protection")
    parser.add_argument(
        "--extra-blacklist",
        nargs="*",
        default=[],
        help="Additional process names to block (e.g. customtrainer.exe)",
    )
    args = parser.parse_args(argv)

    combined_blacklist = list(DEFAULT_SUSPICIOUS_PROCESSES) + list(args.extra_blacklist)
    result = enforce_anti_cheat(blacklist=combined_blacklist)
    return int(result["exit_code"])


if __name__ == "__main__":
    raise SystemExit(main())
