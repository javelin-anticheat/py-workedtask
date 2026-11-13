#!/usr/bin/env python3
"""Javelin Project — Cross-platform Python Anti-Cheat Monitor."""
from __future__ import annotations

import argparse
import ctypes
import os
from pathlib import Path
import subprocess
import sys
from typing import Callable, Iterable, List, Optional, Sequence

TAG = "[Javelin AntiCheat] "

EXIT_OK = 0
EXIT_DEBUGGER_DETECTED = 10
EXIT_SUSPICIOUS_PROCESS = 11

SUSPICIOUS_PROCESS_STEMS: tuple[str, ...] = (
    "cheatengine",
    "ollydbg",
    "x64dbg",
    "x32dbg",
    "httpdebuggerui",
    "ida",
    "ida64",
    "scylla",
    "processhacker",
)


def _normalize_process_stem(name: str) -> str:
    base = os.path.basename(name.strip().strip('"')).lower()
    if base.endswith(".exe"):
        base = base[:-4]
    return base


def _os_debugger_probe() -> bool:
    if sys.platform.startswith("win"):
        try:
            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            if kernel32.IsDebuggerPresent() != 0:
                return True
            remote = ctypes.c_int(0)
            if kernel32.CheckRemoteDebuggerPresent(kernel32.GetCurrentProcess(), ctypes.byref(remote)) != 0 and remote.value != 0:
                return True
        except Exception:
            return False
        return False

    if sys.platform.startswith("linux"):
        status_path = Path("/proc/self/status")
        if status_path.is_file():
            try:
                for line in status_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                    if line.startswith("TracerPid:"):
                        tracer_pid = int(line.split(":", 1)[1].strip())
                        return tracer_pid != 0
            except (OSError, ValueError):
                return False
        return False

    if sys.platform == "darwin":
        try:
            proc = subprocess.run(
                ["ps", "-o", "stat=", "-p", str(os.getpid())],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            if proc.returncode == 0 and "X" in proc.stdout.strip():
                return True
        except Exception:
            return False
    return False


def is_debugger_attached(
    *,
    trace_fn: Optional[Callable[[], object]] = None,
    os_probe: Optional[Callable[[], bool]] = None,
) -> bool:
    eff_trace = trace_fn if trace_fn is not None else sys.gettrace
    if eff_trace() is not None:
        return True
    eff_os_probe = os_probe if os_probe is not None else _os_debugger_probe
    return bool(eff_os_probe())


def list_running_processes() -> List[str]:
    try:
        import psutil  # type: ignore[import-not-found]

        names: List[str] = []
        for proc in psutil.process_iter(["name"]):
            pname = (proc.info or {}).get("name")
            if pname:
                names.append(str(pname))
        if names:
            return names
    except Exception:
        pass

    if sys.platform.startswith("win"):
        proc = subprocess.run(
            ["tasklist", "/FO", "CSV", "/NH"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        out: List[str] = []
        for line in proc.stdout.splitlines():
            parts = line.split(",", 1)
            if parts and parts[0].strip().strip('"'):
                out.append(parts[0].strip().strip('"'))
        return out

    if sys.platform.startswith("linux") and Path("/proc").is_dir():
        out = []
        for entry in Path("/proc").iterdir():
            if entry.name.isdigit():
                comm = entry / "comm"
                try:
                    if comm.is_file():
                        out.append(comm.read_text(encoding="utf-8", errors="ignore").strip())
                except OSError:
                    continue
        if out:
            return out

    proc = subprocess.run(
        ["ps", "-axo", "comm="],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    return [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]


def find_suspicious_processes(
    process_names: Optional[Iterable[str]] = None,
    *,
    denylist: Sequence[str] = SUSPICIOUS_PROCESS_STEMS,
) -> List[str]:
    names = list(process_names) if process_names is not None else list_running_processes()
    deny_norm = {_normalize_process_stem(item) for item in denylist if item.strip()}
    detected: List[str] = []
    for raw_name in names:
        stem = _normalize_process_stem(raw_name)
        if not stem:
            continue
        if stem in deny_norm or any(stem.startswith(f"{bad}-") or stem.startswith(f"{bad}_") for bad in deny_norm):
            detected.append(os.path.basename(raw_name.strip()).lower())
    return detected


def run_checks(
    *,
    process_names: Optional[Iterable[str]] = None,
    ignore_debugger: bool = False,
    force_debugger: bool = False,
) -> int:
    sys.stdout.write(f"{TAG}starting checks...\n")
    if force_debugger or (not ignore_debugger and is_debugger_attached()):
        sys.stderr.write(f"{TAG}Debugger detected. Exiting.\n")
        return EXIT_DEBUGGER_DETECTED

    suspicious = find_suspicious_processes(process_names)
    if suspicious:
        sys.stderr.write(f"{TAG}Suspicious process detected ({suspicious[0]}). Exiting.\n")
        return EXIT_SUSPICIOUS_PROCESS

    sys.stdout.write(f"{TAG}All clear. Continue.\n")
    return EXIT_OK


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Javelin Anti-Cheat Python Monitor")
    parser.add_argument(
        "--check-processes",
        default="",
        help="Optional comma-separated process list override for deterministic verification.",
    )
    parser.add_argument("--ignore-debugger", action="store_true", help="Skip debugger check during process-only tests.")
    parser.add_argument("--simulate-debugger", action="store_true", help="Simulate attached debugger for verification.")
    args = parser.parse_args(list(argv) if argv is not None else None)

    override_procs: Optional[List[str]] = None
    if args.check_processes.strip():
        override_procs = [item.strip() for item in args.check_processes.split(",") if item.strip()]

    return run_checks(
        process_names=override_procs,
        ignore_debugger=bool(args.ignore_debugger),
        force_debugger=bool(args.simulate_debugger),
    )


if __name__ == "__main__":
    raise SystemExit(main())
