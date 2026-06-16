#!/usr/bin/env python3
"""Javelin Project - Minimal Anti-Cheat guards (Python implementation).

Mirrors the behaviour of ``AntiCheat.cpp`` for environments that run the
Python tooling instead of the native C++ build.

Features
--------
* Debugger detection (best-effort, cross-platform).
* Suspicious process scan (cheat / debugging tooling).
* Self-integrity verification using **SHA-256** of the running script file,
  compared against the ``JAVELIN_EXPECTED_SHA256`` environment variable.

The self-integrity check is the security primitive requested in issue #4:
if the on-disk script has been tampered with, the computed SHA-256 will not
match the expected value and the program performs a *guarded exit* instead of
continuing to run untrusted code.

Exit codes
----------
``0``       All checks passed (or integrity check not configured).
``0xDEB``   Debugger detected.
``0xBAD``   Suspicious process detected.
``0x0C8C``  Integrity check failed (SHA-256 mismatch).

The integrity-failure code ``0x0C8C`` is chosen so it fits in a single byte
range on POSIX (``0x0C8C & 0xFF == 0x8C``) while remaining a recognisable
constant in logs; the full value is also written to stderr.
"""

from __future__ import annotations

import hashlib
import os
import sys
from typing import Iterable, Optional

TAG = "[Javelin AntiCheat] "

# Exit codes (kept parallel to AntiCheat.cpp where practical).
EXIT_OK = 0
EXIT_DEBUGGER = 0xDEB
EXIT_BAD_PROCESS = 0xBAD
EXIT_INTEGRITY = 0x0C8C

# Environment variable that holds the expected SHA-256 of this script file.
ENV_EXPECTED_SHA256 = "JAVELIN_EXPECTED_SHA256"

# Tooling commonly used for cheating / reversing. Matched case-insensitively
# against process executable names. Mirrors kSuspiciousProcesses in the C++ side.
SUSPICIOUS_PROCESSES = (
    "cheatengine.exe",
    "ollydbg.exe",
    "x64dbg.exe",
    "httpdebuggerui.exe",
    "ida.exe",
    "ida64.exe",
    "scylla.exe",
    "processhacker.exe",
    # POSIX-friendly additions:
    "cheatengine",
    "ollydbg",
    "x64dbg",
    "ida",
    "ida64",
)

# Read in 64 KiB chunks so large scripts never load fully into memory.
_HASH_CHUNK = 64 * 1024


# --------------------------------------------------------------------------- #
# Self-integrity (SHA-256) — the core feature for issue #4.
# --------------------------------------------------------------------------- #
def compute_sha256(path: str) -> Optional[str]:
    """Return the lowercase hex SHA-256 of *path*, or ``None`` if unreadable."""
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(_HASH_CHUNK), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def _script_path() -> str:
    """Absolute path to the running script file (resolves symlinks)."""
    # ``sys.argv[0]`` reflects the invoked file; fall back to this module's file.
    candidate = sys.argv[0] or __file__
    if not os.path.isfile(candidate):
        candidate = __file__
    return os.path.realpath(candidate)


def check_self_integrity(
    expected: Optional[str] = None,
    script_path: Optional[str] = None,
) -> bool:
    """Verify the on-disk script matches the expected SHA-256.

    Parameters
    ----------
    expected:
        Expected lowercase hex SHA-256. If ``None`` it is read from the
        ``JAVELIN_EXPECTED_SHA256`` environment variable.
    script_path:
        Path to hash. Defaults to the running script file.

    Returns
    -------
    bool
        ``True`` when the hash matches (or no expected value is configured —
        the check is *optional* by design, like the C++ build-time constant).
        ``False`` only when an expected value is configured **and** the
        computed hash differs (or the file cannot be read).
    """
    if expected is None:
        expected = os.environ.get(ENV_EXPECTED_SHA256, "").strip()

    # Not configured -> check is a no-op (optional integrity, matches C++).
    if not expected:
        return True

    expected = expected.lower()
    actual = compute_sha256(script_path or _script_path())
    if actual is None:
        return False
    return actual == expected


# --------------------------------------------------------------------------- #
# Debugger detection (best-effort, cross-platform).
# --------------------------------------------------------------------------- #
def check_debugger() -> bool:
    """Return ``True`` if a debugger appears to be attached."""
    # Active Python tracer (pdb / IDE debugger) hooked into the interpreter.
    if sys.gettrace() is not None:
        return True

    # Windows: IsDebuggerPresent via kernel32.
    if sys.platform.startswith("win"):
        try:
            import ctypes

            if ctypes.windll.kernel32.IsDebuggerPresent():  # type: ignore[attr-defined]
                return True
        except Exception:
            pass
        return False

    # Linux: TracerPid in /proc/self/status is non-zero when traced (ptrace).
    try:
        with open("/proc/self/status", "r", encoding="ascii", errors="ignore") as status:
            for line in status:
                if line.startswith("TracerPid:"):
                    return int(line.split(":", 1)[1].strip() or "0") != 0
    except OSError:
        pass
    return False


# --------------------------------------------------------------------------- #
# Suspicious process scan.
# --------------------------------------------------------------------------- #
def _iter_process_names() -> Iterable[str]:
    """Yield lowercase process executable names for the current platform."""
    if sys.platform.startswith("win"):
        try:
            import subprocess

            output = subprocess.run(
                ["tasklist", "/fo", "csv", "/nh"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            ).stdout
            for line in output.splitlines():
                if line.startswith('"'):
                    yield line.split('","', 1)[0].strip('"').lower()
        except Exception:
            return
        return

    # POSIX: read executable names from /proc.
    proc = "/proc"
    if not os.path.isdir(proc):
        return
    for pid in os.listdir(proc):
        if not pid.isdigit():
            continue
        try:
            with open(os.path.join(proc, pid, "comm"), "r", encoding="ascii", errors="ignore") as f:
                yield f.read().strip().lower()
        except OSError:
            continue


def check_suspicious_processes() -> bool:
    """Return ``True`` if a known cheating/debugging tool is running."""
    bad = {name.lower() for name in SUSPICIOUS_PROCESSES}
    for name in _iter_process_names():
        # Match exact name or basename without extension.
        if name in bad or os.path.splitext(name)[0] in bad:
            return True
    return False


# --------------------------------------------------------------------------- #
# Entry point.
# --------------------------------------------------------------------------- #
def run_checks() -> int:
    """Run all guards in order and return the appropriate exit code."""
    print(f"{TAG}starting checks...")

    if check_debugger():
        print(f"{TAG}Debugger detected. Exiting.", file=sys.stderr)
        return EXIT_DEBUGGER

    if check_suspicious_processes():
        print(f"{TAG}Suspicious process detected. Exiting.", file=sys.stderr)
        return EXIT_BAD_PROCESS

    if not check_self_integrity():
        print(
            f"{TAG}Integrity check failed (SHA-256 mismatch). "
            f"Exiting with code {EXIT_INTEGRITY:#06x}.",
            file=sys.stderr,
        )
        return EXIT_INTEGRITY

    print(f"{TAG}All clear. Continue.")
    return EXIT_OK


def main() -> int:  # pragma: no cover - thin CLI wrapper
    return run_checks()


if __name__ == "__main__":
    sys.exit(run_checks())
