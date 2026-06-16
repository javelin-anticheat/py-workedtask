#!/usr/bin/env python3
"""Tests for the Javelin Python anti-cheat self-integrity feature (issue #4).

Run with:  python3 -m pytest test_anti_cheat.py -v
       or:  python3 test_anti_cheat.py   (built-in fallback runner)
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import tempfile

import anti_cheat


def _write_temp_script(body: str = "print('hi')\n") -> str:
    fd, path = tempfile.mkstemp(suffix=".py")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(body)
    return path


def test_compute_sha256_matches_hashlib():
    path = _write_temp_script("data\n")
    try:
        expected = hashlib.sha256(b"data\n").hexdigest()
        assert anti_cheat.compute_sha256(path) == expected
    finally:
        os.remove(path)


def test_compute_sha256_unreadable_returns_none():
    assert anti_cheat.compute_sha256("/no/such/file/at/all.py") is None


def test_integrity_passes_on_match():
    path = _write_temp_script("matched content\n")
    try:
        good = anti_cheat.compute_sha256(path)
        assert anti_cheat.check_self_integrity(expected=good, script_path=path) is True
    finally:
        os.remove(path)


def test_integrity_fails_on_mismatch():
    path = _write_temp_script("real content\n")
    try:
        wrong = "0" * 64
        assert anti_cheat.check_self_integrity(expected=wrong, script_path=path) is False
    finally:
        os.remove(path)


def test_integrity_case_insensitive_expected():
    path = _write_temp_script("case test\n")
    try:
        good = anti_cheat.compute_sha256(path).upper()  # uppercase expected
        assert anti_cheat.check_self_integrity(expected=good, script_path=path) is True
    finally:
        os.remove(path)


def test_integrity_noop_when_unconfigured():
    # Empty/absent expected value -> optional check is a no-op (returns True).
    assert anti_cheat.check_self_integrity(expected="", script_path=__file__) is True


def test_integrity_reads_env_var(monkeypatch=None):
    path = _write_temp_script("env content\n")
    try:
        good = anti_cheat.compute_sha256(path)
        os.environ[anti_cheat.ENV_EXPECTED_SHA256] = good
        try:
            assert anti_cheat.check_self_integrity(script_path=path) is True
            os.environ[anti_cheat.ENV_EXPECTED_SHA256] = "deadbeef"
            assert anti_cheat.check_self_integrity(script_path=path) is False
        finally:
            os.environ.pop(anti_cheat.ENV_EXPECTED_SHA256, None)
    finally:
        os.remove(path)


def test_end_to_end_guarded_exit_on_tamper():
    """Run the script as a subprocess with a wrong expected hash -> exit 0x0C8C."""
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "anti_cheat.py")
    env = dict(os.environ)
    env[anti_cheat.ENV_EXPECTED_SHA256] = "0" * 64  # deliberately wrong
    env.pop("PYTHONBREAKPOINT", None)
    result = subprocess.run(
        [sys.executable, script],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    # 0x0C8C truncates to 0x8C (140) as a POSIX exit status.
    assert result.returncode == (anti_cheat.EXIT_INTEGRITY & 0xFF)
    assert "Integrity check failed" in result.stderr


def test_end_to_end_pass_with_correct_hash():
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "anti_cheat.py")
    good = anti_cheat.compute_sha256(script)
    env = dict(os.environ)
    env[anti_cheat.ENV_EXPECTED_SHA256] = good
    env.pop("PYTHONBREAKPOINT", None)
    result = subprocess.run(
        [sys.executable, script],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    # No tampering, no debugger/suspicious process expected in CI -> clean exit.
    assert result.returncode == anti_cheat.EXIT_OK
    assert "All clear" in result.stdout


if __name__ == "__main__":
    # Minimal fallback runner when pytest is unavailable.
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as exc:
                failures += 1
                print(f"FAIL {name}: {exc}")
            except Exception as exc:  # noqa: BLE001
                failures += 1
                print(f"ERROR {name}: {exc!r}")
    print(f"\n{'ALL TESTS PASSED' if failures == 0 else f'{failures} FAILURE(S)'}")
    sys.exit(1 if failures else 0)
