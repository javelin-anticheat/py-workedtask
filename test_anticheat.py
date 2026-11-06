"""Unit tests for the Javelin Python anti-cheat module (anticheat.py).

Covers: integrity pass/mismatch/unset, guarded exit code 3, sha256 helper,
suspicious process detection interface, debugger detection interface.
Compatible with both `python -m unittest` and `pytest`.
"""
import contextlib
import hashlib
import io
import os
import platform
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import anticheat

REPO_DIR = Path(__file__).resolve().parent
SELF_HASH = anticheat.sha256_file(anticheat.__file__)


def _run_snippet(env_extra: dict[str, str]) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env.pop("JAVELIN_EXPECTED_SHA256", None)
    env.update(env_extra)
    return subprocess.run(
        [sys.executable, "-c", "import anticheat; anticheat.enforce_self_integrity()"],
        cwd=REPO_DIR,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


class TestAntiCheatIntegrity(unittest.TestCase):
    def test_sha256_file_known_vector(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "hello.txt"
            f.write_bytes(b"hello")
            self.assertEqual(
                anticheat.sha256_file(str(f)),
                "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            )

    def test_self_hash_matches_raw_recompute(self) -> None:
        self.assertEqual(
            SELF_HASH,
            hashlib.sha256(Path(anticheat.__file__).read_bytes()).hexdigest(),
        )

    def test_matching_sha256_passes(self) -> None:
        with mock.patch.dict(os.environ, {"JAVELIN_EXPECTED_SHA256": SELF_HASH}):
            self.assertTrue(anticheat.check_self_integrity())
            anticheat.enforce_self_integrity()

    def test_mismatched_sha256_guarded_exit(self) -> None:
        stderr = io.StringIO()
        stdout = io.StringIO()
        with mock.patch.dict(os.environ, {"JAVELIN_EXPECTED_SHA256": "0" * 64}):
            self.assertFalse(anticheat.check_self_integrity())
            with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(stdout):
                with self.assertRaises(SystemExit) as ctx:
                    anticheat.enforce_self_integrity()
            self.assertEqual(ctx.exception.code, anticheat.EXIT_INTEGRITY_FAILURE)
            self.assertEqual(ctx.exception.code, 3)
            self.assertIn("Integrity check failed", stderr.getvalue())
            self.assertEqual(stdout.getvalue(), "")

    def test_unset_env_var_passes_without_enforcement(self) -> None:
        env = {k: v for k, v in os.environ.items() if k != "JAVELIN_EXPECTED_SHA256"}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertTrue(anticheat.check_self_integrity())
            anticheat.enforce_self_integrity()

    def test_blank_env_var_treated_as_unset(self) -> None:
        with mock.patch.dict(os.environ, {"JAVELIN_EXPECTED_SHA256": "   "}):
            self.assertTrue(anticheat.check_self_integrity())

    def test_check_self_integrity_explicit_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "app.py"
            f.write_bytes(b"print(1)")
            digest = hashlib.sha256(b"print(1)").hexdigest()
            self.assertTrue(anticheat.check_self_integrity(expected_sha256=digest, path=str(f)))
            self.assertTrue(
                anticheat.check_self_integrity(expected_sha256=digest.upper(), path=str(f))
            )
            self.assertFalse(
                anticheat.check_self_integrity(expected_sha256="ff" * 32, path=str(f))
            )

    def test_main_propagates_integrity_exit(self) -> None:
        with (
            mock.patch.object(anticheat, "check_debugger", return_value=False),
            mock.patch.object(anticheat, "find_suspicious_process", return_value=None),
            mock.patch.dict(os.environ, {"JAVELIN_EXPECTED_SHA256": "deadbeef"}),
            contextlib.redirect_stderr(io.StringIO()),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            with self.assertRaises(SystemExit) as ctx:
                anticheat.main()
            self.assertEqual(ctx.exception.code, 3)

    def test_find_suspicious_process_detects_known_tools(self) -> None:
        for name in (
            "cheatengine.exe",
            "CheatEngine-X86_64.EXE",
            "x64dbg.exe",
            "ollydbg.exe",
            "ProcessHacker.exe",
        ):
            with self.subTest(name=name):
                self.assertEqual(anticheat.find_suspicious_process([name]), name)

    def test_find_suspicious_process_clean_list_returns_none(self) -> None:
        self.assertIsNone(
            anticheat.find_suspicious_process(["python.exe", "chrome.exe", "svchost"])
        )

    def test_iter_process_names_interface(self) -> None:
        names = anticheat.iter_process_names()
        self.assertIsInstance(names, list)
        self.assertTrue(all(isinstance(n, str) for n in names))
        if platform.system() in ("Windows", "Linux"):
            me = Path(sys.executable).name.lower()
            self.assertTrue(any(n.lower() == me for n in names))

    def test_check_debugger_returns_bool(self) -> None:
        self.assertIsInstance(anticheat.check_debugger(), bool)

    def test_check_debugger_false_in_clean_environment(self) -> None:
        if sys.gettrace() is None:
            self.assertFalse(anticheat.check_debugger())

    def test_subprocess_mismatch_exits_with_code_3(self) -> None:
        proc = _run_snippet({"JAVELIN_EXPECTED_SHA256": "1" * 64})
        self.assertEqual(proc.returncode, 3)
        self.assertIn("Integrity check failed", proc.stderr)

    def test_subprocess_unset_passes(self) -> None:
        proc = _run_snippet({})
        self.assertEqual(proc.returncode, 0)

    def test_subprocess_matching_hash_passes(self) -> None:
        proc = _run_snippet({"JAVELIN_EXPECTED_SHA256": SELF_HASH})
        self.assertEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main()
