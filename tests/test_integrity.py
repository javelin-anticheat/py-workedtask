"""Automated tests for Javelin integrity verification."""

from __future__ import annotations

import contextlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import anti_cheat  # noqa: E402


class TestPythonIntegrityVerification(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.script_path = Path(self._tmp.name) / "sample_script.py"
        self.script_path.write_text("print('hello javelin')\n", encoding="utf-8")
        self.expected_sha = anti_cheat.compute_file_sha256(self.script_path)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_unset_env_var_passes_as_optional(self) -> None:
        env = {k: v for k, v in os.environ.items() if k != anti_cheat.ENV_EXPECTED_SHA256}
        with mock.patch.dict(os.environ, env, clear=True):
            ok, msg, actual = anti_cheat.verify_script_integrity(script_path=self.script_path)
            self.assertTrue(ok)
            self.assertIn("not set", msg)
            self.assertIsNone(actual)

            result = anti_cheat.enforce_script_integrity(script_path=self.script_path)
            self.assertIsNone(result)

    def test_empty_env_var_passes_as_optional(self) -> None:
        with mock.patch.dict(os.environ, {anti_cheat.ENV_EXPECTED_SHA256: "   "}, clear=False):
            ok, _, actual = anti_cheat.verify_script_integrity(script_path=self.script_path)
            self.assertTrue(ok)
            self.assertIsNone(actual)

    def test_matching_hash_passes_case_insensitive(self) -> None:
        with mock.patch.dict(
            os.environ,
            {anti_cheat.ENV_EXPECTED_SHA256: f"  {self.expected_sha.upper()}  "},
            clear=False,
        ):
            ok, msg, actual = anti_cheat.verify_script_integrity(script_path=self.script_path)
            self.assertTrue(ok)
            self.assertIn("passed", msg.lower())
            self.assertEqual(actual, self.expected_sha)

            enforced = anti_cheat.enforce_script_integrity(script_path=self.script_path)
            self.assertEqual(enforced, self.expected_sha)

    def test_mismatched_hash_exits_guardedly(self) -> None:
        wrong_hash = "0" * 64
        stderr = io.StringIO()
        with mock.patch.dict(os.environ, {anti_cheat.ENV_EXPECTED_SHA256: wrong_hash}, clear=False):
            ok, msg, actual = anti_cheat.verify_script_integrity(script_path=self.script_path)
            self.assertFalse(ok)
            self.assertIn("mismatch", msg.lower())
            self.assertEqual(actual, self.expected_sha)

            with contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as ctx:
                    anti_cheat.enforce_script_integrity(script_path=self.script_path)

        self.assertEqual(ctx.exception.code, anti_cheat.EXIT_INTEGRITY_MISMATCH)
        self.assertIn("SHA-256 mismatch", stderr.getvalue())

    def test_malformed_hash_exits_guardedly(self) -> None:
        stderr = io.StringIO()
        with mock.patch.dict(os.environ, {anti_cheat.ENV_EXPECTED_SHA256: "not-a-sha256"}, clear=False):
            with contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as ctx:
                    anti_cheat.enforce_script_integrity(script_path=self.script_path)

        self.assertEqual(ctx.exception.code, anti_cheat.EXIT_INTEGRITY_MISMATCH)
        self.assertIn("invalid", stderr.getvalue().lower())

    def test_tampered_script_detected(self) -> None:
        self.script_path.write_text("print('tampered!')\n", encoding="utf-8")
        stderr = io.StringIO()
        with mock.patch.dict(os.environ, {anti_cheat.ENV_EXPECTED_SHA256: self.expected_sha}, clear=False):
            with contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as ctx:
                    anti_cheat.enforce_script_integrity(script_path=self.script_path)

        self.assertEqual(ctx.exception.code, anti_cheat.EXIT_INTEGRITY_MISMATCH)
        self.assertIn("mismatch", stderr.getvalue().lower())

    def test_cli_subprocess_end_to_end(self) -> None:
        script_file = REPO_ROOT / "anti_cheat.py"
        base_env = {k: v for k, v in os.environ.items() if k != anti_cheat.ENV_EXPECTED_SHA256}

        # 1. --print-hash prints the exact SHA-256 of anti_cheat.py
        print_proc = subprocess.run(
            [sys.executable, str(script_file), "--print-hash"],
            env=base_env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(print_proc.returncode, 0, msg=print_proc.stderr)
        printed_sha = print_proc.stdout.strip()
        self.assertEqual(printed_sha, anti_cheat.compute_file_sha256(script_file))

        # 2. Unset JAVELIN_EXPECTED_SHA256 -> exits 0
        unset_proc = subprocess.run(
            [sys.executable, str(script_file)],
            env=base_env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(unset_proc.returncode, 0, msg=unset_proc.stderr)
        self.assertIn("All clear. Continue.", unset_proc.stdout)

        # 3. Matching JAVELIN_EXPECTED_SHA256 -> exits 0
        match_env = dict(base_env, **{anti_cheat.ENV_EXPECTED_SHA256: printed_sha})
        match_proc = subprocess.run(
            [sys.executable, str(script_file)],
            env=match_env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(match_proc.returncode, 0, msg=match_proc.stderr)
        self.assertIn("All clear. Continue.", match_proc.stdout)

        # 4. Mismatched JAVELIN_EXPECTED_SHA256 -> guarded exit code 3
        mismatch_env = dict(base_env, **{anti_cheat.ENV_EXPECTED_SHA256: "f" * 64})
        mismatch_proc = subprocess.run(
            [sys.executable, str(script_file)],
            env=mismatch_env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(mismatch_proc.returncode, anti_cheat.EXIT_INTEGRITY_MISMATCH)
        self.assertNotIn("All clear. Continue.", mismatch_proc.stdout)
        self.assertIn("Integrity check failed", mismatch_proc.stderr)


if __name__ == "__main__":
    unittest.main()
