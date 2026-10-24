"""Unit and integration tests for Javelin Anti-Cheat C++ & Python integrity verification."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import anticheat


class TestPythonIntegrityVerification(unittest.TestCase):
    def setUp(self) -> None:
        self._orig_sha = os.environ.pop(anticheat.ENV_EXPECTED_SHA256, None)
        self._orig_strict = os.environ.pop(anticheat.ENV_STRICT_INTEGRITY, None)

    def tearDown(self) -> None:
        if self._orig_sha is not None:
            os.environ[anticheat.ENV_EXPECTED_SHA256] = self._orig_sha
        else:
            os.environ.pop(anticheat.ENV_EXPECTED_SHA256, None)
        if self._orig_strict is not None:
            os.environ[anticheat.ENV_STRICT_INTEGRITY] = self._orig_strict
        else:
            os.environ.pop(anticheat.ENV_STRICT_INTEGRITY, None)

    def test_compute_and_verify_matching_sha256(self) -> None:
        script_path = REPO_ROOT / "anticheat.py"
        expected = anticheat.compute_file_sha256(script_path)
        self.assertEqual(len(expected), 64)

        os.environ[anticheat.ENV_EXPECTED_SHA256] = f"  {expected.upper()}  "
        ok, detail = anticheat.verify_script_integrity(script_path)
        self.assertTrue(ok)
        self.assertIn(expected, detail)

    def test_verify_mismatched_sha256_results_in_guarded_exit(self) -> None:
        script_path = REPO_ROOT / "anticheat.py"
        wrong_hash = "0" * 64
        env = dict(os.environ)
        env[anticheat.ENV_EXPECTED_SHA256] = wrong_hash

        proc = subprocess.run(
            [sys.executable, str(script_path)],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, anticheat.EXIT_INTEGRITY_FAILED)
        self.assertIn("Integrity check failed", proc.stderr)
        self.assertIn("SHA-256 mismatch", proc.stderr)

    def test_tampered_script_fails_verification(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            script_copy = Path(tmpdir) / "sample_script.py"
            script_copy.write_text("print('trusted build')\n", encoding="utf-8")
            baseline_hash = anticheat.compute_file_sha256(script_copy)

            ok_initial, _ = anticheat.verify_script_integrity(
                script_copy, expected_sha256=baseline_hash
            )
            self.assertTrue(ok_initial)

            # Tamper with the script
            script_copy.write_text("print('tampered build')\n", encoding="utf-8")
            ok_tampered, detail = anticheat.verify_script_integrity(
                script_copy, expected_sha256=baseline_hash
            )
            self.assertFalse(ok_tampered)
            self.assertIn("SHA-256 mismatch", detail)

    def test_invalid_hash_format_and_strict_mode(self) -> None:
        script_path = REPO_ROOT / "anticheat.py"
        ok_bad, detail_bad = anticheat.verify_script_integrity(
            script_path, expected_sha256="not-a-valid-sha256"
        )
        self.assertFalse(ok_bad)
        self.assertIn("Invalid JAVELIN_EXPECTED_SHA256", detail_bad)

        os.environ[anticheat.ENV_STRICT_INTEGRITY] = "1"
        ok_strict, detail_strict = anticheat.verify_script_integrity(script_path)
        self.assertFalse(ok_strict)
        self.assertIn("strict integrity verification is enabled", detail_strict)


@unittest.skipUnless(shutil.which("g++"), "g++ is required for C++ binary integrity tests")
class TestCppIntegrityVerification(unittest.TestCase):
    def test_cpp_sha256_and_crc32_integrity_checks(self) -> None:
        cpp_src = REPO_ROOT / "AntiCheat.cpp"
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            target_file = tmp_path / "payload.bin"
            target_file.write_bytes(b"Javelin-AntiCheat-Executable-Payload-v1")

            expected_sha256 = anticheat.compute_file_sha256(target_file)

            # 1. Build with matching JAVELIN_EXPECTED_SHA256
            bin_match = tmp_path / "anticheat_match"
            subprocess.run(
                [
                    "g++",
                    "-std=c++17",
                    "-O2",
                    f'-DJAVELIN_EXPECTED_SHA256="{expected_sha256}"',
                    str(cpp_src),
                    "-o",
                    str(bin_match),
                ],
                check=True,
            )
            res_match = subprocess.run(
                [str(bin_match), "--file", str(target_file)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(res_match.returncode, 0, res_match.stderr)
            self.assertIn("All clear. Continue.", res_match.stdout)

            # 2. Tampering with the verified file causes guarded exit (0xCF)
            target_file.write_bytes(b"Tampered-Executable-Payload")
            res_tampered = subprocess.run(
                [str(bin_match), "--file", str(target_file)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(res_tampered.returncode, anticheat.EXIT_INTEGRITY_FAILED)
            self.assertIn("Integrity check failed (SHA-256 mismatch)", res_tampered.stderr)

            # 3. Build with non-matching JAVELIN_EXPECTED_CRC32 causes guarded exit (0xCF)
            bin_bad_crc = tmp_path / "anticheat_bad_crc"
            subprocess.run(
                [
                    "g++",
                    "-std=c++17",
                    "-O2",
                    "-DJAVELIN_EXPECTED_CRC32=0xDEADBEEFu",
                    str(cpp_src),
                    "-o",
                    str(bin_bad_crc),
                ],
                check=True,
            )
            res_bad_crc = subprocess.run(
                [str(bin_bad_crc)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(res_bad_crc.returncode, anticheat.EXIT_INTEGRITY_FAILED)
            self.assertIn("Integrity check failed (CRC32 mismatch)", res_bad_crc.stderr)


if __name__ == "__main__":
    unittest.main()
