import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import anti_cheat


ROOT = Path(__file__).resolve().parents[1]
PYTHON_GUARD = ROOT / "anti_cheat.py"
CPP_GUARD = ROOT / "AntiCheat.cpp"
CRC_RE = re.compile(r"^0x[0-9a-fA-F]{8}$")


def compiler() -> str | None:
    for candidate in ("c++", "g++", "clang++"):
        result = subprocess.run(
            ["sh", "-c", f"command -v {candidate}"],
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    return None


class PythonIntegrityTests(unittest.TestCase):
    def test_python_integrity_is_disabled_without_expected_hash(self):
        self.assertTrue(anti_cheat.check_self_integrity(expected_sha256="", script_path=PYTHON_GUARD))

    def test_python_integrity_accepts_matching_hash(self):
        expected = anti_cheat.sha256_file(PYTHON_GUARD)
        self.assertTrue(anti_cheat.check_self_integrity(expected_sha256=expected, script_path=PYTHON_GUARD))

    def test_python_integrity_rejects_mismatch_and_malformed_hash(self):
        self.assertFalse(
            anti_cheat.check_self_integrity(expected_sha256="0" * 64, script_path=PYTHON_GUARD)
        )
        with self.assertRaises(ValueError):
            anti_cheat.check_self_integrity(expected_sha256="not-a-sha", script_path=PYTHON_GUARD)

    def test_python_cli_prints_expected_hash_and_accepts_it(self):
        printed = subprocess.run(
            [sys.executable, str(PYTHON_GUARD), "--print-integrity-sha256"],
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()
        self.assertEqual(printed, anti_cheat.sha256_file(PYTHON_GUARD))

        env = os.environ.copy()
        env["JAVELIN_EXPECTED_SHA256"] = printed
        result = subprocess.run(
            [sys.executable, str(PYTHON_GUARD)],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("All clear", result.stdout)

    def test_python_cli_exits_on_mismatch(self):
        env = os.environ.copy()
        env["JAVELIN_EXPECTED_SHA256"] = "0" * 64
        result = subprocess.run(
            [sys.executable, str(PYTHON_GUARD)],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, anti_cheat.EXIT_INTEGRITY)
        self.assertIn("Integrity check failed", result.stderr)


class CppIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.compiler = compiler()
        if self.compiler is None:
            self.skipTest("No C++ compiler available")

    def compile_guard(self, output: Path, expected_crc: str | None = None):
        command = [
            self.compiler,
            "-std=c++17",
            "-Wall",
            "-Wextra",
            "-pedantic",
        ]
        if sys.platform.startswith("linux"):
            command.append("-Wl,--build-id=none")
        if expected_crc is not None:
            command.append(f"-DJAVELIN_EXPECTED_CRC32={expected_crc}")
        command.extend([str(CPP_GUARD), "-o", str(output)])
        subprocess.run(command, cwd=ROOT, check=True)

    def test_cpp_configured_crc_accepts_matching_executable(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            baseline = tmp_path / "javelin-baseline"
            checked = tmp_path / "javelin-checked"

            self.compile_guard(baseline)
            expected_crc = subprocess.run(
                [str(baseline), "--print-integrity-crc32"],
                text=True,
                capture_output=True,
                check=True,
            ).stdout.strip()
            self.assertRegex(expected_crc, CRC_RE)

            self.compile_guard(checked, expected_crc)
            result = subprocess.run([str(checked)], text=True, capture_output=True, check=False)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("All clear", result.stdout)

    def test_cpp_configured_crc_rejects_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            checked = Path(tmp) / "javelin-checked"
            self.compile_guard(checked, "0x00000001")
            result = subprocess.run([str(checked)], text=True, capture_output=True, check=False)

        self.assertEqual(result.returncode, 0xC0)
        self.assertIn("Integrity check failed", result.stderr)


if __name__ == "__main__":
    unittest.main()
