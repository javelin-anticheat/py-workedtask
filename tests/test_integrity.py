import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent.parent
if str(REPO_DIR) not in sys.path:
    sys.path.insert(0, str(REPO_DIR))


class TestScriptAndBinaryIntegrity(unittest.TestCase):
    def test_python_matching_sha256_passes(self) -> None:
        import anti_cheat

        script_path = Path(anti_cheat.__file__).resolve()
        expected = hashlib.sha256(script_path.read_bytes()).hexdigest()
        self.assertEqual(anti_cheat.compute_file_sha256(script_path), expected)
        self.assertTrue(
            anti_cheat.verify_script_integrity(
                script_path=script_path,
                expected_sha256=expected.upper(),
            )
        )

    def test_python_mismatched_or_malformed_sha256_exits_guarded(self) -> None:
        script_src = REPO_DIR / "anti_cheat.py"
        bad_hash = "0" * 64
        env = dict(os.environ)
        env["JAVELIN_EXPECTED_SHA256"] = bad_hash
        env["JAVELIN_SKIP_RUNTIME_SCAN"] = "1"
        proc = subprocess.run(
            [sys.executable, str(script_src)],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("Integrity check failed", proc.stderr)

        env_malformed = dict(env)
        env_malformed["JAVELIN_EXPECTED_SHA256"] = "not-a-valid-sha256"
        proc_malformed = subprocess.run(
            [sys.executable, str(script_src)],
            env=env_malformed,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(proc_malformed.returncode, 0)

    def test_python_tampered_copy_fails_against_original_digest(self) -> None:
        script_src = REPO_DIR / "anti_cheat.py"
        original_digest = hashlib.sha256(script_src.read_bytes()).hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            tampered = Path(tmp) / "anti_cheat.py"
            tampered.write_bytes(script_src.read_bytes() + b"\n# tampered\n")
            env = dict(os.environ)
            env["JAVELIN_EXPECTED_SHA256"] = original_digest
            env["JAVELIN_SKIP_RUNTIME_SCAN"] = "1"
            proc = subprocess.run(
                [sys.executable, str(tampered)],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("Integrity check failed", proc.stderr)

    def test_cpp_executable_crc32_and_sha256_guarded_exit_and_stamp(self) -> None:
        cxx = shutil.which("c++") or shutil.which("clang++") or shutil.which("g++")
        self.assertIsNotNone(cxx)
        assert cxx is not None
        cpp_src = REPO_DIR / "AntiCheat.cpp"
        with tempfile.TemporaryDirectory() as tmp:
            bin_mismatch_crc = Path(tmp) / "ac_bad_crc"
            subprocess.run(
                [
                    cxx,
                    "-std=c++17",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-DJAVELIN_SKIP_RUNTIME_SCAN=1",
                    "-DJAVELIN_EXPECTED_CRC32=0xDEADBEEFu",
                    str(cpp_src),
                    "-o",
                    str(bin_mismatch_crc),
                ],
                check=True,
            )
            res_crc = subprocess.run(
                [str(bin_mismatch_crc)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(res_crc.returncode, 0)
            self.assertIn("CRC", res_crc.stderr)

            bin_mismatch_sha = Path(tmp) / "ac_bad_sha"
            subprocess.run(
                [
                    cxx,
                    "-std=c++17",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-DJAVELIN_SKIP_RUNTIME_SCAN=1",
                    '-DJAVELIN_EXPECTED_SHA256="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"',
                    str(cpp_src),
                    "-o",
                    str(bin_mismatch_sha),
                ],
                check=True,
            )
            res_sha = subprocess.run(
                [str(bin_mismatch_sha)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(res_sha.returncode, 0)
            self.assertIn("SHA-256", res_sha.stderr)

            bin_clean = Path(tmp) / "ac_clean"
            subprocess.run(
                [
                    cxx,
                    "-std=c++17",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-DJAVELIN_SKIP_RUNTIME_SCAN=1",
                    str(cpp_src),
                    "-o",
                    str(bin_clean),
                ],
                check=True,
            )
            res_ok = subprocess.run(
                [str(bin_clean)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(res_ok.returncode, 0, msg=res_ok.stderr)


if __name__ == "__main__":
    unittest.main()
