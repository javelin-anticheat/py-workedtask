import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


class CppAntiCheatBuildTests(unittest.TestCase):
    def test_cpp_client_compiles_and_runs_without_configured_crc(self):
        compiler = shutil.which("c++") or shutil.which("g++") or shutil.which("clang++")
        if compiler is None:
            self.skipTest("No C++ compiler available")

        repo_root = Path(__file__).resolve().parents[1]
        source = repo_root / "AntiCheat.cpp"
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "javelin-anticheat-check"
            subprocess.run(
                [compiler, "-std=c++17", "-Wall", "-Wextra", "-pedantic", str(source), "-o", str(output)],
                check=True,
                cwd=repo_root,
            )
            completed = subprocess.run([str(output)], check=False, capture_output=True, text=True)

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("All clear", completed.stdout)

    def test_cpp_client_exits_on_configured_crc_mismatch(self):
        compiler = shutil.which("c++") or shutil.which("g++") or shutil.which("clang++")
        if compiler is None:
            self.skipTest("No C++ compiler available")

        repo_root = Path(__file__).resolve().parents[1]
        source = repo_root / "AntiCheat.cpp"
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "javelin-anticheat-check"
            subprocess.run(
                [
                    compiler,
                    "-std=c++17",
                    "-Wall",
                    "-Wextra",
                    "-pedantic",
                    "-DJAVELIN_EXPECTED_CRC32=0x1",
                    str(source),
                    "-o",
                    str(output),
                ],
                check=True,
                cwd=repo_root,
            )
            completed = subprocess.run([str(output)], check=False, capture_output=True, text=True)

        self.assertEqual(completed.returncode, 0xC0, completed.stderr)
        self.assertIn("Integrity check failed", completed.stderr)


if __name__ == "__main__":
    unittest.main()
