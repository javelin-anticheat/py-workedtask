"""Run real Python and Windows executable acceptance checks without artifacts."""

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zlib
import struct

from integrity import verify_script
from seal_crc import correction, seal

ROOT = Path(__file__).resolve().parent


class IntegrityTests(unittest.TestCase):
    def test_seal_rejects_invalid_and_signed_pe(self):
        with tempfile.TemporaryDirectory(prefix="javelin-seal-") as directory:
            path = Path(directory) / "sample.exe"
            samples = [b"MZnot a PE executable"]
            for magic, offset in [(0x10B, 96), (0x20B, 112)]:
                data = bytearray(512)
                data[:2] = b"MZ"
                struct.pack_into("<I", data, 60, 64)
                data[64:68] = b"PE\0\0"
                struct.pack_into("<H", data, 84, offset + 40)
                struct.pack_into("<H", data, 88, magic)
                struct.pack_into("<I", data, 88 + offset - 4, 5)
                struct.pack_into("<II", data, 88 + offset + 32, 480, 32)
                samples.append(bytes(data))
            for data in samples:
                with self.subTest(size=len(data)):
                    path.write_bytes(data)
                    with self.assertRaises(ValueError):
                        seal(path, 0)
                    self.assertEqual(path.read_bytes(), data)
            data = bytearray(samples[-1])
            struct.pack_into("<II", data, 88 + 112 + 32, 0, 0)
            path.write_bytes(data)
            seal(path, 0)
            self.assertEqual(zlib.crc32(path.read_bytes()), 0)

    def test_python_actual_script(self):
        with tempfile.TemporaryDirectory(prefix="javelin-test-") as directory:
            script = Path(directory) / "integrity.py"
            shutil.copyfile(ROOT / "integrity.py", script)
            expected = hashlib.sha256(script.read_bytes()).hexdigest()
            environment = dict(os.environ)
            for baseline, code in [(None, 0), (expected.upper(), 0), ("", 3), ("0" * 64, 3)]:
                with self.subTest(baseline=baseline):
                    environment.pop("JAVELIN_EXPECTED_SHA256", None)
                    if baseline is not None:
                        environment["JAVELIN_EXPECTED_SHA256"] = baseline
                    result = subprocess.run([sys.executable, "-B", str(script)], env=environment,
                                            capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, code, result.stderr)
            environment["JAVELIN_EXPECTED_SHA256"] = expected
            with script.open("ab") as output:
                output.write(b"\n# modified after baseline\n")
            result = subprocess.run([sys.executable, "-B", str(script)], env=environment,
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 3, result.stderr)
            self.assertIn("integrity check failed", result.stderr)

    def test_missing_script_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="javelin-test-") as directory:
            self.assertFalse(verify_script(Path(directory) / "missing.py", "0" * 64))

    def test_crc_correction(self):
        for data, target in [(b"", 0), (b"sample", 0x12345678), (bytes(range(256)), 0xFFFFFFFF)]:
            with self.subTest(target=target):
                self.assertEqual(zlib.crc32(data + correction(data, target)), target)

    @unittest.skipUnless(sys.platform == "win32", "Requires Windows executable loader")
    def test_cpp_actual_executable(self):
        compiler = shutil.which("g++")
        self.assertIsNotNone(compiler, "g++ must be installed for live acceptance checks")
        with tempfile.TemporaryDirectory(prefix="javelin-build-") as directory:
            executable = Path(directory) / "AntiCheat.exe"
            # Zero tests that a valid zero baseline does not disable checking.
            for baseline in [None, 0]:
                command = [compiler, "-std=c++17", "-static", str(ROOT / "AntiCheat.cpp"), "-o", str(executable)]
                if baseline is not None:
                    command.insert(1, f"-DJAVELIN_EXPECTED_CRC32={baseline}u")
                build = subprocess.run(command, capture_output=True, text=True, timeout=60)
                self.assertEqual(build.returncode, 0, build.stderr)
                if baseline is not None:
                    before = subprocess.run([str(executable)], capture_output=True, text=True, timeout=10)
                    self.assertEqual(before.returncode, 3, before.stdout + before.stderr)
                    seal(executable, baseline)
                result = subprocess.run([str(executable)], capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                if baseline is not None:
                    with executable.open("ab") as output:
                        output.write(b"tampered")
                    result = subprocess.run([str(executable)], capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
                    self.assertIn("CRC mismatch", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
