"""Run with a Windows developer prompt; REQUIRE_NATIVE=1 makes missing tools fail."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.seal_crc32 import seal


class NativeIntegrity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = os.environ.get("CXX") or shutil.which("cl")
        if sys.platform != "win32" or not compiler:
            if os.environ.get("REQUIRE_NATIVE") == "1":
                raise RuntimeError("Windows MSVC developer environment is required")
            raise unittest.SkipTest("native Windows MSVC environment is unavailable")
        cls.temp = tempfile.TemporaryDirectory()
        cls.compiler = compiler
        cls.addClassCleanup(cls.temp.cleanup)
        cls.folder = Path(cls.temp.name)
        cls.executables = {}
        for expected in (None, 0, 0x12345678):
            name = "disabled" if expected is None else f"guard_{expected:x}"
            path = cls.folder / f"{name}.exe"
            args = [compiler, "/nologo", "/EHsc", "/std:c++17", "/W4", "/WX", "/O2", "/DUNICODE", "/D_UNICODE",
                    str(ROOT / "AntiCheat.cpp"), f"/Fe{path}", f"/Fo{cls.folder / (name + '.obj')}"]
            if expected is not None:
                args.append(f"/DJAVELIN_EXPECTED_CRC32={expected}u")
            result = subprocess.run(args, cwd=cls.folder, capture_output=True, text=True)
            if result.returncode:
                raise AssertionError(result.stdout + result.stderr)
            cls.executables[expected] = path

    def invoke(self, path):
        return subprocess.run([str(path), "--check-integrity"], cwd=self.folder,
                              capture_output=True, text=True, timeout=10)

    def test_disabled_does_not_require_a_seal(self):
        self.assertEqual(self.invoke(self.executables[None]).returncode, 0)

    def test_invalid_build_time_constants_are_rejected(self):
        for expected in ("-1", "0x100000000ULL", "1.5"):
            with self.subTest(expected=expected):
                result = subprocess.run([self.compiler, "/nologo", "/EHsc", "/std:c++17", "/Zs",
                                         f"/DJAVELIN_EXPECTED_CRC32={expected}", str(ROOT / "AntiCheat.cpp")],
                                        cwd=self.folder, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("JAVELIN_EXPECTED_CRC32 must", result.stdout + result.stderr)

    def test_enabled_rejects_unsealed_and_accepts_sealed_full_file(self):
        for target in (0, 0x12345678):
            with self.subTest(target=target):
                path = self.folder / f"sealed_{target}.exe"
                shutil.copyfile(self.executables[target], path)
                before = self.invoke(path)
                self.assertEqual(before.returncode, 3, before.stdout + before.stderr)
                self.assertIn("Integrity check failed", before.stderr)
                seal(path, target)
                self.assertEqual(zlib.crc32(path.read_bytes()), target)
                self.assertEqual(self.invoke(path).returncode, 0)

    def test_tamper_and_truncation_fail_with_guarded_exit(self):
        source = self.executables[0x12345678]
        path = self.folder / "tampered.exe"
        shutil.copyfile(source, path)
        seal(path, 0x12345678)
        original = path.read_bytes()
        changed = bytearray(original)
        changed[-1] ^= 1
        for data in (bytes(changed), original + b"altered", original[:-1]):
            with self.subTest(size=len(data)):
                path.write_bytes(data)
                result = self.invoke(path)
                self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
                self.assertIn("Integrity check failed", result.stderr)

    def test_unicode_path_and_independent_current_directory(self):
        directory = self.folder / "unicode path \u03b4 \u65e5\u672c"
        directory.mkdir()
        path = directory / "guard.exe"
        shutil.copyfile(self.executables[0], path)
        seal(path, 0)
        self.assertEqual(self.invoke(path).returncode, 0)


if __name__ == "__main__":
    unittest.main()
