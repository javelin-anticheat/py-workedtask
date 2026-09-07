import hashlib
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import AntiCheat
from tools.seal_crc32 import crc32_suffix, seal_bytes


class PythonIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.script = Path(self.temp.name) / "script with spaces.py"
        self.script.write_bytes((ROOT / "AntiCheat.py").read_bytes())
        self.expected = hashlib.sha256(self.script.read_bytes()).hexdigest()

    def run_script(self, expected):
        env = dict(os.environ)
        env.pop("JAVELIN_EXPECTED_SHA256", None)
        if expected is not None:
            env["JAVELIN_EXPECTED_SHA256"] = expected
        return subprocess.run([sys.executable, str(self.script)], env=env,
                              capture_output=True, text=True, timeout=10)

    def test_unset_does_not_read_the_file(self):
        self.assertTrue(AntiCheat.check_script_integrity("not-an-existing-file", None))
        self.assertEqual(self.run_script(None).returncode, 0)

    def test_match_and_uppercase_match(self):
        for expected in [self.expected, self.expected.upper()]:
            with self.subTest(expected=expected):
                self.assertEqual(self.run_script(expected).returncode, 0)

    def test_mismatch_exits_before_continue(self):
        result = self.run_script("0" * 64)
        self.assertEqual(result.returncode, 3)
        self.assertIn("Integrity check failed", result.stderr)
        self.assertNotIn("Continue", result.stdout)

    def test_malformed_config_is_not_silently_disabled(self):
        for expected in ["", "abc", "g" * 64, "0" * 63, "0" * 65, " " + self.expected]:
            with self.subTest(expected=expected):
                self.assertEqual(self.run_script(expected).returncode, 3)

    def test_edited_script_is_rejected(self):
        with self.script.open("ab") as script_file:
            script_file.write(b"\n# modified after the baseline was set\n")
        self.assertEqual(self.run_script(self.expected).returncode, 3)

    def test_read_failure_is_rejected(self):
        self.assertFalse(AntiCheat.check_script_integrity(self.script.parent / "missing", self.expected))
        self.assertFalse(AntiCheat.check_script_integrity(self.script.parent, self.expected))

    def test_streamed_hash_of_multiple_chunks(self):
        data = b"javelin fixture\x00\xff" * 150000
        self.script.write_bytes(data)
        self.assertTrue(AntiCheat.check_script_integrity(
            self.script, hashlib.sha256(data).hexdigest()))


class Crc32SealingTests(unittest.TestCase):
    def test_suffix_for_varied_binary_fixtures_and_targets(self):
        generator = random.Random(4)
        for size in [0, 1, 4, 255, 1024, 131073]:
            data = bytes(generator.getrandbits(8) for _ in range(size))
            for target in [0, 1, 0x4A415645, 0xFFFFFFFF]:
                with self.subTest(size=size, target=target):
                    suffix = crc32_suffix(data, target)
                    self.assertEqual(len(suffix), 4)
                    self.assertEqual(zlib.crc32(data + suffix), target)

    def test_sealing_is_idempotent_and_detects_mutations(self):
        data = b"controlled binary fixture"
        target = 0x4A415645
        sealed = seal_bytes(data, target)
        self.assertEqual(len(sealed), len(data) + 4)
        self.assertEqual(seal_bytes(sealed, target), sealed)
        for offset in [0, len(data) - 1, len(sealed) - 1]:
            changed = bytearray(sealed)
            changed[offset] ^= 1
            self.assertNotEqual(zlib.crc32(changed), target)

    def test_invalid_targets_are_rejected(self):
        for target in [-1, 0x100000000]:
            with self.assertRaises(ValueError):
                seal_bytes(b"fixture", target)

    def test_sealer_preserves_input_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "input.bin"
            output = Path(temp_dir) / "output.bin"
            source.write_bytes(b"authorized fixture")
            command = [sys.executable, str(ROOT / "tools" / "seal_crc32.py"),
                       str(source), str(output), "--expected", "0x4A415645"]
            first = subprocess.run(command, capture_output=True, timeout=10)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(source.read_bytes(), b"authorized fixture")
            self.assertEqual(zlib.crc32(output.read_bytes()), 0x4A415645)
            sealed = output.read_bytes()
            second = subprocess.run(command, capture_output=True, timeout=10)
            self.assertNotEqual(second.returncode, 0)
            self.assertEqual(output.read_bytes(), sealed)


@unittest.skipUnless(sys.platform == "win32" and shutil.which("cl"),
                     "native tests require a Visual Studio Developer Command Prompt")
class NativeIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temp.name)
        cls.executables = {}
        for name, expected in [("disabled", None), ("enabled", "0x4A415645u")]:
            executable = cls.directory / (name + ".exe")
            command = ["cl", "/nologo", "/std:c++17", "/EHsc", "/W4",
                       str(ROOT / "tests" / "integrity_harness.cpp"),
                       "/Fe:" + str(executable), "/Fo:" + str(cls.directory / (name + ".obj"))]
            if expected is not None:
                command.append("/DJAVELIN_EXPECTED_CRC32=" + expected)
            result = subprocess.run(command, cwd=cls.directory, capture_output=True, text=True, timeout=60)
            if result.returncode:
                cls.temp.cleanup()
                raise RuntimeError(result.stdout + result.stderr)
            cls.executables[name] = executable

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_fixture(self, executable):
        return subprocess.run([str(executable)], capture_output=True, text=True, timeout=10)

    def test_disabled_and_unsealed_enabled_guards(self):
        self.assertEqual(self.run_fixture(self.executables["disabled"]).returncode, 0)
        self.assertEqual(self.run_fixture(self.executables["enabled"]).returncode, 3)

    def test_sealed_executable_and_overlay_mutation(self):
        original = self.executables["enabled"].read_bytes()
        sealed = seal_bytes(original, 0x4A415645)
        executable = self.directory / "sealed fixture \u03a9.exe"
        executable.write_bytes(sealed)
        self.assertEqual(self.run_fixture(executable).returncode, 0)
        tampered = bytearray(sealed)
        tampered[-1] ^= 1
        executable.write_bytes(tampered)
        result = self.run_fixture(executable)
        self.assertEqual(result.returncode, 3)
        self.assertIn("Integrity check failed", result.stderr)


if __name__ == "__main__":
    unittest.main()
