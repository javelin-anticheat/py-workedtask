import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zlib

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


guard = load("guard", ROOT / "AntiCheat.py")
finalizer = load("finalizer", ROOT / "tools/finalize_crc32.py")


class ScriptIntegrityTests(unittest.TestCase):
    def test_unset_is_optional_but_empty_is_invalid(self):
        self.assertFalse(guard.verify_integrity("not-a-file", None))
        for invalid in ("", "0" * 63, "g" * 64, "0" * 65, " " + "0" * 64):
            with self.subTest(invalid=invalid), self.assertRaises(guard.IntegrityError):
                guard.verify_integrity("not-a-file", invalid)

    def test_hashes_all_bytes_across_chunks_and_accepts_uppercase(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "script.py"
            data = bytes(range(256)) * 1025
            path.write_bytes(data)
            expected = hashlib.sha256(data).hexdigest()
            self.assertTrue(guard.verify_integrity(path, expected.upper()))
            path.write_bytes(data[:-1] + b"!")
            with self.assertRaisesRegex(guard.IntegrityError, "mismatch"):
                guard.verify_integrity(path, expected)

    def test_unreadable_script_fails_closed(self):
        with self.assertRaisesRegex(guard.IntegrityError, "cannot read"):
            guard.verify_integrity(ROOT / "does-not-exist.py", "0" * 64)

    def test_entry_point_hashes_own_script_not_current_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "copied script.py"
            script.write_bytes((ROOT / "AntiCheat.py").read_bytes())
            environment = os.environ.copy()
            environment["JAVELIN_EXPECTED_SHA256"] = hashlib.sha256(script.read_bytes()).hexdigest()
            command = [sys.executable, str(script)]
            good = subprocess.run(command, env=environment, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(good.returncode, 0, good.stderr)
            self.assertIn("integrity verified", good.stdout)
            script.write_bytes(script.read_bytes() + b"\n# changed after release\n")
            bad = subprocess.run(command, env=environment, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(bad.returncode, 3)
            self.assertIn("mismatch", bad.stderr)
            self.assertNotIn("All clear", bad.stdout)
            environment["JAVELIN_EXPECTED_SHA256"] = ""
            invalid = subprocess.run(command, env=environment, capture_output=True, text=True)
            self.assertEqual(invalid.returncode, 3)
            del environment["JAVELIN_EXPECTED_SHA256"]
            disabled = subprocess.run(command, env=environment, capture_output=True, text=True)
            self.assertEqual(disabled.returncode, 0)
            self.assertIn("disabled", disabled.stdout)


class FinalizerTests(unittest.TestCase):
    def test_whole_file_crc_matches_and_refinalization_is_idempotent(self):
        for size in (0, 1, 255, 65537):
            data = b"MZ" + bytes(range(256)) * (size // 256) + b"x" * (size % 256)
            for target in (1, 0xC0DE2026, 0xFFFFFFFF):
                with self.subTest(size=size, target=target):
                    result = finalizer.finalize(data, target)
                    self.assertTrue(result.startswith(data))
                    self.assertEqual(zlib.crc32(result), target)
                    self.assertEqual(finalizer.finalize(result, target), result)
                    changed = finalizer.finalize(result, target ^ 0x1234)
                    self.assertEqual(len(result), len(changed))
                    self.assertEqual(zlib.crc32(changed), target ^ 0x1234)

    def test_rejects_disabled_out_of_range_and_non_executable(self):
        for target in (0, -1, 0x100000000):
            with self.assertRaises(ValueError):
                finalizer.finalize(b"MZpayload", target)
        with self.assertRaises(ValueError):
            finalizer.finalize(b"not executable", 1)


@unittest.skipUnless(os.environ.get("JAVELIN_TEST_EXE"), "set JAVELIN_TEST_EXE to a finalized native build")
class NativeIntegrationTests(unittest.TestCase):
    def test_running_image_passes_and_modified_overlay_fails(self):
        executable = Path(os.environ["JAVELIN_TEST_EXE"]).resolve()
        good = subprocess.run([str(executable), "--verify-integrity"], capture_output=True, text=True)
        self.assertEqual(good.returncode, 0, good.stderr)
        self.assertIn("integrity verified", good.stdout)
        with tempfile.TemporaryDirectory() as directory:
            copy = Path(directory) / "Javelin-測試.exe"
            copy.write_bytes(executable.read_bytes())
            unicode_path = subprocess.run([str(copy), "--verify-integrity"], capture_output=True, text=True)
            self.assertEqual(unicode_path.returncode, 0, unicode_path.stderr)
            changed = bytearray(copy.read_bytes())
            changed[-1] ^= 1
            copy.write_bytes(changed)
            bad = subprocess.run([str(copy), "--verify-integrity"], capture_output=True, text=True)
            self.assertEqual(bad.returncode, 3, bad.stderr)
            self.assertIn("Integrity check failed", bad.stderr)
            self.assertNotIn("All clear", bad.stdout)

    def test_unfinalized_executable_fails_and_zero_baseline_skips(self):
        unfinalized = os.environ["JAVELIN_TEST_UNFINALIZED_EXE"]
        disabled = os.environ["JAVELIN_TEST_DISABLED_EXE"]
        bad = subprocess.run([unfinalized, "--verify-integrity"], capture_output=True, text=True)
        self.assertEqual(bad.returncode, 3)
        good = subprocess.run([disabled, "--verify-integrity"], capture_output=True, text=True)
        self.assertEqual(good.returncode, 0, good.stderr)
        self.assertIn("integrity disabled", good.stdout)


if __name__ == "__main__":
    unittest.main()
