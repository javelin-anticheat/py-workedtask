import hashlib
import io
import os
from pathlib import Path
import random
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from AntiCheat import check_integrity, main
from tools.seal_crc32 import correction, seal, validate_unsigned_pe


def pe_fixture(is_64=True):
    optional_size = 240 if is_64 else 224
    pe = 64
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, pe)
    data[pe:pe + 4] = b"PE\0\0"
    struct.pack_into("<H", data, pe + 6, 1)
    struct.pack_into("<H", data, pe + 20, optional_size)
    struct.pack_into("<H", data, pe + 24, 0x20B if is_64 else 0x10B)
    struct.pack_into("<I", data, pe + 24 + (108 if is_64 else 92), 16)
    struct.pack_into("<II", data, pe + 24 + optional_size + 16, 512, 512)
    return bytes(data)


class PythonIntegrity(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "script.py"
        self.path.write_bytes(b"print('hello')\r\n")
        self.expected = hashlib.sha256(self.path.read_bytes()).hexdigest()

    def test_disabled_does_not_access_the_file(self):
        with mock.patch.object(Path, "open", side_effect=AssertionError("must not read")):
            self.assertTrue(check_integrity(self.path, None))

    def test_match_case_insensitive_and_empty_file(self):
        for digest in (self.expected, self.expected.upper()):
            self.assertTrue(check_integrity(self.path, digest))
        self.path.write_bytes(b"")
        self.assertTrue(check_integrity(self.path, hashlib.sha256(b"").hexdigest()))

    def test_malformed_mismatch_missing_directory_permission_failure(self):
        for invalid in ("", "0" * 63, "0" * 65, "g" * 64, "0" * 64,
                        " " + self.expected, self.expected + "\n", "\x00" * 64,
                        "\N{FULLWIDTH LATIN CAPITAL LETTER A}" * 64):
            with self.subTest(expected=invalid):
                self.assertFalse(check_integrity(self.path, invalid))
        self.assertFalse(check_integrity(self.path.parent, self.expected))
        self.assertFalse(check_integrity(self.path.parent / "absent", self.expected))
        with mock.patch.object(Path, "open", side_effect=PermissionError):
            self.assertFalse(check_integrity(self.path, self.expected))

    def test_raw_line_endings_and_binary_modifications(self):
        for data in (b"print('hello')\n", b"print('hello')\r\n# altered\n", b"\xff\x00"):
            self.path.write_bytes(data)
            self.assertFalse(check_integrity(self.path, self.expected))

    def test_large_file_streaming(self):
        data = bytes(range(256)) * 16385
        self.path.write_bytes(data)
        self.assertTrue(check_integrity(self.path, hashlib.sha256(data).hexdigest()))

    def test_entrypoint_blocks_before_success(self):
        with mock.patch.dict(os.environ, {"JAVELIN_EXPECTED_SHA256": "invalid"}), \
             mock.patch("sys.stdout", new_callable=io.StringIO) as stdout, \
             mock.patch("sys.stderr", new_callable=io.StringIO) as stderr:
            self.assertEqual(main(), 3)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("Integrity check failed", stderr.getvalue())

    def test_real_script_from_unrelated_working_directory(self):
        script = ROOT / "AntiCheat.py"
        expected = hashlib.sha256(script.read_bytes()).hexdigest()
        for value, status in [(None, 0), (expected, 0), (expected.upper(), 0), ("", 3), ("0" * 64, 3)]:
            environment = dict(os.environ)
            environment.pop("JAVELIN_EXPECTED_SHA256", None)
            if value is not None:
                environment["JAVELIN_EXPECTED_SHA256"] = value
            result = subprocess.run([sys.executable, str(script)], cwd=self.temp.name,
                                    env=environment, capture_output=True, text=True)
            with self.subTest(expected=value):
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertEqual("All clear" in result.stdout, status == 0)


class CrcSealing(unittest.TestCase):
    def test_affine_solver_randomized_and_every_target_bit(self):
        rng = random.Random(190904)
        pairs = [(0, 0), (0xFFFFFFFF, 0xFFFFFFFF)]
        pairs += [(rng.getrandbits(32), 1 << bit) for bit in range(32)]
        pairs += [(rng.getrandbits(32), rng.getrandbits(32)) for _ in range(1000)]
        for prefix, target in pairs:
            with self.subTest(prefix=prefix, target=target):
                self.assertEqual(zlib.crc32(correction(prefix, target), prefix), target)

    def test_zero_nonzero_full_file_seal_and_idempotence(self):
        with tempfile.TemporaryDirectory() as folder:
            for is_64 in (False, True):
                for target in (0, 1, 0x12345678, 0xFFFFFFFF):
                    path = Path(folder) / "guard.exe"
                    original = pe_fixture(is_64)
                    path.write_bytes(original)
                    self.assertEqual(seal(path, target), target)
                    self.assertEqual(zlib.crc32(path.read_bytes()), target)
                    self.assertEqual(path.read_bytes()[:-4], original)
                    sealed = path.read_bytes()
                    self.assertEqual(seal(path, target), target)
                    self.assertEqual(path.read_bytes(), sealed)

    def test_invalid_crc_values(self):
        for target in (-1, 1 << 32):
            with self.assertRaises(ValueError):
                correction(0, target)
            with self.assertRaises(ValueError):
                seal(Path("missing.exe"), target)

    def test_malformed_and_signed_files_remain_unchanged(self):
        fixtures = [b"", b"MZ", b"wrong" * 300]
        valid = pe_fixture()
        fixtures += [valid[:end] for end in (63, 65, 87, 327, 600)]
        for offset, value in [(60, 0xFFFFFFFF), (64, 0), (64 + 24 + 108, 500),
                              (64 + 24 + 112 + 32, 1024),
                              (64 + 24 + 112 + 36, 8),
                              (64 + 24 + 240 + 16, 10000)]:
            data = bytearray(valid)
            struct.pack_into("<I", data, offset, value)
            fixtures.append(bytes(data))
        with tempfile.TemporaryDirectory() as folder:
            for data in fixtures:
                path = Path(folder) / "invalid.exe"
                path.write_bytes(data)
                with self.subTest(size=len(data)), self.assertRaises(ValueError):
                    seal(path, 0x12345678)
                self.assertEqual(path.read_bytes(), data)

    def test_failed_replace_preserves_original(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "guard.exe"
            original = pe_fixture()
            path.write_bytes(original)
            with mock.patch("tools.seal_crc32.os.replace", side_effect=PermissionError), \
                 self.assertRaises(PermissionError):
                seal(path, 0x12345678)
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(list(Path(folder).iterdir()), [path])


if __name__ == "__main__":
    unittest.main()
