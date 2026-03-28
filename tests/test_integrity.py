import hashlib
import os
import tempfile
import unittest
from pathlib import Path

import anti_cheat


class IntegrityTests(unittest.TestCase):
    def test_compute_sha256_matches_hashlib(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "sample.txt"
            path.write_text("javelin-integrity", encoding="utf-8")
            expected = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(anti_cheat.compute_sha256(path), expected)

    def test_valid_sha256_format(self) -> None:
        self.assertTrue(anti_cheat.is_valid_sha256("a" * 64))
        self.assertFalse(anti_cheat.is_valid_sha256("g" * 64))
        self.assertFalse(anti_cheat.is_valid_sha256("abcd"))

    def test_verify_script_integrity_passes_with_matching_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "script.py"
            path.write_text("print('ok')\n", encoding="utf-8")
            expected = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertTrue(anti_cheat.verify_script_integrity(expected, path))

    def test_verify_script_integrity_fails_with_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "script.py"
            path.write_text("print('safe')\n", encoding="utf-8")
            self.assertFalse(anti_cheat.verify_script_integrity("0" * 64, path))

    def test_verify_script_integrity_fails_with_invalid_hash_length(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "script.py"
            path.write_text("print('safe')\n", encoding="utf-8")
            self.assertFalse(anti_cheat.verify_script_integrity("abc", path))

    def test_verify_script_integrity_fails_with_invalid_hex(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "script.py"
            path.write_text("print('safe')\n", encoding="utf-8")
            self.assertFalse(anti_cheat.verify_script_integrity("z" * 64, path))

    def test_verify_script_integrity_ignores_missing_expected_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "script.py"
            path.write_text("print('safe')\n", encoding="utf-8")
            self.assertTrue(anti_cheat.verify_script_integrity("", path))

    def test_tampered_file_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "script.py"
            path.write_text("print('v1')\n", encoding="utf-8")
            baseline = hashlib.sha256(path.read_bytes()).hexdigest()
            path.write_text("print('v2')\n", encoding="utf-8")
            self.assertFalse(anti_cheat.verify_script_integrity(baseline, path))

    def test_guarded_exit_non_zero_on_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "script.py"
            path.write_text("print('safe')\n", encoding="utf-8")
            old = os.environ.get("JAVELIN_EXPECTED_SHA256")
            os.environ["JAVELIN_EXPECTED_SHA256"] = "f" * 64
            try:
                with self.assertRaises(SystemExit) as exc:
                    anti_cheat.run_guarded(path)
                self.assertNotEqual(exc.exception.code, 0)
            finally:
                if old is None:
                    os.environ.pop("JAVELIN_EXPECTED_SHA256", None)
                else:
                    os.environ["JAVELIN_EXPECTED_SHA256"] = old

    def test_guarded_pass_on_matching_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "script.py"
            path.write_text("print('safe')\n", encoding="utf-8")
            expected = hashlib.sha256(path.read_bytes()).hexdigest()
            old = os.environ.get("JAVELIN_EXPECTED_SHA256")
            os.environ["JAVELIN_EXPECTED_SHA256"] = expected
            try:
                self.assertEqual(anti_cheat.run_guarded(path), 0)
            finally:
                if old is None:
                    os.environ.pop("JAVELIN_EXPECTED_SHA256", None)
                else:
                    os.environ["JAVELIN_EXPECTED_SHA256"] = old


if __name__ == "__main__":
    unittest.main()
