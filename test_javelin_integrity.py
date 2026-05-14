from pathlib import Path
import tempfile
import unittest

from javelin_integrity import (
    EXIT_CODE_INTEGRITY_FAILURE,
    guard_script_integrity,
    sha256_file,
    verify_script_integrity,
)


class IntegrityTests(unittest.TestCase):
    def test_verify_script_integrity_allows_matching_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            script = Path(temp_dir) / "game.py"
            script.write_text("print('safe')\n", encoding="utf-8")

            self.assertTrue(verify_script_integrity(script, sha256_file(script)))

    def test_verify_script_integrity_rejects_mismatched_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            script = Path(temp_dir) / "game.py"
            script.write_text("print('tampered')\n", encoding="utf-8")

            self.assertFalse(verify_script_integrity(script, "0" * 64))

    def test_guard_script_integrity_exits_on_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            script = Path(temp_dir) / "game.py"
            script.write_text("print('tampered')\n", encoding="utf-8")

            with self.assertRaises(SystemExit) as exc_info:
                guard_script_integrity(script, "0" * 64)

            self.assertEqual(exc_info.exception.code, EXIT_CODE_INTEGRITY_FAILURE)


if __name__ == "__main__":
    unittest.main()
