import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import anti_cheat


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "anti_cheat.py"


class IntegrityTests(unittest.TestCase):
    def test_missing_expected_hash_disables_check(self):
        self.assertTrue(anti_cheat.check_self_integrity(expected_sha256="", script_path=SCRIPT))

    def test_matching_expected_hash_passes(self):
        expected = anti_cheat.sha256_file(SCRIPT)
        self.assertTrue(anti_cheat.check_self_integrity(expected_sha256=expected, script_path=SCRIPT))

    def test_mismatched_expected_hash_fails(self):
        self.assertFalse(anti_cheat.check_self_integrity(expected_sha256="0" * 64, script_path=SCRIPT))

    def test_malformed_expected_hash_raises(self):
        with self.assertRaises(ValueError):
            anti_cheat.check_self_integrity(expected_sha256="not-a-sha", script_path=SCRIPT)

    def test_cli_returns_guarded_exit_for_mismatch(self):
        env = os.environ.copy()
        env["JAVELIN_EXPECTED_SHA256"] = "0" * 64

        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, anti_cheat.EXIT_INTEGRITY)
        self.assertIn("Integrity check failed", result.stderr)

    def test_cli_accepts_matching_hash(self):
        env = os.environ.copy()
        env["JAVELIN_EXPECTED_SHA256"] = anti_cheat.sha256_file(SCRIPT)

        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("All clear", result.stdout)

    def test_file_hash_changes_after_tamper(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "guard.py"
            path.write_text("print('clean')\n", encoding="utf-8")
            original = anti_cheat.sha256_file(path)

            path.write_text("print('tampered')\n", encoding="utf-8")

            self.assertNotEqual(anti_cheat.sha256_file(path), original)


if __name__ == "__main__":
    unittest.main()
