import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import anticheat


class TestJavelinIntegrity(unittest.TestCase):
    def test_matching_sha256_passes(self):
        script = Path(anticheat.__file__).resolve()
        digest = anticheat.compute_file_sha256(script)
        self.assertEqual(len(digest), 64)
        self.assertTrue(anticheat.verify_script_integrity(script_path=script, expected_sha256=digest))

    def test_mismatched_sha256_triggers_guarded_exit(self):
        script = Path(anticheat.__file__).resolve()
        bad_hash = "0" * 64
        self.assertFalse(anticheat.verify_script_integrity(script_path=script, expected_sha256=bad_hash))
        with self.assertRaises(SystemExit) as ctx:
            anticheat.enforce_script_integrity(script_path=script, expected_sha256=bad_hash, exit_code=1)
        self.assertEqual(ctx.exception.code, 1)

    def test_env_var_javelin_expected_sha256_subprocess(self):
        script = Path(anticheat.__file__).resolve()
        digest = anticheat.compute_file_sha256(script)

        # 1. Mismatched env var -> non-zero guarded exit
        env_bad = os.environ.copy()
        env_bad["JAVELIN_EXPECTED_SHA256"] = "f" * 64
        proc_bad = subprocess.run([sys.executable, str(script)], env=env_bad, capture_output=True, text=True)
        self.assertEqual(proc_bad.returncode, 1)
        self.assertIn("Integrity", proc_bad.stderr)

        # 2. Matching env var -> passes integrity verification
        with tempfile.NamedTemporaryFile("wb", suffix=".py", delete=False) as tf:
            tf.write(b"print('ok')\n")
            temp_path = Path(tf.name)
        try:
            temp_digest = anticheat.compute_file_sha256(temp_path)
            self.assertEqual(anticheat.enforce_script_integrity(script_path=temp_path, expected_sha256=temp_digest), temp_digest)
        finally:
            temp_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
