import unittest
import os
import hashlib
import subprocess
import sys

class TestIntegrity(unittest.TestCase):
    def setUp(self):
        self.script_path = os.path.join(os.path.dirname(__file__), "..", "AntiCheat.py")
        with open(self.script_path, "rb") as f:
            self.correct_sha256 = hashlib.sha256(f.read()).hexdigest()

    def test_integrity_match(self):
        """Test that AntiCheat.py passes when the SHA-256 matches."""
        env = os.environ.copy()
        env["JAVELIN_EXPECTED_SHA256"] = self.correct_sha256
        
        # Run AntiCheat.py
        result = subprocess.run([sys.executable, self.script_path], 
                                env=env, capture_output=True, text=True)
        
        self.assertEqual(result.returncode, 0)
        self.assertIn("All clear", result.stdout)

    def test_integrity_mismatch(self):
        """Test that AntiCheat.py fails when the SHA-256 does not match."""
        env = os.environ.copy()
        env["JAVELIN_EXPECTED_SHA256"] = "wronghash"
        
        # Run AntiCheat.py
        result = subprocess.run([sys.executable, self.script_path], 
                                env=env, capture_output=True, text=True)
        
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Integrity check failed", result.stdout)

    def test_print_integrity(self):
        """Test the --print-integrity flag."""
        result = subprocess.run([sys.executable, self.script_path, "--print-integrity"], 
                                capture_output=True, text=True)
        
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), self.correct_sha256)

if __name__ == "__main__":
    unittest.main()
