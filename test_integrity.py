import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import anti_cheat


class IntegrityVerificationTests(unittest.TestCase):
    def test_missing_expected_hash_skips_check(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertTrue(anti_cheat.check_script_integrity(Path("does-not-need-to-exist")))

    def test_matching_hash_passes(self):
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"trusted script")
            path = Path(tmp.name)
        try:
            expected = hashlib.sha256(path.read_bytes()).hexdigest()
            with patch.dict(os.environ, {anti_cheat.EXPECTED_SHA256_ENV: expected}, clear=True):
                self.assertTrue(anti_cheat.check_script_integrity(path))
        finally:
            path.unlink(missing_ok=True)

    def test_mismatched_hash_fails(self):
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"tampered script")
            path = Path(tmp.name)
        try:
            wrong_hash = "0" * 64
            with patch.dict(os.environ, {anti_cheat.EXPECTED_SHA256_ENV: wrong_hash}, clear=True):
                self.assertFalse(anti_cheat.check_script_integrity(path))
        finally:
            path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
