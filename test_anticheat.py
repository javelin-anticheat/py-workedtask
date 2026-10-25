# -*- coding: utf-8 -*-
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import anticheat


class TestJavelinIntegrityVerification(unittest.TestCase):
    def test_optional_when_env_unset(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(anticheat.ENV_EXPECTED_SHA256, None)
            self.assertTrue(anticheat.verify_script_integrity())
            anticheat.guarded_integrity_check()

    def test_matching_sha256_passes(self):
        with tempfile.NamedTemporaryFile("wb", delete=False) as tmp:
            tmp.write(b"print('javelin Verified script')\n")
            tmp_path = Path(tmp.name)
        try:
            expected = anticheat.compute_file_sha256(tmp_path)
            with patch.dict(os.environ, {anticheat.ENV_EXPECTED_SHA256: expected.upper()}):
                self.assertTrue(anticheat.verify_script_integrity(script_path=tmp_path))
                anticheat.guarded_integrity_check(script_path=tmp_path)
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_mismatched_sha256_triggers_guarded_exit(self):
        with tempfile.NamedTemporaryFile("wb", delete=False) as tmp:
            tmp.write(b"print('tampered payload')\n")
            tmp_path = Path(tmp.name)
        try:
            bad_hash = "0" * 64
            with patch.dict(os.environ, {anticheat.ENV_EXPECTED_SHA256: bad_hash}):
                self.assertFalse(anticheat.verify_script_integrity(script_path=tmp_path))
                with self.assertRaises(SystemExit) as ctx:
                    anticheat.guarded_integrity_check(script_path=tmp_path)
                self.assertEqual(ctx.exception.code, anticheat.EXIT_INTEGRITY_FAILED)
        finally:
            tmp_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
