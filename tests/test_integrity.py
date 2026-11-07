"""Unit tests for Javelin script and executable SHA-256 integrity verification."""

import os
import pathlib
import tempfile
import unittest
from unittest import mock

import anticheat


class TestJavelinIntegrity(unittest.TestCase):
    """Verify guarded exit and pass-through semantics for JAVELIN_EXPECTED_SHA256."""

    def test_no_expected_hash_passes(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertTrue(anticheat.verify_script_integrity())

    def test_matching_sha256_passes(self) -> None:
        with tempfile.NamedTemporaryFile("wb", delete=False) as tmp:
            tmp.write(b"print('hello javelin')\n")
            tmp_path = pathlib.Path(tmp.name)
        try:
            digest = anticheat.compute_file_sha256(tmp_path)
            self.assertTrue(anticheat.verify_script_integrity(tmp_path, digest))
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_mismatched_sha256_triggers_guarded_exit(self) -> None:
        with tempfile.NamedTemporaryFile("wb", delete=False) as tmp:
            tmp.write(b"print('tampered script')\n")
            tmp_path = pathlib.Path(tmp.name)
        try:
            with self.assertRaises(SystemExit) as ctx:
                anticheat.verify_script_integrity(tmp_path, "0" * 64)
            self.assertEqual(ctx.exception.code, anticheat.EXIT_INTEGRITY_FAILED)
        finally:
            tmp_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
