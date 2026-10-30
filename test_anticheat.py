"""Unit tests for Javelin Python Anti-Cheat & SHA-256 Integrity Verification (Issue #4)."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import anticheat


class TestJavelinIntegrityVerification(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.NamedTemporaryFile("wb", delete=False)
        self.tmp.write(b"print('hello javelin')\n")
        self.tmp.close()
        self.tmp_path = Path(self.tmp.name)
        self.actual_hash = anticheat.compute_file_sha256(self.tmp_path)

    def tearDown(self) -> None:
        if self.tmp_path.exists():
            self.tmp_path.unlink()

    def test_optional_when_env_unset(self) -> None:
        with mock.patch.dict(os.environ, {"JAVELIN_EXPECTED_SHA256": ""}, clear=False):
            self.assertTrue(anticheat.check_self_integrity(script_path=self.tmp_path))
            self.assertEqual(anticheat.run_guards(script_path=self.tmp_path), anticheat.EXIT_OK)

    def test_matching_sha256_passes(self) -> None:
        with mock.patch.dict(os.environ, {"JAVELIN_EXPECTED_SHA256": self.actual_hash.upper()}, clear=False):
            self.assertTrue(anticheat.check_self_integrity(script_path=self.tmp_path))
            self.assertEqual(anticheat.run_guards(script_path=self.tmp_path), anticheat.EXIT_OK)

    def test_non_matching_sha256_triggers_guarded_exit(self) -> None:
        bad_hash = "0" * 64
        with mock.patch.dict(os.environ, {"JAVELIN_EXPECTED_SHA256": bad_hash}, clear=False):
            self.assertFalse(anticheat.check_self_integrity(script_path=self.tmp_path))
            self.assertEqual(
                anticheat.run_guards(script_path=self.tmp_path),
                anticheat.EXIT_INTEGRITY_FAILED,
            )


if __name__ == "__main__":
    unittest.main()
