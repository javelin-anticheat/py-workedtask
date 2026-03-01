#!/usr/bin/env python3
"""Tests for Javelin integrity verification."""

import hashlib
import os
import sys
import tempfile
import unittest

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from integrity_check import compute_file_sha256, verify_integrity


class TestComputeFileSHA256(unittest.TestCase):
    """Tests for compute_file_sha256."""

    def test_known_content(self):
        """Hash of known content should match expected value."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".txt") as f:
            f.write(b"hello world")
            path = f.name
        try:
            result = compute_file_sha256(path)
            expected = hashlib.sha256(b"hello world").hexdigest()
            self.assertEqual(result, expected)
        finally:
            os.unlink(path)

    def test_empty_file(self):
        """Hash of empty file should be SHA-256 of empty bytes."""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            path = f.name
        try:
            result = compute_file_sha256(path)
            expected = hashlib.sha256(b"").hexdigest()
            self.assertEqual(result, expected)
        finally:
            os.unlink(path)

    def test_nonexistent_file(self):
        """Should raise FileNotFoundError for missing files."""
        with self.assertRaises(FileNotFoundError):
            compute_file_sha256("/tmp/nonexistent_javelin_test_file_xyz")

    def test_large_file(self):
        """Should correctly hash files larger than the read buffer."""
        data = os.urandom(1024 * 1024)  # 1 MB
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            f.write(data)
            path = f.name
        try:
            result = compute_file_sha256(path)
            expected = hashlib.sha256(data).hexdigest()
            self.assertEqual(result, expected)
        finally:
            os.unlink(path)


class TestVerifyIntegrity(unittest.TestCase):
    """Tests for verify_integrity."""

    def setUp(self):
        """Create a temp file for testing."""
        self.content = b"test script content for javelin"
        self.tmpfile = tempfile.NamedTemporaryFile(
            mode="wb", delete=False, suffix=".py"
        )
        self.tmpfile.write(self.content)
        self.tmpfile.close()
        self.expected_hash = hashlib.sha256(self.content).hexdigest()

    def tearDown(self):
        os.unlink(self.tmpfile.name)
        # Clean env var if set
        os.environ.pop("JAVELIN_EXPECTED_SHA256", None)

    def test_matching_hash(self):
        """Should return True when hash matches."""
        os.environ["JAVELIN_EXPECTED_SHA256"] = self.expected_hash
        self.assertTrue(verify_integrity(self.tmpfile.name))

    def test_mismatching_hash(self):
        """Should return False when hash does not match."""
        os.environ["JAVELIN_EXPECTED_SHA256"] = "a" * 64
        self.assertFalse(verify_integrity(self.tmpfile.name))

    def test_no_env_var(self):
        """Should return True (skip) when env var is not set."""
        os.environ.pop("JAVELIN_EXPECTED_SHA256", None)
        self.assertTrue(verify_integrity(self.tmpfile.name))

    def test_case_insensitive(self):
        """Should match hashes case-insensitively."""
        os.environ["JAVELIN_EXPECTED_SHA256"] = self.expected_hash.upper()
        self.assertTrue(verify_integrity(self.tmpfile.name))

    def test_whitespace_trimmed(self):
        """Should trim whitespace from env var value."""
        os.environ["JAVELIN_EXPECTED_SHA256"] = f"  {self.expected_hash}  \n"
        self.assertTrue(verify_integrity(self.tmpfile.name))

    def test_tampered_file(self):
        """Should detect file modification."""
        os.environ["JAVELIN_EXPECTED_SHA256"] = self.expected_hash
        # Tamper with the file
        with open(self.tmpfile.name, "ab") as f:
            f.write(b"TAMPERED")
        self.assertFalse(verify_integrity(self.tmpfile.name))

    def test_missing_file_path(self):
        """Should return False for a missing file."""
        os.environ["JAVELIN_EXPECTED_SHA256"] = self.expected_hash
        self.assertFalse(verify_integrity("/tmp/does_not_exist_javelin_xyz"))


if __name__ == "__main__":
    unittest.main()
