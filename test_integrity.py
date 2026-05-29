from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from AntiCheat import (
    EXIT_INTEGRITY_FAILURE,
    EXPECTED_SHA256_ENV,
    check_script_integrity,
    run_integrity_guard,
)


class IntegrityTests(unittest.TestCase):
    def test_missing_expected_hash_disables_python_integrity_check(self) -> None:
        with tempfile.NamedTemporaryFile(delete=False) as file:
            script_path = Path(file.name)
            file.write(b"print('untagged build')\n")

        self.addCleanup(script_path.unlink)

        with mock.patch.dict("os.environ", {EXPECTED_SHA256_ENV: ""}, clear=False):
            self.assertTrue(check_script_integrity(script_path))

    def test_matching_sha256_allows_python_script(self) -> None:
        with tempfile.NamedTemporaryFile(delete=False) as file:
            script_path = Path(file.name)
            payload = b"print('release build')\n"
            file.write(payload)

        self.addCleanup(script_path.unlink)

        expected_hash = hashlib.sha256(payload).hexdigest().upper()
        self.assertTrue(check_script_integrity(script_path, expected_hash))

    def test_non_matching_sha256_causes_guarded_exit(self) -> None:
        with tempfile.NamedTemporaryFile(delete=False) as file:
            script_path = Path(file.name)
            file.write(b"print('tampered build')\n")

        self.addCleanup(script_path.unlink)

        with mock.patch.dict("os.environ", {EXPECTED_SHA256_ENV: "0" * 64}, clear=False):
            with self.assertRaises(SystemExit) as error:
                run_integrity_guard(script_path)

        self.assertEqual(error.exception.code, EXIT_INTEGRITY_FAILURE)


if __name__ == "__main__":
    unittest.main()
