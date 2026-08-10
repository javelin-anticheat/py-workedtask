import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import anti_cheat


class IntegrityVerificationTests(unittest.TestCase):
    def test_sha256_file_and_integrity_match(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            script = Path(temp_dir) / "sample.py"
            script.write_bytes(b"print('original')\n")

            expected = anti_cheat.sha256_file(script)

            self.assertEqual(
                expected,
                "bc1301140376ba45d85f23da83fcad2c78a9931fda9ca74e8e9696031b033e24",
            )
            self.assertTrue(anti_cheat.check_script_integrity(script, expected))

    def test_integrity_check_detects_modified_script(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            script = Path(temp_dir) / "sample.py"
            script.write_bytes(b"print('original')\n")
            expected = anti_cheat.sha256_file(script)

            script.write_bytes(b"print('modified')\n")

            self.assertFalse(anti_cheat.check_script_integrity(script, expected))

    def test_expected_hash_is_optional_and_normalized(self) -> None:
        self.assertIsNone(anti_cheat.expected_script_sha256({}))
        self.assertIsNone(
            anti_cheat.expected_script_sha256(
                {anti_cheat.EXPECTED_HASH_ENV: "  "}
            )
        )
        self.assertEqual(
            anti_cheat.expected_script_sha256(
                {anti_cheat.EXPECTED_HASH_ENV: "A" * 64}
            ),
            "a" * 64,
        )

    def test_expected_hash_rejects_invalid_value(self) -> None:
        with self.assertRaisesRegex(ValueError, "64 hex characters"):
            anti_cheat.expected_script_sha256(
                {anti_cheat.EXPECTED_HASH_ENV: "not-a-sha256"}
            )

    def test_main_accepts_matching_hash(self) -> None:
        expected = anti_cheat.sha256_file(Path(anti_cheat.__file__).resolve())
        output = io.StringIO()

        with patch.dict(
            os.environ,
            {anti_cheat.EXPECTED_HASH_ENV: expected},
        ), redirect_stdout(output):
            result = anti_cheat.main([])

        self.assertEqual(result, 0)
        self.assertIn("All clear", output.getvalue())

    def test_main_guards_on_mismatch(self) -> None:
        errors = io.StringIO()

        with patch.dict(
            os.environ,
            {anti_cheat.EXPECTED_HASH_ENV: "0" * 64},
        ), redirect_stderr(errors):
            result = anti_cheat.main([])

        self.assertEqual(result, anti_cheat.INTEGRITY_FAILURE_EXIT_CODE)
        self.assertIn("SHA-256 mismatch", errors.getvalue())

    def test_print_hash_ignores_configured_expected_hash(self) -> None:
        output = io.StringIO()

        with patch.dict(
            os.environ,
            {anti_cheat.EXPECTED_HASH_ENV: "invalid"},
        ), redirect_stdout(output):
            result = anti_cheat.main(["--print-sha256"])

        self.assertEqual(result, 0)
        self.assertEqual(
            output.getvalue().strip(),
            anti_cheat.sha256_file(Path(anti_cheat.__file__).resolve()),
        )


if __name__ == "__main__":
    unittest.main()
