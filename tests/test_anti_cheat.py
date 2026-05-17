import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import anti_cheat


class AntiCheatMonitorTests(unittest.TestCase):
    def test_parse_tasklist_csv_extracts_names(self):
        output = '"python.exe","123","Console","1","10,000 K"\n"x64dbg.exe","99","Console","1","5,000 K"'

        self.assertEqual(anti_cheat.parse_tasklist_csv(output), ["python.exe", "x64dbg.exe"])

    def test_find_suspicious_process_matches_case_insensitively(self):
        match = anti_cheat.find_suspicious_process(["Explorer.EXE", "CheatEngine.exe"])

        self.assertEqual(match, "cheatengine.exe")

    def test_find_suspicious_process_returns_none_for_clean_list(self):
        self.assertIsNone(anti_cheat.find_suspicious_process(["python.exe", "game.exe"]))

    def test_integrity_check_allows_missing_expected_hash(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertTrue(anti_cheat.verify_script_integrity(Path(__file__)))

    def test_integrity_check_accepts_matching_hash(self):
        with tempfile.NamedTemporaryFile(delete=False) as temp:
            temp.write(b"trusted script")
            temp_path = Path(temp.name)

        try:
            expected = anti_cheat.sha256_file(temp_path)
            self.assertTrue(anti_cheat.verify_script_integrity(temp_path, expected))
        finally:
            temp_path.unlink(missing_ok=True)

    def test_integrity_check_rejects_mismatch(self):
        with tempfile.NamedTemporaryFile(delete=False) as temp:
            temp.write(b"tampered script")
            temp_path = Path(temp.name)

        try:
            self.assertFalse(anti_cheat.verify_script_integrity(temp_path, "0" * 64))
        finally:
            temp_path.unlink(missing_ok=True)

    def test_integrity_check_rejects_malformed_expected_hash(self):
        self.assertFalse(anti_cheat.verify_script_integrity(Path(__file__), "not-a-sha"))

    def test_run_checks_exits_on_debugger(self):
        with mock.patch("anti_cheat.is_debugger_present", return_value=True):
            code = anti_cheat.run_checks(process_names=[])

        self.assertEqual(code, anti_cheat.EXIT_DEBUGGER)

    def test_run_checks_exits_on_suspicious_process(self):
        with mock.patch("anti_cheat.is_debugger_present", return_value=False):
            code = anti_cheat.run_checks(process_names=["x64dbg.exe"])

        self.assertEqual(code, anti_cheat.EXIT_SUSPICIOUS_PROCESS)

    def test_run_checks_exits_on_integrity_failure(self):
        with mock.patch("anti_cheat.is_debugger_present", return_value=False), mock.patch(
            "anti_cheat.verify_script_integrity", return_value=False
        ):
            code = anti_cheat.run_checks(process_names=[])

        self.assertEqual(code, anti_cheat.EXIT_INTEGRITY_FAILURE)

    def test_run_checks_returns_zero_when_all_clear(self):
        with mock.patch("anti_cheat.is_debugger_present", return_value=False), mock.patch(
            "anti_cheat.verify_script_integrity", return_value=True
        ):
            code = anti_cheat.run_checks(process_names=["python.exe"])

        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
