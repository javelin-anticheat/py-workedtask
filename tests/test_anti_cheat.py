import tempfile
import unittest
from unittest import mock

import anti_cheat


class AntiCheatTests(unittest.TestCase):
    def test_normalizes_process_names(self):
        self.assertEqual(anti_cheat.normalize_process_name('"CheatEngine.EXE"'), "cheatengine.exe")

    def test_parses_tasklist_csv_output(self):
        output = '"Explorer.EXE","101"\n" x64dbg.exe ","202"\n'

        self.assertEqual(
            anti_cheat.parse_tasklist_csv(output),
            ["explorer.exe", "x64dbg.exe"],
        )

    @mock.patch("anti_cheat.platform.system", return_value="Windows")
    @mock.patch("anti_cheat.subprocess.check_output", side_effect=OSError)
    def test_process_scan_fails_closed_to_empty_list(self, _check_output, _system):
        self.assertEqual(anti_cheat.iter_windows_process_names(), [])

    def test_detects_known_suspicious_process(self):
        self.assertTrue(
            anti_cheat.has_suspicious_process(
                ["explorer.exe", "X64DBG.EXE"],
                suspicious_names=("x64dbg.exe",),
            )
        )

    def test_allows_clean_process_list(self):
        self.assertFalse(
            anti_cheat.has_suspicious_process(
                ["explorer.exe", "python.exe"],
                suspicious_names=("cheatengine.exe",),
            )
        )

    @mock.patch("anti_cheat.is_debugger_attached", return_value=True)
    def test_run_checks_exits_for_debugger(self, _debugger):
        result = anti_cheat.run_checks(["python.exe"])

        self.assertFalse(result.ok)
        self.assertEqual(result.exit_code, anti_cheat.EXIT_DEBUGGER)

    @mock.patch("anti_cheat.is_debugger_attached", return_value=False)
    def test_run_checks_exits_for_suspicious_process(self, _debugger):
        result = anti_cheat.run_checks(["cheatengine.exe"])

        self.assertFalse(result.ok)
        self.assertEqual(result.exit_code, anti_cheat.EXIT_SUSPICIOUS_PROCESS)

    def test_script_integrity_allows_missing_expected_hash(self):
        with tempfile.NamedTemporaryFile() as script:
            script.write(b"print('ok')\n")
            script.flush()

            self.assertTrue(anti_cheat.check_script_integrity(script.name, expected_sha256=""))

    def test_script_integrity_allows_matching_hash(self):
        with tempfile.NamedTemporaryFile() as script:
            script.write(b"print('ok')\n")
            script.flush()
            expected = anti_cheat.sha256_file(script.name)

            self.assertTrue(anti_cheat.check_script_integrity(script.name, expected))

    def test_script_integrity_rejects_mismatch(self):
        with tempfile.NamedTemporaryFile() as script:
            script.write(b"print('tampered')\n")
            script.flush()

            self.assertFalse(anti_cheat.check_script_integrity(script.name, "0" * 64))

    @mock.patch("anti_cheat.is_debugger_attached", return_value=False)
    def test_run_checks_exits_for_integrity_mismatch(self, _debugger):
        with tempfile.NamedTemporaryFile() as script:
            script.write(b"print('tampered')\n")
            script.flush()
            result = anti_cheat.run_checks(
                ["python.exe"],
                script_path=script.name,
                expected_sha256="0" * 64,
            )

        self.assertFalse(result.ok)
        self.assertEqual(result.exit_code, anti_cheat.EXIT_INTEGRITY)

    @mock.patch("anti_cheat.is_debugger_attached", return_value=False)
    def test_run_checks_allows_clean_runtime(self, _debugger):
        result = anti_cheat.run_checks(["python.exe"])

        self.assertTrue(result.ok)
        self.assertEqual(result.exit_code, anti_cheat.EXIT_OK)


if __name__ == "__main__":
    unittest.main()
