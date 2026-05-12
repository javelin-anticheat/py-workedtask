import unittest
from unittest import mock

import anti_cheat


class AntiCheatTests(unittest.TestCase):
    def test_normalizes_process_names(self):
        self.assertEqual(anti_cheat.normalize_process_name('"CheatEngine.EXE"'), "cheatengine.exe")

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

    @mock.patch("anti_cheat.is_debugger_attached", return_value=False)
    def test_run_checks_allows_clean_runtime(self, _debugger):
        result = anti_cheat.run_checks(["python.exe"])

        self.assertTrue(result.ok)
        self.assertEqual(result.exit_code, anti_cheat.EXIT_OK)


if __name__ == "__main__":
    unittest.main()
