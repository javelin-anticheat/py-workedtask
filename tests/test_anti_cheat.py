import sys
import unittest
from unittest import mock

import anti_cheat
from anti_cheat import ExitCode


class AntiCheatMonitorTests(unittest.TestCase):
    def test_suspicious_process_detection_matches_known_tools(self):
        process_names = ["WindowServer", "/tmp/CheatEngine.exe", "python3"]

        self.assertTrue(anti_cheat.has_suspicious_process(process_names))

    def test_suspicious_process_detection_allows_clean_process_list(self):
        process_names = ["launchd", "python3", "node"]

        self.assertFalse(anti_cheat.has_suspicious_process(process_names))

    def test_debugger_detection_uses_python_trace_hook(self):
        with mock.patch.object(sys, "gettrace", return_value=lambda *_: None):
            self.assertTrue(anti_cheat.is_debugger_attached())

    def test_run_checks_returns_debugger_exit_code_first(self):
        with mock.patch.object(anti_cheat, "is_debugger_attached", return_value=True):
            result = anti_cheat.run_checks(["cheatengine.exe"])

        self.assertFalse(result.ok)
        self.assertEqual(result.exit_code, ExitCode.DEBUGGER_DETECTED)

    def test_run_checks_returns_suspicious_process_exit_code(self):
        with mock.patch.object(anti_cheat, "is_debugger_attached", return_value=False):
            result = anti_cheat.run_checks(["x64dbg.exe"])

        self.assertFalse(result.ok)
        self.assertEqual(result.exit_code, ExitCode.SUSPICIOUS_PROCESS_DETECTED)

    def test_run_checks_allows_clean_environment(self):
        with mock.patch.object(anti_cheat, "is_debugger_attached", return_value=False):
            result = anti_cheat.run_checks(["python3", "node"])

        self.assertTrue(result.ok)
        self.assertEqual(result.exit_code, ExitCode.OK)

    def test_main_exits_with_detection_code(self):
        result = anti_cheat.CheckResult(
            ok=False,
            exit_code=ExitCode.SUSPICIOUS_PROCESS_DETECTED,
            message="Suspicious process detected",
        )
        with mock.patch.object(anti_cheat, "run_checks", return_value=result):
            self.assertEqual(anti_cheat.main(), int(ExitCode.SUSPICIOUS_PROCESS_DETECTED))


if __name__ == "__main__":
    unittest.main()
