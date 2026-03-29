import subprocess
import unittest
from unittest import mock

import anti_cheat


class AntiCheatTests(unittest.TestCase):
    def test_list_process_names_parses_tasklist_csv(self) -> None:
        sample = '"explorer.exe","1234","Console","1","11,000 K"\n"x64dbg.exe","999","Console","1","4,096 K"\n'
        with mock.patch.object(anti_cheat, "is_windows", return_value=True):
            self.assertEqual(
                anti_cheat.list_process_names(sample),
                ["explorer.exe", "x64dbg.exe"],
            )

    def test_list_process_names_returns_empty_off_windows(self) -> None:
        with mock.patch.object(anti_cheat, "is_windows", return_value=False):
            self.assertEqual(anti_cheat.list_process_names(""), [])

    def test_debugger_attached_uses_kernel32_on_windows(self) -> None:
        kernel32 = mock.Mock()
        kernel32.IsDebuggerPresent.return_value = 1
        with mock.patch.object(anti_cheat, "is_windows", return_value=True):
            self.assertTrue(anti_cheat.debugger_attached(kernel32=kernel32))

    def test_debugger_attached_is_false_off_windows(self) -> None:
        kernel32 = mock.Mock()
        kernel32.IsDebuggerPresent.return_value = 1
        with mock.patch.object(anti_cheat, "is_windows", return_value=False):
            self.assertFalse(anti_cheat.debugger_attached(kernel32=kernel32))

    def test_suspicious_process_found_detects_known_tool(self) -> None:
        found = anti_cheat.suspicious_process_found(["explorer.exe", "CheatEngine.exe"])
        self.assertEqual(found, "cheatengine.exe")

    def test_suspicious_process_found_returns_none_when_clean(self) -> None:
        self.assertIsNone(anti_cheat.suspicious_process_found(["explorer.exe", "python.exe"]))

    def test_run_checks_returns_debugger_exit_code(self) -> None:
        with mock.patch.object(anti_cheat, "debugger_attached", return_value=True):
            self.assertEqual(anti_cheat.run_checks(), anti_cheat.DEBUGGER_EXIT_CODE)

    def test_run_checks_returns_suspicious_process_exit_code(self) -> None:
        with mock.patch.object(anti_cheat, "debugger_attached", return_value=False):
            with mock.patch.object(
                anti_cheat,
                "suspicious_process_found",
                return_value="x64dbg.exe",
            ):
                self.assertEqual(
                    anti_cheat.run_checks(),
                    anti_cheat.SUSPICIOUS_PROCESS_EXIT_CODE,
                )

    def test_run_checks_returns_success_when_clean(self) -> None:
        with mock.patch.object(anti_cheat, "debugger_attached", return_value=False):
            with mock.patch.object(anti_cheat, "suspicious_process_found", return_value=None):
                self.assertEqual(anti_cheat.run_checks(), 0)

    def test_tasklist_command_failure_propagates(self) -> None:
        with mock.patch.object(anti_cheat, "is_windows", return_value=True):
            with mock.patch("anti_cheat.subprocess.run") as run:
                run.side_effect = subprocess.CalledProcessError(1, "tasklist")
                with self.assertRaises(subprocess.CalledProcessError):
                    anti_cheat.list_process_names()


if __name__ == "__main__":
    unittest.main()
