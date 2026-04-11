import importlib
import unittest


class AntiCheatTests(unittest.TestCase):
    def test_module_exists(self):
        importlib.import_module("anti_cheat")

    def test_debugger_detection_exits(self):
        anti_cheat = importlib.import_module("anti_cheat")
        code = anti_cheat.run_checks(
            debugger_check=lambda: True,
            process_check=lambda: False,
        )
        self.assertEqual(code, anti_cheat.EXIT_DEBUGGER_DETECTED)

    def test_suspicious_process_detection_exits(self):
        anti_cheat = importlib.import_module("anti_cheat")
        code = anti_cheat.run_checks(
            debugger_check=lambda: False,
            process_check=lambda: True,
        )
        self.assertEqual(code, anti_cheat.EXIT_SUSPICIOUS_PROCESS)

    def test_clean_environment_passes(self):
        anti_cheat = importlib.import_module("anti_cheat")
        code = anti_cheat.run_checks(
            debugger_check=lambda: False,
            process_check=lambda: False,
        )
        self.assertEqual(code, anti_cheat.EXIT_OK)

    def test_tasklist_parser_normalizes_names(self):
        anti_cheat = importlib.import_module("anti_cheat")
        output = '"CheatEngine.exe","123","Console","1","10,000 K"\n"x64dbg.exe","456","Console","1","8,000 K"\n'
        self.assertEqual(
            anti_cheat.parse_tasklist_output(output),
            ["cheatengine.exe", "x64dbg.exe"],
        )

    def test_suspicious_process_match_is_case_insensitive(self):
        anti_cheat = importlib.import_module("anti_cheat")
        self.assertTrue(anti_cheat.has_suspicious_process(["CheatEngine.exe"]))
        self.assertFalse(anti_cheat.has_suspicious_process(["explorer.exe"]))


if __name__ == "__main__":
    unittest.main()
