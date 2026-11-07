import unittest
from unittest.mock import patch
import python.anticheat as anticheat


class TestJavelinAntiCheat(unittest.TestCase):
    def test_detect_suspicious_process_matches_blacklist(self):
        procs = ["explorer.exe", "svchost.exe", "x64dbg.exe"]
        detected = anticheat.detect_suspicious_process(running_processes=procs)
        self.assertEqual(detected, "x64dbg.exe")

    def test_detect_suspicious_process_clean_list(self):
        procs = ["systemd", "bash", "python3"]
        detected = anticheat.detect_suspicious_process(running_processes=procs)
        self.assertIsNone(detected)

    def test_enforce_exits_when_debugger_present(self):
        with patch.object(anticheat, "is_debugger_present", return_value=True):
            with self.assertRaises(SystemExit) as ctx:
                anticheat.enforce_anticheat_guards(running_processes=["python3"])
            self.assertEqual(ctx.exception.code, anticheat.EXIT_CODE_DEBUGGER)

    def test_enforce_exits_when_suspicious_process_found(self):
        with patch.object(anticheat, "is_debugger_present", return_value=False):
            with self.assertRaises(SystemExit) as ctx:
                anticheat.enforce_anticheat_guards(
                    running_processes=["python3", "CheatEngine.exe"]
                )
            self.assertEqual(ctx.exception.code, anticheat.EXIT_CODE_SUSPICIOUS_PROCESS)

    def test_enforce_passes_when_clean(self):
        with patch.object(anticheat, "is_debugger_present", return_value=False):
            rc = anticheat.enforce_anticheat_guards(running_processes=["python3"])
            self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
