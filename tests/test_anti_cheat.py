import hashlib
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import anti_cheat


class AntiCheatMonitorTests(unittest.TestCase):
    def test_suspicious_process_matching_is_case_insensitive_and_path_safe(self):
        self.assertTrue(anti_cheat.is_suspicious_process_name(r"C:\Tools\X64DBG.EXE"))
        self.assertTrue(anti_cheat.is_suspicious_process_name("/opt/tools/cheatengine"))
        self.assertFalse(anti_cheat.is_suspicious_process_name("/usr/bin/python3"))

    def test_parse_process_names_from_posix_output(self):
        with mock.patch.object(anti_cheat.os, "name", "posix"):
            self.assertEqual(
                anti_cheat._parse_process_names("python3\nx64dbg\n\n"),
                ["python3", "x64dbg"],
            )

    def test_list_process_names_uses_runner_output(self):
        def fake_runner(*args, **kwargs):
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="python3\nida64\n", stderr="")

        with mock.patch.object(anti_cheat.os, "name", "posix"):
            self.assertEqual(anti_cheat.list_process_names(runner=fake_runner), ["python3", "ida64"])

    def test_has_suspicious_process_detects_known_tool(self):
        self.assertTrue(anti_cheat.has_suspicious_process(["python3", "processhacker.exe"]))
        self.assertFalse(anti_cheat.has_suspicious_process(["python3", "node"]))

    def test_self_integrity_accepts_matching_sha256(self):
        with TemporaryDirectory() as tmpdir:
            script = Path(tmpdir) / "anti_cheat.py"
            script.write_text("print('ok')\n", encoding="utf-8")
            expected = hashlib.sha256(script.read_bytes()).hexdigest()

            self.assertTrue(anti_cheat.check_self_integrity(expected, script))

    def test_self_integrity_rejects_mismatch_and_malformed_hash(self):
        with TemporaryDirectory() as tmpdir:
            script = Path(tmpdir) / "anti_cheat.py"
            script.write_text("print('tampered')\n", encoding="utf-8")

            self.assertFalse(anti_cheat.check_self_integrity("0" * 64, script))
            self.assertFalse(anti_cheat.check_self_integrity("not-a-sha", script))

    def test_run_checks_stops_on_debugger(self):
        with mock.patch.object(anti_cheat, "is_debugger_attached", return_value=True):
            result = anti_cheat.run_checks()

        self.assertFalse(result.ok)
        self.assertEqual(result.exit_code, anti_cheat.EXIT_DEBUGGER)

    def test_run_checks_stops_on_suspicious_process(self):
        with mock.patch.object(anti_cheat, "is_debugger_attached", return_value=False), mock.patch.object(
            anti_cheat, "has_suspicious_process", return_value=True
        ):
            result = anti_cheat.run_checks()

        self.assertFalse(result.ok)
        self.assertEqual(result.exit_code, anti_cheat.EXIT_SUSPICIOUS_PROCESS)

    def test_run_checks_stops_on_integrity_failure(self):
        with mock.patch.object(anti_cheat, "is_debugger_attached", return_value=False), mock.patch.object(
            anti_cheat, "has_suspicious_process", return_value=False
        ), mock.patch.object(anti_cheat, "check_self_integrity", return_value=False):
            result = anti_cheat.run_checks()

        self.assertFalse(result.ok)
        self.assertEqual(result.exit_code, anti_cheat.EXIT_INTEGRITY)

    def test_run_checks_all_clear(self):
        with mock.patch.object(anti_cheat, "is_debugger_attached", return_value=False), mock.patch.object(
            anti_cheat, "has_suspicious_process", return_value=False
        ), mock.patch.object(anti_cheat, "check_self_integrity", return_value=True):
            result = anti_cheat.run_checks()

        self.assertTrue(result.ok)
        self.assertEqual(result.exit_code, 0)


if __name__ == "__main__":
    unittest.main()
