import unittest

from anti_cheat import (
    EXIT_DEBUGGER_DETECTED,
    EXIT_SUSPICIOUS_PROCESS,
    detect_debugger,
    detect_suspicious_processes,
    enforce_anti_cheat,
)


class AntiCheatTests(unittest.TestCase):
    def test_detect_debugger_via_trace_win32_env_and_linux_tracer_pid(self):
        detected, reason = detect_debugger(
            trace_getter=lambda: object(),
            win32_checker=lambda: False,
            proc_status_text="Name:\tpython\nTracerPid:\t0\n",
            environ={},
        )
        self.assertTrue(detected)
        self.assertEqual(reason, "python_sys_gettrace")

        detected_env, reason_env = detect_debugger(
            trace_getter=lambda: None,
            win32_checker=lambda: False,
            proc_status_text="Name:\tpython\nTracerPid:\t0\n",
            environ={"DEBUGPY_RUNNING": "true"},
        )
        self.assertTrue(detected_env)
        self.assertEqual(reason_env, "env_debugpy_running")

        detected_w32, reason_w32 = detect_debugger(
            trace_getter=lambda: None,
            win32_checker=lambda: True,
            proc_status_text="Name:\tpython\nTracerPid:\t0\n",
            environ={},
        )
        self.assertTrue(detected_w32)
        self.assertEqual(reason_w32, "win32_debugger_api")

        detected_linux, reason_linux = detect_debugger(
            trace_getter=lambda: None,
            win32_checker=lambda: False,
            proc_status_text="Name:\tpython\nTracerPid:\t4129\n",
            environ={},
        )
        self.assertTrue(detected_linux)
        self.assertEqual(reason_linux, "linux_tracer_pid_4129")

        clean, clean_reason = detect_debugger(
            trace_getter=lambda: None,
            win32_checker=lambda: False,
            proc_status_text="Name:\tpython\nTracerPid:\t0\n",
            environ={},
        )
        self.assertFalse(clean)
        self.assertEqual(clean_reason, "clean")

    def test_detect_suspicious_processes_matches_cheat_engine_and_debuggers(self):
        running = ["explorer.exe", "chrome.exe", "CheatEngine-x86_64.exe", "x64dbg.exe", "ollydbg"]
        matched = detect_suspicious_processes(running_processes=running)
        self.assertEqual(matched, ["CheatEngine-x86_64.exe", "x64dbg.exe", "ollydbg"])

    def test_enforce_anti_cheat_exits_immediately_on_debugger_or_suspicious_process(self):
        exits: list[int] = []

        res_dbg = enforce_anti_cheat(
            running_processes=["explorer.exe"],
            trace_getter=lambda: None,
            win32_checker=lambda: True,
            environ={},
            exit_fn=lambda code: exits.append(code),
        )
        self.assertFalse(res_dbg["ok"])
        self.assertEqual(exits, [EXIT_DEBUGGER_DETECTED])

        exits.clear()
        res_proc = enforce_anti_cheat(
            running_processes=["explorer.exe", "ollydbg.exe"],
            trace_getter=lambda: None,
            win32_checker=lambda: False,
            proc_status_text="TracerPid:\t0\n",
            environ={},
            exit_fn=lambda code: exits.append(code),
        )
        self.assertFalse(res_proc["ok"])
        self.assertEqual(exits, [EXIT_SUSPICIOUS_PROCESS])

    def test_enforce_anti_cheat_passes_when_environment_is_clean(self):
        exits: list[int] = []
        res_ok = enforce_anti_cheat(
            running_processes=["explorer.exe", "python.exe"],
            trace_getter=lambda: None,
            win32_checker=lambda: False,
            proc_status_text="TracerPid:\t0\n",
            environ={},
            exit_fn=lambda code: exits.append(code),
        )
        self.assertTrue(res_ok["ok"])
        self.assertEqual(res_ok["exit_code"], 0)
        self.assertEqual(exits, [])


if __name__ == "__main__":
    unittest.main()
