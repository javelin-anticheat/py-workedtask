# py-workedtask

Baseline anti-cheat protection for the Javelin project.

This repository now contains both runtime paths required by issue #2:

- `AntiCheat.cpp` — native C++ client guard.
- `anti_cheat.py` — dependency-free Python monitor.

Both paths perform the same baseline checks:

1. Detect an attached debugger and exit before the protected application continues.
2. Detect known cheat/debugging processes such as Cheat Engine, x64dbg, OllyDbg, IDA, Scylla, Process Hacker, Fiddler, Wireshark, and Ghidra.

## Python monitor

Run the monitor directly:

```bash
python3 anti_cheat.py
```

Machine-readable result:

```bash
python3 anti_cheat.py --json
```

Exit codes:

- `0` — all checks passed.
- `17` — debugger detected.
- `18` — suspicious process detected.
- `19` — monitor failed closed because a check could not run.

The Python implementation uses only the standard library. It checks Python debuggers via `sys.gettrace()`, Windows native debugging via `IsDebuggerPresent`, Linux native tracing via `/proc/self/status`, and process names through `tasklist` on Windows or `ps` on POSIX systems.

## C++ client

Build locally on POSIX systems:

```bash
c++ -std=c++17 -Wall -Wextra -pedantic AntiCheat.cpp -o /tmp/javelin-anticheat-check
/tmp/javelin-anticheat-check
```

Build on Windows with MSVC:

```powershell
cl /std:c++17 /EHsc AntiCheat.cpp
.\AntiCheat.exe
```

The C++ path uses Win32 process enumeration and debugger APIs on Windows. POSIX fallback code is included so the same source stays buildable and testable in CI and development environments.

## Tests

```bash
python3 -m unittest discover -s tests
c++ -std=c++17 -Wall -Wextra -pedantic AntiCheat.cpp -o /tmp/javelin-anticheat-check
/tmp/javelin-anticheat-check
```

The Python tests inject fake process lists and debugger probes so the anti-cheat exits are verified without needing to run real cheat tools or attach a debugger.
