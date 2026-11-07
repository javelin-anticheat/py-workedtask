# py-workedtask

## Anti-Cheat Protection (#2)
- **C++ (`AntiCheat.cpp`)**: Debugger detection (`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, PEB `BeingDebugged`, Linux `/proc/self/status` `TracerPid`) and suspicious process scanning (`Cheat Engine`, `x64dbg`, `OllyDbg`, `IDA`, `Scylla`, `Process Hacker`).
- **Python (`python/anticheat.py` & `python/test_anticheat.py`)**: Cross-platform debugger and process guard that terminates immediately (`0xDEB` / `0xBAD`) on violation.
