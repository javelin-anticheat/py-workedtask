# py-workedtask — Javelin Basic Anti-Cheat Protection

Minimal, self-contained Anti-Cheat protection guards in C++ (`AntiCheat.cpp`) and Python (`basic_anti_cheat.py`).

## Features

1. **Multi-Layer Debugger Detection**
   - **C++ (`AntiCheat.cpp`):** `IsDebuggerPresent()`, `CheckRemoteDebuggerPresent()`, and PEB `BeingDebugged` / `NtGlobalFlag` inspection.
   - **Python (`basic_anti_cheat.py`):** `sys.gettrace()`, Win32 `IsDebuggerPresent()` / `CheckRemoteDebuggerPresent()`, and Linux `/proc/self/status` `TracerPid` inspection.
2. **Suspicious Process Detection**
   - Scans active OS processes and immediately terminates if known reverse-engineering or memory-tampering tools are running (`Cheat Engine`, `x64dbg`, `x32dbg`, `OllyDbg`, `IDA`, `Scylla`, `Process Hacker`, `HTTPDebuggerUI`, `dnSpy`, `Ghidra`).
3. **Self-Integrity Verification**
   - CRC32 self-hash verification against tamper modifications.

## Usage

### Python Runtime Guard
```bash
python basic_anti_cheat.py
```

### Run Unit Tests
```bash
python -m unittest discover -v
```
