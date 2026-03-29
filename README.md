# py-workedtask

Minimal anti-cheat guards for the Javelin project.

## Included protections

- `AntiCheat.cpp`: debugger detection plus suspicious process scanning for the native client.
- `anti_cheat.py`: debugger detection plus suspicious process scanning for the Python monitor.

Known suspicious tools currently blocked in both paths:

- `cheatengine.exe`
- `ollydbg.exe`
- `x64dbg.exe`
- `httpdebuggerui.exe`
- `ida.exe`
- `ida64.exe`
- `scylla.exe`
- `processhacker.exe`

## Run the Python monitor

```powershell
python anti_cheat.py
```

Exit codes:

- `0x6B` when a debugger is detected
- `0x6C` when a suspicious process is detected

## Test the Python monitor

```powershell
python -m unittest discover -s . -p "test_*.py" -v
```

## Build the C++ client

Example with MSVC:

```powershell
cl /EHsc AntiCheat.cpp
```
