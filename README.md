# py-workedtask

Minimal Javelin anti-cheat guards for both the C++ client and the Python monitor.

## Features

- C++ debugger detection with `IsDebuggerPresent` and `CheckRemoteDebuggerPresent`.
- C++ suspicious process detection for common cheat/debug tools.
- Optional C++ executable integrity verification with build-time CRC32.
- Python debugger detection with `sys.gettrace()` and `IsDebuggerPresent` on Windows.
- Python suspicious process detection using Windows `tasklist`.
- Optional Python script integrity verification with `JAVELIN_EXPECTED_SHA256`.

## C++ Client

Build on Windows with a C++17 compiler:

```powershell
cl /std:c++17 /EHsc AntiCheat.cpp
```

To enable executable integrity checks, compile once, calculate the CRC32 for the shipped executable, then rebuild with the expected value:

```powershell
cl /std:c++17 /EHsc /DJAVELIN_EXPECTED_CRC32=0x12345678 AntiCheat.cpp
```

When `JAVELIN_EXPECTED_CRC32` is left as `0`, the CRC guard is disabled and the debugger/process guards still run.

## Python Monitor

Run the monitor directly:

```powershell
python anti_cheat.py
```

To enable script integrity checks, calculate the SHA-256 of `anti_cheat.py` and export it before running:

```powershell
$env:JAVELIN_EXPECTED_SHA256 = (Get-FileHash .\anti_cheat.py -Algorithm SHA256).Hash.ToLower()
python anti_cheat.py
```

If `JAVELIN_EXPECTED_SHA256` is unset, the Python integrity guard is skipped. If it is set and the script hash does not match, the monitor exits with a guarded non-zero code.

## Tests

```powershell
python -m unittest discover -s tests
```
