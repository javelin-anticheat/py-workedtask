# py-workedtask

Minimal Javelin anti-cheat examples for C++ and Python.

## C++ integrity check

`AntiCheat.cpp` supports debugger detection, suspicious-process detection, and an optional CRC32 self-integrity check for the running executable.

Build once without an expected CRC:

```powershell
cl /EHsc AntiCheat.cpp /Fe:JavelinAntiCheat.exe
```

Print the normalized CRC32 for that build:

```powershell
.\JavelinAntiCheat.exe --print-integrity-crc32
```

Rebuild with the expected CRC:

```powershell
cl /EHsc /DJAVELIN_EXPECTED_CRC32=0x12345678 AntiCheat.cpp /Fe:JavelinAntiCheat.exe
```

Replace `0x12345678` with the value printed by the first build. At runtime, if the executable has been modified and the CRC no longer matches, the program exits before continuing.

The embedded expected CRC bytes are normalized before hashing. This avoids the circular problem where changing the expected CRC value changes the executable hash.

## Python integrity check

`AntiCheat.py` supports an optional SHA-256 integrity check of the script file.

Print the expected SHA-256:

```powershell
python AntiCheat.py --print-integrity-sha256
```

Run with integrity checking enabled:

```powershell
$env:JAVELIN_EXPECTED_SHA256 = "paste-the-64-character-sha256-here"
python AntiCheat.py
```

If `JAVELIN_EXPECTED_SHA256` is unset, the Python integrity check is skipped. If it is set and does not match the current script file, the script exits with a guarded integrity failure.
