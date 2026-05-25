# py-workedtask

Minimal Javelin anti-cheat examples for C++ and Python.

## C++ integrity verification

`AntiCheat.cpp` includes an optional self-integrity check. By default the check is disabled. Build with `JAVELIN_EXPECTED_CRC32` set to the expected CRC32 for the shipped executable to enable guarded exit on tampering.

Example MSVC flow:

```powershell
cl /EHsc AntiCheat.cpp
.\AntiCheat.exe
```

After producing a release build, calculate the executable CRC32 with your release tooling and rebuild with the value embedded:

```powershell
cl /EHsc /DJAVELIN_EXPECTED_CRC32=0x12345678 AntiCheat.cpp
```

When the embedded value is non-zero and the running executable hash does not match, the program exits through the integrity-failure guard.

## Python integrity verification

`anti_cheat.py` checks its own SHA-256 when `JAVELIN_EXPECTED_SHA256` is present. Without the environment variable, the integrity check is skipped so local development remains simple.

Calculate the expected hash:

```powershell
python -c "import hashlib, pathlib; print(hashlib.sha256(pathlib.Path('anti_cheat.py').read_bytes()).hexdigest())"
```

Run with the expected hash:

```powershell
$env:JAVELIN_EXPECTED_SHA256 = "<sha256 from previous command>"
python anti_cheat.py
```

If the file changes after the expected hash is set, `anti_cheat.py` prints an integrity-failure message and exits with a guarded non-zero status.
