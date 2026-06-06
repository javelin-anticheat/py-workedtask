# py-workedtask

A minimal Anti-Cheat guard system with debugger detection, suspicious process scanning, and self-integrity verification for both C++ and Python.

## Integrity Verification

To protect against tampering, both the C++ and Python clients support self-integrity verification.

### C++ Client
The C++ client computes the CRC32 of its own executable at runtime and compares it to a build-time constant (`JAVELIN_EXPECTED_CRC32`).

To enable this:
1. Compile the program normally.
2. Compute the CRC32 of the resulting executable.
3. Recompile the program, passing the computed CRC32 via the preprocessor definition.

Example (MSVC):
```bash
cl /EHsc /DJAVELIN_EXPECTED_CRC32=0x12345678 AntiCheat.cpp
```
Example (GCC/Clang):
```bash
c++ -std=c++17 -DJAVELIN_EXPECTED_CRC32=0x12345678 AntiCheat.cpp
```

### Python Monitor
The Python monitor computes the SHA-256 hash of its own script file (`anti_cheat.py`) and compares it against the environment variable `JAVELIN_EXPECTED_SHA256`.

To enable this:
1. Compute the SHA-256 hash of `anti_cheat.py`.
2. Set the `JAVELIN_EXPECTED_SHA256` environment variable to the computed hash before running the script.

Example (Linux/macOS):
```bash
export JAVELIN_EXPECTED_SHA256=$(shasum -a 256 anti_cheat.py | awk '{print $1}')
python3 anti_cheat.py
```

Example (Windows PowerShell):
```powershell
$hash = (Get-FileHash .\anti_cheat.py -Algorithm SHA256).Hash.ToLower()
$env:JAVELIN_EXPECTED_SHA256 = $hash
python anti_cheat.py
```
