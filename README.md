# py-workedtask

Minimal Javelin anti-cheat examples for C++ and Python.

## Integrity verification

Integrity checks are optional. If the expected value is not configured, the guard is skipped.

### C++ executable CRC32

`AntiCheat.cpp` can verify the running executable with a build-time CRC32 value.

1. Build once without an expected CRC:

   ```powershell
   cl /EHsc AntiCheat.cpp
   ```

2. Print the normalized CRC32 for that executable:

   ```powershell
   .\AntiCheat.exe --print-crc32
   ```

3. Rebuild with the printed value:

   ```powershell
   cl /EHsc /DJAVELIN_EXPECTED_CRC32=0x12345678 AntiCheat.cpp
   ```

When `JAVELIN_EXPECTED_CRC32` is non-zero, a mismatch prints an integrity failure message and exits with a guarded non-zero code.

### Python script SHA-256

`AntiCheat.py` verifies its script file when `JAVELIN_EXPECTED_SHA256` is set.

PowerShell:

```powershell
$env:JAVELIN_EXPECTED_SHA256 = (Get-FileHash .\AntiCheat.py -Algorithm SHA256).Hash.ToLower()
python .\AntiCheat.py
```

POSIX shell:

```sh
export JAVELIN_EXPECTED_SHA256="$(python -c "import hashlib, pathlib; print(hashlib.sha256(pathlib.Path('AntiCheat.py').read_bytes()).hexdigest())")"
python AntiCheat.py
```

If `JAVELIN_EXPECTED_SHA256` is absent, the Python guard is skipped. If it is set and does not match the script SHA-256, the script prints an integrity failure message and exits non-zero.
