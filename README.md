# py-workedtask

Minimal anti-cheat guards for the Javelin Project.

## C++ client

`AntiCheat.cpp` checks for:

- an attached debugger
- known suspicious process names
- optional executable integrity via `JAVELIN_EXPECTED_CRC32`

Build once without `JAVELIN_EXPECTED_CRC32`, then print the integrity CRC for
that build artifact:

```powershell
cl /std:c++17 /EHsc AntiCheat.cpp /Fe:AntiCheat.exe
.\AntiCheat.exe --print-integrity-crc32
```

Rebuild with the returned value:

```powershell
cl /std:c++17 /EHsc /DJAVELIN_EXPECTED_CRC32=0x12345678 AntiCheat.cpp /Fe:AntiCheat.exe
```

When `JAVELIN_EXPECTED_CRC32` is non-zero, a mismatch exits with code `0x0C0D`.
Leaving it as `0u` disables the integrity check.

## Python monitor

`anti_cheat.py` enables script integrity checks through
`JAVELIN_EXPECTED_SHA256`.

Print the expected SHA-256 value:

```sh
python - <<'PY'
from pathlib import Path
from anti_cheat import sha256_file
print(sha256_file(Path("anti_cheat.py")))
PY
```

Run with the expected value:

```sh
JAVELIN_EXPECTED_SHA256=<64-character sha256> python anti_cheat.py
```

If the script hash does not match, the monitor exits with code `13`. If
`JAVELIN_EXPECTED_SHA256` is unset or empty, the integrity check is disabled.

## Tests

```sh
python -m unittest discover -s tests
python -m py_compile anti_cheat.py tests/test_anti_cheat.py
```
