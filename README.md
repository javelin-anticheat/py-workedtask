# py-workedtask

Minimal Javelin anti-cheat guards for C++ and Python.

## C++ Integrity Verification

`AntiCheat.cpp` supports an optional executable integrity check. Build once, compute
the CRC32 of the shipped executable, then embed it in production builds:

```powershell
cl /std:c++17 /EHsc /DJAVELIN_EXPECTED_CRC32=0x12345678 AntiCheat.cpp
```

When `JAVELIN_EXPECTED_CRC32` is left as `0`, the integrity check is disabled.
When it is set and the running executable hash does not match, the guard exits
with a non-zero integrity failure code.

## Python Integrity Verification

`AntiCheat.py` supports an optional SHA-256 integrity check for the running
script. Set `JAVELIN_EXPECTED_SHA256` to the expected lowercase or uppercase
SHA-256 digest:

```powershell
$env:JAVELIN_EXPECTED_SHA256 = "expected_sha256_hex_digest"
python AntiCheat.py
```

When `JAVELIN_EXPECTED_SHA256` is unset or empty, the integrity check is
disabled. When it is set and the script hash does not match, the guard exits
with a non-zero integrity failure code.

## Tests

```powershell
python -m pytest
```
