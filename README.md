# py-workedtask

Minimal Javelin anti-cheat guards with optional self-integrity checks.

## C++ executable integrity

`AntiCheat.cpp` computes CRC32 over the running executable and compares it to
the optional `JAVELIN_EXPECTED_CRC32` build-time constant. The guard is disabled
when the constant is left at `0u`.

Build with MSVC and an expected CRC32 value:

```powershell
cl /EHsc /std:c++17 /DJAVELIN_EXPECTED_CRC32=0x12345678 AntiCheat.cpp
```

If the executable CRC32 does not match, the process exits before continuing.

## Python script integrity

`AntiCheat.py` computes SHA-256 over the Python script file and compares it to
the `JAVELIN_EXPECTED_SHA256` environment variable. The guard is disabled when
the environment variable is unset or empty.

Set the expected SHA-256 value before launching the script:

```powershell
$env:JAVELIN_EXPECTED_SHA256 = "expected_sha256_hex_digest"
python AntiCheat.py
```

If the script SHA-256 does not match, the process exits with a guarded failure.

## Tests

Run the Python integrity tests with:

```powershell
python -m unittest test_integrity.py
```
